use std::{
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::{Component, Path, PathBuf},
    time::{Duration as StdDuration, SystemTime},
};

use axum::http::StatusCode;
use chrono::{Duration, Timelike, Utc};
use rusqlite::{params, TransactionBehavior, MAIN_DB};
use serde_json::json;
use tokio::fs as async_fs;
use uuid::Uuid;

use crate::{
    db::{blocking, internal_error, read_database, read_only, write_database},
    model::{AppError, AppResult},
    AppState,
};

const RETENTION_HOUR_UTC: u32 = 3;

#[derive(Debug, Default)]
struct RetentionReport {
    usage_logs: usize,
    tasks: usize,
    sessions: usize,
    ip_locations: usize,
    audit_logs: usize,
    backups: usize,
}

impl RetentionReport {
    fn database_changes(&self) -> usize {
        self.usage_logs + self.tasks + self.sessions + self.ip_locations + self.audit_logs
    }
}

pub fn spawn_daily(state: AppState) {
    tokio::spawn(async move {
        // 首次部署默认 dry-run，立即输出候选数量，便于确认策略后再开启删除。
        if state.config.retention_dry_run {
            if let Err(error) = run_once(&state).await {
                tracing::error!(error = %error, "data retention task failed");
            }
        }
        loop {
            tokio::time::sleep(next_run_delay(Utc::now())).await;
            if let Err(error) = run_once(&state).await {
                tracing::error!(error = %error, "data retention task failed");
            }
        }
    });
}

fn next_run_delay(now: chrono::DateTime<Utc>) -> StdDuration {
    let today = now
        .with_hour(RETENTION_HOUR_UTC)
        .and_then(|value| value.with_minute(0))
        .and_then(|value| value.with_second(0))
        .and_then(|value| value.with_nanosecond(0))
        .expect("retention hour is valid");
    let next = if today > now {
        today
    } else {
        today + Duration::days(1)
    };
    (next - now)
        .to_std()
        .unwrap_or_else(|_| StdDuration::from_secs(24 * 60 * 60))
}

async fn run_once(state: &AppState) -> AppResult<RetentionReport> {
    let now = Utc::now();
    let usage_cutoff = (now - Duration::days(state.config.usage_retention_days)).to_rfc3339();
    let task_cutoff = (now - Duration::days(state.config.task_retention_days)).to_rfc3339();
    let ip_cutoff = (now - Duration::days(state.config.ip_location_retention_days)).to_rfc3339();
    let audit_cutoff = (now - Duration::days(state.config.audit_retention_days)).to_rfc3339();
    let now_text = now.to_rfc3339();

    let mut report = read_database(&state.db, |connection| {
        Ok(RetentionReport {
            usage_logs: connection
                .query_row(
                    "SELECT COUNT(*) FROM usage_logs WHERE created_at < ?1",
                    [&usage_cutoff],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)? as usize,
            tasks: connection
                .query_row(
                    "SELECT COUNT(*) FROM tasks
                     WHERE status IN ('success', 'error') AND updated_at < ?1",
                    [&task_cutoff],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)? as usize,
            sessions: connection
                .query_row(
                    "SELECT COUNT(*) FROM sessions
                     WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                    [&now_text],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)? as usize,
            ip_locations: connection
                .query_row(
                    "SELECT COUNT(*) FROM ip_locations WHERE updated_at < ?1",
                    [&ip_cutoff],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)? as usize,
            audit_logs: connection
                .query_row(
                    "SELECT COUNT(*) FROM admin_audit_logs WHERE created_at < ?1",
                    [&audit_cutoff],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)? as usize,
            backups: 0,
        })
    })?;
    report.backups = expired_backup_paths(
        &state.config.data_directory.join("backups"),
        state.config.backup_retention_count,
    )
    .await?
    .len();

    if state.config.retention_dry_run {
        log_report(&report, true);
        return Ok(report);
    }

    if report.database_changes() > 0 {
        let backup = create_database_backup(state).await?;
        tracing::info!(path = %backup.display(), "retention database backup created");
    }
    if report.audit_logs > 0 {
        let archive = archive_audit_logs(state, &audit_cutoff)?;
        tracing::info!(path = %archive.display(), "admin audit archive created");
    }

    let task_ids = read_database(&state.db, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT id FROM tasks
                 WHERE status IN ('success', 'error') AND updated_at < ?1",
            )
            .map_err(internal_error)?;
        let task_ids = statement
            .query_map([&task_cutoff], |row| row.get::<_, String>(0))
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(task_ids)
    })?;
    let task_ids = cleanup_task_directories(&state.config.task_directory, task_ids).await;
    report.tasks = task_ids.len();

    if report.database_changes() > 0 {
        apply_database_retention(
            state,
            &usage_cutoff,
            &now_text,
            &ip_cutoff,
            &audit_cutoff,
            &task_ids,
        )?;
    }
    report.backups = remove_expired_backups(
        &state.config.data_directory.join("backups"),
        state.config.backup_retention_count,
    )
    .await?;
    log_report(&report, false);
    Ok(report)
}

fn log_report(report: &RetentionReport, dry_run: bool) {
    tracing::info!(
        dry_run,
        usage_logs = report.usage_logs,
        tasks = report.tasks,
        sessions = report.sessions,
        ip_locations = report.ip_locations,
        audit_logs = report.audit_logs,
        backups = report.backups,
        "data retention completed"
    );
}

async fn create_database_backup(state: &AppState) -> AppResult<PathBuf> {
    let directory = state.config.data_directory.join("backups");
    async_fs::create_dir_all(&directory)
        .await
        .map_err(|error| retention_error("create backup directory", error))?;
    let path = directory.join(format!(
        "lumora-retention-{}-{}.db",
        Utc::now().format("%Y%m%d%H%M%S"),
        Uuid::new_v4().simple()
    ));
    let result = write_database(&state.db, |connection| {
        connection
            .backup(MAIN_DB, &path, None)
            .map_err(internal_error)
    });
    if result.is_err() {
        let _ = async_fs::remove_file(&path).await;
    }
    result?;
    Ok(path)
}

fn archive_audit_logs(state: &AppState, cutoff: &str) -> AppResult<PathBuf> {
    let directory = state.config.data_directory.join("audit-archives");
    let final_path = directory.join(format!(
        "admin-audit-before-{}-{}.jsonl",
        Utc::now().format("%Y%m%d%H%M%S"),
        Uuid::new_v4().simple()
    ));
    let temporary_path = final_path.with_extension("jsonl.tmp");

    blocking(|| {
        let result = (|| -> AppResult<()> {
            fs::create_dir_all(&directory)
                .map_err(|error| retention_error("create audit archive directory", error))?;
            let connection = read_only(&state.db)?;
            let mut statement = connection
                .prepare(
                    "SELECT id, admin_user_id, action, target_type, target_id, detail, created_at
                     FROM admin_audit_logs WHERE created_at < ?1 ORDER BY created_at",
                )
                .map_err(internal_error)?;
            let mut rows = statement.query([cutoff]).map_err(internal_error)?;
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path)
                .map_err(|error| retention_error("create audit archive", error))?;
            let mut writer = BufWriter::new(file);
            while let Some(row) = rows.next().map_err(internal_error)? {
                let item = json!({
                    "id": row.get::<_, String>(0).map_err(internal_error)?,
                    "adminUserId": row.get::<_, String>(1).map_err(internal_error)?,
                    "action": row.get::<_, String>(2).map_err(internal_error)?,
                    "targetType": row.get::<_, String>(3).map_err(internal_error)?,
                    "targetId": row.get::<_, String>(4).map_err(internal_error)?,
                    "detail": row.get::<_, String>(5).map_err(internal_error)?,
                    "createdAt": row.get::<_, String>(6).map_err(internal_error)?,
                });
                serde_json::to_writer(&mut writer, &item)
                    .map_err(|error| retention_error("write audit archive", error))?;
                writer
                    .write_all(b"\n")
                    .map_err(|error| retention_error("write audit archive", error))?;
            }
            writer
                .flush()
                .map_err(|error| retention_error("flush audit archive", error))?;
            writer
                .get_ref()
                .sync_all()
                .map_err(|error| retention_error("sync audit archive", error))?;
            drop(writer);
            fs::rename(&temporary_path, &final_path)
                .map_err(|error| retention_error("publish audit archive", error))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result?;
        Ok(final_path)
    })
}

async fn cleanup_task_directories(base: &Path, task_ids: Vec<String>) -> Vec<String> {
    let mut removable = Vec::with_capacity(task_ids.len());
    for id in task_ids {
        let Some(path) = direct_child(base, &id) else {
            tracing::error!(task_id = id, "unsafe task directory name rejected");
            continue;
        };
        match async_fs::remove_dir_all(path).await {
            Ok(()) => removable.push(id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => removable.push(id),
            Err(error) => {
                tracing::error!(task_id = id, error = %error, "task directory cleanup failed");
            }
        }
    }
    removable
}

fn direct_child(base: &Path, name: &str) -> Option<PathBuf> {
    // 数据库内容损坏时也不能让清理任务越过 task_directory 删除任意目录。
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Some(base.join(name)),
        _ => None,
    }
}

fn apply_database_retention(
    state: &AppState,
    usage_cutoff: &str,
    now: &str,
    ip_cutoff: &str,
    audit_cutoff: &str,
    task_ids: &[String],
) -> AppResult<()> {
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        transaction
            .execute(
                "INSERT INTO usage_daily_summary (
                   summary_date, user_id, provider_id, endpoint, model, status,
                   request_count, total_duration_ms, total_credits_used
                 )
                 SELECT substr(created_at, 1, 10), user_id, COALESCE(provider_id, ''),
                        endpoint, model, status, COUNT(*),
                        COALESCE(SUM(duration_ms), 0), COALESCE(SUM(credits_used), 0)
                 FROM usage_logs WHERE created_at < ?1
                 GROUP BY substr(created_at, 1, 10), user_id, COALESCE(provider_id, ''),
                          endpoint, model, status
                 ON CONFLICT(summary_date, user_id, provider_id, endpoint, model, status)
                 DO UPDATE SET
                   request_count = usage_daily_summary.request_count + excluded.request_count,
                   total_duration_ms = usage_daily_summary.total_duration_ms + excluded.total_duration_ms,
                   total_credits_used = usage_daily_summary.total_credits_used + excluded.total_credits_used",
                [usage_cutoff],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "DELETE FROM usage_logs WHERE created_at < ?1",
                [usage_cutoff],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                [now],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "DELETE FROM ip_locations WHERE updated_at < ?1",
                [ip_cutoff],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "DELETE FROM admin_audit_logs WHERE created_at < ?1",
                [audit_cutoff],
            )
            .map_err(internal_error)?;
        for id in task_ids {
            transaction
                .execute(
                    "DELETE FROM tasks
                     WHERE id = ?1 AND status IN ('success', 'error')",
                    params![id],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(internal_error)?;
        Ok(())
    })
}

async fn expired_backup_paths(directory: &Path, keep: usize) -> AppResult<Vec<PathBuf>> {
    let mut entries = match async_fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(retention_error("read backup directory", error)),
    };
    let mut backups = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| retention_error("read backup directory", error))?
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("lumora-") || !name.ends_with(".db") {
            continue;
        }
        let metadata = entry
            .metadata()
            .await
            .map_err(|error| retention_error("read backup metadata", error))?;
        if metadata.is_file() {
            backups.push((
                metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                name.into_owned(),
                entry.path(),
            ));
        }
    }
    backups.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    Ok(backups
        .into_iter()
        .skip(keep)
        .map(|(_, _, path)| path)
        .collect())
}

async fn remove_expired_backups(directory: &Path, keep: usize) -> AppResult<usize> {
    let paths = expired_backup_paths(directory, keep).await?;
    let mut removed = 0;
    for path in paths {
        match async_fs::remove_file(&path).await {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::error!(path = %path.display(), error = %error, "old backup cleanup failed");
            }
        }
    }
    Ok(removed)
}

fn retention_error(action: &'static str, error: impl std::fmt::Display) -> AppError {
    tracing::error!(action, error = %error, "retention file operation failed");
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据保留任务失败".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        db::{database, open_database},
        presence::PresenceThrottle,
    };
    use reqwest::Client;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::Semaphore;

    fn test_state(dry_run: bool) -> (TempDir, AppState) {
        let directory = tempfile::tempdir().unwrap();
        let image_directory = directory.path().join("images");
        let task_directory = directory.path().join("tasks");
        fs::create_dir_all(&image_directory).unwrap();
        fs::create_dir_all(&task_directory).unwrap();
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_directory: directory.path().to_path_buf(),
            image_directory,
            task_directory,
            static_directory: directory.path().join("static"),
            production: false,
            master_key: [7_u8; 32],
            worker_concurrency: 1,
            support_email: None,
            support_wechat: None,
            retention_dry_run: dry_run,
            usage_retention_days: 90,
            task_retention_days: 7,
            ip_location_retention_days: 30,
            audit_retention_days: 365,
            backup_retention_count: 5,
            metrics_token_hash: None,
        };
        let state = AppState {
            db: open_database(directory.path(), &[7_u8; 32]).unwrap(),
            client: Client::new(),
            config,
            task_semaphore: Arc::new(Semaphore::new(1)),
            presence: PresenceThrottle::new(),
        };
        (directory, state)
    }

    fn insert_retention_fixtures(state: &AppState) {
        let old = (Utc::now() - Duration::days(400)).to_rfc3339();
        let recent = Utc::now().to_rfc3339();
        let future = (Utc::now() + Duration::days(1)).to_rfc3339();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits, created_at, is_admin
                 ) VALUES ('user-1', 'Test', 'test@example.test', 'hash', '', 'Free', 100, ?1, 1)",
                [&recent],
            )
            .unwrap();
        for (id, created_at) in [("usage-old", &old), ("usage-recent", &recent)] {
            connection
                .execute(
                    "INSERT INTO usage_logs (
                       id, user_id, endpoint, model, status, duration_ms, credits_used, created_at
                     ) VALUES (?1, 'user-1', '/v1/images/generations', 'test-model',
                               'success', 25, 2, ?2)",
                    params![id, created_at],
                )
                .unwrap();
        }
        for (id, status) in [("task-old", "success"), ("task-running", "running")] {
            connection
                .execute(
                    "INSERT INTO tasks (
                       id, user_id, kind, status, request_json, credits_reserved,
                       credits_used, created_at, updated_at
                     ) VALUES (?1, 'user-1', 'generation', ?2, '{}', 1, 0, ?3, ?3)",
                    params![id, status, old],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('expired', 'user-1', ?1, ?1), ('active', 'user-1', ?1, ?2)",
                params![old, future],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ip_locations (ip, location, isp, updated_at)
                 VALUES ('203.0.113.1', 'old', '', ?1), ('203.0.113.2', 'new', '', ?2)",
                params![old, recent],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO admin_audit_logs (
                   id, admin_user_id, action, target_type, target_id, detail, created_at
                 ) VALUES ('audit-old', 'user-1', 'test', 'user', 'user-1', '{}', ?1)",
                [&old],
            )
            .unwrap();
        drop(connection);
        fs::create_dir_all(state.config.task_directory.join("task-old")).unwrap();
        fs::write(
            state
                .config
                .task_directory
                .join("task-old")
                .join("input.png"),
            b"test",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn dry_run_reports_without_deleting() {
        let (_directory, state) = test_state(true);
        insert_retention_fixtures(&state);

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.usage_logs, 1);
        assert_eq!(report.tasks, 1);
        assert!(state.config.task_directory.join("task-old").exists());
        assert_eq!(
            database(&state.db)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM usage_logs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert!(!state.config.data_directory.join("audit-archives").exists());
    }

    #[tokio::test]
    async fn live_run_aggregates_archives_and_deletes_only_expired_data() {
        let (_directory, state) = test_state(false);
        insert_retention_fixtures(&state);
        let backup_directory = state.config.data_directory.join("backups");
        fs::create_dir_all(&backup_directory).unwrap();
        for index in 0..7 {
            fs::write(
                backup_directory.join(format!("lumora-test-{index}.db")),
                b"test",
            )
            .unwrap();
        }

        run_once(&state).await.unwrap();

        let connection = database(&state.db).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM usage_logs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT request_count, total_duration_ms, total_credits_used
                     FROM usage_daily_summary",
                    [],
                    |row| Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?
                    )),
                )
                .unwrap(),
            (1, 25, 2)
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM ip_locations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM admin_audit_logs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(connection);

        assert!(!state.config.task_directory.join("task-old").exists());
        let archives = fs::read_dir(state.config.data_directory.join("audit-archives"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert!(fs::read_to_string(archives[0].path())
            .unwrap()
            .contains("audit-old"));
        let backups = fs::read_dir(backup_directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(backups.len(), 5);
    }

    #[test]
    fn task_directory_must_be_a_direct_child() {
        let base = Path::new("tasks");
        assert_eq!(direct_child(base, "task-1"), Some(base.join("task-1")));
        assert_eq!(direct_child(base, "../outside"), None);
        assert_eq!(direct_child(base, "nested/task"), None);
        assert_eq!(direct_child(base, ""), None);
    }

    #[test]
    fn schedules_live_retention_at_three_utc() {
        use chrono::TimeZone;

        let before = Utc.with_ymd_and_hms(2026, 8, 5, 2, 0, 0).unwrap();
        assert_eq!(next_run_delay(before), StdDuration::from_secs(60 * 60));

        let after = Utc.with_ymd_and_hms(2026, 8, 5, 4, 0, 0).unwrap();
        assert_eq!(next_run_delay(after), StdDuration::from_secs(23 * 60 * 60));
    }
}
