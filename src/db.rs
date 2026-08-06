use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Instant,
};

use chrono::Utc;
use rusqlite::{params, Connection, OpenFlags, MAIN_DB};

use crate::{
    classification::{classify_prompt, CATEGORY_VERSION},
    model::{AppError, AppResult},
    security::{encrypt_secret, key_parts},
};
use axum::http::StatusCode;

const SCHEMA_VERSION: i64 = 11;
const MIN_READERS: usize = 2;
const MAX_READERS: usize = 8;

/// 数据库句柄。
///
/// SQLite 只允许单个写者，因此写连接始终是全局唯一的一把锁；
/// 读连接来自一个按需增长的池，WAL 模式下可与写者并发执行（OPT-01）。
#[derive(Clone)]
pub struct Database {
    inner: Arc<DatabaseInner>,
}

struct DatabaseInner {
    path: PathBuf,
    write: Mutex<Connection>,
    readers: Mutex<ReaderPool>,
    reader_available: Condvar,
    max_readers: usize,
}

struct ReaderPool {
    idle: Vec<Connection>,
    open: usize,
}

/// 从池中借出的只读连接，析构时归还。
pub struct ReadConnection {
    connection: Option<Connection>,
    inner: Arc<DatabaseInner>,
}

impl Deref for ReadConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("read connection taken before drop")
    }
}

impl Drop for ReadConnection {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        let mut readers = self
            .inner
            .readers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        readers.idle.push(connection);
        self.inner.reader_available.notify_one();
    }
}

fn reader_count() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(MIN_READERS)
        .clamp(MIN_READERS, MAX_READERS)
}

fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_millis(5000))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "query_only", "ON")?;
    Ok(connection)
}

pub fn open_database(
    data_directory: &Path,
    master_key: &[u8; 32],
) -> Result<Database, Box<dyn std::error::Error>> {
    let path = data_directory.join("lumora.db");
    if path.exists() {
        let connection = Connection::open(&path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < SCHEMA_VERSION {
            let backup_directory = data_directory.join("backups");
            fs::create_dir_all(&backup_directory)?;
            let backup =
                backup_directory.join(format!("lumora-{}.db", Utc::now().format("%Y%m%d%H%M%S")));
            // 在线备份会包含尚未 checkpoint 的 WAL 页面，直接复制主文件可能得到不完整快照。
            connection.backup(MAIN_DB, backup, None)?;
        }
    }

    let mut connection = Connection::open(&path)?;
    initialize_database(&mut connection)?;
    migrate_provider_secrets(&mut connection, master_key)?;
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(Database {
        inner: Arc::new(DatabaseInner {
            path,
            write: Mutex::new(connection),
            readers: Mutex::new(ReaderPool {
                idle: Vec::new(),
                open: 0,
            }),
            reader_available: Condvar::new(),
            max_readers: reader_count(),
        }),
    })
}

/// 取得写连接。全局串行——所有事务与写操作都必须走这里。
pub fn database(db: &Database) -> AppResult<MutexGuard<'_, Connection>> {
    db.inner
        .write
        .lock()
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库不可用".into()))
}

/// 取得只读连接。可并行，禁止用于任何写操作。
pub fn read_only(db: &Database) -> AppResult<ReadConnection> {
    loop {
        let mut readers = db
            .inner
            .readers
            .lock()
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库不可用".into()))?;
        if let Some(connection) = readers.idle.pop() {
            return Ok(ReadConnection {
                connection: Some(connection),
                inner: Arc::clone(&db.inner),
            });
        }
        if readers.open < db.inner.max_readers {
            // 先占用名额再开连接，避免并发请求同时越过上限造成连接数失控。
            readers.open += 1;
            drop(readers);
            return match open_reader(&db.inner.path) {
                Ok(connection) => Ok(ReadConnection {
                    connection: Some(connection),
                    inner: Arc::clone(&db.inner),
                }),
                Err(error) => {
                    let mut readers = db.inner.readers.lock().map_err(|_| {
                        AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库不可用".into())
                    })?;
                    readers.open -= 1;
                    db.inner.reader_available.notify_one();
                    Err(internal_error(error))
                }
            };
        }
        let readers = db
            .inner
            .reader_available
            .wait(readers)
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库不可用".into()))?;
        drop(readers);
    }
}

/// 在阻塞线程上执行同步数据库操作（OPT-02）。
///
/// rusqlite 是同步阻塞的，直接在 async handler 里调用会独占一个 tokio worker
/// 直到查询返回。多线程 runtime 下用 `block_in_place` 把同 worker 上的其他任务
/// 迁走；单线程 runtime（`#[tokio::test]` 默认）不支持该调用，直接执行。
///
/// 可重入：handler 之间会互相调用（如 `admin_user` → `user_from_headers`），
/// 嵌套进入时直接执行，不再重复 `block_in_place`。
pub fn blocking<T>(operation: impl FnOnce() -> T) -> T {
    use std::cell::Cell;
    use tokio::runtime::{Handle, RuntimeFlavor};

    thread_local! {
        static IN_BLOCKING_SECTION: Cell<bool> = const { Cell::new(false) };
    }

    struct SectionGuard;

    impl Drop for SectionGuard {
        fn drop(&mut self) {
            IN_BLOCKING_SECTION.with(|flag| flag.set(false));
        }
    }

    let already_blocking = IN_BLOCKING_SECTION.with(Cell::get);
    let multi_thread = matches!(
        Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(RuntimeFlavor::MultiThread)
    );
    if already_blocking || !multi_thread {
        return operation();
    }
    tokio::task::block_in_place(|| {
        IN_BLOCKING_SECTION.with(|flag| flag.set(true));
        let _guard = SectionGuard;
        operation()
    })
}

pub fn read_database<T>(
    db: &Database,
    operation: impl FnOnce(&Connection) -> AppResult<T>,
) -> AppResult<T> {
    let started = Instant::now();
    // 调用方只描述数据库逻辑，阻塞线程切换与只读连接归还统一在边界内完成。
    let result = blocking(|| {
        let connection = read_only(db)?;
        operation(&connection)
    });
    metrics::histogram!("lumora_db_operation_duration_seconds", "operation" => "read")
        .record(started.elapsed().as_secs_f64());
    result
}

pub fn write_database<T>(
    db: &Database,
    operation: impl FnOnce(&mut Connection) -> AppResult<T>,
) -> AppResult<T> {
    let started = Instant::now();
    // 写事务必须始终经过唯一写连接，避免调用点绕开 SQLite 单写者约束。
    let result = blocking(|| {
        let mut connection = database(db)?;
        operation(&mut connection)
    });
    metrics::histogram!("lumora_db_operation_duration_seconds", "operation" => "write")
        .record(started.elapsed().as_secs_f64());
    result
}

pub fn utc_day_bounds(now: chrono::DateTime<Utc>) -> (String, String) {
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end = start + chrono::Duration::days(1);
    (start.to_rfc3339(), end.to_rfc3339())
}

fn initialize_database(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA synchronous = NORMAL;
         CREATE TABLE IF NOT EXISTS users (
           id TEXT PRIMARY KEY,
           name TEXT NOT NULL,
           email TEXT NOT NULL UNIQUE,
           password_hash TEXT NOT NULL,
           avatar TEXT NOT NULL,
           plan TEXT NOT NULL,
           credits INTEGER NOT NULL,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sessions (
           token TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS email_verifications (
           email TEXT PRIMARY KEY,
           code_hash TEXT NOT NULL,
           expires_at TEXT NOT NULL,
           last_sent_at TEXT NOT NULL,
           attempts INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS api_keys (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           name TEXT NOT NULL,
           key_value TEXT NOT NULL UNIQUE,
           scope TEXT NOT NULL,
           status TEXT NOT NULL,
           created_at TEXT NOT NULL,
           last_used TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS providers (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           name TEXT NOT NULL,
           base_url TEXT NOT NULL,
           api_key TEXT NOT NULL,
           model TEXT NOT NULL,
           is_active INTEGER NOT NULL DEFAULT 0,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS images (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           file_name TEXT NOT NULL UNIQUE,
           prompt TEXT NOT NULL,
           size TEXT NOT NULL,
           model TEXT NOT NULL,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS announcements (
           id TEXT PRIMARY KEY,
           title TEXT NOT NULL,
           content TEXT NOT NULL,
           date TEXT NOT NULL,
           type TEXT NOT NULL,
           is_new INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS usage_logs (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           provider_id TEXT REFERENCES providers(id) ON DELETE SET NULL,
           endpoint TEXT NOT NULL,
           model TEXT NOT NULL,
           status TEXT NOT NULL,
           duration_ms INTEGER NOT NULL,
           credits_used INTEGER NOT NULL,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS tasks (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           kind TEXT NOT NULL,
           status TEXT NOT NULL,
           request_json TEXT NOT NULL,
           image_id TEXT REFERENCES images(id) ON DELETE SET NULL,
           error TEXT,
           credits_reserved INTEGER NOT NULL DEFAULT 1,
           credits_used INTEGER NOT NULL DEFAULT 0,
           created_at TEXT NOT NULL,
           updated_at TEXT NOT NULL,
           confirmed_at TEXT
         );
         CREATE TABLE IF NOT EXISTS devices (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           platform TEXT NOT NULL,
           app_version TEXT NOT NULL,
           first_seen_at TEXT NOT NULL,
           last_seen_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS activity_days (
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           activity_date TEXT NOT NULL,
           last_seen_at TEXT NOT NULL,
           PRIMARY KEY (user_id, activity_date)
         );
         CREATE TABLE IF NOT EXISTS credit_ledger (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           delta INTEGER NOT NULL,
           balance_after INTEGER NOT NULL,
           reason TEXT NOT NULL,
           reference_id TEXT NOT NULL UNIQUE,
           operator_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS admin_audit_logs (
           id TEXT PRIMARY KEY,
           admin_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           action TEXT NOT NULL,
           target_type TEXT NOT NULL,
           target_id TEXT NOT NULL,
           detail TEXT NOT NULL,
           created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS system_settings (
           key TEXT PRIMARY KEY,
           value INTEGER NOT NULL,
           updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS ip_locations (
           ip TEXT PRIMARY KEY,
           location TEXT NOT NULL,
           isp TEXT NOT NULL,
           updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS login_attempts (
           scope TEXT PRIMARY KEY,
           failures INTEGER NOT NULL DEFAULT 0,
           locked_until TEXT,
           updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS usage_daily_summary (
           summary_date TEXT NOT NULL,
           user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           provider_id TEXT NOT NULL DEFAULT '',
           endpoint TEXT NOT NULL,
           model TEXT NOT NULL,
           status TEXT NOT NULL,
           request_count INTEGER NOT NULL,
           total_duration_ms INTEGER NOT NULL,
           total_credits_used INTEGER NOT NULL,
           PRIMARY KEY (summary_date, user_id, provider_id, endpoint, model, status)
         );
         CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
         CREATE INDEX IF NOT EXISTS idx_images_user_created ON images(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage_logs(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_tasks_user_created ON tasks(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_devices_user_seen ON devices(user_id, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_activity_date ON activity_days(activity_date);
         CREATE INDEX IF NOT EXISTS idx_credit_ledger_user_created
           ON credit_ledger(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_admin_audit_created
           ON admin_audit_logs(created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_usage_summary_user_date
           ON usage_daily_summary(user_id, summary_date DESC);",
    )?;

    add_column(
        connection,
        "users",
        "credits_reserved",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column(
        connection,
        "users",
        "daily_limit",
        "INTEGER NOT NULL DEFAULT 10000",
    )?;
    add_column(
        connection,
        "users",
        "status",
        "TEXT NOT NULL DEFAULT 'active'",
    )?;
    add_column(
        connection,
        "users",
        "is_admin",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column(connection, "users", "last_login_at", "TEXT")?;
    add_column(connection, "users", "last_seen_at", "TEXT")?;
    add_column(connection, "sessions", "expires_at", "TEXT")?;
    add_column(connection, "api_keys", "key_hash", "TEXT")?;
    add_column(connection, "api_keys", "key_prefix", "TEXT")?;
    add_column(connection, "api_keys", "key_suffix", "TEXT")?;
    add_column(
        connection,
        "api_keys",
        "is_legacy",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    add_column(connection, "providers", "api_key_cipher", "TEXT")?;
    add_column(connection, "providers", "key_prefix", "TEXT")?;
    add_column(connection, "providers", "key_suffix", "TEXT")?;
    add_column(
        connection,
        "providers",
        "encryption_version",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column(
        connection,
        "providers",
        "is_global",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column(
        connection,
        "images",
        "visibility",
        "TEXT NOT NULL DEFAULT 'private'",
    )?;
    add_column(
        connection,
        "images",
        "format",
        "TEXT NOT NULL DEFAULT 'png'",
    )?;
    add_column(
        connection,
        "images",
        "category",
        "TEXT NOT NULL DEFAULT '其他'",
    )?;
    add_column(
        connection,
        "images",
        "category_version",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column(
        connection,
        "images",
        "storage",
        "TEXT NOT NULL DEFAULT 'server'",
    )?;
    add_column(
        connection,
        "images",
        "device_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "images",
        "reference_files",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    add_column(
        connection,
        "images",
        "usage_log_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "ip_address",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "device_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "platform",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "app_version",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "user_agent",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "prompt",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    add_column(
        connection,
        "usage_logs",
        "error",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_images_public_storage_created
         ON images(visibility, storage, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_images_usage_log
           ON images(usage_log_id);
         CREATE INDEX IF NOT EXISTS idx_usage_created
           ON usage_logs(created_at DESC);
         INSERT OR IGNORE INTO system_settings (key, value, updated_at)
           VALUES ('registration_credits', 3000, CURRENT_TIMESTAMP);
         INSERT OR IGNORE INTO system_settings (key, value, updated_at)
           VALUES ('default_daily_limit', 10000, CURRENT_TIMESTAMP);
         UPDATE usage_logs
         SET prompt = COALESCE((
           SELECT image.prompt FROM images image
           WHERE image.usage_log_id = usage_logs.id
           ORDER BY image.created_at, image.id LIMIT 1
         ), '')
         WHERE prompt = '';
         INSERT OR IGNORE INTO credit_ledger (
           id, user_id, delta, balance_after, reason, reference_id, created_at
         )
         SELECT 'opening-' || id, id, credits, credits, 'opening_balance',
                'opening:' || id, created_at
         FROM users
         WHERE NOT EXISTS (
           SELECT 1 FROM credit_ledger WHERE credit_ledger.user_id = users.id
         );",
    )?;
    reclassify_images(connection)?;

    Ok(())
}

fn reclassify_images(connection: &mut Connection) -> rusqlite::Result<()> {
    let images = {
        let mut statement =
            connection.prepare("SELECT id, prompt FROM images WHERE category_version < ?1")?;
        let rows = statement.query_map([CATEGORY_VERSION], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let transaction = connection.transaction()?;
    for (id, prompt) in images {
        transaction.execute(
            "UPDATE images SET category = ?1, category_version = ?2 WHERE id = ?3",
            params![classify_prompt(&prompt), CATEGORY_VERSION, id],
        )?;
    }
    transaction.commit()
}

fn migrate_provider_secrets(
    connection: &mut Connection,
    master_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let transaction = connection.transaction()?;
    let providers = {
        let mut statement = transaction.prepare(
            "SELECT id, api_key FROM providers
             WHERE encryption_version = 0 AND api_key <> ''",
        )?;
        let providers = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        providers
    };
    for (id, api_key) in providers {
        let encrypted = encrypt_secret(master_key, &api_key)?;
        let (prefix, suffix) = key_parts(&api_key);
        transaction.execute(
            "UPDATE providers
             SET api_key = '', api_key_cipher = ?1, key_prefix = ?2, key_suffix = ?3,
                 encryption_version = 1
             WHERE id = ?4",
            params![encrypted, prefix, suffix, id],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn add_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == column);
    if !exists {
        connection.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))?;
    }
    Ok(())
}

pub fn internal_error(error: rusqlite::Error) -> AppError {
    tracing::error!(error = %error, "database operation failed");
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库操作失败".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::decrypt_secret;
    use tempfile::tempdir;

    #[test]
    fn serves_concurrent_readers_alongside_a_writer() {
        let directory = tempdir().unwrap();
        let db = open_database(directory.path(), &[3_u8; 32]).unwrap();
        database(&db)
            .unwrap()
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits, created_at
                 ) VALUES ('pool-user', 'Pool', 'pool@example.test', 'hash', '', 'Free', 1, ?1)",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();

        // 多个只读连接可同时持有——旧的全局单连接做不到这一点。
        let reader_count = db.inner.max_readers;
        let readers = (0..reader_count)
            .map(|_| read_only(&db).unwrap())
            .collect::<Vec<_>>();
        for reader in &readers {
            let count: i64 = reader
                .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }

        // 写连接在读连接持有期间仍可提交（WAL 模式）。
        database(&db)
            .unwrap()
            .execute("UPDATE users SET credits = 2 WHERE id = 'pool-user'", [])
            .unwrap();

        // 归还后连接进入空闲池，不会无限增长。
        drop(readers);
        assert_eq!(db.inner.readers.lock().unwrap().idle.len(), reader_count);
        let reused = read_only(&db).unwrap();
        assert_eq!(
            db.inner.readers.lock().unwrap().idle.len(),
            reader_count - 1
        );
        drop(reused);
        assert_eq!(db.inner.readers.lock().unwrap().idle.len(), reader_count);
    }

    #[test]
    fn rejects_writes_on_read_only_connections() {
        let directory = tempdir().unwrap();
        let db = open_database(directory.path(), &[3_u8; 32]).unwrap();
        let reader = read_only(&db).unwrap();
        let result = reader.execute("DELETE FROM users", []);
        assert!(result.is_err(), "read-only connection accepted a write");
    }

    #[test]
    fn usage_count_range_uses_user_created_index() {
        let directory = tempdir().unwrap();
        let db = open_database(directory.path(), &[3_u8; 32]).unwrap();
        let connection = database(&db).unwrap();
        let details = connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT COUNT(*) FROM usage_logs
                 WHERE user_id = ?1 AND created_at >= ?2 AND created_at < ?3",
            )
            .unwrap()
            .query_map(
                params![
                    "user-1",
                    "2026-08-05T00:00:00+00:00",
                    "2026-08-06T00:00:00+00:00"
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("idx_usage_user_created")),
            "query plan did not use idx_usage_user_created: {details:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_sections_nest_without_panicking() {
        let value = blocking(|| blocking(|| blocking(|| 7)));
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn blocking_runs_inline_on_single_threaded_runtime() {
        assert_eq!(blocking(|| 11), 11);
    }

    #[test]
    fn migrates_and_backs_up_legacy_database() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("lumora.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (
                   id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
                   password_hash TEXT NOT NULL, avatar TEXT NOT NULL, plan TEXT NOT NULL,
                   credits INTEGER NOT NULL, created_at TEXT NOT NULL
                 );
                 INSERT INTO users VALUES (
                   'legacy-user', 'Legacy', 'legacy@example.test', 'hash', '', 'Free', 12,
                   '2026-01-01T00:00:00Z'
                 );
                 CREATE TABLE providers (
                   id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                   base_url TEXT NOT NULL, api_key TEXT NOT NULL, model TEXT NOT NULL,
                   is_active INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
                 );
                 INSERT INTO providers VALUES (
                   'legacy-provider', 'legacy-user', 'Legacy Provider',
                   'https://example.test/v1', 'legacy-provider-key', 'gpt-image-2', 1,
                   '2026-01-01T00:00:00Z'
                 );",
            )
            .unwrap();
        drop(connection);

        let master_key = [7_u8; 32];
        let db = open_database(directory.path(), &master_key).unwrap();
        let connection = database(&db).unwrap();
        let user: (i64, i64) = connection
            .query_row(
                "SELECT credits, credits_reserved FROM users WHERE id = 'legacy-user'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(user, (12, 0));
        let provider: (String, String, String, String, i64) = connection
            .query_row(
                "SELECT api_key, api_key_cipher, key_prefix, key_suffix, encryption_version
                 FROM providers WHERE id = 'legacy-provider'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert!(provider.0.is_empty());
        assert_eq!(
            decrypt_secret(&master_key, &provider.1).unwrap(),
            "legacy-provider-key"
        );
        assert_eq!(
            (provider.2.as_str(), provider.3.as_str()),
            ("legacy-pr", "-key")
        );
        assert_eq!(provider.4, 1);
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        drop(connection);

        let backups = fs::read_dir(directory.path().join("backups"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn does_not_duplicate_registration_credits_on_restart() {
        let directory = tempdir().unwrap();
        let master_key = [9_u8; 32];
        let db = open_database(directory.path(), &master_key).unwrap();
        database(&db)
            .unwrap()
            .execute_batch(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits, created_at
                 ) VALUES (
                   'registered-user', 'Registered', 'registered@example.test',
                   'hash', '', 'Free', 3000, '2026-01-01T00:00:00Z'
                 );
                 INSERT INTO credit_ledger (
                   id, user_id, delta, balance_after, reason, reference_id, created_at
                 ) VALUES (
                   'registration-credit', 'registered-user', 3000, 3000,
                   'registration_grant', 'registration:registered-user',
                   '2026-01-01T00:00:00Z'
                 );",
            )
            .unwrap();
        drop(db);

        let db = open_database(directory.path(), &master_key).unwrap();
        let count = database(&db)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM credit_ledger WHERE user_id = 'registered-user'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn reclassifies_existing_images_after_rule_upgrade() {
        let directory = tempdir().unwrap();
        let master_key = [3_u8; 32];
        let db = open_database(directory.path(), &master_key).unwrap();
        database(&db)
            .unwrap()
            .execute_batch(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits, created_at
                 ) VALUES (
                   'category-user', 'Category', 'category@example.test',
                   'hash', '', 'Free', 1, '2026-01-01T00:00:00Z'
                 );
                 INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   category, category_version
                 ) VALUES (
                   'category-image', 'category-user', 'category.png',
                   '一只在咖啡杯旁打盹的橘猫', '1024x1024', 'gpt-image-2',
                   '2026-01-01T00:00:00Z', '其他', 0
                 );",
            )
            .unwrap();
        drop(db);

        let db = open_database(directory.path(), &master_key).unwrap();
        let category: (String, i64) = database(&db)
            .unwrap()
            .query_row(
                "SELECT category, category_version FROM images WHERE id = 'category-image'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(category, ("动物宠物".into(), CATEGORY_VERSION));
    }
}
