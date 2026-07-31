use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use chrono::Utc;
use rusqlite::{params, Connection};

use crate::{
    model::{AppError, AppResult},
    security::{encrypt_secret, key_parts},
};
use axum::http::StatusCode;

pub type Database = Arc<Mutex<Connection>>;
const SCHEMA_VERSION: i64 = 6;

pub fn open_database(
    data_directory: &Path,
    master_key: &[u8; 32],
) -> Result<Database, Box<dyn std::error::Error>> {
    let path = data_directory.join("lumora.db");
    if path.exists() {
        let connection = Connection::open(&path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        drop(connection);
        if version < SCHEMA_VERSION {
            let backup_directory = data_directory.join("backups");
            fs::create_dir_all(&backup_directory)?;
            let backup =
                backup_directory.join(format!("lumora-{}.db", Utc::now().format("%Y%m%d%H%M%S")));
            fs::copy(&path, backup)?;
        }
    }

    let mut connection = Connection::open(path)?;
    initialize_database(&mut connection)?;
    migrate_provider_secrets(&mut connection, master_key)?;
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(Arc::new(Mutex::new(connection)))
}

pub fn database(db: &Database) -> AppResult<MutexGuard<'_, Connection>> {
    db.lock()
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "数据库不可用".into()))
}

fn initialize_database(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
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
         CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
         CREATE INDEX IF NOT EXISTS idx_images_user_created ON images(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage_logs(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_tasks_user_created ON tasks(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_devices_user_seen ON devices(user_id, last_seen_at DESC);
         CREATE INDEX IF NOT EXISTS idx_activity_date ON activity_days(activity_date);
         CREATE INDEX IF NOT EXISTS idx_credit_ledger_user_created
           ON credit_ledger(user_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_admin_audit_created
           ON admin_audit_logs(created_at DESC);",
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
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_images_public_storage_created
         ON images(visibility, storage, created_at DESC);
         CREATE INDEX IF NOT EXISTS idx_usage_created
           ON usage_logs(created_at DESC);
         INSERT OR IGNORE INTO system_settings (key, value, updated_at)
           VALUES ('registration_credits', 3000, CURRENT_TIMESTAMP);
         INSERT OR IGNORE INTO system_settings (key, value, updated_at)
           VALUES ('default_daily_limit', 10000, CURRENT_TIMESTAMP);
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

    Ok(())
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
        let connection = db.lock().unwrap();
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
        db.lock()
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
        let count = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM credit_ledger WHERE user_id = 'registered-user'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
