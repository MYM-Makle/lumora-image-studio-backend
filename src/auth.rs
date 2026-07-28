use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{rejection::JsonRejection, Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use rand_core::OsRng;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    db::{database, internal_error},
    model::{
        api_json, api_success, ApiKeyItemResponse, ApiPrincipal, ApiResponse, AppError, AppResult,
        AuthRequest, CreateApiKeyRequest, CreatedApiKeyResponse, UserResponse, SESSION_COOKIE,
    },
    security::{hash_api_key, key_parts, mask_key},
    AppState,
};

pub fn user_from_headers(headers: &HeaderMap, state: &AppState) -> AppResult<UserResponse> {
    let token = cookie_value(headers, SESSION_COOKIE)
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "请先登录".into()))?;
    let now = Utc::now().to_rfc3339();
    database(&state.db)?
        .query_row(
            "SELECT u.id, u.name, u.email, u.avatar, u.plan, u.credits, u.credits_reserved
             FROM users u JOIN sessions s ON s.user_id = u.id
             WHERE s.token = ?1 AND (s.expires_at IS NULL OR s.expires_at > ?2)",
            params![token, now],
            user_from_row,
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "登录状态已失效".into()))
}

pub fn user_from_api_key(
    headers: &HeaderMap,
    state: &AppState,
    allowed_scopes: &[&str],
) -> AppResult<ApiPrincipal> {
    let api_key = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "API Key 无效或缺失".into()))?;
    let key_hash = hash_api_key(api_key);
    let connection = database(&state.db)?;
    let principal = connection
        .query_row(
            "SELECT u.id, u.name, u.email, u.avatar, u.plan, u.credits,
                    u.credits_reserved, k.scope
             FROM users u JOIN api_keys k ON k.user_id = u.id
             WHERE k.status = 'active' AND (
               (k.is_legacy = 0 AND k.key_hash = ?1) OR
               (k.is_legacy = 1 AND k.key_value = ?2)
             )",
            params![key_hash, api_key],
            |row| {
                Ok(ApiPrincipal {
                    user: user_from_row(row)?,
                    scope: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "API Key 无效或缺失".into()))?;
    if !allowed_scopes.contains(&principal.scope.as_str()) {
        return Err(AppError(StatusCode::FORBIDDEN, "API Key 权限不足".into()));
    }
    connection
        .execute(
            "UPDATE api_keys SET last_used = ?1 WHERE status = 'active' AND (
               (is_legacy = 0 AND key_hash = ?2) OR (is_legacy = 1 AND key_value = ?3)
             )",
            params![Utc::now().to_rfc3339(), key_hash, api_key],
        )
        .map_err(internal_error)?;
    Ok(principal)
}

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserResponse> {
    Ok(UserResponse {
        id: row.get(0)?,
        name: row.get(1)?,
        email: row.get(2)?,
        avatar: row.get(3)?,
        plan: row.get(4)?,
        credits: row.get(5)?,
        credits_reserved: row.get(6)?,
    })
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|item| {
            item.trim()
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
}

fn validate_auth(request: &AuthRequest) -> AppResult<(String, String)> {
    let email = request.email.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') {
        return Err(AppError(StatusCode::BAD_REQUEST, "邮箱格式无效".into()));
    }
    if request.password.len() < 8 || request.password.len() > 128 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "密码长度需为 8-128 位".into(),
        ));
    }
    Ok((email, request.password.clone()))
}

fn create_session(state: &AppState, user_id: &str) -> AppResult<String> {
    let token = Uuid::new_v4().simple().to_string();
    let now = Utc::now();
    let connection = database(&state.db)?;
    connection
        .execute(
            "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now.to_rfc3339()],
        )
        .map_err(internal_error)?;
    connection
        .execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                token,
                user_id,
                now.to_rfc3339(),
                (now + Duration::days(30)).to_rfc3339()
            ],
        )
        .map_err(internal_error)?;
    Ok(token)
}

fn session_cookie(state: &AppState, token: &str, max_age: i64) -> String {
    let secure = if state.config.production {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE}={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age={max_age}{secure}")
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<ApiResponse<Option<UserResponse>>> {
    Json(api_success(user_from_headers(&headers, &state).ok()))
}

pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<AuthRequest>, JsonRejection>,
) -> AppResult<Response> {
    let request = api_json(payload)?;
    let (email, password) = validate_auth(&request)?;
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败".into()))?
        .to_string();
    let id = format!("usr-{}", Uuid::new_v4().simple());
    let name = email
        .split('@')
        .next()
        .unwrap_or("Lumora 创作者")
        .to_owned();
    let connection = database(&state.db)?;
    connection
        .execute(
            "INSERT INTO users (
               id, name, email, password_hash, avatar, plan, credits,
               credits_reserved, daily_limit, created_at
             ) VALUES (?1, ?2, ?3, ?4, '', 'Free', 3000, 0, 10000, ?5)",
            params![id, name, email, password_hash, Utc::now().to_rfc3339()],
        )
        .map_err(|error| {
            if error.to_string().contains("UNIQUE") {
                AppError(StatusCode::CONFLICT, "该邮箱已注册".into())
            } else {
                internal_error(error)
            }
        })?;
    drop(connection);
    let token = create_session(&state, &id)?;
    let user = UserResponse {
        id,
        name,
        email,
        avatar: String::new(),
        plan: "Free".into(),
        credits: 3000,
        credits_reserved: 0,
    };
    Ok((
        StatusCode::CREATED,
        [(
            header::SET_COOKIE,
            session_cookie(&state, &token, 2_592_000),
        )],
        Json(api_success(user)),
    )
        .into_response())
}

pub async fn login(
    State(state): State<AppState>,
    payload: Result<Json<AuthRequest>, JsonRejection>,
) -> AppResult<Response> {
    let request = api_json(payload)?;
    let (email, password) = validate_auth(&request)?;
    let result = database(&state.db)?
        .query_row(
            "SELECT id, name, email, password_hash, avatar, plan, credits, credits_reserved
             FROM users WHERE email = ?1",
            [email],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "邮箱或密码错误".into()))?;
    let parsed_hash = PasswordHash::new(&result.3)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "密码数据无效".into()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError(StatusCode::UNAUTHORIZED, "邮箱或密码错误".into()))?;
    let token = create_session(&state, &result.0)?;
    let user = UserResponse {
        id: result.0,
        name: result.1,
        email: result.2,
        avatar: result.4,
        plan: result.5,
        credits: result.6,
        credits_reserved: result.7,
    };
    Ok((
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            session_cookie(&state, &token, 2_592_000),
        )],
        Json(api_success(user)),
    )
        .into_response())
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        database(&state.db)?
            .execute("DELETE FROM sessions WHERE token = ?1", [token])
            .map_err(internal_error)?;
    }
    Ok((
        [(header::SET_COOKIE, session_cookie(&state, "", 0))],
        Json(api_success(Value::Null)),
    )
        .into_response())
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let connection = database(&state.db)?;
    let mut statement = connection
        .prepare(
            "SELECT id, name,
                    COALESCE(key_prefix, substr(key_value, 1, 9)),
                    COALESCE(key_suffix, substr(key_value, -4)),
                    created_at, last_used, status, scope, is_legacy
             FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map([user.id], |row| {
            let prefix: String = row.get(2)?;
            let suffix: String = row.get(3)?;
            Ok(ApiKeyItemResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                masked_key: mask_key(&prefix, &suffix),
                created_at: row.get(4)?,
                last_used: row.get(5)?,
                status: row.get(6)?,
                scope: row.get(7)?,
                needs_rotation: row.get::<_, i64>(8)? != 0,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(Json(api_success(json!({ "items": items }))))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<CreatedApiKeyResponse>>)> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let name = request.name.trim();
    if name.is_empty()
        || name.len() > 80
        || !["full", "read", "generate"].contains(&request.scope.as_str())
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "API Key 参数无效".into()));
    }
    let id = format!("key-{}", Uuid::new_v4().simple());
    let secret = format!("lum-live-{}", Uuid::new_v4().simple());
    let (prefix, suffix) = key_parts(&secret);
    let item = ApiKeyItemResponse {
        id: id.clone(),
        name: name.into(),
        masked_key: mask_key(&prefix, &suffix),
        created_at: Utc::now().to_rfc3339(),
        last_used: "未调用".into(),
        status: "active".into(),
        scope: request.scope,
        needs_rotation: false,
    };
    database(&state.db)?
        .execute(
            "INSERT INTO api_keys (
               id, user_id, name, key_value, key_hash, key_prefix, key_suffix,
               is_legacy, scope, status, created_at, last_used
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, 'active', ?9, ?10)",
            params![
                item.id,
                user.id,
                item.name,
                format!("hashed:{id}"),
                hash_api_key(&secret),
                prefix,
                suffix,
                item.scope,
                item.created_at,
                item.last_used
            ],
        )
        .map_err(internal_error)?;
    Ok((
        StatusCode::CREATED,
        Json(api_success(CreatedApiKeyResponse { item, secret })),
    ))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let changed = database(&state.db)?
        .execute(
            "UPDATE api_keys SET status = 'revoked' WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
        )
        .map_err(internal_error)?;
    if changed == 0 {
        return Err(AppError(StatusCode::NOT_FOUND, "API Key 不存在".into()));
    }
    Ok(Json(api_success(Value::Null)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, db::open_database};
    use axum::http::HeaderValue;
    use reqwest::Client;
    use std::{fs, sync::Arc};
    use tempfile::TempDir;
    use tokio::sync::Semaphore;

    fn test_state() -> (TempDir, AppState) {
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
            master_key: [4_u8; 32],
            worker_concurrency: 1,
            support_email: None,
            support_wechat: None,
        };
        let state = AppState {
            db: open_database(directory.path(), &[5_u8; 32]).unwrap(),
            client: Client::new(),
            config,
            task_semaphore: Arc::new(Semaphore::new(1)),
        };
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits,
                   credits_reserved, daily_limit, created_at
                 ) VALUES ('user-1', 'Test', 'test@example.test', 'hash', '', 'Free', 10, 0, 100, ?1)",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();
        (directory, state)
    }

    #[test]
    fn enforces_key_scopes_and_accepts_legacy_keys() {
        let (_directory, state) = test_state();
        let key = "lum-live-test-key";
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO api_keys (
                   id, user_id, name, key_value, key_hash, key_prefix, key_suffix,
                   is_legacy, scope, status, created_at, last_used
                 ) VALUES ('key-1', 'user-1', 'Read', 'hashed:key-1', ?1,
                   'lum-live', '-key', 0, 'read', 'active', ?2, '未调用')",
                params![hash_api_key(key), Utc::now().to_rfc3339()],
            )
            .unwrap();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO api_keys (
                   id, user_id, name, key_value, is_legacy, scope, status, created_at, last_used
                 ) VALUES ('key-2', 'user-1', 'Legacy', 'legacy-key', 1, 'full',
                   'active', ?1, '未调用')",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer lum-live-test-key"),
        );
        assert!(user_from_api_key(&headers, &state, &["read"]).is_ok());
        match user_from_api_key(&headers, &state, &["generate"]) {
            Err(error) => assert_eq!(error.0, StatusCode::FORBIDDEN),
            Ok(_) => panic!("read key unexpectedly allowed generation"),
        }
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer legacy-key"),
        );
        assert!(user_from_api_key(&headers, &state, &["full"]).is_ok());
    }

    #[tokio::test]
    async fn expires_sessions_and_stores_new_keys_as_hashes() {
        let (_directory, state) = test_state();
        let mut headers = HeaderMap::new();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('expired', 'user-1', ?1, '2020-01-01T00:00:00Z')",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("lumora_session=expired"),
        );
        match user_from_headers(&headers, &state) {
            Err(error) => assert_eq!(error.0, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("expired session unexpectedly authenticated"),
        }

        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('valid', 'user-1', ?1, '2099-01-01T00:00:00Z')",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("lumora_session=valid"),
        );
        let created = create_api_key(
            State(state.clone()),
            headers,
            Ok(Json(CreateApiKeyRequest {
                name: "Test key".into(),
                scope: "generate".into(),
            })),
        )
        .await
        .unwrap()
        .1
         .0;
        let stored: (String, String, i64) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT key_value, key_hash, is_legacy FROM api_keys WHERE id = ?1",
                [created.data.item.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_ne!(stored.0, created.data.secret);
        assert_eq!(stored.1, hash_api_key(&created.data.secret));
        assert_eq!(stored.2, 0);
    }
}
