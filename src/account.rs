use axum::{
    extract::{rejection::JsonRejection, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use reqwest::Url;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{user_from_api_key, user_from_headers},
    db::{database, internal_error},
    model::{
        api_json, api_success, AnnouncementResponse, ApiResponse, AppError, AppResult,
        CreateProviderRequest, OpenAiResult, ProviderConfiguration, ProviderResponse,
        UpdateProfileRequest, UsageItemResponse, UsageResponse, UserResponse, MODEL,
    },
    security::{decrypt_secret, encrypt_secret, key_parts, mask_key},
    AppState,
};

pub async fn liveness() -> Json<ApiResponse<Value>> {
    Json(api_success(json!({ "status": "ok" })))
}

pub async fn api_not_found() -> AppError {
    AppError(StatusCode::NOT_FOUND, "接口不存在".into())
}

pub async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state).ok();
    let provider_configured = if let Some(user) = &user {
        database(&state.db)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM providers WHERE user_id = ?1 AND is_active = 1)",
                [&user.id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(internal_error)?
    } else {
        false
    };
    Ok(Json(api_success(json!({
        "server": "ready",
        "authenticated": user.is_some(),
        "providerConfigured": provider_configured,
        "model": MODEL
    }))))
}

pub async fn public_config(State(state): State<AppState>) -> Json<ApiResponse<Value>> {
    Json(api_success(json!({
        "supportEmail": state.config.support_email,
        "supportWechat": state.config.support_wechat
    })))
}

pub async fn public_stats(State(state): State<AppState>) -> AppResult<Json<ApiResponse<Value>>> {
    let connection = database(&state.db)?;
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let today_generations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM images WHERE substr(created_at, 1, 10) = ?1",
            [today],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    let public_images: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM images WHERE visibility = 'public'",
            [],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    let mut statement = connection
        .prepare(
            "SELECT category, COUNT(*) FROM images
             WHERE visibility = 'public'
             GROUP BY category ORDER BY COUNT(*) DESC",
        )
        .map_err(internal_error)?;
    let categories = statement
        .query_map([], |row| {
            Ok(json!({
                "name": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?
            }))
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(Json(api_success(json!({
        "todayGenerations": today_generations,
        "publicImages": public_images,
        "categories": categories
    }))))
}

pub async fn list_announcements(
    State(state): State<AppState>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let connection = database(&state.db)?;
    let mut statement = connection
        .prepare(
            "SELECT id, title, content, date, type, is_new
             FROM announcements ORDER BY date DESC, id",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map([], |row| {
            Ok(AnnouncementResponse {
                id: row.get(0)?,
                title: row.get(1)?,
                content: row.get(2)?,
                date: row.get(3)?,
                r#type: row.get(4)?,
                is_new: row.get(5)?,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(Json(api_success(json!({ "items": items }))))
}

pub async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let connection = database(&state.db)?;
    let mut statement = connection
        .prepare(
            "SELECT id, name, base_url,
                    COALESCE(key_prefix, substr(api_key, 1, 9)),
                    COALESCE(key_suffix, substr(api_key, -4)),
                    model, is_active, created_at, encryption_version
             FROM providers WHERE user_id = ?1 ORDER BY is_active DESC, created_at DESC",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map([user.id], |row| {
            let prefix: String = row.get(3)?;
            let suffix: String = row.get(4)?;
            Ok(ProviderResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                base_url: row.get(2)?,
                masked_api_key: mask_key(&prefix, &suffix),
                model: row.get(5)?,
                is_active: row.get(6)?,
                created_at: row.get(7)?,
                needs_rotation: row.get::<_, i64>(8)? == 0,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(Json(api_success(json!({ "items": items }))))
}

pub async fn create_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateProviderRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<ProviderResponse>>)> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let name = request.name.trim();
    let api_key = request.api_key.trim();
    if name.is_empty() || name.len() > 80 || api_key.is_empty() || api_key.len() > 500 {
        return Err(AppError(StatusCode::BAD_REQUEST, "调用方参数无效".into()));
    }
    let base_url = normalize_base_url(&request.base_url)?;
    let id = format!("provider-{}", Uuid::new_v4().simple());
    let created_at = Utc::now().to_rfc3339();
    let encrypted = encrypt_secret(&state.config.master_key, api_key)?;
    let (prefix, suffix) = key_parts(api_key);
    let mut connection = database(&state.db)?;
    let transaction = connection.transaction().map_err(internal_error)?;
    let count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM providers WHERE user_id = ?1",
            [&user.id],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    transaction
        .execute(
            "INSERT INTO providers (
               id, user_id, name, base_url, api_key, api_key_cipher,
               key_prefix, key_suffix, encryption_version, model, is_active, created_at
             ) VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7, 1, ?8, ?9, ?10)",
            params![
                id,
                user.id,
                name,
                base_url,
                encrypted,
                prefix,
                suffix,
                MODEL,
                count == 0,
                created_at
            ],
        )
        .map_err(internal_error)?;
    transaction.commit().map_err(internal_error)?;
    Ok((
        StatusCode::CREATED,
        Json(api_success(ProviderResponse {
            id,
            name: name.into(),
            base_url,
            masked_api_key: mask_key(&prefix, &suffix),
            model: MODEL.into(),
            is_active: count == 0,
            created_at,
            needs_rotation: false,
        })),
    ))
}

pub async fn activate_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let mut connection = database(&state.db)?;
    let transaction = connection.transaction().map_err(internal_error)?;
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM providers WHERE id = ?1 AND user_id = ?2)",
            params![id, user.id],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    if !exists {
        return Err(AppError(StatusCode::NOT_FOUND, "调用方不存在".into()));
    }
    transaction
        .execute(
            "UPDATE providers SET is_active = 0 WHERE user_id = ?1",
            [&user.id],
        )
        .map_err(internal_error)?;
    transaction
        .execute(
            "UPDATE providers SET is_active = 1 WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
        )
        .map_err(internal_error)?;
    transaction.commit().map_err(internal_error)?;
    Ok(Json(api_success(Value::Null)))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let mut connection = database(&state.db)?;
    let transaction = connection.transaction().map_err(internal_error)?;
    let was_active = transaction
        .query_row(
            "SELECT is_active FROM providers WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
            |row| row.get::<_, bool>(0),
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "调用方不存在".into()))?;
    transaction
        .execute(
            "DELETE FROM providers WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
        )
        .map_err(internal_error)?;
    if was_active {
        transaction
            .execute(
                "UPDATE providers SET is_active = 1 WHERE id = (
                   SELECT id FROM providers WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1
                 )",
                [&user.id],
            )
            .map_err(internal_error)?;
    }
    transaction.commit().map_err(internal_error)?;
    Ok(Json(api_success(Value::Null)))
}

pub fn active_provider(state: &AppState, user_id: &str) -> AppResult<ProviderConfiguration> {
    let row = database(&state.db)?
        .query_row(
            "SELECT id, base_url, api_key, api_key_cipher, encryption_version, model
             FROM providers WHERE user_id = ?1 AND is_active = 1",
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "请先配置并启用生图调用方".into(),
            )
        })?;
    let api_key = if row.4 == 1 {
        decrypt_secret(
            &state.config.master_key,
            row.3.as_deref().ok_or_else(|| {
                AppError(StatusCode::INTERNAL_SERVER_ERROR, "调用方凭证无效".into())
            })?,
        )?
    } else {
        row.2
    };
    Ok(ProviderConfiguration {
        id: row.0,
        base_url: row.1,
        api_key,
        model: row.5,
    })
}

pub async fn get_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<UsageResponse>>> {
    let user = user_from_headers(&headers, &state)?;
    Ok(Json(api_success(usage_for_user(&state, &user.id)?)))
}

pub async fn external_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> OpenAiResult<Json<Value>> {
    let principal = user_from_api_key(&headers, &state, &["read", "generate", "full"])?;
    let usage = usage_for_user(&state, &principal.user.id)?;
    Ok(Json(json!({
        "totalCalls": usage.today_calls,
        "recentCalls": usage.items,
        "dailyLimit": usage.daily_limit,
        "averageLatencyMs": usage.average_latency_ms
    })))
}

pub async fn external_credits(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> OpenAiResult<Json<Value>> {
    let principal = user_from_api_key(&headers, &state, &["read", "generate", "full"])?;
    Ok(Json(json!({
        "credits": principal.user.credits,
        "creditsReserved": principal.user.credits_reserved,
        "plan": principal.user.plan,
        "creditCostPerImage": 1
    })))
}

fn usage_for_user(state: &AppState, user_id: &str) -> AppResult<UsageResponse> {
    let connection = database(&state.db)?;
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let (today_calls, average_latency_ms, daily_limit) = connection
        .query_row(
            "SELECT COUNT(l.id), COALESCE(AVG(l.duration_ms), 0), u.daily_limit
             FROM users u LEFT JOIN usage_logs l
               ON l.user_id = u.id AND substr(l.created_at, 1, 10) = ?2
             WHERE u.id = ?1 GROUP BY u.id",
            params![user_id, today],
            |row| Ok((row.get(0)?, row.get::<_, f64>(1)? as i64, row.get(2)?)),
        )
        .map_err(internal_error)?;
    let mut statement = connection
        .prepare(
            "SELECT id, endpoint, model, status, duration_ms, credits_used, created_at
             FROM usage_logs WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map([user_id], |row| {
            Ok(UsageItemResponse {
                id: row.get(0)?,
                endpoint: row.get(1)?,
                model: row.get(2)?,
                status: row.get(3)?,
                duration_ms: row.get(4)?,
                credits_used: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(UsageResponse {
        today_calls,
        daily_limit,
        average_latency_ms,
        items,
    })
}

fn normalize_base_url(value: &str) -> AppResult<String> {
    let trimmed = value.trim().trim_end_matches('/');
    let url = Url::parse(trimmed)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Base URL 无效".into()))?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    if url.scheme() != "https" && !local {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Base URL 必须使用 HTTPS".into(),
        ));
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "Base URL 无效".into()));
    }
    Ok(trimmed.into())
}

pub async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateProfileRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<UserResponse>>> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let connection = database(&state.db)?;

    let mut email = user.email.clone();
    let mut name = user.name.clone();
    let mut avatar = user.avatar.clone();
    let mut password_hash = None;

    if let Some(req_email) = request.email {
        let trimmed = req_email.trim().to_lowercase();
        if trimmed.len() > 254 || !trimmed.contains('@') {
            return Err(AppError(StatusCode::BAD_REQUEST, "邮箱格式无效".into()));
        }
        if trimmed != user.email {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1 AND id <> ?2)",
                    params![trimmed, user.id],
                    |row| row.get(0),
                )
                .map_err(internal_error)?;
            if exists {
                return Err(AppError(StatusCode::CONFLICT, "该邮箱已被使用".into()));
            }
            email = trimmed;
        }
    }

    if let Some(req_name) = request.name {
        let trimmed = req_name.trim().to_string();
        if trimmed.is_empty() || trimmed.len() > 80 {
            return Err(AppError(StatusCode::BAD_REQUEST, "昵称长度无效".into()));
        }
        name = trimmed;
    }

    if let Some(req_avatar) = request.avatar {
        avatar = req_avatar.trim().to_string();
    }

    if let Some(req_pwd) = request.password {
        if req_pwd.len() < 8 || req_pwd.len() > 128 {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "密码长度需为 8-128 位".into(),
            ));
        }
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand_core::OsRng;
        let hashed = Argon2::default()
            .hash_password(req_pwd.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败".into()))?
            .to_string();
        password_hash = Some(hashed);
    }

    if let Some(hash) = password_hash {
        connection
            .execute(
                "UPDATE users SET email = ?1, name = ?2, avatar = ?3, password_hash = ?4 WHERE id = ?5",
                params![email, name, avatar, hash, user.id],
            )
            .map_err(internal_error)?;
    } else {
        connection
            .execute(
                "UPDATE users SET email = ?1, name = ?2, avatar = ?3 WHERE id = ?4",
                params![email, name, avatar, user.id],
            )
            .map_err(internal_error)?;
    }

    Ok(Json(api_success(UserResponse {
        id: user.id,
        name,
        email,
        avatar,
        plan: user.plan,
        credits: user.credits,
        credits_reserved: user.credits_reserved,
    })))
}
