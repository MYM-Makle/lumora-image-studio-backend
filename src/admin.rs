use std::{net::IpAddr, time::Duration as StdDuration};

use axum::{
    extract::{rejection::JsonRejection, Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{
    account::normalize_base_url,
    auth::user_from_headers,
    db::{internal_error, read_database, utc_day_bounds, write_database},
    model::{
        api_json, api_success, ApiResponse, AppError, AppResult, CreateProviderRequest,
        ProviderResponse, UserResponse, MODEL,
    },
    security::{encrypt_secret, key_parts, mask_key},
    AppState,
};

fn admin_user(headers: &HeaderMap, state: &AppState) -> AppResult<UserResponse> {
    let user = user_from_headers(headers, state)?;
    let is_admin = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT is_admin FROM users WHERE id = ?1 AND status = 'active'",
                [&user.id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(internal_error)
            .map(|value| value.unwrap_or(false))
    })?;
    if !is_admin {
        return Err(AppError(StatusCode::FORBIDDEN, "需要管理员权限".into()));
    }
    Ok(user)
}

fn write_audit(
    connection: &Connection,
    admin_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: Value,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO admin_audit_logs (
           id, admin_user_id, action, target_type, target_id, detail, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            format!("audit-{}", Uuid::new_v4().simple()),
            admin_id,
            action,
            target_type,
            target_id,
            detail.to_string(),
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = admin_user(&headers, &state)?;
    Ok(Json(api_success(json!({ "user": user }))))
}

pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    read_database(&state.db, |connection| {
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let (today_start, tomorrow_start) = utc_day_bounds(now);
        let month_start = (now - Duration::days(29)).format("%Y-%m-%d").to_string();
        let online_cutoff = (now - Duration::minutes(5)).to_rfc3339();
        let total_users = connection
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
            .map_err(internal_error)?;
        let today_new_users = connection
            .query_row(
                "SELECT COUNT(*) FROM users WHERE created_at >= ?1 AND created_at < ?2",
                params![today_start, tomorrow_start],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let daily_active_users = connection
            .query_row(
                "SELECT COUNT(*) FROM activity_days WHERE activity_date = ?1",
                [&today],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let monthly_active_users = connection
            .query_row(
                "SELECT COUNT(DISTINCT user_id) FROM activity_days WHERE activity_date >= ?1",
                [&month_start],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let online_users = connection
            .query_row(
                "SELECT COUNT(*) FROM users WHERE status = 'active' AND last_seen_at >= ?1",
                [&online_cutoff],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let devices = connection
            .query_row("SELECT COUNT(*) FROM devices", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(internal_error)?;
        let (total_calls, success_calls, today_calls, credits_used) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM usage_logs) +
                     (SELECT COALESCE(SUM(request_count), 0) FROM usage_daily_summary),
                   (SELECT COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0)
                    FROM usage_logs) +
                     (SELECT COALESCE(SUM(request_count), 0) FROM usage_daily_summary
                      WHERE status = 'success'),
                   (SELECT COUNT(*) FROM usage_logs
                    WHERE created_at >= ?1 AND created_at < ?2),
                   (SELECT COALESCE(SUM(credits_used), 0) FROM usage_logs) +
                     (SELECT COALESCE(SUM(total_credits_used), 0) FROM usage_daily_summary)",
                params![today_start, tomorrow_start],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .map_err(internal_error)?;
        let total_images = connection
            .query_row("SELECT COUNT(*) FROM images", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(internal_error)?;
        let success_rate = if total_calls == 0 {
            0.0
        } else {
            success_calls as f64 / total_calls as f64 * 100.0
        };
        let mut daily = Vec::with_capacity(14);
        for offset in (0..14).rev() {
            let day = now - Duration::days(offset);
            let date = day.format("%Y-%m-%d").to_string();
            let (day_start, next_day_start) = utc_day_bounds(day);
            let active_users = connection
                .query_row(
                    "SELECT COUNT(*) FROM activity_days WHERE activity_date = ?1",
                    [&date],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)?;
            let generations = connection
                .query_row(
                    "SELECT COUNT(*) FROM usage_logs
                     WHERE status = 'success' AND created_at >= ?1 AND created_at < ?2",
                    params![day_start, next_day_start],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(internal_error)?;
            daily.push(json!({
                "date": date,
                "activeUsers": active_users,
                "generations": generations
            }));
        }

        Ok(Json(api_success(json!({
            "totalUsers": total_users,
            "todayNewUsers": today_new_users,
            "dailyActiveUsers": daily_active_users,
            "monthlyActiveUsers": monthly_active_users,
            "onlineUsers": online_users,
            "devices": devices,
            "totalCalls": total_calls,
            "todayCalls": today_calls,
            "successRate": success_rate,
            "creditsUsed": credits_used,
            "totalImages": total_images,
            "daily": daily
        }))))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    q: Option<String>,
    status: Option<String>,
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let search = query.q.unwrap_or_default().trim().to_lowercase();
    let pattern = format!("%{search}%");
    let status = query.status.unwrap_or_default();
    if !status.is_empty() && !["active", "disabled"].contains(&status.as_str()) {
        return Err(AppError(StatusCode::BAD_REQUEST, "用户状态无效".into()));
    }
    read_database(&state.db, |connection| {
        let total = connection
            .query_row(
                "SELECT COUNT(*) FROM users
             WHERE (?1 = '' OR lower(email) LIKE ?2 OR lower(name) LIKE ?2)
               AND (?3 = '' OR status = ?3)",
                params![search, pattern, status],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let mut statement = connection
            .prepare(
                "SELECT u.id, u.name, u.email, u.plan, u.credits, u.credits_reserved,
                    u.daily_limit, u.status, u.is_admin, u.created_at,
                    u.last_login_at, u.last_seen_at,
                    (SELECT COUNT(*) FROM usage_logs l WHERE l.user_id = u.id) +
                      (SELECT COALESCE(SUM(s.request_count), 0)
                       FROM usage_daily_summary s WHERE s.user_id = u.id),
                    (SELECT COALESCE(SUM(l.credits_used), 0)
                     FROM usage_logs l WHERE l.user_id = u.id) +
                      (SELECT COALESCE(SUM(s.total_credits_used), 0)
                       FROM usage_daily_summary s WHERE s.user_id = u.id)
             FROM users u
             WHERE (?1 = '' OR lower(u.email) LIKE ?2 OR lower(u.name) LIKE ?2)
               AND (?3 = '' OR u.status = ?3)
             ORDER BY u.created_at DESC LIMIT ?4 OFFSET ?5",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map(
                params![search, pattern, status, page_size, (page - 1) * page_size],
                |row| {
                    let credits = row.get::<_, i64>(4)?;
                    let reserved = row.get::<_, i64>(5)?;
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "name": row.get::<_, String>(1)?,
                        "email": row.get::<_, String>(2)?,
                        "plan": row.get::<_, String>(3)?,
                        "credits": credits,
                        "creditsReserved": reserved,
                        "availableCredits": credits - reserved,
                        "dailyLimit": row.get::<_, i64>(6)?,
                        "status": row.get::<_, String>(7)?,
                        "isAdmin": row.get::<_, bool>(8)?,
                        "createdAt": row.get::<_, String>(9)?,
                        "lastLoginAt": row.get::<_, Option<String>>(10)?,
                        "lastSeenAt": row.get::<_, Option<String>>(11)?,
                        "totalCalls": row.get::<_, i64>(12)?,
                        "creditsUsed": row.get::<_, i64>(13)?
                    }))
                },
            )
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(Json(api_success(json!({
            "items": items,
            "total": total,
            "page": page,
            "pageSize": page_size
        }))))
    })
}

pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    read_database(&state.db, |connection| {
        let mut detail = connection
            .query_row(
                "SELECT id, name, email, avatar, plan, credits, credits_reserved,
                    daily_limit, status, is_admin, created_at, last_login_at,
                    last_seen_at, password_hash <> ''
                 FROM users WHERE id = ?1",
                [&id],
                |row| {
                    let credits = row.get::<_, i64>(5)?;
                    let reserved = row.get::<_, i64>(6)?;
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "name": row.get::<_, String>(1)?,
                        "email": row.get::<_, String>(2)?,
                        "avatar": row.get::<_, String>(3)?,
                        "plan": row.get::<_, String>(4)?,
                        "credits": credits,
                        "creditsReserved": reserved,
                        "availableCredits": credits - reserved,
                        "dailyLimit": row.get::<_, i64>(7)?,
                        "status": row.get::<_, String>(8)?,
                        "isAdmin": row.get::<_, bool>(9)?,
                        "createdAt": row.get::<_, String>(10)?,
                        "lastLoginAt": row.get::<_, Option<String>>(11)?,
                        "lastSeenAt": row.get::<_, Option<String>>(12)?,
                        "passwordConfigured": row.get::<_, bool>(13)?
                    }))
                },
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "用户不存在".into()))?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, base_url,
                    COALESCE(key_prefix, substr(api_key, 1, 9)),
                    COALESCE(key_suffix, substr(api_key, -4)),
                    model, is_active, created_at, encryption_version, is_global
                 FROM providers
                 WHERE user_id = ?1 OR is_global = 1
                 ORDER BY is_global ASC, is_active DESC, created_at DESC",
            )
            .map_err(internal_error)?;
        let providers = statement
            .query_map([&id], |row| {
                let prefix = row.get::<_, String>(3)?;
                let suffix = row.get::<_, String>(4)?;
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "baseUrl": row.get::<_, String>(2)?,
                    "maskedApiKey": mask_key(&prefix, &suffix),
                    "model": row.get::<_, String>(5)?,
                    "isActive": row.get::<_, bool>(6)?,
                    "createdAt": row.get::<_, String>(7)?,
                    "needsRotation": row.get::<_, i64>(8)? == 0,
                    "source": if row.get::<_, bool>(9)? { "system" } else { "user" }
                }))
            })
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        detail["providers"] = json!(providers);
        Ok(Json(api_success(detail)))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    status: Option<String>,
    plan: Option<String>,
    daily_limit: Option<i64>,
    is_admin: Option<bool>,
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    payload: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let admin = admin_user(&headers, &state)?;
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let current = transaction
            .query_row(
                "SELECT status, plan, daily_limit, is_admin FROM users WHERE id = ?1",
                [&id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "用户不存在".into()))?;
        let status = request.status.unwrap_or(current.0);
        let plan = request.plan.unwrap_or(current.1).trim().to_string();
        let daily_limit = request.daily_limit.unwrap_or(current.2);
        let is_admin = request.is_admin.unwrap_or(current.3);
        if !["active", "disabled"].contains(&status.as_str())
            || plan.is_empty()
            || plan.len() > 40
            || !(1..=1_000_000).contains(&daily_limit)
        {
            return Err(AppError(StatusCode::BAD_REQUEST, "用户参数无效".into()));
        }
        if id == admin.id && (status != "active" || !is_admin) {
            return Err(AppError(
                StatusCode::CONFLICT,
                "不能停用自己的管理员权限".into(),
            ));
        }
        transaction
            .execute(
                "UPDATE users
                 SET status = ?1, plan = ?2, daily_limit = ?3, is_admin = ?4
                 WHERE id = ?5",
                params![status, plan, daily_limit, is_admin, id],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "update_user",
            "user",
            &id,
            json!({
                "status": status,
                "plan": plan,
                "dailyLimit": daily_limit,
                "isAdmin": is_admin
            }),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditAdjustmentRequest {
    delta: i64,
    reason: String,
    request_id: String,
}

pub async fn adjust_credits(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    payload: Result<Json<CreditAdjustmentRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let admin = admin_user(&headers, &state)?;
    let reason = request.reason.trim();
    let request_id = request.request_id.trim();
    if request.delta == 0
        || request.delta.unsigned_abs() > 1_000_000_000
        || reason.len() < 2
        || reason.len() > 200
        || request_id.len() < 8
        || request_id.len() > 128
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "积分调整参数无效".into()));
    }
    let reference_id = format!("admin:{request_id}");
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT user_id, delta, balance_after FROM credit_ledger WHERE reference_id = ?1",
                [&reference_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?
        {
            if existing.0 != id || existing.1 != request.delta {
                return Err(AppError(StatusCode::CONFLICT, "请求流水号已被使用".into()));
            }
            return Ok(Json(api_success(json!({ "credits": existing.2 }))));
        }
        let (credits, reserved) = transaction
            .query_row(
                "SELECT credits, credits_reserved FROM users WHERE id = ?1",
                [&id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "用户不存在".into()))?;
        let balance = credits
            .checked_add(request.delta)
            .filter(|value| *value >= reserved && *value >= 0)
            .ok_or_else(|| AppError(StatusCode::CONFLICT, "积分余额不能低于已预扣积分".into()))?;
        transaction
            .execute(
                "UPDATE users SET credits = ?1 WHERE id = ?2",
                params![balance, id],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "INSERT INTO credit_ledger (
                   id, user_id, delta, balance_after, reason, reference_id,
                   operator_user_id, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    format!("credit-{}", Uuid::new_v4().simple()),
                    id,
                    request.delta,
                    balance,
                    reason,
                    reference_id,
                    admin.id,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "adjust_credits",
            "user",
            &id,
            json!({ "delta": request.delta, "balance": balance, "reason": reason }),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(Json(api_success(json!({ "credits": balance }))))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCreditSetRequest {
    user_ids: Vec<String>,
    credits: i64,
    reason: String,
    request_id: String,
}

pub async fn bulk_set_credits(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<BulkCreditSetRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let admin = admin_user(&headers, &state)?;
    let mut user_ids = request
        .user_ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .collect::<Vec<_>>();
    user_ids.sort();
    user_ids.dedup();
    let reason = request.reason.trim().to_string();
    let request_id = request.request_id.trim().to_string();
    if user_ids.is_empty()
        || user_ids.len() > 100
        || user_ids.iter().any(|id| id.is_empty() || id.len() > 128)
        || !(0..=1_000_000_000).contains(&request.credits)
        || reason.len() < 2
        || reason.len() > 200
        || request_id.len() < 8
        || request_id.len() > 128
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "批量积分参数无效".into()));
    }
    let updated = write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let mut updated = 0;
        for id in &user_ids {
            let reference_id = format!("admin-bulk:{request_id}:{id}");
            if let Some((existing_user_id, balance)) = transaction
                .query_row(
                    "SELECT user_id, balance_after FROM credit_ledger WHERE reference_id = ?1",
                    [&reference_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(internal_error)?
            {
                if existing_user_id != *id || balance != request.credits {
                    return Err(AppError(StatusCode::CONFLICT, "请求流水号已被使用".into()));
                }
                continue;
            }
            let (current, reserved) = transaction
                .query_row(
                    "SELECT credits, credits_reserved FROM users WHERE id = ?1",
                    [id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(internal_error)?
                .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "用户不存在".into()))?;
            if request.credits < reserved {
                return Err(AppError(
                    StatusCode::CONFLICT,
                    "统一积分不能低于用户已预扣积分".into(),
                ));
            }
            transaction
                .execute(
                    "UPDATE users SET credits = ?1 WHERE id = ?2",
                    params![request.credits, id],
                )
                .map_err(internal_error)?;
            transaction
                .execute(
                    "INSERT INTO credit_ledger (
                       id, user_id, delta, balance_after, reason, reference_id,
                       operator_user_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        format!("credit-{}", Uuid::new_v4().simple()),
                        id,
                        request.credits - current,
                        request.credits,
                        reason,
                        reference_id,
                        admin.id,
                        Utc::now().to_rfc3339()
                    ],
                )
                .map_err(internal_error)?;
            updated += 1;
        }
        if updated > 0 {
            write_audit(
                &transaction,
                &admin.id,
                "bulk_set_credits",
                "users",
                &request_id,
                json!({
                    "userIds": user_ids,
                    "credits": request.credits,
                    "reason": reason
                }),
            )
            .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok(updated)
    })?;
    Ok(Json(api_success(json!({
        "updated": updated,
        "credits": request.credits
    }))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    user_id: Option<String>,
}

pub async fn list_credit_ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LedgerQuery>,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(30).clamp(1, 100);
    let user_id = query.user_id.unwrap_or_default();
    read_database(&state.db, |connection| {
        let total = connection
            .query_row(
                "SELECT COUNT(*) FROM credit_ledger WHERE (?1 = '' OR user_id = ?1)",
                [&user_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let mut statement = connection
            .prepare(
                "SELECT l.id, l.user_id, u.email, l.delta, l.balance_after, l.reason,
                    l.reference_id, l.created_at, operator.email
             FROM credit_ledger l
             JOIN users u ON u.id = l.user_id
             LEFT JOIN users operator ON operator.id = l.operator_user_id
             WHERE (?1 = '' OR l.user_id = ?1)
             ORDER BY l.created_at DESC LIMIT ?2 OFFSET ?3",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map(params![user_id, page_size, (page - 1) * page_size], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "userId": row.get::<_, String>(1)?,
                    "userEmail": row.get::<_, String>(2)?,
                    "delta": row.get::<_, i64>(3)?,
                    "balanceAfter": row.get::<_, i64>(4)?,
                    "reason": row.get::<_, String>(5)?,
                    "referenceId": row.get::<_, String>(6)?,
                    "createdAt": row.get::<_, String>(7)?,
                    "operatorEmail": row.get::<_, Option<String>>(8)?
                }))
            })
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(Json(api_success(json!({
            "items": items,
            "total": total,
            "page": page,
            "pageSize": page_size
        }))))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageLogQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    q: Option<String>,
    status: Option<String>,
}

pub async fn list_usage_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsageLogQuery>,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(30).clamp(1, 100);
    let search = query.q.unwrap_or_default().trim().to_lowercase();
    let pattern = format!("%{search}%");
    let status = query.status.unwrap_or_default();
    if !status.is_empty() && !["success", "error"].contains(&status.as_str()) {
        return Err(AppError(StatusCode::BAD_REQUEST, "调用状态无效".into()));
    }
    read_database(&state.db, |connection| {
        let total = connection
            .query_row(
                "SELECT COUNT(*)
             FROM usage_logs l JOIN users u ON u.id = l.user_id
             WHERE (?1 = '' OR lower(u.email) LIKE ?2 OR lower(l.ip_address) LIKE ?2
                    OR lower(l.device_id) LIKE ?2 OR lower(l.endpoint) LIKE ?2
                    OR lower(l.prompt) LIKE ?2 OR lower(l.error) LIKE ?2)
               AND (?3 = '' OR l.status = ?3)",
                params![search, pattern, status],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let mut statement = connection
            .prepare(
                "SELECT l.id, l.user_id, u.email, COALESCE(p.name, ''), l.endpoint,
                    l.model, l.status, l.duration_ms, l.credits_used,
                    l.ip_address, l.device_id, l.platform, l.app_version,
                    l.user_agent, l.created_at, l.prompt, l.error, i.id
             FROM usage_logs l
             JOIN users u ON u.id = l.user_id
             LEFT JOIN providers p ON p.id = l.provider_id
             LEFT JOIN images i ON i.id = (
               SELECT image.id FROM images image
               WHERE image.usage_log_id = l.id
               ORDER BY image.created_at, image.id LIMIT 1
             )
             WHERE (?1 = '' OR lower(u.email) LIKE ?2 OR lower(l.ip_address) LIKE ?2
                    OR lower(l.device_id) LIKE ?2 OR lower(l.endpoint) LIKE ?2
                    OR lower(l.prompt) LIKE ?2 OR lower(l.error) LIKE ?2)
               AND (?3 = '' OR l.status = ?3)
             ORDER BY l.created_at DESC LIMIT ?4 OFFSET ?5",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map(
                params![search, pattern, status, page_size, (page - 1) * page_size],
                |row| {
                    let image_url = row
                        .get::<_, Option<String>>(17)?
                        .map(|id| format!("/api/admin/images/{id}/file"));
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "userId": row.get::<_, String>(1)?,
                        "userEmail": row.get::<_, String>(2)?,
                        "providerName": row.get::<_, String>(3)?,
                        "endpoint": row.get::<_, String>(4)?,
                        "model": row.get::<_, String>(5)?,
                        "status": row.get::<_, String>(6)?,
                        "durationMs": row.get::<_, i64>(7)?,
                        "creditsUsed": row.get::<_, i64>(8)?,
                        "ipAddress": row.get::<_, String>(9)?,
                        "deviceId": row.get::<_, String>(10)?,
                        "platform": row.get::<_, String>(11)?,
                        "appVersion": row.get::<_, String>(12)?,
                        "userAgent": row.get::<_, String>(13)?,
                        "createdAt": row.get::<_, String>(14)?,
                        "prompt": row.get::<_, String>(15)?,
                        "error": row.get::<_, String>(16)?,
                        "imageUrl": image_url
                    }))
                },
            )
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(Json(api_success(json!({
            "items": items,
            "total": total,
            "page": page,
            "pageSize": page_size
        }))))
    })
}

pub async fn image_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    admin_user(&headers, &state)?;
    let record = read_database(&state.db, |connection| {
        connection
            .query_row("SELECT file_name FROM images WHERE id = ?1", [&id], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))
    })?;
    crate::images::serve_stored_file(
        &headers,
        state.config.image_directory.join(&record),
        &record,
        "private, max-age=0, must-revalidate",
        "图片文件不存在",
    )
    .await
}

#[derive(Deserialize)]
pub struct IpLocationQuery {
    ip: String,
}

#[derive(Deserialize)]
struct IpWhoResponse {
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    city: String,
    connection: Option<IpWhoConnection>,
}

#[derive(Deserialize)]
struct IpWhoConnection {
    #[serde(default)]
    isp: String,
}

pub async fn ip_location(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IpLocationQuery>,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    let ip = query
        .ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "IP 地址无效".into()))?
        .to_string();
    let cached = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT location, isp FROM ip_locations WHERE ip = ?1",
                [&ip],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(internal_error)
    })?;
    if let Some((location, isp)) = cached {
        return Ok(Json(api_success(json!({
            "ip": ip,
            "location": location,
            "isp": isp,
            "cached": true
        }))));
    }

    let lookup_url = format!("https://ipwho.is/{ip}");
    let result = timeout(StdDuration::from_secs(8), async {
        state
            .client
            .get(lookup_url)
            .query(&[
                (
                    "fields",
                    "success,message,country,region,city,connection.isp",
                ),
                ("lang", "zh-CN"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<IpWhoResponse>()
            .await
    })
    .await
    .map_err(|_| AppError(StatusCode::GATEWAY_TIMEOUT, "IP 地区查询超时".into()))?
    .map_err(|error| {
        tracing::error!(error = %error, "IP location lookup failed");
        AppError(StatusCode::BAD_GATEWAY, "IP 地区查询失败".into())
    })?;
    if !result.success {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            if result.message.is_empty() {
                "IP 地区查询失败".into()
            } else {
                result.message
            },
        ));
    }
    let mut parts = Vec::new();
    for part in [result.country, result.region, result.city] {
        if !part.is_empty() && !parts.contains(&part) {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        return Err(AppError(StatusCode::BAD_GATEWAY, "未查询到 IP 地区".into()));
    }
    let location = parts.join(" · ");
    let isp = result.connection.map(|item| item.isp).unwrap_or_default();
    write_database(&state.db, |connection| {
        connection
            .execute(
                "INSERT INTO ip_locations (ip, location, isp, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET
               location = excluded.location,
               isp = excluded.isp,
               updated_at = excluded.updated_at",
                params![ip, location, isp, Utc::now().to_rfc3339()],
            )
            .map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(json!({
        "ip": ip,
        "location": location,
        "isp": isp,
        "cached": false
    }))))
}

pub async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    read_database(&state.db, |connection| {
        let registration_credits = connection
            .query_row(
                "SELECT value FROM system_settings WHERE key = 'registration_credits'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        let default_daily_limit = connection
            .query_row(
                "SELECT value FROM system_settings WHERE key = 'default_daily_limit'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        // 仍以明文保存的历史 Key 数量，用于驱动退役进度（OPT-07）。
        let legacy_api_keys = connection
            .query_row(
                "SELECT COUNT(*) FROM api_keys WHERE is_legacy = 1 AND status = 'active'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        Ok(Json(api_success(json!({
            "registrationCredits": registration_credits,
            "defaultDailyLimit": default_daily_limit,
            "legacyApiKeys": legacy_api_keys
        }))))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingsRequest {
    registration_credits: i64,
    default_daily_limit: i64,
}

/// 批量吊销遗留的明文 API Key（OPT-07）。
///
/// `is_legacy = 1` 的 Key 在数据库中以明文保存，任何一次库泄露（含
/// `data/backups/` 里的历史快照）都会直接暴露可用凭证。用户侧已有
/// `needs_rotation` 提示，但没有强制期限，因此需要运营侧的兜底手段。
pub async fn revoke_legacy_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let admin = admin_user(&headers, &state)?;
    let revoked = write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let revoked = transaction
            .execute(
                "UPDATE api_keys SET status = 'revoked'
                 WHERE is_legacy = 1 AND status = 'active'",
                [],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "revoke_legacy_api_keys",
            "api_keys",
            "legacy",
            json!({ "revoked": revoked }),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(revoked)
    })?;
    tracing::warn!(revoked, admin = %admin.id, "legacy api keys revoked");
    Ok(Json(api_success(json!({ "revoked": revoked }))))
}

pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateSettingsRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let admin = admin_user(&headers, &state)?;
    if !(0..=1_000_000).contains(&request.registration_credits)
        || !(1..=1_000_000).contains(&request.default_daily_limit)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "系统配置无效".into()));
    }
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let now = Utc::now().to_rfc3339();
        transaction
            .execute(
                "UPDATE system_settings SET value = ?1, updated_at = ?2
             WHERE key = 'registration_credits'",
                params![request.registration_credits, now],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "UPDATE system_settings SET value = ?1, updated_at = ?2
             WHERE key = 'default_daily_limit'",
                params![request.default_daily_limit, now],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "update_settings",
            "system_settings",
            "global",
            json!({
                "registrationCredits": request.registration_credits,
                "defaultDailyLimit": request.default_daily_limit
            }),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

pub async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    admin_user(&headers, &state)?;
    read_database(&state.db, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT id, name, base_url, key_prefix, key_suffix, model,
                    is_active, created_at, encryption_version
             FROM providers WHERE is_global = 1
             ORDER BY is_active DESC, created_at DESC",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map([], |row| {
                let prefix = row.get::<_, Option<String>>(3)?.unwrap_or_default();
                let suffix = row.get::<_, Option<String>>(4)?.unwrap_or_default();
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
    })
}

pub async fn create_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateProviderRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<ProviderResponse>>)> {
    let request = api_json(payload)?;
    let admin = admin_user(&headers, &state)?;
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
    let activate = write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let activate = transaction
            .query_row(
                "SELECT COUNT(*) = 0 FROM providers WHERE is_global = 1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "INSERT INTO providers (
               id, user_id, name, base_url, api_key, api_key_cipher,
               key_prefix, key_suffix, encryption_version, model,
               is_active, is_global, created_at
             ) VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7, 1, ?8, ?9, 1, ?10)",
                params![
                    id, admin.id, name, base_url, encrypted, prefix, suffix, MODEL, activate,
                    created_at
                ],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "create_provider",
            "provider",
            &id,
            json!({ "name": name, "baseUrl": base_url }),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(activate)
    })?;
    Ok((
        StatusCode::CREATED,
        Json(api_success(ProviderResponse {
            id,
            name: name.into(),
            base_url,
            masked_api_key: mask_key(&prefix, &suffix),
            model: MODEL.into(),
            is_active: activate,
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
    let admin = admin_user(&headers, &state)?;
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let exists = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM providers WHERE id = ?1 AND is_global = 1)",
                [&id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(internal_error)?;
        if !exists {
            return Err(AppError(StatusCode::NOT_FOUND, "调用方不存在".into()));
        }
        transaction
            .execute("UPDATE providers SET is_active = 0 WHERE is_global = 1", [])
            .map_err(internal_error)?;
        transaction
            .execute(
                "UPDATE providers SET is_active = 1 WHERE id = ?1 AND is_global = 1",
                [&id],
            )
            .map_err(internal_error)?;
        write_audit(
            &transaction,
            &admin.id,
            "activate_provider",
            "provider",
            &id,
            json!({}),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let admin = admin_user(&headers, &state)?;
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let was_active = transaction
            .query_row(
                "SELECT is_active FROM providers WHERE id = ?1 AND is_global = 1",
                [&id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "调用方不存在".into()))?;
        transaction
            .execute(
                "DELETE FROM providers WHERE id = ?1 AND is_global = 1",
                [&id],
            )
            .map_err(internal_error)?;
        if was_active {
            transaction
                .execute(
                    "UPDATE providers SET is_active = 1 WHERE id = (
                       SELECT id FROM providers WHERE is_global = 1
                       ORDER BY created_at DESC LIMIT 1
                     )",
                    [],
                )
                .map_err(internal_error)?;
        }
        write_audit(
            &transaction,
            &admin.id,
            "delete_provider",
            "provider",
            &id,
            json!({}),
        )
        .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnouncementRequest {
    title: String,
    content: String,
    date: Option<String>,
    r#type: String,
    is_new: Option<bool>,
}

fn validate_announcement(request: &AnnouncementRequest) -> AppResult<()> {
    if request.title.trim().is_empty()
        || request.title.len() > 120
        || request.content.trim().is_empty()
        || request.content.len() > 5000
        || !["feature", "system", "update"].contains(&request.r#type.as_str())
        || request.date.as_ref().is_some_and(|date| date.len() != 10)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "公告参数无效".into()));
    }
    Ok(())
}

pub async fn create_announcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AnnouncementRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<Value>>)> {
    let request = api_json(payload)?;
    validate_announcement(&request)?;
    let admin = admin_user(&headers, &state)?;
    let id = format!("ann-{}", Uuid::new_v4().simple());
    let date = request
        .date
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    write_database(&state.db, |connection| {
        connection
            .execute(
                "INSERT INTO announcements (id, title, content, date, type, is_new)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    request.title.trim(),
                    request.content.trim(),
                    date,
                    request.r#type,
                    request.is_new.unwrap_or(true)
                ],
            )
            .map_err(internal_error)?;
        write_audit(
            connection,
            &admin.id,
            "create_announcement",
            "announcement",
            &id,
            json!({ "title": request.title.trim() }),
        )
        .map_err(internal_error)?;
        Ok(())
    })?;
    Ok((StatusCode::CREATED, Json(api_success(json!({ "id": id })))))
}

pub async fn update_announcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    payload: Result<Json<AnnouncementRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    validate_announcement(&request)?;
    let admin = admin_user(&headers, &state)?;
    let date = request
        .date
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    write_database(&state.db, |connection| {
        let changed = connection
            .execute(
                "UPDATE announcements
                 SET title = ?1, content = ?2, date = ?3, type = ?4, is_new = ?5
                 WHERE id = ?6",
                params![
                    request.title.trim(),
                    request.content.trim(),
                    date,
                    request.r#type,
                    request.is_new.unwrap_or(true),
                    id
                ],
            )
            .map_err(internal_error)?;
        if changed == 0 {
            return Err(AppError(StatusCode::NOT_FOUND, "公告不存在".into()));
        }
        write_audit(
            connection,
            &admin.id,
            "update_announcement",
            "announcement",
            &id,
            json!({ "title": request.title.trim() }),
        )
        .map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

pub async fn delete_announcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let admin = admin_user(&headers, &state)?;
    write_database(&state.db, |connection| {
        let changed = connection
            .execute("DELETE FROM announcements WHERE id = ?1", [&id])
            .map_err(internal_error)?;
        if changed == 0 {
            return Err(AppError(StatusCode::NOT_FOUND, "公告不存在".into()));
        }
        write_audit(
            connection,
            &admin.id,
            "delete_announcement",
            "announcement",
            &id,
            json!({}),
        )
        .map_err(internal_error)?;
        Ok(())
    })?;
    Ok(Json(api_success(Value::Null)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        db::{database, open_database},
        presence::PresenceThrottle,
    };
    use axum::http::{header, HeaderValue};
    use reqwest::Client;
    use std::{fs as std_fs, sync::Arc};
    use tempfile::TempDir;
    use tokio::sync::Semaphore;

    fn test_state() -> (TempDir, AppState) {
        let directory = tempfile::tempdir().unwrap();
        let image_directory = directory.path().join("images");
        let task_directory = directory.path().join("tasks");
        std_fs::create_dir_all(&image_directory).unwrap();
        std_fs::create_dir_all(&task_directory).unwrap();
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
            retention_dry_run: true,
            usage_retention_days: 90,
            task_retention_days: 7,
            ip_location_retention_days: 30,
            audit_retention_days: 365,
            backup_retention_count: 5,
            metrics_token_hash: None,
        };
        let state = AppState {
            db: open_database(directory.path(), &[5_u8; 32]).unwrap(),
            client: Client::new(),
            config,
            task_semaphore: Arc::new(Semaphore::new(1)),
            presence: PresenceThrottle::new(),
        };
        let now = Utc::now().to_rfc3339();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits,
                   credits_reserved, daily_limit, status, is_admin, created_at
                 ) VALUES ('admin-1', 'Admin', 'admin@example.test', 'hash', '', 'Free',
                           0, 0, 100, 'active', 1, ?1)",
                [&now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('admin-session', 'admin-1', ?1, '2099-01-01T00:00:00Z')",
                [&now],
            )
            .unwrap();
        for (id, legacy, status) in [
            ("key-legacy-active", 1, "active"),
            ("key-legacy-revoked", 1, "revoked"),
            ("key-hashed-active", 0, "active"),
        ] {
            connection
                .execute(
                    "INSERT INTO api_keys (
                       id, user_id, name, key_value, is_legacy, scope, status,
                       created_at, last_used
                     ) VALUES (?1, 'admin-1', ?1, ?1, ?2, 'full', ?3, ?4, '未调用')",
                    params![id, legacy, status, now],
                )
                .unwrap();
        }
        drop(connection);
        (directory, state)
    }

    fn admin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("lumora_session=admin-session"),
        );
        headers
    }

    #[tokio::test]
    async fn revokes_only_active_legacy_api_keys() {
        let (_directory, state) = test_state();

        let response = revoke_legacy_api_keys(State(state.clone()), admin_headers())
            .await
            .unwrap();
        assert_eq!(response.0.data["revoked"], 1);

        let statuses = |id: &str| -> String {
            database(&state.db)
                .unwrap()
                .query_row("SELECT status FROM api_keys WHERE id = ?1", [id], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        assert_eq!(statuses("key-legacy-active"), "revoked");
        assert_eq!(statuses("key-legacy-revoked"), "revoked");
        // 哈希存储的 Key 不受影响
        assert_eq!(statuses("key-hashed-active"), "active");

        // 操作写入审计日志
        let audited = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM admin_audit_logs WHERE action = 'revoke_legacy_api_keys'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(audited, 1);

        // 再次执行是幂等的：已无活跃遗留 Key
        let again = revoke_legacy_api_keys(State(state.clone()), admin_headers())
            .await
            .unwrap();
        assert_eq!(again.0.data["revoked"], 0);
    }

    #[tokio::test]
    async fn reports_legacy_key_exposure_in_settings() {
        let (_directory, state) = test_state();
        let settings = get_settings(State(state.clone()), admin_headers())
            .await
            .unwrap();
        assert_eq!(settings.0.data["legacyApiKeys"], 1);
    }

    #[tokio::test]
    async fn includes_retained_usage_summaries_in_all_time_totals() {
        let (_directory, state) = test_state();
        {
            let connection = database(&state.db).unwrap();
            connection
                .execute(
                    "INSERT INTO usage_logs (
                       id, user_id, endpoint, model, status, duration_ms, credits_used, created_at
                     ) VALUES ('usage-live', 'admin-1', '/v1/images/generations', 'test',
                               'success', 10, 2, ?1)",
                    [Utc::now().to_rfc3339()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO usage_daily_summary (
                       summary_date, user_id, provider_id, endpoint, model, status,
                       request_count, total_duration_ms, total_credits_used
                     ) VALUES ('2025-01-01', 'admin-1', '', '/v1/images/generations', 'test',
                               'success', 2, 30, 4)",
                    [],
                )
                .unwrap();
        }

        let overview = overview(State(state.clone()), admin_headers())
            .await
            .unwrap();
        assert_eq!(overview.0.data["totalCalls"], 3);
        assert_eq!(overview.0.data["creditsUsed"], 6);
        assert_eq!(overview.0.data["successRate"], 100.0);

        let users = list_users(
            State(state),
            admin_headers(),
            Query(UserQuery {
                page: Some(1),
                page_size: Some(20),
                q: None,
                status: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(users.0.data["items"][0]["totalCalls"], 3);
        assert_eq!(users.0.data["items"][0]["creditsUsed"], 6);
    }

    #[tokio::test]
    async fn bulk_sets_user_credits_idempotently() {
        let (_directory, state) = test_state();
        database(&state.db)
            .unwrap()
            .execute_batch(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits,
                   credits_reserved, daily_limit, status, is_admin, created_at
                 ) VALUES
                   ('user-2', 'User 2', 'user2@example.test', 'hash', '', 'Free',
                    10, 2, 100, 'active', 0, '2026-01-01T00:00:00Z'),
                   ('user-3', 'User 3', 'user3@example.test', 'hash', '', 'Free',
                    20, 0, 100, 'active', 0, '2026-01-01T00:00:00Z');",
            )
            .unwrap();

        let request = || -> Result<Json<BulkCreditSetRequest>, JsonRejection> {
            Ok(Json(BulkCreditSetRequest {
                user_ids: vec!["user-2".into(), "user-3".into()],
                credits: 80,
                reason: "统一发放".into(),
                request_id: "bulk-request-1".into(),
            }))
        };
        let response = bulk_set_credits(State(state.clone()), admin_headers(), request())
            .await
            .unwrap();
        assert_eq!(response.0.data["updated"], 2);

        let balances = {
            let connection = database(&state.db).unwrap();
            let mut statement = connection
                .prepare("SELECT credits FROM users WHERE id IN ('user-2', 'user-3') ORDER BY id")
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(balances, vec![80, 80]);

        let repeated = bulk_set_credits(State(state.clone()), admin_headers(), request())
            .await
            .unwrap();
        assert_eq!(repeated.0.data["updated"], 0);
        let ledger_count = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM credit_ledger
                 WHERE reference_id LIKE 'admin-bulk:bulk-request-1:%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(ledger_count, 2);
    }

    #[tokio::test]
    async fn returns_user_details_with_masked_providers() {
        let (_directory, state) = test_state();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO providers (
                   id, user_id, name, base_url, api_key, api_key_cipher,
                   key_prefix, key_suffix, encryption_version, model,
                   is_active, is_global, created_at
                 ) VALUES (
                   'provider-user', 'admin-1', 'User Provider', 'https://example.test',
                   '', 'cipher', 'sk-admin-', 'tail', 1, 'test-model', 1, 0,
                   '2026-01-01T00:00:00Z'
                 )",
                [],
            )
            .unwrap();

        let response = get_user(State(state), admin_headers(), AxumPath("admin-1".into()))
            .await
            .unwrap();
        assert_eq!(response.0.data["email"], "admin@example.test");
        assert_eq!(response.0.data["passwordConfigured"], true);
        assert!(response.0.data.get("passwordHash").is_none());
        assert_eq!(response.0.data["providers"][0]["name"], "User Provider");
        assert_eq!(
            response.0.data["providers"][0]["maskedApiKey"],
            "sk-admin-••••••••••••tail"
        );
    }

    #[tokio::test]
    async fn usage_logs_include_prompt_and_error() {
        let (_directory, state) = test_state();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO usage_logs (
                   id, user_id, endpoint, model, status, duration_ms, credits_used,
                   prompt, error, created_at
                 ) VALUES (
                   'usage-error', 'admin-1', '/v1/images/generations', 'test-model',
                   'error', 25, 0, '测试提示词', '上游请求失败', ?1
                 )",
                [Utc::now().to_rfc3339()],
            )
            .unwrap();

        let response = list_usage_logs(
            State(state),
            admin_headers(),
            Query(UsageLogQuery {
                page: Some(1),
                page_size: Some(20),
                q: None,
                status: Some("error".into()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0.data["items"][0]["prompt"], "测试提示词");
        assert_eq!(response.0.data["items"][0]["error"], "上游请求失败");
    }

    #[tokio::test]
    async fn rejects_non_admin_callers() {
        let (_directory, state) = test_state();
        database(&state.db)
            .unwrap()
            .execute("UPDATE users SET is_admin = 0 WHERE id = 'admin-1'", [])
            .unwrap();
        match revoke_legacy_api_keys(State(state), admin_headers()).await {
            Err(error) => assert_eq!(error.0, StatusCode::FORBIDDEN),
            Ok(_) => panic!("非管理员账号仍能吊销遗留 Key"),
        }
    }
}
