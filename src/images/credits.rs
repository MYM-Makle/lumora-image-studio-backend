use axum::http::StatusCode;
use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    db::{internal_error, utc_day_bounds, write_database},
    model::{AppError, AppResult, MODEL},
    AppState,
};

use super::RequestMetadata;

pub(super) fn reserve_credits(state: &AppState, user_id: &str, amount: i64) -> AppResult<()> {
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let (today_start, tomorrow_start) = utc_day_bounds(Utc::now());
        let (credits, reserved, daily_limit, today_calls): (i64, i64, i64, i64) = transaction
            .query_row(
                "SELECT u.credits, u.credits_reserved, u.daily_limit,
                    (SELECT COUNT(*) FROM usage_logs l
                     WHERE l.user_id = u.id AND l.created_at >= ?2 AND l.created_at < ?3)
             FROM users u WHERE u.id = ?1",
                params![user_id, today_start, tomorrow_start],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(internal_error)?;
        if today_calls + amount > daily_limit {
            return Err(AppError(
                StatusCode::TOO_MANY_REQUESTS,
                "今日调用次数已达上限".into(),
            ));
        }
        if credits - reserved < amount {
            return Err(AppError(StatusCode::FORBIDDEN, "积分不足".into()));
        }
        transaction
            .execute(
                "UPDATE users SET credits_reserved = credits_reserved + ?1 WHERE id = ?2",
                params![amount, user_id],
            )
            .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn settle_failure(
    state: &AppState,
    user_id: &str,
    provider_id: Option<&str>,
    reserved: i64,
    metadata: &RequestMetadata,
    endpoint: &str,
    duration_ms: i64,
    task_id: Option<&str>,
    message: &str,
) -> AppResult<()> {
    write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        transaction
            .execute(
                "UPDATE users
                 SET credits_reserved = MAX(credits_reserved - ?1, 0) WHERE id = ?2",
                params![reserved, user_id],
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "INSERT INTO usage_logs (
                   id, user_id, provider_id, endpoint, model, status,
                   duration_ms, credits_used, ip_address, device_id, platform,
                   app_version, user_agent, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'error', ?6, 0, ?7, ?8, ?9,
                           ?10, ?11, ?12)",
                params![
                    format!("log-{}", Uuid::new_v4().simple()),
                    user_id,
                    provider_id,
                    endpoint,
                    MODEL,
                    duration_ms,
                    metadata.ip_address,
                    metadata.device_id,
                    metadata.platform,
                    metadata.app_version,
                    metadata.user_agent,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(internal_error)?;
        if let Some(task_id) = task_id {
            transaction
                .execute(
                    "UPDATE tasks SET status = 'error', error = ?1, credits_used = 0,
                     updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
                    params![message, Utc::now().to_rfc3339(), task_id, user_id],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })?;
    record_generation_metrics(endpoint, "error", duration_ms, 0);
    Ok(())
}

pub(super) fn record_generation_metrics(
    endpoint: &str,
    status: &'static str,
    duration_ms: i64,
    credits: i64,
) {
    metrics::counter!(
        "lumora_generation_requests_total",
        "endpoint" => endpoint.to_owned(),
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "lumora_generation_duration_seconds",
        "endpoint" => endpoint.to_owned(),
        "status" => status
    )
    .record(duration_ms.max(0) as f64 / 1000.0);
    if credits > 0 {
        metrics::counter!("lumora_credits_consumed_total", "endpoint" => endpoint.to_owned())
            .increment(credits as u64);
    }
}
