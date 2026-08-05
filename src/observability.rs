use std::sync::OnceLock;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use metrics::{describe_counter, describe_gauge, describe_histogram, gauge, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

use crate::{
    model::{AppError, AppResult},
    AppState,
};

static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_tracing(production: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "lumora_server=info,tower_http=info".into());
    if production {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .flatten_event(true)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

pub fn install_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    PROMETHEUS
        .set(handle)
        .map_err(|_| "metrics recorder already installed")?;

    describe_counter!(
        "lumora_http_requests_total",
        "HTTP requests by route and status"
    );
    describe_histogram!(
        "lumora_http_request_duration_seconds",
        Unit::Seconds,
        "HTTP request duration"
    );
    describe_histogram!(
        "lumora_db_operation_duration_seconds",
        Unit::Seconds,
        "SQLite operation duration including pool wait"
    );
    describe_counter!(
        "lumora_generation_requests_total",
        "Generation attempts by endpoint and result"
    );
    describe_histogram!(
        "lumora_generation_duration_seconds",
        Unit::Seconds,
        "Generation duration by endpoint and result"
    );
    describe_gauge!(
        "lumora_task_queue_depth",
        "Tasks waiting for a worker permit"
    );
    describe_counter!(
        "lumora_credits_consumed_total",
        "Credits consumed by successful generation"
    );
    gauge!("lumora_task_queue_depth").set(0.0);
    Ok(())
}

pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let expected = state.config.metrics_token_hash.ok_or_else(|| {
        // 未配置令牌时隐藏端点，避免误以为指标已受保护。
        AppError(StatusCode::NOT_FOUND, "接口不存在".into())
    })?;
    let supplied = bearer_token(&headers)
        .map(|value| Sha256::digest(value.as_bytes()).into())
        .filter(|digest| constant_time_eq(&expected, digest));
    if supplied.is_none() {
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            "指标访问令牌无效".into(),
        ));
    }

    let body = PROMETHEUS
        .get()
        .ok_or_else(|| AppError(StatusCode::SERVICE_UNAVAILABLE, "指标尚未初始化".into()))?
        .render();
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok(response)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn constant_time_eq(expected: &[u8; 32], supplied: &[u8; 32]) -> bool {
    expected
        .iter()
        .zip(supplied)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_digest_comparison_checks_all_bytes() {
        let expected = [7_u8; 32];
        assert!(constant_time_eq(&expected, &[7_u8; 32]));
        assert!(!constant_time_eq(&expected, &[8_u8; 32]));
    }
}
