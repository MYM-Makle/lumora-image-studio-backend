use std::{
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, MatchedPath, Request as AxumRequest},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use metrics::{counter, histogram};
use tower_governor::{key_extractor::KeyExtractor, GovernorError};
use tracing::Instrument;
use uuid::Uuid;

use crate::model::AppError;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone, Copy, Debug)]
pub struct TrustedClientIpKeyExtractor;

impl KeyExtractor for TrustedClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| client_ip_addr(request.headers(), peer.0))
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// 从请求中提取客户端 IP。
///
/// 只有当直连对端本身是回环/私网地址（即请求确实经由本地反代进来）时才信任
/// `X-Forwarded-For` / `X-Real-IP`，否则任何人都能伪造来源 IP，使基于 IP 的
/// 限流与审计失效。
pub fn client_ip(headers: &HeaderMap, peer_addr: SocketAddr) -> String {
    client_ip_addr(headers, peer_addr).to_string()
}

fn client_ip_addr(headers: &HeaderMap, peer_addr: SocketAddr) -> IpAddr {
    let trusted_proxy = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    };
    trusted_proxy
        .then(|| header_text(headers, "x-forwarded-for", 64))
        .flatten()
        .and_then(|value| value.split(',').next()?.trim().parse().ok())
        .or_else(|| {
            trusted_proxy
                .then(|| header_text(headers, "x-real-ip", 64))
                .flatten()
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or_else(|| peer_addr.ip())
}

/// 读取请求头文本，去除空白并按字符数截断。
pub fn header_text(headers: &HeaderMap, name: &str, max_len: usize) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(max_len).collect())
}

pub fn request_id(headers: &HeaderMap) -> Option<String> {
    header_text(headers, REQUEST_ID_HEADER.as_str(), 128).filter(|value| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    })
}

/// 为每个请求建立同一个追踪上下文，并把 ID 回写到所有响应（包括错误响应）。
pub async fn observe_request(mut request: AxumRequest, next: Next) -> Response {
    let request_id =
        request_id(request.headers()).unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let request_id_header =
        HeaderValue::from_str(&request_id).expect("validated request ID is a valid header value");
    request
        .headers_mut()
        .insert(REQUEST_ID_HEADER.clone(), request_id_header.clone());

    let method = request.method().as_str().to_owned();
    // 使用路由模板而不是原始 URL，避免图片/任务 ID 造成指标标签无限增长。
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_owned();
    let span = tracing::info_span!(
        "http.request",
        request_id = %request_id,
        method = %method,
        route = %route
    );
    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let elapsed = started.elapsed();
    let status = response.status().as_u16().to_string();

    counter!(
        "lumora_http_requests_total",
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status.clone()
    )
    .increment(1);
    histogram!(
        "lumora_http_request_duration_seconds",
        "method" => method,
        "route" => route
    )
    .record(elapsed.as_secs_f64());
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER.clone(), request_id_header);
    tracing::info!(
        parent: &span,
        status = %status,
        duration_ms = elapsed.as_millis() as u64,
        "request completed"
    );
    response
}

/// 校验请求来自本站客户端，用于堵住 multipart 端点的 CSRF 缺口（OPT-06）。
///
/// 生产环境的会话 Cookie 是 `SameSite=None`（桌面端跨源访问所必需），而
/// `multipart/form-data` 属于 CORS 规范中的"简单请求"，**不触发预检**。因此第三方
/// 页面可以用 `fetch(..., { mode: 'no-cors', credentials: 'include' })` 携带
/// `FormData` 提交到改图接口——响应读不到，但积分已经被消耗。
///
/// 自定义请求头必然触发预检，会被 CORS 白名单挡下，因此它本身就等价于 CSRF token。
/// 前端 `services/http.ts` 已无条件发送该头，无需改动客户端。
///
/// 仅用于站内 `/api/*` 的 multipart 端点：`/v1/*` 走 Bearer 鉴权、不依赖 Cookie，
/// 管理后台也不调用这些端点。
pub fn ensure_first_party_client(headers: &HeaderMap) -> crate::model::AppResult<()> {
    if header_text(headers, "x-lumora-device-id", 128).is_none() {
        return Err(crate::model::AppError(
            axum::http::StatusCode::FORBIDDEN,
            "缺少客户端标识".into(),
        ));
    }
    Ok(())
}

/// 所有修改站内状态的请求都必须携带自定义头；外部 `/v1/*` 路由不挂载此中间件。
pub async fn require_first_party_request(
    request: AxumRequest,
    next: Next,
) -> Result<Response, AppError> {
    if matches!(
        *request.method(),
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE
    ) && header_text(request.headers(), "x-lumora-device-id", 128).is_none()
    {
        return Err(AppError(StatusCode::FORBIDDEN, "缺少客户端标识".into()));
    }
    Ok(next.run(request).await)
}

pub fn rate_limit_response(error: GovernorError) -> Response<Body> {
    let (status, message, headers) = match error {
        GovernorError::TooManyRequests { headers, .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            "请求过于频繁，请稍后再试".to_owned(),
            headers,
        ),
        GovernorError::UnableToExtractKey => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法识别请求来源".to_owned(),
            None,
        ),
        GovernorError::Other { code, msg, headers } => (
            code,
            msg.unwrap_or_else(|| "请求限制检查失败".to_owned()),
            headers,
        ),
    };
    let mut response = AppError(status, message).into_response();
    if let Some(headers) = headers {
        response.headers_mut().extend(headers);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderValue, Method, Request},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn headers_with(name: &'static str, value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn trusts_forwarded_headers_only_behind_a_local_proxy() {
        let headers = headers_with("x-forwarded-for", "203.0.113.9, 10.0.0.1");

        let via_proxy: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(client_ip(&headers, via_proxy), "203.0.113.9");

        // 直连的公网对端不可信，必须回退到真实 peer 地址。
        let direct: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        assert_eq!(client_ip(&headers, direct), "198.51.100.7");
    }

    #[test]
    fn falls_back_to_real_ip_then_peer_address() {
        let via_proxy: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        let headers = headers_with("x-real-ip", "203.0.113.20");
        assert_eq!(client_ip(&headers, via_proxy), "203.0.113.20");
        assert_eq!(client_ip(&HeaderMap::new(), via_proxy), "10.0.0.5");
    }

    #[test]
    fn ignores_invalid_forwarded_addresses() {
        let via_proxy: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        let headers = headers_with("x-forwarded-for", "not-an-ip");
        assert_eq!(client_ip(&headers, via_proxy), "10.0.0.5");
    }

    #[test]
    fn truncates_and_trims_header_text() {
        let headers = headers_with("x-lumora-platform", "  windows  ");
        assert_eq!(
            header_text(&headers, "x-lumora-platform", 64).as_deref(),
            Some("windows")
        );
        assert_eq!(
            header_text(&headers, "x-lumora-platform", 3).as_deref(),
            Some("win")
        );
        assert_eq!(header_text(&headers, "missing", 64), None);
    }

    #[test]
    fn rate_limit_response_preserves_retry_after() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "2".parse().unwrap());
        let response = rate_limit_response(GovernorError::TooManyRequests {
            wait_time: 2,
            headers: Some(headers),
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "2");
    }

    #[tokio::test]
    async fn csrf_middleware_protects_only_state_changing_requests() {
        let app = Router::new()
            .route("/test", get(|| async {}).post(|| async {}))
            .layer(axum::middleware::from_fn(require_first_party_request));

        let get_response = app
            .clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let post_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_response.status(), StatusCode::FORBIDDEN);

        let allowed_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .header("x-lumora-device-id", "test-device")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_id_is_preserved_on_error_responses() {
        let app = Router::new()
            .route("/test", get(|| async { StatusCode::BAD_REQUEST }))
            .layer(axum::middleware::from_fn(observe_request));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(REQUEST_ID_HEADER.clone(), "request-test-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[&REQUEST_ID_HEADER], "request-test-1");
    }
}
