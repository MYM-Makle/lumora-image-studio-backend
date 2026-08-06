use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        Query,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MODEL: &str = "gpt-image-2";
pub const SESSION_COOKIE: &str = "lumora_session";

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: T,
    pub timestamp: i64,
}

pub fn api_success<T>(data: T) -> ApiResponse<T> {
    ApiResponse {
        code: 0,
        message: "success".into(),
        data,
        timestamp: Utc::now().timestamp_millis(),
    }
}

pub fn api_json<T>(payload: Result<Json<T>, JsonRejection>) -> AppResult<T> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        let status = match rejection.status() {
            StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
            status => status,
        };
        AppError(status, "JSON 参数无效".into())
    })
}

pub fn api_query<T>(payload: Result<Query<T>, QueryRejection>) -> AppResult<T> {
    payload
        .map(|Query(value)| value)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "查询参数无效".into()))
}

pub struct AppError(pub StatusCode, pub String);

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.1)
    }
}

impl std::fmt::Debug for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AppError")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let AppError(status, message) = self;
        (
            status,
            Json(ApiResponse {
                code: i32::from(status.as_u16()),
                message,
                data: Value::Null,
                timestamp: Utc::now().timestamp_millis(),
            }),
        )
            .into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

pub struct OpenAiError(pub AppError);

impl From<AppError> for OpenAiError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl IntoResponse for OpenAiError {
    fn into_response(self) -> Response {
        let AppError(status, message) = self.0;
        let error_type = match status {
            StatusCode::UNAUTHORIZED => "authentication_error",
            StatusCode::FORBIDDEN => "permission_error",
            StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
            status if status.is_client_error() => "invalid_request_error",
            _ => "api_error",
        };
        (
            status,
            Json(json!({
                "error": {
                    "message": message,
                    "type": error_type,
                    "param": null,
                    "code": null
                }
            })),
        )
            .into_response()
    }
}

pub type OpenAiResult<T> = Result<T, OpenAiError>;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: String,
    pub name: String,
    pub email: String,
    pub avatar: String,
    pub plan: String,
    pub credits: i64,
    pub credits_reserved: i64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageResponse {
    pub id: String,
    pub url: String,
    pub thumbnail_url: String,
    pub prompt: String,
    pub size: String,
    pub model: String,
    pub created_at: String,
    pub source: &'static str,
    pub format: String,
    pub is_public: bool,
    pub category: String,
    pub storage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reference_images: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyItemResponse {
    pub id: String,
    pub name: String,
    pub masked_key: String,
    pub created_at: String,
    pub last_used: String,
    pub status: String,
    pub scope: String,
    pub needs_rotation: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedApiKeyResponse {
    pub item: ApiKeyItemResponse,
    pub secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResponse {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub masked_api_key: String,
    pub model: String,
    pub is_active: bool,
    pub created_at: String,
    pub needs_rotation: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnouncementResponse {
    pub id: String,
    pub title: String,
    pub content: String,
    pub date: String,
    pub r#type: String,
    pub is_new: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageItemResponse {
    pub id: String,
    pub endpoint: String,
    pub model: String,
    pub status: String,
    pub duration_ms: i64,
    pub credits_used: i64,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    pub today_calls: i64,
    pub daily_limit: i64,
    pub average_latency_ms: i64,
    pub items: Vec<UsageItemResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
    pub verification_code: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailCodeRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub password: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scope: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProviderRequest {
    pub name: String,
    pub base_url: String,
    pub api_key: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateRequest {
    pub prompt: String,
    #[serde(default = "default_size")]
    pub size: String,
    #[serde(default = "default_quality")]
    pub quality: String,
    #[serde(default = "default_count")]
    pub n: u8,
    #[serde(default)]
    #[serde(alias = "is_public")]
    pub is_public: bool,
    #[serde(default = "default_output_format")]
    #[serde(alias = "output_format")]
    pub output_format: String,
    pub model: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateImageVisibilityRequest {
    pub is_public: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditJsonRequest {
    pub prompt: String,
    pub images: Vec<serde_json::Value>,
    pub mask: Option<serde_json::Value>,
    #[serde(default = "default_size")]
    pub size: String,
    #[serde(default = "default_quality")]
    pub quality: String,
    #[serde(default = "default_count")]
    pub n: u8,
    #[serde(default)]
    #[serde(alias = "is_public")]
    pub is_public: bool,
    #[serde(default = "default_output_format")]
    #[serde(alias = "output_format")]
    pub output_format: String,
    pub model: Option<String>,
    #[serde(default)]
    pub batch: bool,
}

#[derive(Clone)]
pub struct ImageInput {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub mime_type: String,
}

#[derive(Clone)]
pub struct EditRequest {
    pub generation: GenerateRequest,
    pub images: Vec<ImageInput>,
    pub mask: Option<ImageInput>,
    pub batch: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmTasksRequest {
    pub task_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct UpstreamResponse {
    pub data: Option<Vec<UpstreamImage>>,
    pub error: Option<UpstreamError>,
    pub usage: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct UpstreamImage {
    pub b64_json: Option<String>,
}

#[derive(Deserialize)]
pub struct UpstreamError {
    pub message: Option<String>,
}

#[derive(Clone)]
pub struct ProviderConfiguration {
    pub id: String,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

#[derive(Clone)]
pub struct ApiPrincipal {
    pub user: UserResponse,
    pub scope: String,
}

#[derive(Serialize)]
pub struct OpenAiImageData {
    pub b64_json: String,
}

#[derive(Serialize)]
pub struct OpenAiImagesResponse {
    pub created: i64,
    pub data: Vec<OpenAiImageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<serde_json::Value>,
}

pub fn default_size() -> String {
    "1024x1024".into()
}

pub fn default_quality() -> String {
    "auto".into()
}

pub fn default_count() -> u8 {
    1
}

pub fn default_output_format() -> String {
    "png".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn serializes_success_envelope() {
        let body = serde_json::to_value(api_success(json!({ "value": 1 }))).unwrap();
        assert_eq!(body["code"], 0);
        assert_eq!(body["message"], "success");
        assert_eq!(body["data"]["value"], 1);
        assert!(body["timestamp"].as_i64().is_some());
    }

    #[tokio::test]
    async fn serializes_error_envelope() {
        let response = AppError(StatusCode::CONFLICT, "冲突".into()).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], 409);
        assert_eq!(body["message"], "冲突");
        assert!(body["data"].is_null());
    }
}
