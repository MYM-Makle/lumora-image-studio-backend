use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};

use crate::{
    model::{
        AppError, AppResult, EditRequest, GenerateRequest, ImageInput, ProviderConfiguration,
        UpstreamResponse,
    },
    request::REQUEST_ID_HEADER,
};

use super::{detect_image_format, GeneratedOutput};

pub(super) async fn request_upstream_generation(
    client: &reqwest::Client,
    provider: &ProviderConfiguration,
    request: &GenerateRequest,
    request_id: &str,
) -> AppResult<(Vec<GeneratedOutput>, Option<Value>)> {
    let endpoint = provider_endpoint(&provider.base_url, "/images/generations");
    let mut payload = json!({
        "model": provider.model,
        "prompt": request.prompt.trim()
    });
    if request.size != "auto" {
        payload["size"] = json!(request.size);
    }
    if request.quality != "auto" {
        payload["quality"] = json!(request.quality);
    }
    if request.output_format != "png" {
        payload["output_format"] = json!(request.output_format);
    }
    let response = client
        .post(endpoint)
        .bearer_auth(&provider.api_key)
        .header(REQUEST_ID_HEADER.clone(), request_id)
        .json(&payload)
        .send()
        .await
        .map_err(|_| AppError(StatusCode::BAD_GATEWAY, "调用上游失败".into()))?;
    parse_upstream_response(response, 1).await
}

pub(super) async fn request_upstream_edit(
    client: &reqwest::Client,
    provider: &ProviderConfiguration,
    request: &EditRequest,
    request_id: &str,
) -> AppResult<(Vec<GeneratedOutput>, Option<Value>)> {
    let endpoint = provider_endpoint(&provider.base_url, "/images/edits");
    let mut form = Form::new()
        .text("model", provider.model.clone())
        .text("prompt", request.generation.prompt.trim().to_string());
    if request.generation.size != "auto" {
        form = form.text("size", request.generation.size.clone());
    }
    if request.generation.quality != "auto" {
        form = form.text("quality", request.generation.quality.clone());
    }
    if request.generation.output_format != "png" {
        form = form.text("output_format", request.generation.output_format.clone());
    }
    for image in &request.images {
        form = form.part("image[]", multipart_part(image)?);
    }
    if let Some(mask) = &request.mask {
        form = form.part("mask", multipart_part(mask)?);
    }
    let response = client
        .post(endpoint)
        .bearer_auth(&provider.api_key)
        .header(REQUEST_ID_HEADER.clone(), request_id)
        .multipart(form)
        .send()
        .await
        .map_err(|_| AppError(StatusCode::BAD_GATEWAY, "调用上游失败".into()))?;
    parse_upstream_response(response, 1).await
}

fn multipart_part(input: &ImageInput) -> AppResult<Part> {
    Part::bytes(input.bytes.clone())
        .file_name(input.file_name.clone())
        .mime_str(&input.mime_type)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "图片类型无效".into()))
}

async fn parse_upstream_response(
    response: reqwest::Response,
    expected: usize,
) -> AppResult<(Vec<GeneratedOutput>, Option<Value>)> {
    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|_| AppError(StatusCode::BAD_GATEWAY, "上游响应读取失败".into()))?;
    let body = serde_json::from_str::<UpstreamResponse>(&response_body);
    if !status.is_success() {
        let fallback = response_body.trim();
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            body.ok()
                .and_then(|body| body.error)
                .and_then(|error| error.message)
                .unwrap_or_else(|| {
                    if fallback.is_empty() {
                        format!("上游返回 {status}")
                    } else {
                        format!(
                            "上游返回 {status}: {}",
                            fallback.chars().take(500).collect::<String>()
                        )
                    }
                }),
        ));
    }
    let body = body.map_err(|_| {
        let preview = response_body.trim().chars().take(500).collect::<String>();
        AppError(
            StatusCode::BAD_GATEWAY,
            if preview.is_empty() {
                "上游响应为空".into()
            } else {
                format!("上游响应无效: {preview}")
            },
        )
    })?;
    let mut outputs = Vec::new();
    for item in body.data.unwrap_or_default().into_iter().take(expected) {
        let encoded = item
            .b64_json
            .ok_or_else(|| AppError(StatusCode::BAD_GATEWAY, "上游响应缺少图片数据".into()))?;
        let bytes = BASE64
            .decode(&encoded)
            .map_err(|_| AppError(StatusCode::BAD_GATEWAY, "上游图片数据无法解码".into()))?;
        let (format, _) = detect_image_format(&bytes)
            .ok_or_else(|| AppError(StatusCode::BAD_GATEWAY, "上游返回的图片格式无效".into()))?;
        outputs.push(GeneratedOutput {
            encoded,
            bytes,
            format: format.into(),
        });
    }
    if outputs.is_empty() {
        return Err(AppError(StatusCode::BAD_GATEWAY, "上游未返回图片".into()));
    }
    Ok((outputs, body.usage))
}

fn provider_endpoint(base_url: &str, suffix: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}{suffix}")
    } else {
        format!("{base}/v1{suffix}")
    }
}
