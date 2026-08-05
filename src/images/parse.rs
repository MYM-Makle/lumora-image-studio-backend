use std::collections::HashMap;

use axum::{
    body::{to_bytes, Body},
    extract::{FromRequest, Multipart},
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;

use crate::{
    model::{
        default_quality, default_size, AppError, AppResult, EditJsonRequest, EditRequest,
        GenerateRequest, ImageInput, MODEL,
    },
    AppState,
};

const MAX_EDIT_BODY: usize = 100 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 50 * 1024 * 1024;

pub(super) fn validate_generation(request: &GenerateRequest) -> AppResult<()> {
    let prompt = request.prompt.trim();
    if prompt.is_empty() || prompt.len() > 32_000 {
        return Err(AppError(StatusCode::BAD_REQUEST, "提示词长度无效".into()));
    }
    if request.model.as_deref().is_some_and(|model| model != MODEL) {
        return Err(AppError(StatusCode::BAD_REQUEST, "模型不受支持".into()));
    }
    if !(1..=4).contains(&request.n) {
        return Err(AppError(StatusCode::BAD_REQUEST, "n 必须为 1-4".into()));
    }
    if !["auto", "low", "medium", "high"].contains(&request.quality.as_str()) {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片质量无效".into()));
    }
    if !["png", "jpeg", "webp"].contains(&request.output_format.as_str()) {
        return Err(AppError(StatusCode::BAD_REQUEST, "输出格式无效".into()));
    }
    validate_size(&request.size)
}

pub(super) fn validate_size(size: &str) -> AppResult<()> {
    if size == "auto" {
        return Ok(());
    }
    let Some((width, height)) = size.split_once('x') else {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片尺寸无效".into()));
    };
    let (Ok(width), Ok(height)) = (width.parse::<u64>(), height.parse::<u64>()) else {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片尺寸无效".into()));
    };
    let long = width.max(height);
    let short = width.min(height);
    let pixels = width.saturating_mul(height);
    if width == 0
        || height == 0
        || long > 7168
        || width % 16 != 0
        || height % 16 != 0
        || long > short.saturating_mul(3)
        || !(655_360..=29_360_128).contains(&pixels)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片尺寸无效".into()));
    }
    Ok(())
}

pub(super) fn validate_edit_inputs(request: &EditRequest) -> AppResult<()> {
    if request.images.is_empty() || request.images.len() > 4 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "参考图片数量必须为 1-4".into(),
        ));
    }
    for input in request.images.iter().chain(request.mask.iter()) {
        if input.bytes.is_empty() || input.bytes.len() > MAX_IMAGE_BYTES {
            return Err(AppError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "图片文件过大".into(),
            ));
        }
        if detect_image_format(&input.bytes).is_none() {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "仅支持 PNG、JPEG 和 WebP 图片".into(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn parse_edit_request(
    state: &AppState,
    request: Request<Body>,
) -> AppResult<EditRequest> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    if content_type.starts_with("application/json") {
        let body = to_bytes(request.into_body(), MAX_EDIT_BODY)
            .await
            .map_err(|_| AppError(StatusCode::PAYLOAD_TOO_LARGE, "请求体过大".into()))?;
        let json: EditJsonRequest = serde_json::from_slice(&body)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "JSON 参数无效".into()))?;
        return edit_from_json(json);
    }
    if !content_type.starts_with("multipart/form-data") {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "编辑请求必须使用 multipart/form-data 或 application/json".into(),
        ));
    }
    let mut multipart = Multipart::from_request(request, state)
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "multipart 请求无效".into()))?;
    let mut fields = HashMap::new();
    let mut images = Vec::new();
    let mut mask = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "上传数据无效".into()))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if matches!(name.as_str(), "image" | "image[]" | "images") {
            images.push(input_from_field(field).await?);
        } else if name == "mask" {
            mask = Some(input_from_field(field).await?);
        } else {
            let value = field
                .text()
                .await
                .map_err(|_| AppError(StatusCode::BAD_REQUEST, "表单参数无效".into()))?;
            fields.insert(name, value);
        }
    }
    let request = GenerateRequest {
        prompt: fields.remove("prompt").unwrap_or_default(),
        size: fields.remove("size").unwrap_or_else(default_size),
        quality: fields.remove("quality").unwrap_or_else(default_quality),
        n: fields
            .remove("n")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
        is_public: fields
            .remove("isPublic")
            .or_else(|| fields.remove("is_public"))
            .is_some_and(|value| value == "true"),
        output_format: fields
            .remove("output_format")
            .or_else(|| fields.remove("outputFormat"))
            .unwrap_or_else(|| "png".into()),
        model: fields.remove("model"),
    };
    Ok(EditRequest {
        generation: request,
        images,
        mask,
        batch: fields.remove("batch").is_some_and(|value| value == "true"),
    })
}

pub(super) async fn input_from_field(
    field: axum::extract::multipart::Field<'_>,
) -> AppResult<ImageInput> {
    let file_name = field.file_name().unwrap_or("image").to_string();
    let declared_type = field.content_type().unwrap_or("").to_string();
    let bytes = field
        .bytes()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "图片上传失败".into()))?
        .to_vec();
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(AppError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "图片文件过大".into(),
        ));
    }
    let (_, detected_type) = detect_image_format(&bytes)
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "图片格式无效".into()))?;
    if !declared_type.is_empty() && !declared_type.starts_with("image/") {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片类型无效".into()));
    }
    Ok(ImageInput {
        bytes,
        file_name,
        mime_type: detected_type.into(),
    })
}

fn edit_from_json(request: EditJsonRequest) -> AppResult<EditRequest> {
    let images = request
        .images
        .iter()
        .enumerate()
        .map(|(index, value)| image_input_from_json(value, &format!("image-{index}")))
        .collect::<AppResult<Vec<_>>>()?;
    let mask = request
        .mask
        .as_ref()
        .map(|value| image_input_from_json(value, "mask"))
        .transpose()?;
    Ok(EditRequest {
        generation: GenerateRequest {
            prompt: request.prompt,
            size: request.size,
            quality: request.quality,
            n: request.n,
            is_public: request.is_public,
            output_format: request.output_format,
            model: request.model,
        },
        images,
        mask,
        batch: request.batch,
    })
}

pub(super) fn image_input_from_json(value: &Value, fallback_name: &str) -> AppResult<ImageInput> {
    let (encoded, declared_type, file_name) = if let Some(value) = value.as_str() {
        parse_data_url(value, fallback_name)?
    } else if let Some(object) = value.as_object() {
        if let Some(encoded) = object.get("b64_json").and_then(Value::as_str) {
            (
                encoded.to_string(),
                object
                    .get("mime_type")
                    .and_then(Value::as_str)
                    .unwrap_or("image/png")
                    .to_string(),
                object
                    .get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or(fallback_name)
                    .to_string(),
            )
        } else if let Some(url) = object.get("image_url") {
            let url = url
                .as_str()
                .or_else(|| url.get("url").and_then(Value::as_str))
                .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "image_url 无效".into()))?;
            parse_data_url(url, fallback_name)?
        } else {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "图片 JSON 格式无效".into(),
            ));
        }
    } else {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "图片 JSON 格式无效".into(),
        ));
    };
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "图片 base64 无效".into()))?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(AppError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "图片文件过大".into(),
        ));
    }
    let (_, detected_type) = detect_image_format(&bytes)
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "图片格式无效".into()))?;
    if !declared_type.starts_with("image/") {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片类型无效".into()));
    }
    Ok(ImageInput {
        bytes,
        file_name,
        mime_type: detected_type.into(),
    })
}

fn parse_data_url(value: &str, fallback_name: &str) -> AppResult<(String, String, String)> {
    let Some(rest) = value.strip_prefix("data:") else {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "仅支持 data URL 或 base64 图片，不支持远程 URL".into(),
        ));
    };
    let Some((metadata, encoded)) = rest.split_once(',') else {
        return Err(AppError(StatusCode::BAD_REQUEST, "data URL 无效".into()));
    };
    let Some(mime_type) = metadata.strip_suffix(";base64") else {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "data URL 必须使用 base64".into(),
        ));
    };
    Ok((encoded.into(), mime_type.into(), fallback_name.into()))
}

pub(super) fn detect_image_format(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(("png", "image/png"))
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some(("jpeg", "image/jpeg"))
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(("webp", "image/webp"))
    } else {
        None
    }
}
