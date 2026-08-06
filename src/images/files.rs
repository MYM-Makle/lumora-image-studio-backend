use std::path::PathBuf;

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, GenericImageView};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use tokio::fs;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use uuid::Uuid;

use crate::{
    auth::user_from_headers,
    db::{internal_error, read_database},
    model::{AppError, AppResult},
    AppState,
};

use super::TaskPayload;

pub(crate) async fn private_image_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    let user = user_from_headers(&headers, &state)?;
    serve_image(&state, &headers, &id, Some(&user.id), false, false).await
}

pub(crate) async fn private_image_thumbnail(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    let user = user_from_headers(&headers, &state)?;
    serve_image(&state, &headers, &id, Some(&user.id), false, true).await
}

pub(crate) async fn private_image_reference_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, index)): AxumPath<(String, usize)>,
) -> AppResult<Response> {
    let user = user_from_headers(&headers, &state)?;
    let reference_files = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT reference_files FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "参考图不存在".into()))
    })?;
    let file_name = serde_json::from_str::<Vec<String>>(&reference_files)
        .unwrap_or_default()
        .get(index)
        .cloned()
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "参考图不存在".into()))?;
    serve_stored_file(
        &headers,
        state.config.image_directory.join(&file_name),
        &file_name,
        "private, max-age=0, must-revalidate",
        "参考图文件不存在",
    )
    .await
}

pub(crate) async fn public_image_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    serve_image(&state, &headers, &id, None, true, false).await
}

pub(crate) async fn public_image_thumbnail(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    serve_image(&state, &headers, &id, None, true, true).await
}

pub(crate) async fn private_task_reference_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, index)): AxumPath<(String, usize)>,
) -> AppResult<Response> {
    let user = user_from_headers(&headers, &state)?;
    let request_json = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT request_json FROM tasks WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "参考图不存在".into()))
    })?;
    let payload = serde_json::from_str::<TaskPayload>(&request_json)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "参考图不存在".into()))?;
    let file_name = payload
        .input_files
        .get(index)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "参考图不存在".into()))?;
    let etag_key = format!("{id}/{file_name}");
    serve_stored_file(
        &headers,
        state.config.task_directory.join(&id).join(file_name),
        &etag_key,
        "private, max-age=0, must-revalidate",
        "参考图文件不存在",
    )
    .await
}

async fn serve_image(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    user_id: Option<&str>,
    public: bool,
    thumbnail: bool,
) -> AppResult<Response> {
    let record = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT file_name, user_id, visibility
             FROM images WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))
    })?;
    let allowed = if public {
        record.2 == "public"
    } else {
        user_id.is_some_and(|value| value == record.1)
    };
    if !allowed {
        return Err(AppError(StatusCode::NOT_FOUND, "图片不存在".into()));
    }
    let cache = if public {
        "public, max-age=86400"
    } else {
        "private, max-age=0, must-revalidate"
    };
    let original_path = state.config.image_directory.join(&record.0);
    if thumbnail {
        let file_name = thumbnail_file_name(id);
        let path = state.config.image_directory.join(&file_name);
        ensure_thumbnail(&original_path, &path).await?;
        return serve_stored_file(headers, path, &file_name, cache, "缩略图文件不存在").await;
    }
    serve_stored_file(headers, original_path, &record.0, cache, "图片文件不存在").await
}

pub(crate) fn thumbnail_file_name(id: &str) -> String {
    format!(
        "thumbnail-{}.jpg",
        hex::encode(Sha256::digest(id.as_bytes()))
    )
}

async fn ensure_thumbnail(source: &std::path::Path, target: &std::path::Path) -> AppResult<()> {
    if fs::metadata(target)
        .await
        .is_ok_and(|metadata| metadata.is_file())
    {
        return Ok(());
    }
    if !fs::metadata(source)
        .await
        .is_ok_and(|metadata| metadata.is_file())
    {
        return Err(AppError(StatusCode::NOT_FOUND, "图片文件不存在".into()));
    }

    let source = source.to_path_buf();
    let encoded = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let image = image::open(source).map_err(|error| error.to_string())?;
        let (width, height) = image.dimensions();
        let thumbnail = if width > 640 || height > 640 {
            image.resize(640, 640, FilterType::Triangle)
        } else {
            image
        };
        let rgb = thumbnail.to_rgb8();
        let mut encoded = Vec::new();
        JpegEncoder::new_with_quality(&mut encoded, 78)
            .encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ExtendedColorType::Rgb8,
            )
            .map_err(|error| error.to_string())?;
        Ok(encoded)
    })
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "thumbnail worker failed");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "缩略图生成失败".into())
    })?
    .map_err(|error| {
        tracing::error!(error, "thumbnail generation failed");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "缩略图生成失败".into())
    })?;

    let temporary = target.with_extension(format!("{}.tmp", Uuid::new_v4().simple()));
    fs::write(&temporary, encoded).await.map_err(|error| {
        tracing::error!(error = %error, "thumbnail write failed");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "缩略图保存失败".into())
    })?;
    if let Err(error) = fs::rename(&temporary, target).await {
        let _ = fs::remove_file(&temporary).await;
        if !fs::metadata(target)
            .await
            .is_ok_and(|metadata| metadata.is_file())
        {
            tracing::error!(error = %error, "thumbnail publish failed");
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "缩略图保存失败".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn serve_stored_file(
    headers: &HeaderMap,
    path: PathBuf,
    etag_key: &str,
    cache_control: &'static str,
    missing_message: &'static str,
) -> AppResult<Response> {
    let metadata = fs::metadata(&path).await.map_err(|error| {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::error!(error = %error, "stored image metadata read failed");
        }
        AppError(StatusCode::NOT_FOUND, missing_message.into())
    })?;
    if !metadata.is_file() {
        return Err(AppError(StatusCode::NOT_FOUND, missing_message.into()));
    }

    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let etag_source = format!("{etag_key}:{}:{modified}", metadata.len());
    let etag = format!(
        "\"{}\"",
        hex::encode(Sha256::digest(etag_source.as_bytes()))
    );
    if if_none_match_matches(headers, &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag).expect("SHA-256 ETag is a valid header value"),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control),
        );
        return Ok(response);
    }

    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.headers_mut() = headers.clone();
    let response = ServeFile::new(path)
        .oneshot(request)
        .await
        .expect("ServeFile uses an infallible response error");
    if response.status() == StatusCode::NOT_FOUND {
        return Err(AppError(StatusCode::NOT_FOUND, missing_message.into()));
    }
    let mut response = response.map(Body::new);
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("SHA-256 ETag is a valid header value"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    Ok(response)
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*"
                || candidate == etag
                || candidate
                    .strip_prefix("W/")
                    .is_some_and(|value| value == etag)
        })
}

#[cfg(test)]
mod tests {
    use image::{DynamicImage, GenericImageView, ImageFormat, RgbImage};
    use tempfile::tempdir;

    use super::{ensure_thumbnail, thumbnail_file_name};

    #[tokio::test]
    async fn creates_and_reuses_resized_jpeg_thumbnail() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.png");
        let target = directory.path().join(thumbnail_file_name("image-1"));
        DynamicImage::ImageRgb8(RgbImage::new(1200, 800))
            .save_with_format(&source, ImageFormat::Png)
            .unwrap();

        ensure_thumbnail(&source, &target).await.unwrap();
        let first_modified = tokio::fs::metadata(&target)
            .await
            .unwrap()
            .modified()
            .unwrap();
        let thumbnail = image::open(&target).unwrap();
        assert_eq!(thumbnail.dimensions(), (640, 427));

        ensure_thumbnail(&source, &target).await.unwrap();
        assert_eq!(
            tokio::fs::metadata(&target)
                .await
                .unwrap()
                .modified()
                .unwrap(),
            first_modified
        );
    }
}
