use std::path::PathBuf;

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use tokio::fs;
use tower::ServiceExt;
use tower_http::services::ServeFile;

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
    serve_image(&state, &headers, &id, Some(&user.id), false).await
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
    serve_image(&state, &headers, &id, None, true).await
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
    serve_stored_file(
        headers,
        state.config.image_directory.join(&record.0),
        &record.0,
        cache,
        "图片文件不存在",
    )
    .await
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
