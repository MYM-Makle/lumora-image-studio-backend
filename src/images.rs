use std::{net::SocketAddr, time::Instant};

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, ConnectInfo, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, Request, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{fs, task::JoinSet};
use uuid::Uuid;

use crate::{
    account::active_provider,
    auth::{user_from_api_key, user_from_headers},
    db::{internal_error, read_database, write_database},
    model::{
        api_json, api_query, api_success, ApiResponse, AppError, AppResult, ConfirmTasksRequest,
        EditRequest, GenerateRequest, ImageResponse, OpenAiImageData, OpenAiImagesResponse,
        OpenAiResult, UpdateImageVisibilityRequest, UserResponse, MODEL,
    },
    AppState,
};

mod files;
pub(crate) use files::{
    private_image_file, private_image_reference_file, private_task_reference_file,
    public_image_file, serve_stored_file,
};
mod credits;
use credits::{record_generation_metrics, reserve_credits, settle_failure};
mod parse;
use parse::{
    detect_image_format, input_from_field, parse_edit_request, validate_edit_inputs,
    validate_generation,
};
mod upstream;
use upstream::{request_upstream_edit, request_upstream_generation};
mod storage;
use storage::{store_outputs, GeneratedOutput, StoreContext};
mod tasks;
use tasks::create_tasks;
pub(crate) use tasks::recover_tasks;

struct GenerationResult {
    images: Vec<ImageResponse>,
    encoded: Vec<String>,
    credits: i64,
    usage: Option<Value>,
    errors: Vec<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestMetadata {
    #[serde(default)]
    request_id: String,
    ip_address: String,
    device_id: String,
    platform: String,
    app_version: String,
    user_agent: String,
    desktop: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GalleryQuery {
    q: Option<String>,
    category: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct TaskPayload {
    generation: GenerateRequest,
    input_files: Vec<String>,
    mask_file: Option<String>,
    #[serde(default)]
    request_metadata: RequestMetadata,
}

fn request_metadata(headers: &HeaderMap, peer_addr: SocketAddr) -> RequestMetadata {
    RequestMetadata {
        request_id: crate::request::request_id(headers).unwrap_or_default(),
        ip_address: crate::request::client_ip(headers, peer_addr),
        device_id: header_text(headers, "x-lumora-device-id", 128).unwrap_or_default(),
        platform: header_text(headers, "x-lumora-platform", 64).unwrap_or_default(),
        app_version: header_text(headers, "x-lumora-app-version", 32).unwrap_or_default(),
        user_agent: header_text(headers, "user-agent", 300).unwrap_or_default(),
        desktop: header_text(headers, "x-lumora-client", 32).as_deref() == Some("desktop"),
    }
}

use crate::request::{ensure_first_party_client, header_text};

pub async fn list_images(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let device_id = header_text(&headers, "x-lumora-device-id", 128).unwrap_or_default();
    read_database(&state.db, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT id, prompt, size, model, created_at, format, visibility, category,
                    storage, reference_files
             FROM images
             WHERE user_id = ?1 AND (storage = 'server' OR device_id = ?2)
             ORDER BY created_at DESC",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map(params![user.id, device_id], |row| {
                image_from_row(row, false, None)
            })
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(Json(api_success(json!({ "items": items }))))
    })
}

pub async fn update_image_visibility(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    payload: Result<Json<UpdateImageVisibilityRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let visibility = if request.is_public {
        "public"
    } else {
        "private"
    };
    let record = write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let record = transaction
            .query_row(
                "SELECT file_name, storage FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))?;
        transaction
            .execute(
                "UPDATE images SET visibility = ?1 WHERE id = ?2 AND user_id = ?3",
                params![visibility, id, user.id],
            )
            .map_err(internal_error)?;
        transaction.commit().map_err(internal_error)?;
        Ok(record)
    })?;
    if !request.is_public && record.1 == "local" {
        if let Err(error) = fs::remove_file(state.config.image_directory.join(&record.0)).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                let _ = write_database(&state.db, |connection| {
                    connection
                        .execute(
                            "UPDATE images SET visibility = 'public' WHERE id = ?1 AND user_id = ?2",
                            params![id, user.id],
                        )
                        .map_err(internal_error)?;
                    Ok(())
                });
                tracing::error!(error = %error, image_id = id, "private server image cleanup failed");
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "服务器图片清理失败".into(),
                ));
            }
        }
    }
    Ok(Json(api_success(json!({
        "id": id,
        "isPublic": request.is_public
    }))))
}

pub async fn publish_local_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    mut multipart: Multipart,
) -> AppResult<Json<ApiResponse<Value>>> {
    ensure_first_party_client(&headers)?;
    let user = user_from_headers(&headers, &state)?;
    let mut image = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "图片上传参数无效".into()))?
    {
        if field.name() == Some("image") {
            if image.is_some() {
                return Err(AppError(StatusCode::BAD_REQUEST, "只能上传一张图片".into()));
            }
            image = Some(input_from_field(field).await?);
        }
    }
    let image = image.ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "图片文件缺失".into()))?;
    let record = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT file_name, format, storage FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
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
    if record.2 != "local" {
        return Err(AppError(StatusCode::CONFLICT, "该图片不是本地图片".into()));
    }
    let detected_format = detect_image_format(&image.bytes).map(|item| item.0);
    if detected_format != Some(record.1.as_str()) {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片格式不匹配".into()));
    }
    fs::write(state.config.image_directory.join(record.0), image.bytes)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, image_id = id, "server image backup failed");
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "服务器图片保存失败".into(),
            )
        })?;
    let updated = write_database(&state.db, |connection| {
        connection
            .execute(
                "UPDATE images SET visibility = 'public'
             WHERE id = ?1 AND user_id = ?2 AND storage = 'local'",
                params![id, user.id],
            )
            .map_err(internal_error)
    })?;
    if updated == 0 {
        return Err(AppError(StatusCode::NOT_FOUND, "图片不存在".into()));
    }
    Ok(Json(api_success(json!({ "id": id, "isPublic": true }))))
}

pub async fn localize_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let device_id = header_text(&headers, "x-lumora-device-id", 128)
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "设备 ID 缺失".into()))?;
    let record = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT file_name, storage, device_id, visibility
             FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))
    })?;
    if record.1 != "server" && record.2 != device_id {
        return Err(AppError(StatusCode::CONFLICT, "图片不属于当前设备".into()));
    }
    if !matches!(record.1.as_str(), "server" | "pending" | "local") {
        return Err(AppError(
            StatusCode::CONFLICT,
            "该图片不是桌面端待转存图片".into(),
        ));
    }
    write_database(&state.db, |connection| {
        connection
            .execute(
                "UPDATE images SET storage = 'local', device_id = ?1
             WHERE id = ?2 AND user_id = ?3",
                params![device_id, id, user.id],
            )
            .map_err(internal_error)?;
        Ok(())
    })?;
    if record.3 != "public" {
        if let Err(error) = fs::remove_file(state.config.image_directory.join(&record.0)).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                let _ = write_database(&state.db, |connection| {
                    connection
                        .execute(
                            "UPDATE images SET storage = ?1, device_id = ?2 WHERE id = ?3 AND user_id = ?4",
                            params![record.1, record.2, id, user.id],
                        )
                        .map_err(internal_error)?;
                    Ok(())
                });
                tracing::error!(error = %error, image_id = id, "localized private image cleanup failed");
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "服务器图片清理失败".into(),
                ));
            }
        }
    }
    Ok(Json(api_success(json!({
        "id": id,
        "storage": "local",
        "isPublic": record.3 == "public"
    }))))
}

pub async fn public_gallery(
    State(state): State<AppState>,
    query: Result<Query<GalleryQuery>, axum::extract::rejection::QueryRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let query = api_query(query)?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(24).clamp(1, 100);
    let search = query.q.unwrap_or_default().trim().to_string();
    let category = query.category.unwrap_or_default().trim().to_string();
    read_database(&state.db, |connection| {
        let total: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM images
             WHERE visibility = 'public'
               AND (?1 = '' OR lower(prompt) LIKE '%' || lower(?1) || '%')
               AND (?2 = '' OR ?2 = '全部' OR category = ?2)",
                params![search, category],
                |row| row.get(0),
            )
            .map_err(internal_error)?;
        let mut statement = connection
            .prepare(
                "SELECT i.id, i.prompt, i.size, i.model, i.created_at, i.format,
                    i.visibility, i.category, i.storage, '[]', u.name
             FROM images i JOIN users u ON u.id = i.user_id
             WHERE i.visibility = 'public'
               AND (?1 = '' OR lower(i.prompt) LIKE '%' || lower(?1) || '%')
               AND (?2 = '' OR ?2 = '全部' OR i.category = ?2)
             ORDER BY i.created_at DESC LIMIT ?3 OFFSET ?4",
            )
            .map_err(internal_error)?;
        let items = statement
            .query_map(
                params![search, category, page_size, (page - 1) * page_size],
                |row| {
                    let author: String = row.get(10)?;
                    image_from_row(row, true, Some(author))
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

fn image_from_row(
    row: &rusqlite::Row<'_>,
    public: bool,
    author: Option<String>,
) -> rusqlite::Result<ImageResponse> {
    let id: String = row.get(0)?;
    let reference_images = if public {
        Vec::new()
    } else {
        serde_json::from_str::<Vec<String>>(&row.get::<_, String>(9)?)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(index, _)| format!("/api/images/{id}/references/{index}"))
            .collect()
    };
    Ok(ImageResponse {
        url: if public {
            format!("/public/images/{id}")
        } else {
            format!("/api/images/{id}/file")
        },
        id,
        prompt: row.get(1)?,
        size: row.get(2)?,
        model: row.get(3)?,
        created_at: row.get(4)?,
        source: "generated",
        format: row.get(5)?,
        is_public: row.get::<_, String>(6)? == "public",
        category: row.get(7)?,
        storage: row.get(8)?,
        author,
        reference_images,
    })
}

pub async fn generate_image(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let metadata = request_metadata(&headers, peer_addr);
    let result = perform_generation(
        &state,
        &user,
        request,
        &metadata,
        "/api/images/generate",
        None,
        false,
    )
    .await?;
    Ok(Json(api_success(json!({
        "images": result.images,
        "credits": result.credits,
        "errors": result.errors
    }))))
}

pub async fn generate_image_async(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<Value>>)> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    validate_generation(&request)?;
    active_provider(&state, &user.id)?;
    let metadata = request_metadata(&headers, peer_addr);
    let task_ids = create_tasks(&state, &user, "generation", request, None, metadata).await?;
    let items = task_summaries(&state, &user.id, &task_ids)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(api_success(json!({ "items": items }))),
    ))
}

pub async fn edit_image(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let headers = request.headers().clone();
    ensure_first_party_client(&headers)?;
    let user = user_from_headers(&headers, &state)?;
    let metadata = request_metadata(&headers, peer_addr);
    let edit = parse_edit_request(&state, request).await?;
    let result = perform_edit(
        &state,
        &user,
        edit,
        &metadata,
        "/api/images/edit",
        None,
        false,
    )
    .await?;
    Ok(Json(api_success(json!({
        "images": result.images,
        "credits": result.credits,
        "errors": result.errors
    }))))
}

pub async fn edit_image_async(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> AppResult<(StatusCode, Json<ApiResponse<Value>>)> {
    let headers = request.headers().clone();
    ensure_first_party_client(&headers)?;
    let user = user_from_headers(&headers, &state)?;
    let metadata = request_metadata(&headers, peer_addr);
    let edit = parse_edit_request(&state, request).await?;
    validate_generation(&edit.generation)?;
    validate_edit_inputs(&edit)?;
    active_provider(&state, &user.id)?;
    let generation = edit.generation.clone();
    let task_ids = create_tasks(&state, &user, "edit", generation, Some(edit), metadata).await?;
    let items = task_summaries(&state, &user.id, &task_ids)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(api_success(json!({ "items": items }))),
    ))
}

pub async fn external_generate(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> OpenAiResult<Json<OpenAiImagesResponse>> {
    let request = external_json(payload)?;
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let metadata = request_metadata(&headers, peer_addr);
    let result = perform_generation(
        &state,
        &principal.user,
        request,
        &metadata,
        "/v1/images/generations",
        None,
        false,
    )
    .await?;
    Ok(Json(openai_response(result)))
}

fn external_json<T>(payload: Result<Json<T>, JsonRejection>) -> OpenAiResult<T> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        let status = match rejection.status() {
            StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
            status => status,
        };
        AppError(status, "JSON 参数无效".into()).into()
    })
}

pub async fn external_edit(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> OpenAiResult<Json<OpenAiImagesResponse>> {
    let headers = request.headers().clone();
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let metadata = request_metadata(&headers, peer_addr);
    let mut edit = parse_edit_request(&state, request).await?;
    edit.batch = false;
    let result = perform_edit(
        &state,
        &principal.user,
        edit,
        &metadata,
        "/v1/images/edits",
        None,
        false,
    )
    .await?;
    Ok(Json(openai_response(result)))
}

fn openai_response(result: GenerationResult) -> OpenAiImagesResponse {
    OpenAiImagesResponse {
        created: Utc::now().timestamp(),
        data: result
            .encoded
            .into_iter()
            .map(|b64_json| OpenAiImageData { b64_json })
            .collect(),
        usage: result.usage,
    }
}

async fn perform_generation(
    state: &AppState,
    user: &UserResponse,
    request: GenerateRequest,
    metadata: &RequestMetadata,
    endpoint: &str,
    task_id: Option<&str>,
    credit_already_reserved: bool,
) -> AppResult<GenerationResult> {
    validate_generation(&request)?;
    let provider = active_provider(state, &user.id)?;
    if !credit_already_reserved {
        reserve_credits(state, &user.id, request.n as i64)?;
    }
    let started = Instant::now();
    let mut requests = JoinSet::new();
    for _ in 0..request.n {
        let client = state.client.clone();
        let provider = provider.clone();
        let request_id = metadata.request_id.clone();
        let one = GenerateRequest {
            n: 1,
            ..request.clone()
        };
        requests.spawn(async move {
            request_upstream_generation(&client, &provider, &one, &request_id).await
        });
    }
    let mut outputs = Vec::new();
    let mut errors = Vec::new();
    let mut usage = None;
    while let Some(result) = requests.join_next().await {
        match result {
            Ok(Ok((mut generated, current_usage))) => {
                outputs.append(&mut generated);
                usage = current_usage.or(usage);
            }
            Ok(Err(error)) => errors.push(error.1),
            Err(_) => errors.push("上游任务执行失败".into()),
        }
    }
    let duration_ms = started.elapsed().as_millis() as i64;
    if outputs.is_empty() {
        let message = errors
            .first()
            .cloned()
            .unwrap_or_else(|| "上游未返回图片".into());
        settle_failure(
            state,
            &user.id,
            Some(&provider.id),
            request.n as i64,
            metadata,
            endpoint,
            duration_ms,
            task_id,
            request.prompt.trim(),
            &message,
        )?;
        return Err(AppError(StatusCode::BAD_GATEWAY, message));
    }
    store_outputs(
        StoreContext {
            state,
            user,
            provider: &provider,
            request: &request,
            metadata,
            reserved: request.n as i64,
            endpoint,
            duration_ms,
            task_id,
        },
        outputs,
        &[],
        usage,
        errors,
    )
    .await
}

async fn perform_edit(
    state: &AppState,
    user: &UserResponse,
    request: EditRequest,
    metadata: &RequestMetadata,
    endpoint: &str,
    task_id: Option<&str>,
    credit_already_reserved: bool,
) -> AppResult<GenerationResult> {
    validate_generation(&request.generation)?;
    validate_edit_inputs(&request)?;
    let provider = active_provider(state, &user.id)?;
    let reserved = if request.batch {
        request.images.len() as i64
    } else {
        request.generation.n as i64
    };
    if !credit_already_reserved {
        reserve_credits(state, &user.id, reserved)?;
    }
    let started = Instant::now();
    let mut outputs = Vec::new();
    let mut output_references = Vec::new();
    let mut errors = Vec::new();
    let mut usage = None;
    if request.batch {
        for input in &request.images {
            let one = EditRequest {
                generation: GenerateRequest {
                    n: 1,
                    ..request.generation.clone()
                },
                images: vec![input.clone()],
                mask: None,
                batch: false,
            };
            match request_upstream_edit(&state.client, &provider, &one, &metadata.request_id).await
            {
                Ok((mut generated, current_usage)) => {
                    output_references
                        .extend(std::iter::repeat_n(vec![input.clone()], generated.len()));
                    outputs.append(&mut generated);
                    usage = current_usage.or(usage);
                }
                Err(error) => errors.push(error.1),
            }
        }
    } else {
        let mut requests = JoinSet::new();
        for _ in 0..request.generation.n {
            let client = state.client.clone();
            let provider = provider.clone();
            let request_id = metadata.request_id.clone();
            let one = EditRequest {
                generation: GenerateRequest {
                    n: 1,
                    ..request.generation.clone()
                },
                ..request.clone()
            };
            requests.spawn(async move {
                request_upstream_edit(&client, &provider, &one, &request_id).await
            });
        }
        while let Some(result) = requests.join_next().await {
            match result {
                Ok(Ok((mut generated, current_usage))) => {
                    output_references
                        .extend(std::iter::repeat_n(request.images.clone(), generated.len()));
                    outputs.append(&mut generated);
                    usage = current_usage.or(usage);
                }
                Ok(Err(error)) => errors.push(error.1),
                Err(_) => errors.push("上游任务执行失败".into()),
            }
        }
    }
    let duration_ms = started.elapsed().as_millis() as i64;
    if outputs.is_empty() {
        let message = errors
            .first()
            .cloned()
            .unwrap_or_else(|| "上游未返回图片".into());
        settle_failure(
            state,
            &user.id,
            Some(&provider.id),
            reserved,
            metadata,
            endpoint,
            duration_ms,
            task_id,
            request.generation.prompt.trim(),
            &message,
        )?;
        return Err(AppError(StatusCode::BAD_GATEWAY, message));
    }
    store_outputs(
        StoreContext {
            state,
            user,
            provider: &provider,
            request: &request.generation,
            metadata,
            reserved,
            endpoint,
            duration_ms,
            task_id,
        },
        outputs,
        &output_references,
        usage,
        errors,
    )
    .await
}

pub async fn delete_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let record = read_database(&state.db, |connection| {
        connection
            .query_row(
                "SELECT file_name, reference_files
             FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(internal_error)?
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))
    })?;
    let mut file_names = serde_json::from_str::<Vec<String>>(&record.1).unwrap_or_default();
    file_names.push(record.0);
    let mut moved = Vec::new();
    for file_name in file_names {
        let original = state.config.image_directory.join(file_name);
        let trash = state
            .config
            .image_directory
            .join(format!(".deleting-{}", Uuid::new_v4().simple()));
        if fs::rename(&original, &trash).await.is_ok() {
            moved.push((original, trash));
        }
    }
    let changed = write_database(&state.db, |connection| {
        connection
            .execute(
                "DELETE FROM images WHERE id = ?1 AND user_id = ?2",
                params![id, user.id],
            )
            .map_err(internal_error)
    });
    if let Err(error) = changed {
        for (original, trash) in moved {
            let _ = fs::rename(trash, original).await;
        }
        return Err(error);
    }
    for (_, trash) in moved {
        let _ = fs::remove_file(trash).await;
    }
    Ok(Json(api_success(Value::Null)))
}

pub async fn clear_images(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let file_names = read_database(&state.db, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT file_name, reference_files
                 FROM images WHERE user_id = ?1",
            )
            .map_err(internal_error)?;
        let records = statement
            .query_map([&user.id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        let mut file_names = Vec::new();
        for (file_name, reference_files) in records {
            file_names.push(file_name);
            file_names
                .extend(serde_json::from_str::<Vec<String>>(&reference_files).unwrap_or_default());
        }
        Ok(file_names)
    })?;
    let mut moved = Vec::new();
    for file_name in file_names {
        let original = state.config.image_directory.join(&file_name);
        let trash = state
            .config
            .image_directory
            .join(format!(".deleting-{}", Uuid::new_v4().simple()));
        if fs::rename(&original, &trash).await.is_ok() {
            moved.push((original, trash));
        }
    }
    let delete_result = write_database(&state.db, |connection| {
        connection
            .execute("DELETE FROM images WHERE user_id = ?1", [&user.id])
            .map_err(internal_error)
    });
    if let Err(error) = delete_result {
        for (original, trash) in moved {
            let _ = fs::rename(trash, original).await;
        }
        return Err(error);
    }
    for (_, trash) in moved {
        let _ = fs::remove_file(trash).await;
    }
    Ok(Json(api_success(Value::Null)))
}

pub async fn external_generate_async(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> OpenAiResult<(StatusCode, Json<Value>)> {
    let request = external_json(payload)?;
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    validate_generation(&request)?;
    active_provider(&state, &principal.user.id)?;
    let metadata = request_metadata(&headers, peer_addr);
    let task_ids = create_tasks(
        &state,
        &principal.user,
        "generation",
        request,
        None,
        metadata,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "taskIds": task_ids,
            "creditsReserved": task_ids.len(),
            "model": MODEL
        })),
    ))
}

pub async fn external_edit_async(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> OpenAiResult<(StatusCode, Json<Value>)> {
    let headers = request.headers().clone();
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let metadata = request_metadata(&headers, peer_addr);
    let edit = parse_edit_request(&state, request).await?;
    validate_generation(&edit.generation)?;
    validate_edit_inputs(&edit)?;
    active_provider(&state, &principal.user.id)?;
    let generation = edit.generation.clone();
    let task_ids = create_tasks(
        &state,
        &principal.user,
        "edit",
        generation,
        Some(edit),
        metadata,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "taskIds": task_ids,
            "creditsReserved": task_ids.len(),
            "model": MODEL
        })),
    ))
}

pub async fn list_active_image_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let ids = read_database(&state.db, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT id FROM tasks
                 WHERE user_id = ?1 AND status IN ('queued', 'running')
                 ORDER BY created_at",
            )
            .map_err(internal_error)?;
        let ids = statement
            .query_map([&user.id], |row| row.get::<_, String>(0))
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        Ok(ids)
    })?;
    Ok(Json(api_success(json!({
        "items": task_summaries(&state, &user.id, &ids)?
    }))))
}

pub async fn get_image_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(ids): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let ids = task_ids(&ids)?;
    Ok(Json(api_success(json!({
        "items": task_summaries(&state, &user.id, &ids)?
    }))))
}

fn task_summaries(state: &AppState, user_id: &str, ids: &[String]) -> AppResult<Vec<Value>> {
    read_database(&state.db, |connection| {
        let mut items = Vec::new();
        for id in ids {
            let record = connection
                .query_row(
                    "SELECT status, image_id, error, request_json, created_at, updated_at
                 FROM tasks WHERE id = ?1 AND user_id = ?2",
                    params![id, user_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(internal_error)?;
            let Some((status, image_id, error, request_json, created_at, updated_at)) = record
            else {
                continue;
            };
            let payload: TaskPayload = serde_json::from_str(&request_json)
                .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务数据无效".into()))?;
            let reference_images = payload
                .input_files
                .iter()
                .enumerate()
                .map(|(index, _)| format!("/api/image-tasks/{id}/references/{index}"))
                .collect::<Vec<_>>();
            items.push(json!({
                "id": id,
                "status": status,
                "prompt": payload.generation.prompt,
                "referenceImages": reference_images,
                "imageId": image_id,
                "error": error,
                "createdAt": created_at,
                "updatedAt": updated_at
            }));
        }
        Ok(items)
    })
}

pub async fn get_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(ids): AxumPath<String>,
) -> OpenAiResult<Json<Value>> {
    let principal = user_from_api_key(&headers, &state, &["read", "generate", "full"])?;
    let ids = task_ids(&ids)?;
    let mut items = Vec::new();
    for id in ids {
        let record = read_database(&state.db, |connection| {
            connection
                .query_row(
                    "SELECT t.status, t.image_id, t.error, t.created_at, t.updated_at, i.file_name
                     FROM tasks t LEFT JOIN images i
                       ON i.id = t.image_id AND i.user_id = t.user_id
                     WHERE t.id = ?1 AND t.user_id = ?2",
                    params![id, principal.user.id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(internal_error)
        })?;
        let Some((status, image_id, error, created_at, updated_at, file_name)) = record else {
            continue;
        };
        let data = if let (Some(_), Some(file_name)) = (image_id, file_name) {
            let bytes = fs::read(state.config.image_directory.join(file_name))
                .await
                .map_err(|_| {
                    AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务结果不存在".into())
                })?;
            json!([{ "b64_json": BASE64.encode(bytes) }])
        } else {
            json!([])
        };
        items.push(json!({
            "id": id,
            "status": status,
            "data": data,
            "error": error,
            "createdAt": created_at,
            "updatedAt": updated_at
        }));
    }
    Ok(Json(json!({ "items": items })))
}

pub async fn confirm_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ConfirmTasksRequest>, JsonRejection>,
) -> OpenAiResult<Json<Value>> {
    let request = external_json(payload)?;
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    if request.task_ids.is_empty() || request.task_ids.len() > 100 {
        return Err(AppError(StatusCode::BAD_REQUEST, "taskIds 无效".into()).into());
    }
    let (success_count, fail_count, credits_used) = write_database(&state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let mut success_count = 0_i64;
        let mut fail_count = 0_i64;
        let mut credits_used = 0_i64;
        for id in &request.task_ids {
            let record = transaction
                .query_row(
                    "SELECT status, credits_used FROM tasks WHERE id = ?1 AND user_id = ?2",
                    params![id, principal.user.id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(internal_error)?
                .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "任务不存在".into()))?;
            match record.0.as_str() {
                "success" => {
                    success_count += 1;
                    credits_used += record.1;
                }
                "error" => fail_count += 1,
                _ => return Err(AppError(StatusCode::CONFLICT, "任务尚未完成".into())),
            }
            transaction
                .execute(
                    "UPDATE tasks SET confirmed_at = COALESCE(confirmed_at, ?1) WHERE id = ?2",
                    params![Utc::now().to_rfc3339(), id],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok((success_count, fail_count, credits_used))
    })?;
    Ok(Json(json!({
        "ok": true,
        "successCount": success_count,
        "failCount": fail_count,
        "creditsUsed": credits_used,
        "creditsRefunded": fail_count
    })))
}

fn task_ids(value: &str) -> AppResult<Vec<String>> {
    let ids = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if ids.is_empty() || ids.len() > 100 {
        return Err(AppError(StatusCode::BAD_REQUEST, "任务 ID 无效".into()));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    // clippy::await_holding_lock 在这里是误报：每处 `.await` 之前都有显式
    // `drop(connection)`，但该 lint 不跟踪显式 drop。连接池改造（OPT-01）完成后
    // 全局 MutexGuard 消失，本 allow 应一并移除。
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use crate::{
        config::Config,
        db::{database, open_database},
        model::{default_quality, default_size, ImageInput, ProviderConfiguration},
    };
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request},
        routing::{get, post, put},
        Extension, Router,
    };
    use reqwest::Client;
    use std::{fs as std_fs, sync::Arc, time::Duration};
    use tempfile::TempDir;
    use tokio::sync::Semaphore;
    use tower::ServiceExt;

    fn png_bytes() -> Vec<u8> {
        b"\x89PNG\r\n\x1a\nmock-image".to_vec()
    }

    async fn test_state(credits: i64) -> (TempDir, AppState, UserResponse) {
        let encoded = BASE64.encode(png_bytes());
        let upstream_response = json!({
            "data": [
                { "b64_json": encoded }, { "b64_json": encoded },
                { "b64_json": encoded }, { "b64_json": encoded }
            ],
            "usage": { "total_tokens": 10 }
        });
        let generation_response = upstream_response.clone();
        let edit_response = upstream_response.clone();
        let upstream = Router::new()
            .route(
                "/v1/images/generations",
                post(move |Json(request): Json<Value>| {
                    let fields = request.as_object().unwrap();
                    assert_eq!(fields.len(), 3);
                    assert_eq!(request["model"], MODEL);
                    assert_eq!(request["prompt"], "A test image");
                    assert_eq!(request["size"], "1024x1024");
                    assert!(request.get("n").is_none());
                    let response = generation_response.clone();
                    async move { Json(response) }
                }),
            )
            .route(
                "/v1/images/edits",
                post(move || {
                    let response = edit_response.clone();
                    async move { Json(response) }
                }),
            )
            .fallback(|| async { StatusCode::OK });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

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
            master_key: [6_u8; 32],
            worker_concurrency: 2,
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
            db: open_database(directory.path(), &[6_u8; 32]).unwrap(),
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            config,
            task_semaphore: Arc::new(Semaphore::new(2)),
            presence: crate::presence::PresenceThrottle::new(),
        };
        let user = UserResponse {
            id: "user-1".into(),
            name: "Test".into(),
            email: "test@example.test".into(),
            avatar: String::new(),
            plan: "Free".into(),
            credits,
            credits_reserved: 0,
        };
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits,
                   credits_reserved, daily_limit, created_at
                 ) VALUES (?1, ?2, ?3, 'hash', '', 'Free', ?4, 0, 100, ?5)",
                params![
                    user.id,
                    user.name,
                    user.email,
                    credits,
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO providers (
                   id, user_id, name, base_url, api_key, model, is_active,
                   created_at, encryption_version
                 ) VALUES ('provider-1', ?1, 'Mock', ?2, 'test-key', ?3, 1, ?4, 0)",
                params![
                    user.id,
                    format!("http://{upstream_address}"),
                    MODEL,
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();
        drop(connection);
        (directory, state, user)
    }

    fn generation_request(n: u8) -> GenerateRequest {
        GenerateRequest {
            prompt: "A test image".into(),
            size: default_size(),
            quality: default_quality(),
            n,
            is_public: true,
            output_format: "png".into(),
            model: Some(MODEL.into()),
        }
    }

    #[tokio::test]
    async fn generates_and_batch_edits_with_mock_upstream() {
        let (_directory, state, user) = test_state(10).await;
        let metadata = RequestMetadata {
            request_id: "test-request".into(),
            ip_address: "203.0.113.10".into(),
            device_id: "device-test".into(),
            platform: "Windows".into(),
            app_version: "1.0.9".into(),
            user_agent: "Lumora Test".into(),
            desktop: false,
        };
        let generated = perform_generation(
            &state,
            &user,
            generation_request(2),
            &metadata,
            "/api/images/generate",
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(generated.images.len(), 2);
        assert!(generated.images.iter().all(|image| image.is_public));
        assert_eq!(
            std_fs::read_dir(&state.config.image_directory)
                .unwrap()
                .count(),
            2
        );

        let edited = perform_edit(
            &state,
            &user,
            EditRequest {
                generation: generation_request(4),
                images: vec![
                    ImageInput {
                        bytes: png_bytes(),
                        file_name: "one.png".into(),
                        mime_type: "image/png".into(),
                    },
                    ImageInput {
                        bytes: png_bytes(),
                        file_name: "two.png".into(),
                        mime_type: "image/png".into(),
                    },
                ],
                mask: None,
                batch: true,
            },
            &metadata,
            "/api/images/edit",
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(edited.images.len(), 2);
        assert!(edited
            .images
            .iter()
            .all(|image| image.reference_images.len() == 1));
        let balances: (i64, i64) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT credits, credits_reserved FROM users WHERE id = ?1",
                [&user.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(balances, (6, 0));
        let logged: (String, String, String, String, String) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT ip_address, device_id, platform, app_version, user_agent
                 FROM usage_logs ORDER BY created_at DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            logged,
            (
                "203.0.113.10".into(),
                "device-test".into(),
                "Windows".into(),
                "1.0.9".into(),
                "Lumora Test".into()
            )
        );
    }

    #[tokio::test]
    async fn prevents_concurrent_credit_overdraft() {
        let (_directory, state, user) = test_state(1).await;
        let mut attempts = Vec::new();
        for _ in 0..8 {
            let state = state.clone();
            let user_id = user.id.clone();
            attempts.push(tokio::task::spawn_blocking(move || {
                reserve_credits(&state, &user_id, 1).is_ok()
            }));
        }
        let mut successes = 0;
        for attempt in attempts {
            successes += i32::from(attempt.await.unwrap());
        }
        assert_eq!(successes, 1);
        let reserved: i64 = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT credits_reserved FROM users WHERE id = ?1",
                [&user.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 1);
    }

    #[tokio::test]
    async fn rolls_back_credits_and_files_when_image_transaction_fails() {
        let (_directory, state, user) = test_state(3).await;
        let metadata = RequestMetadata::default();
        database(&state.db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_test_image BEFORE INSERT ON images
                 BEGIN SELECT RAISE(ABORT, 'test rollback'); END;",
            )
            .unwrap();
        let result = perform_generation(
            &state,
            &user,
            generation_request(1),
            &metadata,
            "/api/images/generate",
            None,
            false,
        )
        .await;
        assert!(result.is_err());
        let balances: (i64, i64) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT credits, credits_reserved FROM users WHERE id = ?1",
                [&user.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(balances, (3, 0));
        assert_eq!(
            std_fs::read_dir(&state.config.image_directory)
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn recovers_queued_tasks_and_refunds_invalid_tasks() {
        let (_directory, state, user) = test_state(3).await;
        reserve_credits(&state, &user.id, 1).unwrap();
        let payload = serde_json::to_string(&TaskPayload {
            generation: generation_request(1),
            input_files: Vec::new(),
            mask_file: None,
            request_metadata: RequestMetadata::default(),
        })
        .unwrap();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO tasks (
                   id, user_id, kind, status, request_json, credits_reserved,
                   credits_used, created_at, updated_at
                 ) VALUES ('task-recover', ?1, 'generation', 'queued', ?2, 1, 0, ?3, ?3)",
                params![user.id, payload, Utc::now().to_rfc3339()],
            )
            .unwrap();
        recover_tasks(&state).unwrap();
        let mut status = String::new();
        for _ in 0..100 {
            status = database(&state.db)
                .unwrap()
                .query_row(
                    "SELECT status FROM tasks WHERE id = 'task-recover'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if status == "success" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(status, "success");

        reserve_credits(&state, &user.id, 1).unwrap();
        database(&state.db)
            .unwrap()
            .execute(
                "INSERT INTO tasks (
                   id, user_id, kind, status, request_json, credits_reserved,
                   credits_used, created_at, updated_at
                 ) VALUES ('task-invalid', ?1, 'generation', 'queued', '{', 1, 0, ?2, ?2)",
                params![user.id, Utc::now().to_rfc3339()],
            )
            .unwrap();
        assert!(tasks::run_task(&state, "task-invalid").await.is_err());
        let invalid: (String, i64) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT t.status, u.credits_reserved FROM tasks t
                 JOIN users u ON u.id = t.user_id WHERE t.id = 'task-invalid'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(invalid, ("error".into(), 0));
    }

    #[tokio::test]
    async fn reloads_active_and_requested_image_tasks() {
        let (_directory, state, user) = test_state(3).await;
        let now = Utc::now().to_rfc3339();
        let payload = serde_json::to_string(&TaskPayload {
            generation: generation_request(1),
            input_files: vec!["input-0.png".into()],
            mask_file: None,
            request_metadata: RequestMetadata::default(),
        })
        .unwrap();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('task-session', ?1, ?2, '2099-01-01T00:00:00Z')",
                params![user.id, now],
            )
            .unwrap();
        for (id, status) in [("task-active", "running"), ("task-done", "success")] {
            connection
                .execute(
                    "INSERT INTO tasks (
                       id, user_id, kind, status, request_json, credits_reserved,
                       credits_used, created_at, updated_at
                     ) VALUES (?1, ?2, 'generation', ?3, ?4, 1, 0, ?5, ?5)",
                    params![id, user.id, status, payload, now],
                )
                .unwrap();
        }
        drop(connection);

        let app = Router::new()
            .route("/api/image-tasks", get(list_active_image_tasks))
            .route("/api/image-tasks/{ids}", get(get_image_tasks))
            .with_state(state);
        let active_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/image-tasks")
                    .header(header::COOKIE, "lumora_session=task-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(active_response.status(), StatusCode::OK);
        let active: Value =
            serde_json::from_slice(&to_bytes(active_response.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(active["code"], 0);
        assert_eq!(active["message"], "success");
        assert!(active["timestamp"].as_i64().is_some());
        assert_eq!(active["data"]["items"].as_array().unwrap().len(), 1);
        assert_eq!(active["data"]["items"][0]["id"], "task-active");
        assert_eq!(active["data"]["items"][0]["prompt"], "A test image");
        assert_eq!(
            active["data"]["items"][0]["referenceImages"][0],
            "/api/image-tasks/task-active/references/0"
        );
        assert_eq!(active["data"]["items"][0]["createdAt"], now);

        let requested_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/image-tasks/task-active,task-done")
                    .header(header::COOKIE, "lumora_session=task-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(requested_response.status(), StatusCode::OK);
        let requested: Value = serde_json::from_slice(
            &to_bytes(requested_response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(requested["data"]["items"].as_array().unwrap().len(), 2);
        assert_eq!(requested["data"]["items"][1]["status"], "success");
    }

    #[tokio::test]
    async fn returns_openai_error_for_invalid_generation_json() {
        let (_directory, state, _user) = test_state(1).await;
        let app = Router::new()
            .route("/v1/images/generations", post(external_generate))
            .layer(Extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )))
            .with_state(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/images/generations")
                    .header("content-type", "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(body["error"]["type"], "invalid_request_error");
    }

    #[tokio::test]
    async fn updates_image_visibility_for_its_owner() {
        let (_directory, state, user) = test_state(1).await;
        let now = Utc::now().to_rfc3339();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category
                 ) VALUES ('private-image', ?1, 'private.png', 'test', '1024x1024',
                           ?2, ?3, 'private', 'png', 'test')",
                params![user.id, MODEL, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category, storage, device_id
                 ) VALUES ('local-public-image', ?1, 'local-public.png', 'test',
                           '1024x1024', ?2, ?3, 'public', 'png', 'test',
                           'local', 'device-test')",
                params![user.id, MODEL, now],
            )
            .unwrap();
        std_fs::write(
            state.config.image_directory.join("private.png"),
            png_bytes(),
        )
        .unwrap();
        std_fs::write(
            state.config.image_directory.join("local-public.png"),
            png_bytes(),
        )
        .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('visibility-session', ?1, ?2, '2099-01-01T00:00:00Z')",
                params![user.id, now],
            )
            .unwrap();
        drop(connection);

        let app = Router::new()
            .route("/api/images/{id}/visibility", put(update_image_visibility))
            .with_state(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/images/private-image/visibility")
                    .header(header::COOKIE, "lumora_session=visibility-session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"isPublic":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(body["data"]["isPublic"], true);
        let published: String = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT visibility FROM images WHERE id = 'private-image'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(published, "public");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/images/private-image/visibility")
                    .header(header::COOKIE, "lumora_session=visibility-session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"isPublic":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let unpublished: String = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT visibility FROM images WHERE id = 'private-image'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unpublished, "private");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/images/local-public-image/visibility")
                    .header(header::COOKIE, "lumora_session=visibility-session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"isPublic":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state
            .config
            .image_directory
            .join("local-public.png")
            .exists());
    }

    #[tokio::test]
    async fn localizes_desktop_images_and_only_keeps_public_server_copy() {
        let (_directory, state, user) = test_state(1).await;
        let now = Utc::now().to_rfc3339();
        let file_name = "pending.png";
        std_fs::write(state.config.image_directory.join(file_name), png_bytes()).unwrap();
        std_fs::write(
            state.config.image_directory.join("private-server.png"),
            png_bytes(),
        )
        .unwrap();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category, storage, device_id
                 ) VALUES ('pending-image', ?1, ?2, 'test', '1024x1024', ?3, ?4,
                           'public', 'png', 'test', 'pending', 'device-test')",
                params![user.id, file_name, MODEL, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category, storage, device_id
                 ) VALUES ('private-server-image', ?1, 'private-server.png', 'test',
                           '1024x1024', ?2, ?3, 'private', 'png', 'test', 'server', '')",
                params![user.id, MODEL, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('local-session', ?1, ?2, '2099-01-01T00:00:00Z')",
                params![user.id, now],
            )
            .unwrap();
        drop(connection);

        let app = Router::new()
            .route("/api/images/{id}/local", post(localize_image))
            .with_state(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/images/pending-image/local")
                    .header(header::COOKIE, "lumora_session=local-session")
                    .header("x-lumora-device-id", "device-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let record: (String, String) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT storage, visibility FROM images WHERE id = 'pending-image'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(record, ("local".into(), "public".into()));
        assert!(state.config.image_directory.join(file_name).exists());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/images/private-server-image/local")
                    .header(header::COOKIE, "lumora_session=local-session")
                    .header("x-lumora-device-id", "device-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let record: (String, String) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT storage, device_id FROM images WHERE id = 'private-server-image'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(record, ("local".into(), "device-test".into()));
        assert!(!state
            .config
            .image_directory
            .join("private-server.png")
            .exists());
    }

    #[tokio::test]
    async fn publishes_a_local_desktop_image_to_server_storage() {
        let (_directory, state, user) = test_state(1).await;
        let now = Utc::now().to_rfc3339();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category, storage, device_id
                 ) VALUES ('local-image', ?1, 'local.png', 'test', '1024x1024', ?2, ?3,
                           'private', 'png', 'test', 'local', 'device-test')",
                params![user.id, MODEL, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('publish-session', ?1, ?2, '2099-01-01T00:00:00Z')",
                params![user.id, now],
            )
            .unwrap();
        drop(connection);

        let boundary = "lumora-test-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"local.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .into_bytes();
        body.extend(png_bytes());
        body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
        let app = Router::new()
            .route("/api/images/{id}/publish", post(publish_local_image))
            .with_state(state.clone());

        // 缺少客户端标识的跨站表单提交必须被拒（OPT-06）。
        let forged = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/images/local-image/publish")
                    .header(header::COOKIE, "lumora_session=publish-session")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/images/local-image/publish")
                    .header(header::COOKIE, "lumora_session=publish-session")
                    .header("x-lumora-device-id", "device-1")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let published: String = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT visibility FROM images WHERE id = 'local-image'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(published, "public");
        assert_eq!(
            std_fs::read(state.config.image_directory.join("local.png")).unwrap(),
            png_bytes()
        );
    }

    #[tokio::test]
    async fn streams_images_with_etag_range_and_ownership_checks() {
        let (_directory, state, user) = test_state(1).await;
        let now = Utc::now().to_rfc3339();
        let bytes = png_bytes();
        std_fs::write(state.config.image_directory.join("stream.png"), &bytes).unwrap();
        let connection = database(&state.db).unwrap();
        connection
            .execute(
                "INSERT INTO users (
                   id, name, email, password_hash, avatar, plan, credits, created_at
                 ) VALUES ('user-2', 'Other', 'other@example.test', 'hash', '', 'Free', 1, ?1)",
                [&now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at)
                 VALUES ('owner-session', ?1, ?2, '2099-01-01T00:00:00Z'),
                        ('other-session', 'user-2', ?2, '2099-01-01T00:00:00Z')",
                params![user.id, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO images (
                   id, user_id, file_name, prompt, size, model, created_at,
                   visibility, format, category, storage
                 ) VALUES ('stream-image', ?1, 'stream.png', 'test', '1024x1024', ?2, ?3,
                           'public', 'png', 'test', 'server')",
                params![user.id, MODEL, now],
            )
            .unwrap();
        drop(connection);

        let app = Router::new()
            .route("/api/images/{id}/file", get(private_image_file))
            .route("/public/images/{id}", get(public_image_file))
            .with_state(state);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/images/stream-image/file")
                    .header(header::COOKIE, "lumora_session=other-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);

        let full = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/images/stream-image/file")
                    .header(header::COOKIE, "lumora_session=owner-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(
            full.headers()[header::CACHE_CONTROL],
            "private, max-age=0, must-revalidate"
        );
        assert_eq!(full.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(
            full.headers()[header::CONTENT_LENGTH],
            bytes.len().to_string()
        );
        let etag = full.headers()[header::ETAG].to_str().unwrap().to_owned();
        assert_eq!(to_bytes(full.into_body(), 1024).await.unwrap(), bytes);

        let not_modified = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/images/stream-image/file")
                    .header(header::COOKIE, "lumora_session=owner-session")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers()[header::ETAG], etag);
        assert!(to_bytes(not_modified.into_body(), 1024)
            .await
            .unwrap()
            .is_empty());

        let partial = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/images/stream-image/file")
                    .header(header::COOKIE, "lumora_session=owner-session")
                    .header(header::RANGE, "bytes=0-7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            partial.headers()[header::CONTENT_RANGE],
            format!("bytes 0-7/{}", bytes.len())
        );
        assert_eq!(partial.headers()[header::CONTENT_LENGTH], "8");
        assert_eq!(
            to_bytes(partial.into_body(), 1024).await.unwrap(),
            &bytes[..8]
        );

        let public = app
            .oneshot(
                Request::builder()
                    .uri("/public/images/stream-image")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public.status(), StatusCode::OK);
        assert_eq!(
            public.headers()[header::CACHE_CONTROL],
            "public, max-age=86400"
        );
    }

    #[tokio::test]
    async fn excludes_private_images_from_public_endpoints() {
        let (_directory, state, user) = test_state(1).await;
        let now = Utc::now().to_rfc3339();
        let connection = database(&state.db).unwrap();
        for (id, visibility, storage) in [
            ("public-image", "public", "server"),
            ("local-public-image", "public", "local"),
            ("private-image", "private", "server"),
        ] {
            let file_name = format!("{id}.png");
            std_fs::write(state.config.image_directory.join(&file_name), png_bytes()).unwrap();
            connection
                .execute(
                    "INSERT INTO images (
                       id, user_id, file_name, prompt, size, model, created_at,
                       visibility, format, category, storage
                     ) VALUES (?1, ?2, ?3, ?4, '1024x1024', ?5, ?6, ?7, 'png', 'test', ?8)",
                    params![id, user.id, file_name, id, MODEL, now, visibility, storage],
                )
                .unwrap();
        }
        drop(connection);

        let app = Router::new()
            .route("/api/gallery", get(public_gallery))
            .route("/api/stats", get(crate::account::public_stats))
            .route("/public/images/{id}", get(public_image_file))
            .with_state(state);
        let gallery_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/gallery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let gallery: Value =
            serde_json::from_slice(&to_bytes(gallery_response.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(gallery["data"]["total"], 2);

        let stats_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let stats: Value =
            serde_json::from_slice(&to_bytes(stats_response.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(stats["data"]["publicImages"], 2);
        assert_eq!(stats["data"]["categories"][0]["count"], 2);

        let private_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/public/images/private-image")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(private_response.status(), StatusCode::NOT_FOUND);
        let public_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/public/images/public-image")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_response.status(), StatusCode::OK);
        let local_public_response = app
            .oneshot(
                Request::builder()
                    .uri("/public/images/local-public-image")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(local_public_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn preserves_non_json_upstream_errors() {
        let upstream = Router::new().route(
            "/v1/images/generations",
            post(|| async { (StatusCode::BAD_REQUEST, "unsupported parameter") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let provider = ProviderConfiguration {
            id: "provider-1".into(),
            base_url: format!("http://{address}"),
            api_key: "test-key".into(),
            model: MODEL.into(),
        };

        let error = match request_upstream_generation(
            &Client::new(),
            &provider,
            &generation_request(1),
            "test-request",
        )
        .await
        {
            Ok(_) => panic!("expected upstream error"),
            Err(error) => error,
        };

        assert!(error.1.contains("unsupported parameter"));
    }

    #[test]
    fn rejects_remote_json_images_and_invalid_parameters() {
        assert!(
            parse::image_input_from_json(&json!("https://example.test/image.png"), "image")
                .is_err()
        );
        assert!(parse::validate_size("4096x6144").is_ok());
        assert!(parse::validate_size("8192x4096").is_err());
        assert!(parse::validate_generation(&generation_request(0)).is_err());
        assert!(parse::validate_generation(&generation_request(5)).is_err());
    }
}
