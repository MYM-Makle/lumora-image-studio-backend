use std::{collections::HashMap, time::Instant};

use axum::{
    body::{to_bytes, Body},
    extract::{rejection::JsonRejection, FromRequest, Multipart, Path as AxumPath, Query, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{fs, task::JoinSet};
use uuid::Uuid;

use crate::{
    account::active_provider,
    auth::{user_from_api_key, user_from_headers},
    db::{database, internal_error},
    model::{
        api_json, api_query, api_success, default_quality, default_size, ApiResponse, AppError,
        AppResult, ConfirmTasksRequest, EditJsonRequest, EditRequest, GenerateRequest, ImageInput,
        ImageResponse, OpenAiImageData, OpenAiImagesResponse, OpenAiResult, ProviderConfiguration,
        UpstreamResponse, UserResponse, MODEL,
    },
    AppState,
};

const MAX_EDIT_BODY: usize = 100 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 50 * 1024 * 1024;

struct GeneratedOutput {
    encoded: String,
    bytes: Vec<u8>,
    format: String,
}

struct GenerationResult {
    images: Vec<ImageResponse>,
    encoded: Vec<String>,
    credits: i64,
    usage: Option<Value>,
    errors: Vec<String>,
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
}

pub async fn list_images(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let connection = database(&state.db)?;
    let mut statement = connection
        .prepare(
            "SELECT id, prompt, size, model, created_at, format, visibility, category
             FROM images WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map([user.id], |row| image_from_row(row, false, None))
        .map_err(internal_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal_error)?;
    Ok(Json(api_success(json!({ "items": items }))))
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
    let connection = database(&state.db)?;
    let total: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM images
             WHERE (?1 = '' OR lower(prompt) LIKE '%' || lower(?1) || '%')
               AND (?2 = '' OR ?2 = '全部' OR category = ?2)",
            params![search, category],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    let mut statement = connection
        .prepare(
            "SELECT i.id, i.prompt, i.size, i.model, i.created_at, i.format,
                    i.visibility, i.category, u.name
             FROM images i JOIN users u ON u.id = i.user_id
             WHERE (?1 = '' OR lower(i.prompt) LIKE '%' || lower(?1) || '%')
               AND (?2 = '' OR ?2 = '全部' OR i.category = ?2)
             ORDER BY i.created_at DESC LIMIT ?3 OFFSET ?4",
        )
        .map_err(internal_error)?;
    let items = statement
        .query_map(
            params![search, category, page_size, (page - 1) * page_size],
            |row| {
                let author: String = row.get(8)?;
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
}

fn image_from_row(
    row: &rusqlite::Row<'_>,
    public: bool,
    author: Option<String>,
) -> rusqlite::Result<ImageResponse> {
    let id: String = row.get(0)?;
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
        author,
    })
}

pub async fn private_image_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    let user = user_from_headers(&headers, &state)?;
    serve_image(&state, &id, Some(&user.id), false).await
}

pub async fn public_image_file(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    serve_image(&state, &id, None, true).await
}

async fn serve_image(
    state: &AppState,
    id: &str,
    user_id: Option<&str>,
    public: bool,
) -> AppResult<Response> {
    let record = database(&state.db)?
        .query_row(
            "SELECT file_name, format, user_id, visibility FROM images WHERE id = ?1",
            [id],
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
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))?;
    let allowed = public || user_id.is_some_and(|value| value == record.2);
    if !allowed {
        return Err(AppError(StatusCode::NOT_FOUND, "图片不存在".into()));
    }
    let bytes = fs::read(state.config.image_directory.join(record.0))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, image_id = id, "image read failed");
            AppError(StatusCode::NOT_FOUND, "图片文件不存在".into())
        })?;
    let cache = if public {
        "public, max-age=86400"
    } else {
        "private, no-store"
    };
    Ok((
        [
            (header::CONTENT_TYPE, mime_for_format(&record.1)),
            (header::CACHE_CONTROL, cache),
        ],
        Body::from(bytes),
    )
        .into_response())
}

pub async fn generate_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    let result =
        perform_generation(&state, &user, request, "/api/images/generate", None, false).await?;
    Ok(Json(api_success(json!({
        "images": result.images,
        "credits": result.credits,
        "errors": result.errors
    }))))
}

pub async fn generate_image_async(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> AppResult<(StatusCode, Json<ApiResponse<Value>>)> {
    let request = api_json(payload)?;
    let user = user_from_headers(&headers, &state)?;
    validate_generation(&request)?;
    active_provider(&state, &user.id)?;
    let task_ids = create_tasks(&state, &user, "generation", request, None).await?;
    let items = task_summaries(&state, &user.id, &task_ids)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(api_success(json!({ "items": items }))),
    ))
}

pub async fn edit_image(
    State(state): State<AppState>,
    request: Request<Body>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let headers = request.headers().clone();
    let user = user_from_headers(&headers, &state)?;
    let edit = parse_edit_request(&state, request).await?;
    let result = perform_edit(&state, &user, edit, "/api/images/edit", None, false).await?;
    Ok(Json(api_success(json!({
        "images": result.images,
        "credits": result.credits,
        "errors": result.errors
    }))))
}

pub async fn edit_image_async(
    State(state): State<AppState>,
    request: Request<Body>,
) -> AppResult<(StatusCode, Json<ApiResponse<Value>>)> {
    let headers = request.headers().clone();
    let user = user_from_headers(&headers, &state)?;
    let edit = parse_edit_request(&state, request).await?;
    validate_generation(&edit.generation)?;
    validate_edit_inputs(&edit)?;
    active_provider(&state, &user.id)?;
    let generation = edit.generation.clone();
    let task_ids = create_tasks(&state, &user, "edit", generation, Some(edit)).await?;
    let items = task_summaries(&state, &user.id, &task_ids)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(api_success(json!({ "items": items }))),
    ))
}

pub async fn external_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> OpenAiResult<Json<OpenAiImagesResponse>> {
    let request = external_json(payload)?;
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let result = perform_generation(
        &state,
        &principal.user,
        request,
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
    request: Request<Body>,
) -> OpenAiResult<Json<OpenAiImagesResponse>> {
    let headers = request.headers().clone();
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let mut edit = parse_edit_request(&state, request).await?;
    edit.batch = false;
    let result = perform_edit(
        &state,
        &principal.user,
        edit,
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
        let one = GenerateRequest {
            n: 1,
            ..request.clone()
        };
        requests.spawn(async move { request_upstream_generation(&client, &provider, &one).await });
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
            endpoint,
            duration_ms,
            task_id,
            &message,
        )?;
        return Err(AppError(StatusCode::BAD_GATEWAY, message));
    }
    store_outputs(
        state,
        user,
        &provider,
        &request,
        outputs,
        request.n as i64,
        endpoint,
        duration_ms,
        task_id,
        usage,
        errors,
    )
    .await
}

async fn perform_edit(
    state: &AppState,
    user: &UserResponse,
    request: EditRequest,
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
            match request_upstream_edit(&state.client, &provider, &one).await {
                Ok((mut generated, current_usage)) => {
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
            let one = EditRequest {
                generation: GenerateRequest {
                    n: 1,
                    ..request.generation.clone()
                },
                ..request.clone()
            };
            requests.spawn(async move { request_upstream_edit(&client, &provider, &one).await });
        }
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
            endpoint,
            duration_ms,
            task_id,
            &message,
        )?;
        return Err(AppError(StatusCode::BAD_GATEWAY, message));
    }
    store_outputs(
        state,
        user,
        &provider,
        &request.generation,
        outputs,
        reserved,
        endpoint,
        duration_ms,
        task_id,
        usage,
        errors,
    )
    .await
}

async fn request_upstream_generation(
    client: &reqwest::Client,
    provider: &ProviderConfiguration,
    request: &GenerateRequest,
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
        .json(&payload)
        .send()
        .await
        .map_err(|_| AppError(StatusCode::BAD_GATEWAY, "调用上游失败".into()))?;
    parse_upstream_response(response, 1).await
}

async fn request_upstream_edit(
    client: &reqwest::Client,
    provider: &ProviderConfiguration,
    request: &EditRequest,
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

#[allow(clippy::too_many_arguments)]
async fn store_outputs(
    state: &AppState,
    user: &UserResponse,
    provider: &ProviderConfiguration,
    request: &GenerateRequest,
    outputs: Vec<GeneratedOutput>,
    reserved: i64,
    endpoint: &str,
    duration_ms: i64,
    task_id: Option<&str>,
    usage: Option<Value>,
    errors: Vec<String>,
) -> AppResult<GenerationResult> {
    let created_at = Utc::now().to_rfc3339();
    let category = prompt_category(&request.prompt);
    let mut files = Vec::new();
    for output in outputs {
        let image_id = format!("img-{}", Uuid::new_v4().simple());
        let file_name = format!("{}.{}", Uuid::new_v4().simple(), output.format);
        let path = state.config.image_directory.join(&file_name);
        if let Err(error) = fs::write(&path, &output.bytes).await {
            for (_, _, existing_path, _, _) in &files {
                let _ = fs::remove_file(existing_path).await;
            }
            settle_failure(
                state,
                &user.id,
                Some(&provider.id),
                reserved,
                endpoint,
                duration_ms,
                task_id,
                "图片保存失败",
            )?;
            tracing::error!(error = %error, "image write failed");
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "图片保存失败".into(),
            ));
        }
        files.push((image_id, file_name, path, output.encoded, output.format));
    }

    let used = files.len() as i64;
    let visibility = if request.is_public {
        "public"
    } else {
        "private"
    };
    let transaction_result = (|| -> AppResult<()> {
        let mut connection = database(&state.db)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let changed = transaction
            .execute(
                "UPDATE users
                 SET credits = credits - ?1, credits_reserved = credits_reserved - ?2
                 WHERE id = ?3 AND credits >= ?1 AND credits_reserved >= ?2",
                params![used, reserved, user.id],
            )
            .map_err(internal_error)?;
        if changed == 0 {
            return Err(AppError(StatusCode::CONFLICT, "积分结算状态冲突".into()));
        }
        for (image_id, file_name, _, _, format) in &files {
            transaction
                .execute(
                    "INSERT INTO images (
                       id, user_id, file_name, prompt, size, model, created_at,
                       visibility, format, category
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        image_id,
                        user.id,
                        file_name,
                        request.prompt.trim(),
                        request.size,
                        provider.model,
                        created_at,
                        visibility,
                        format,
                        category
                    ],
                )
                .map_err(internal_error)?;
        }
        transaction
            .execute(
                "INSERT INTO usage_logs (
                   id, user_id, provider_id, endpoint, model, status,
                   duration_ms, credits_used, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'success', ?6, ?7, ?8)",
                params![
                    format!("log-{}", Uuid::new_v4().simple()),
                    user.id,
                    provider.id,
                    endpoint,
                    MODEL,
                    duration_ms,
                    used,
                    created_at
                ],
            )
            .map_err(internal_error)?;
        if let Some(task_id) = task_id {
            transaction
                .execute(
                    "UPDATE tasks SET status = 'success', image_id = ?1, credits_used = ?2,
                     error = NULL, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
                    params![files[0].0, used, created_at, task_id, user.id],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })();
    if let Err(error) = transaction_result {
        for (_, _, path, _, _) in &files {
            let _ = fs::remove_file(path).await;
        }
        settle_failure(
            state,
            &user.id,
            Some(&provider.id),
            reserved,
            endpoint,
            duration_ms,
            task_id,
            "图片记录保存失败",
        )?;
        return Err(error);
    }

    let credits = database(&state.db)?
        .query_row(
            "SELECT credits FROM users WHERE id = ?1",
            [&user.id],
            |row| row.get(0),
        )
        .map_err(internal_error)?;
    let images = files
        .iter()
        .map(|(id, _, _, _, format)| ImageResponse {
            id: id.clone(),
            url: format!("/api/images/{id}/file"),
            prompt: request.prompt.trim().into(),
            size: request.size.clone(),
            model: provider.model.clone(),
            created_at: created_at.clone(),
            source: "generated",
            format: format.clone(),
            is_public: request.is_public,
            category: category.into(),
            author: None,
        })
        .collect();
    Ok(GenerationResult {
        images,
        encoded: files.into_iter().map(|item| item.3).collect(),
        credits,
        usage,
        errors,
    })
}

fn reserve_credits(state: &AppState, user_id: &str, amount: i64) -> AppResult<()> {
    let mut connection = database(&state.db)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal_error)?;
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let (credits, reserved, daily_limit, today_calls): (i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT u.credits, u.credits_reserved, u.daily_limit,
                    (SELECT COUNT(*) FROM usage_logs l
                     WHERE l.user_id = u.id AND substr(l.created_at, 1, 10) = ?2)
             FROM users u WHERE u.id = ?1",
            params![user_id, today],
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
}

#[allow(clippy::too_many_arguments)]
fn settle_failure(
    state: &AppState,
    user_id: &str,
    provider_id: Option<&str>,
    reserved: i64,
    endpoint: &str,
    duration_ms: i64,
    task_id: Option<&str>,
    message: &str,
) -> AppResult<()> {
    let mut connection = database(&state.db)?;
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
               duration_ms, credits_used, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'error', ?6, 0, ?7)",
            params![
                format!("log-{}", Uuid::new_v4().simple()),
                user_id,
                provider_id,
                endpoint,
                MODEL,
                duration_ms,
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
}

fn validate_generation(request: &GenerateRequest) -> AppResult<()> {
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

fn validate_size(size: &str) -> AppResult<()> {
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
        || long > 3840
        || width % 16 != 0
        || height % 16 != 0
        || long > short.saturating_mul(3)
        || !(655_360..=8_294_400).contains(&pixels)
    {
        return Err(AppError(StatusCode::BAD_REQUEST, "图片尺寸无效".into()));
    }
    Ok(())
}

fn validate_edit_inputs(request: &EditRequest) -> AppResult<()> {
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

async fn parse_edit_request(state: &AppState, request: Request<Body>) -> AppResult<EditRequest> {
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

async fn input_from_field(field: axum::extract::multipart::Field<'_>) -> AppResult<ImageInput> {
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

fn image_input_from_json(value: &Value, fallback_name: &str) -> AppResult<ImageInput> {
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

fn detect_image_format(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
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

fn mime_for_format(format: &str) -> &'static str {
    match format {
        "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "image/png",
    }
}

fn prompt_category(prompt: &str) -> &'static str {
    let prompt = prompt.to_lowercase();
    if ["海报", "poster", "插画", "illustration"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
    {
        "海报插画"
    } else if ["产品", "product", "电商", "包装"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
    {
        "产品电商"
    } else if ["人像", "portrait", "人物", "摄影"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
    {
        "人像摄影"
    } else if ["ui", "界面", "app", "网页"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
    {
        "UI/界面"
    } else if ["3d", "渲染", "cgi"]
        .iter()
        .any(|keyword| prompt.contains(keyword))
    {
        "3D 渲染"
    } else {
        "其他"
    }
}

pub async fn delete_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let file_name = database(&state.db)?
        .query_row(
            "SELECT file_name FROM images WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "图片不存在".into()))?;
    let original = state.config.image_directory.join(&file_name);
    let trash = state
        .config
        .image_directory
        .join(format!(".deleting-{}", Uuid::new_v4().simple()));
    let renamed = fs::rename(&original, &trash).await.is_ok();
    let changed = database(&state.db)?
        .execute(
            "DELETE FROM images WHERE id = ?1 AND user_id = ?2",
            params![id, user.id],
        )
        .map_err(internal_error);
    if let Err(error) = changed {
        if renamed {
            let _ = fs::rename(&trash, &original).await;
        }
        return Err(error);
    }
    if renamed {
        let _ = fs::remove_file(trash).await;
    }
    Ok(Json(api_success(Value::Null)))
}

pub async fn clear_images(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let file_names = {
        let connection = database(&state.db)?;
        let mut statement = connection
            .prepare("SELECT file_name FROM images WHERE user_id = ?1")
            .map_err(internal_error)?;
        let file_names = statement
            .query_map([&user.id], |row| row.get::<_, String>(0))
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        file_names
    };
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
    let delete_result = {
        database(&state.db)?
            .execute("DELETE FROM images WHERE user_id = ?1", [&user.id])
            .map_err(internal_error)
    };
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
    headers: HeaderMap,
    payload: Result<Json<GenerateRequest>, JsonRejection>,
) -> OpenAiResult<(StatusCode, Json<Value>)> {
    let request = external_json(payload)?;
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    validate_generation(&request)?;
    active_provider(&state, &principal.user.id)?;
    let task_ids = create_tasks(&state, &principal.user, "generation", request, None).await?;
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
    request: Request<Body>,
) -> OpenAiResult<(StatusCode, Json<Value>)> {
    let headers = request.headers().clone();
    let principal = user_from_api_key(&headers, &state, &["generate", "full"])?;
    let edit = parse_edit_request(&state, request).await?;
    validate_generation(&edit.generation)?;
    validate_edit_inputs(&edit)?;
    active_provider(&state, &principal.user.id)?;
    let generation = edit.generation.clone();
    let task_ids = create_tasks(&state, &principal.user, "edit", generation, Some(edit)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "taskIds": task_ids,
            "creditsReserved": task_ids.len(),
            "model": MODEL
        })),
    ))
}

async fn create_tasks(
    state: &AppState,
    user: &UserResponse,
    kind: &str,
    generation: GenerateRequest,
    edit: Option<EditRequest>,
) -> AppResult<Vec<String>> {
    let count = edit
        .as_ref()
        .filter(|request| request.batch)
        .map_or(generation.n as usize, |request| request.images.len());
    reserve_credits(state, &user.id, count as i64)?;
    let mut tasks = Vec::new();
    let mut task_directories = Vec::new();
    let build_result = async {
        for index in 0..count {
            let id = format!("task-{}", Uuid::new_v4().simple());
            let task_directory = state.config.task_directory.join(&id);
            fs::create_dir_all(&task_directory).await.map_err(|error| {
                tracing::error!(error = %error, "task directory creation failed");
                AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务创建失败".into())
            })?;
            task_directories.push(id.clone());
            let mut task_generation = generation.clone();
            task_generation.n = 1;
            let mut input_files = Vec::new();
            let mut mask_file = None;
            if let Some(edit) = &edit {
                let selected = if edit.batch {
                    vec![edit.images[index].clone()]
                } else {
                    edit.images.clone()
                };
                for (input_index, input) in selected.iter().enumerate() {
                    let extension = detect_image_format(&input.bytes).map_or("png", |item| item.0);
                    let file_name = format!("input-{input_index}.{extension}");
                    fs::write(task_directory.join(&file_name), &input.bytes)
                        .await
                        .map_err(|_| {
                            AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务文件保存失败".into())
                        })?;
                    input_files.push(file_name);
                }
                if let Some(mask) = &edit.mask {
                    let extension = detect_image_format(&mask.bytes).map_or("png", |item| item.0);
                    let file_name = format!("mask.{extension}");
                    fs::write(task_directory.join(&file_name), &mask.bytes)
                        .await
                        .map_err(|_| {
                            AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务文件保存失败".into())
                        })?;
                    mask_file = Some(file_name);
                }
            }
            let payload = TaskPayload {
                generation: task_generation,
                input_files,
                mask_file,
            };
            tasks.push((
                id,
                serde_json::to_string(&payload).map_err(|_| {
                    AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务序列化失败".into())
                })?,
            ));
        }
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(error) = build_result {
        cleanup_task_directories(state, &task_directories).await;
        settle_failure(
            state,
            &user.id,
            None,
            count as i64,
            "/v1/tasks",
            0,
            None,
            "任务创建失败",
        )?;
        return Err(error);
    }

    let inserted = (|| -> AppResult<()> {
        let mut connection = database(&state.db)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let now = Utc::now().to_rfc3339();
        for (id, payload) in &tasks {
            transaction
                .execute(
                    "INSERT INTO tasks (
                       id, user_id, kind, status, request_json, credits_reserved,
                       credits_used, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, 'queued', ?4, 1, 0, ?5, ?5)",
                    params![id, user.id, kind, payload, now],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok(())
    })();
    if let Err(error) = inserted {
        cleanup_task_directories(state, &task_directories).await;
        settle_failure(
            state,
            &user.id,
            None,
            count as i64,
            "/v1/tasks",
            0,
            None,
            "任务创建失败",
        )?;
        return Err(error);
    }
    let ids = tasks.into_iter().map(|item| item.0).collect::<Vec<_>>();
    for id in &ids {
        spawn_task(state.clone(), id.clone());
    }
    Ok(ids)
}

async fn cleanup_task_directories(state: &AppState, task_ids: &[String]) {
    for id in task_ids {
        let _ = fs::remove_dir_all(state.config.task_directory.join(id)).await;
    }
}

fn spawn_task(state: AppState, id: String) {
    tokio::spawn(async move {
        let permit = state.task_semaphore.clone().acquire_owned().await;
        if permit.is_err() {
            return;
        }
        if let Err(error) = run_task(&state, &id).await {
            tracing::error!(task_id = id, error = %error.1, "asynchronous task failed");
        }
    });
}

async fn run_task(state: &AppState, id: &str) -> AppResult<()> {
    let record = {
        let connection = database(&state.db)?;
        connection
            .query_row(
                "SELECT t.user_id, t.kind, t.request_json,
                        u.id, u.name, u.email, u.avatar, u.plan, u.credits, u.credits_reserved
                 FROM tasks t JOIN users u ON u.id = t.user_id
                 WHERE t.id = ?1 AND t.status IN ('queued', 'running')",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        UserResponse {
                            id: row.get(3)?,
                            name: row.get(4)?,
                            email: row.get(5)?,
                            avatar: row.get(6)?,
                            plan: row.get(7)?,
                            credits: row.get(8)?,
                            credits_reserved: row.get(9)?,
                        },
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?
    };
    let Some((user_id, kind, payload_json, user)) = record else {
        return Ok(());
    };
    database(&state.db)?
        .execute(
            "UPDATE tasks SET status = 'running', updated_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id],
        )
        .map_err(internal_error)?;
    let result = async {
        let payload: TaskPayload = serde_json::from_str(&payload_json)
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务数据无效".into()))?;
        if kind == "generation" {
            perform_generation(
                state,
                &user,
                payload.generation,
                "/v1/images/generations/async",
                Some(id),
                true,
            )
            .await
            .map(|_| ())
        } else {
            let task_directory = state.config.task_directory.join(id);
            let images = load_task_inputs(&task_directory, &payload.input_files).await?;
            let mask = if let Some(file_name) = &payload.mask_file {
                Some(load_task_input(&task_directory, file_name).await?)
            } else {
                None
            };
            perform_edit(
                state,
                &user,
                EditRequest {
                    generation: payload.generation,
                    images,
                    mask,
                    batch: false,
                },
                "/v1/images/edits/async",
                Some(id),
                true,
            )
            .await
            .map(|_| ())
        }
    }
    .await;
    let _ = fs::remove_dir_all(state.config.task_directory.join(id)).await;
    if let Err(error) = result {
        let status = database(&state.db)?
            .query_row("SELECT status FROM tasks WHERE id = ?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(internal_error)?;
        if status.as_deref() == Some("running") {
            settle_failure(state, &user_id, None, 1, "/v1/tasks", 0, Some(id), &error.1)?;
        }
        return Err(error);
    }
    Ok(())
}

async fn load_task_inputs(
    directory: &std::path::Path,
    files: &[String],
) -> AppResult<Vec<ImageInput>> {
    let mut inputs = Vec::new();
    for file in files {
        inputs.push(load_task_input(directory, file).await?);
    }
    Ok(inputs)
}

async fn load_task_input(directory: &std::path::Path, file: &str) -> AppResult<ImageInput> {
    let bytes = fs::read(directory.join(file))
        .await
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务图片不存在".into()))?;
    let (_, mime_type) = detect_image_format(&bytes)
        .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务图片无效".into()))?;
    Ok(ImageInput {
        bytes,
        file_name: file.into(),
        mime_type: mime_type.into(),
    })
}

pub fn recover_tasks(state: &AppState) -> AppResult<()> {
    let ids = {
        let connection = database(&state.db)?;
        connection
            .execute(
                "UPDATE tasks SET status = 'queued' WHERE status = 'running'",
                [],
            )
            .map_err(internal_error)?;
        let mut statement = connection
            .prepare("SELECT id FROM tasks WHERE status = 'queued' ORDER BY created_at")
            .map_err(internal_error)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(internal_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_error)?;
        ids
    };
    for id in ids {
        spawn_task(state.clone(), id);
    }
    Ok(())
}

pub async fn list_active_image_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Value>>> {
    let user = user_from_headers(&headers, &state)?;
    let ids = {
        let connection = database(&state.db)?;
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
        ids
    };
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
    let connection = database(&state.db)?;
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
        let Some((status, image_id, error, request_json, created_at, updated_at)) = record else {
            continue;
        };
        let payload: TaskPayload = serde_json::from_str(&request_json)
            .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务数据无效".into()))?;
        items.push(json!({
            "id": id,
            "status": status,
            "prompt": payload.generation.prompt,
            "imageId": image_id,
            "error": error,
            "createdAt": created_at,
            "updatedAt": updated_at
        }));
    }
    Ok(items)
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
        let record = database(&state.db)?
            .query_row(
                "SELECT status, image_id, error, created_at, updated_at
                 FROM tasks WHERE id = ?1 AND user_id = ?2",
                params![id, principal.user.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(internal_error)?;
        let Some((status, image_id, error, created_at, updated_at)) = record else {
            continue;
        };
        let data = if let Some(image_id) = image_id {
            let file_name = database(&state.db)?
                .query_row(
                    "SELECT file_name FROM images WHERE id = ?1 AND user_id = ?2",
                    params![image_id, principal.user.id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(internal_error)?;
            if let Some(file_name) = file_name {
                let bytes = fs::read(state.config.image_directory.join(file_name))
                    .await
                    .map_err(|_| {
                        AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务结果不存在".into())
                    })?;
                json!([{ "b64_json": BASE64.encode(bytes) }])
            } else {
                json!([])
            }
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
    let mut connection = database(&state.db)?;
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
            _ => return Err(AppError(StatusCode::CONFLICT, "任务尚未完成".into()).into()),
        }
        transaction
            .execute(
                "UPDATE tasks SET confirmed_at = COALESCE(confirmed_at, ?1) WHERE id = ?2",
                params![Utc::now().to_rfc3339(), id],
            )
            .map_err(internal_error)?;
    }
    transaction.commit().map_err(internal_error)?;
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
    use super::*;
    use crate::{config::Config, db::open_database};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        routing::{get, post},
        Router,
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
                    assert_eq!(fields.len(), 2);
                    assert_eq!(request["model"], MODEL);
                    assert_eq!(request["prompt"], "A test image");
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
            );
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
        };
        let state = AppState {
            db: open_database(directory.path(), &[6_u8; 32]).unwrap(),
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            config,
            task_semaphore: Arc::new(Semaphore::new(2)),
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
        let generated = perform_generation(
            &state,
            &user,
            generation_request(2),
            "/api/images/generate",
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(generated.images.len(), 2);
        assert!(generated.images.iter().all(|image| image.is_public));

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
            "/api/images/edit",
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(edited.images.len(), 2);
        let balances: (i64, i64) = database(&state.db)
            .unwrap()
            .query_row(
                "SELECT credits, credits_reserved FROM users WHERE id = ?1",
                [&user.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(balances, (6, 0));
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
        assert!(run_task(&state, "task-invalid").await.is_err());
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
            input_files: Vec::new(),
            mask_file: None,
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
            .with_state(state);
        let response = app
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

        let error =
            match request_upstream_generation(&Client::new(), &provider, &generation_request(1))
                .await
            {
                Ok(_) => panic!("expected upstream error"),
                Err(error) => error,
            };

        assert!(error.1.contains("unsupported parameter"));
    }

    #[test]
    fn rejects_remote_json_images_and_invalid_parameters() {
        assert!(image_input_from_json(&json!("https://example.test/image.png"), "image").is_err());
        assert!(validate_generation(&generation_request(0)).is_err());
        assert!(validate_generation(&generation_request(5)).is_err());
    }
}
