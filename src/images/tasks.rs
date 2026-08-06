use axum::http::StatusCode;
use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use tokio::fs;
use uuid::Uuid;

use crate::{
    db::{internal_error, read_database, write_database},
    model::{AppError, AppResult, EditRequest, GenerateRequest, ImageInput, UserResponse},
    AppState,
};

use super::{
    detect_image_format, perform_edit, perform_generation, reserve_credits, settle_failure,
    RequestMetadata, TaskPayload,
};

pub(super) async fn create_tasks(
    state: &AppState,
    user: &UserResponse,
    kind: &str,
    generation: GenerateRequest,
    edit: Option<EditRequest>,
    metadata: RequestMetadata,
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
                request_metadata: metadata.clone(),
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
            &metadata,
            "/v1/tasks",
            0,
            None,
            generation.prompt.trim(),
            "任务创建失败",
        )?;
        return Err(error);
    }

    let inserted = write_database(&state.db, |connection| {
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
    });
    if let Err(error) = inserted {
        cleanup_task_directories(state, &task_directories).await;
        settle_failure(
            state,
            &user.id,
            None,
            count as i64,
            &metadata,
            "/v1/tasks",
            0,
            None,
            generation.prompt.trim(),
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
    metrics::gauge!("lumora_task_queue_depth").increment(1.0);
    tokio::spawn(async move {
        let permit = state.task_semaphore.clone().acquire_owned().await;
        metrics::gauge!("lumora_task_queue_depth").decrement(1.0);
        if permit.is_err() {
            return;
        }
        if let Err(error) = run_task(&state, &id).await {
            tracing::error!(task_id = id, error = %error.1, "asynchronous task failed");
        }
    });
}

pub(super) async fn run_task(state: &AppState, id: &str) -> AppResult<()> {
    let record = read_database(&state.db, |connection| {
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
            .map_err(internal_error)
    })?;
    let Some((user_id, kind, payload_json, user)) = record else {
        return Ok(());
    };
    write_database(&state.db, |connection| {
        connection
            .execute(
                "UPDATE tasks SET status = 'running', updated_at = ?1 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), id],
            )
            .map_err(internal_error)?;
        Ok(())
    })?;
    let payload = serde_json::from_str::<TaskPayload>(&payload_json)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "任务数据无效".into()));
    let metadata = payload
        .as_ref()
        .map(|payload| payload.request_metadata.clone())
        .unwrap_or_default();
    let prompt = payload
        .as_ref()
        .map(|payload| payload.generation.prompt.clone())
        .unwrap_or_default();
    let result = async {
        let payload = payload?;
        if kind == "generation" {
            perform_generation(
                state,
                &user,
                payload.generation,
                &metadata,
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
                &metadata,
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
        let status = read_database(&state.db, |connection| {
            connection
                .query_row("SELECT status FROM tasks WHERE id = ?1", [id], |row| {
                    row.get::<_, String>(0)
                })
                .optional()
                .map_err(internal_error)
        })?;
        if status.as_deref() == Some("running") {
            settle_failure(
                state,
                &user_id,
                None,
                1,
                &metadata,
                "/v1/tasks",
                0,
                Some(id),
                prompt.trim(),
                &error.1,
            )?;
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

pub(crate) fn recover_tasks(state: &AppState) -> AppResult<()> {
    let ids = write_database(&state.db, |connection| {
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
        Ok(ids)
    })?;
    for id in ids {
        spawn_task(state.clone(), id);
    }
    Ok(())
}
