use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use serde_json::Value;
use tokio::fs;
use uuid::Uuid;

use crate::{
    classification::{classify_prompt, CATEGORY_VERSION},
    db::{internal_error, read_database, write_database},
    model::{
        AppError, AppResult, GenerateRequest, ImageInput, ImageResponse, ProviderConfiguration,
        UserResponse, MODEL,
    },
    AppState,
};

use super::{record_generation_metrics, settle_failure, GenerationResult, RequestMetadata};

pub(super) struct GeneratedOutput {
    pub(super) encoded: String,
    pub(super) bytes: Vec<u8>,
    pub(super) format: String,
}

struct StoredOutput {
    id: String,
    file_name: String,
    encoded: String,
    format: String,
    reference_files: Vec<String>,
}

pub(super) struct StoreContext<'a> {
    pub(super) state: &'a AppState,
    pub(super) user: &'a UserResponse,
    pub(super) provider: &'a ProviderConfiguration,
    pub(super) request: &'a GenerateRequest,
    pub(super) metadata: &'a RequestMetadata,
    pub(super) reserved: i64,
    pub(super) endpoint: &'a str,
    pub(super) duration_ms: i64,
    pub(super) task_id: Option<&'a str>,
}

#[derive(Default)]
struct OutputRollback {
    paths: Vec<PathBuf>,
    committed: bool,
}

impl OutputRollback {
    async fn write(&mut self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.paths.push(path.to_path_buf());
        fs::write(path, bytes).await
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for OutputRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Drop cannot await; this short failure-only cleanup prevents orphaned files.
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(super) async fn store_outputs(
    context: StoreContext<'_>,
    outputs: Vec<GeneratedOutput>,
    output_references: &[Vec<ImageInput>],
    usage: Option<Value>,
    errors: Vec<String>,
) -> AppResult<GenerationResult> {
    let created_at = Utc::now().to_rfc3339();
    let category = classify_prompt(&context.request.prompt);
    let mut rollback = OutputRollback::default();
    let mut stored = Vec::new();
    for (output_index, output) in outputs.into_iter().enumerate() {
        let image_id = format!("img-{}", Uuid::new_v4().simple());
        let file_name = format!("{}.{}", Uuid::new_v4().simple(), output.format);
        let path = context.state.config.image_directory.join(&file_name);
        if let Err(error) = rollback.write(&path, &output.bytes).await {
            settle_failure(
                context.state,
                &context.user.id,
                Some(&context.provider.id),
                context.reserved,
                context.metadata,
                context.endpoint,
                context.duration_ms,
                context.task_id,
                context.request.prompt.trim(),
                "图片保存失败",
            )?;
            tracing::error!(error = %error, "image write failed");
            return Err(AppError(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "图片保存失败".into(),
            ));
        }
        let mut reference_files = Vec::new();
        for (reference_index, input) in output_references
            .get(output_index)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let extension = super::detect_image_format(&input.bytes).map_or("png", |item| item.0);
            let reference_file_name = format!("{image_id}-reference-{reference_index}.{extension}");
            let reference_path = context
                .state
                .config
                .image_directory
                .join(&reference_file_name);
            if rollback.write(&reference_path, &input.bytes).await.is_err() {
                settle_failure(
                    context.state,
                    &context.user.id,
                    Some(&context.provider.id),
                    context.reserved,
                    context.metadata,
                    context.endpoint,
                    context.duration_ms,
                    context.task_id,
                    context.request.prompt.trim(),
                    "参考图保存失败",
                )?;
                return Err(AppError(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "参考图保存失败".into(),
                ));
            }
            reference_files.push(reference_file_name);
        }
        stored.push(StoredOutput {
            id: image_id,
            file_name,
            encoded: output.encoded,
            format: output.format,
            reference_files,
        });
    }

    let used = stored.len() as i64;
    let visibility = if context.request.is_public {
        "public"
    } else {
        "private"
    };
    let storage = if context.metadata.desktop && !context.metadata.device_id.is_empty() {
        "pending"
    } else {
        "server"
    };
    let device_id = if storage == "pending" {
        context.metadata.device_id.as_str()
    } else {
        ""
    };
    let usage_log_id = format!("log-{}", Uuid::new_v4().simple());
    let credit_reference = format!("generation:{}", context.task_id.unwrap_or(&usage_log_id));
    let log_error = errors.join("；");
    let transaction_result = write_database(&context.state.db, |connection| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal_error)?;
        let changed = transaction
            .execute(
                "UPDATE users
                 SET credits = credits - ?1, credits_reserved = credits_reserved - ?2
                 WHERE id = ?3 AND credits >= ?1 AND credits_reserved >= ?2",
                params![used, context.reserved, context.user.id],
            )
            .map_err(internal_error)?;
        if changed == 0 {
            return Err(AppError(
                axum::http::StatusCode::CONFLICT,
                "积分结算状态冲突".into(),
            ));
        }
        let balance = transaction
            .query_row(
                "SELECT credits FROM users WHERE id = ?1",
                [&context.user.id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(internal_error)?;
        transaction
            .execute(
                "INSERT INTO credit_ledger (
                   id, user_id, delta, balance_after, reason, reference_id, created_at
                 ) VALUES (?1, ?2, ?3, ?4, 'image_generation', ?5, ?6)",
                params![
                    format!("credit-{}", Uuid::new_v4().simple()),
                    context.user.id,
                    -used,
                    balance,
                    credit_reference,
                    created_at
                ],
            )
            .map_err(internal_error)?;
        for file in &stored {
            let reference_files = serde_json::to_string(&file.reference_files).map_err(|_| {
                AppError(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "参考图记录无效".into(),
                )
            })?;
            transaction
                .execute(
                    "INSERT INTO images (
                       id, user_id, file_name, prompt, size, model, created_at,
                       visibility, format, category, storage, device_id, reference_files,
                       usage_log_id, category_version
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        file.id,
                        context.user.id,
                        file.file_name,
                        context.request.prompt.trim(),
                        context.request.size,
                        context.provider.model,
                        created_at,
                        visibility,
                        file.format,
                        category,
                        storage,
                        device_id,
                        reference_files,
                        usage_log_id,
                        CATEGORY_VERSION
                    ],
                )
                .map_err(internal_error)?;
        }
        transaction
            .execute(
                "INSERT INTO usage_logs (
                   id, user_id, provider_id, endpoint, model, status,
                   duration_ms, credits_used, ip_address, device_id, platform,
                   app_version, user_agent, prompt, error, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'success', ?6, ?7, ?8, ?9,
                          ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    usage_log_id,
                    context.user.id,
                    context.provider.id,
                    context.endpoint,
                    MODEL,
                    context.duration_ms,
                    used,
                    context.metadata.ip_address,
                    context.metadata.device_id,
                    context.metadata.platform,
                    context.metadata.app_version,
                    context.metadata.user_agent,
                    context.request.prompt.trim(),
                    log_error,
                    created_at
                ],
            )
            .map_err(internal_error)?;
        if let Some(task_id) = context.task_id {
            transaction
                .execute(
                    "UPDATE tasks SET status = 'success', image_id = ?1, credits_used = ?2,
                     error = NULL, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
                    params![stored[0].id, used, created_at, task_id, context.user.id],
                )
                .map_err(internal_error)?;
        }
        transaction.commit().map_err(internal_error)?;
        Ok(())
    });
    if let Err(error) = transaction_result {
        settle_failure(
            context.state,
            &context.user.id,
            Some(&context.provider.id),
            context.reserved,
            context.metadata,
            context.endpoint,
            context.duration_ms,
            context.task_id,
            context.request.prompt.trim(),
            "图片记录保存失败",
        )?;
        return Err(error);
    }
    rollback.commit();

    record_generation_metrics(context.endpoint, "success", context.duration_ms, used);

    let credits = read_database(&context.state.db, |connection| {
        connection
            .query_row(
                "SELECT credits FROM users WHERE id = ?1",
                [&context.user.id],
                |row| row.get(0),
            )
            .map_err(internal_error)
    })?;
    let images = stored
        .iter()
        .map(|file| ImageResponse {
            id: file.id.clone(),
            url: format!("/api/images/{}/file", file.id),
            thumbnail_url: format!("/api/images/{}/thumbnail", file.id),
            prompt: context.request.prompt.trim().into(),
            size: context.request.size.clone(),
            model: context.provider.model.clone(),
            created_at: created_at.clone(),
            source: "generated",
            format: file.format.clone(),
            is_public: context.request.is_public,
            is_favorited: false,
            category: category.into(),
            storage: storage.into(),
            author: None,
            favorited_at: None,
            reference_images: file
                .reference_files
                .iter()
                .enumerate()
                .map(|(index, _)| format!("/api/images/{}/references/{index}", file.id))
                .collect(),
        })
        .collect();
    Ok(GenerationResult {
        images,
        encoded: stored.into_iter().map(|file| file.encoded).collect(),
        credits,
        usage,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::OutputRollback;

    #[tokio::test]
    async fn rollback_removes_tracked_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("output.png");
        {
            let mut rollback = OutputRollback::default();
            rollback.write(&path, b"output").await.unwrap();
        }
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn committed_rollback_keeps_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("output.png");
        {
            let mut rollback = OutputRollback::default();
            rollback.write(&path, b"output").await.unwrap();
            rollback.commit();
        }
        assert!(path.exists());
    }
}
