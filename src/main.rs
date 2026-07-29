mod account;
mod auth;
mod config;
mod db;
mod images;
mod model;
mod security;

use std::{io, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    routing::{any, delete, get, post, put},
    Router,
};
use reqwest::Client;
use tokio::sync::Semaphore;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;
use db::{open_database, Database};

#[derive(Clone)]
pub struct AppState {
    db: Database,
    client: Client,
    config: Config,
    task_semaphore: Arc<Semaphore>,
}

fn apply_desktop_overrides(config: &mut Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let Some(name) = argument.to_str() else {
            continue;
        };
        if !name.starts_with("--desktop-") {
            continue;
        }
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing value for {name}"),
            )
        })?;
        match name {
            "--desktop-data" => config.data_directory = PathBuf::from(value),
            "--desktop-images" => config.image_directory = PathBuf::from(value),
            "--desktop-tasks" => config.task_directory = PathBuf::from(value),
            "--desktop-static" => config.static_directory = PathBuf::from(value),
            "--desktop-master-key-file" => {
                let key = std::fs::read(value)?;
                config.master_key = key.try_into().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "desktop master key must contain exactly 32 bytes",
                    )
                })?;
            }
            _ => {}
        }
    }
    std::fs::create_dir_all(&config.data_directory)?;
    std::fs::create_dir_all(&config.image_directory)?;
    std::fs::create_dir_all(&config.task_directory)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lumora_server=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut config = Config::load()?;
    apply_desktop_overrides(&mut config)?;
    let db = open_database(&config.data_directory, &config.master_key)?;
    let state = AppState {
        db,
        client: Client::builder()
            .timeout(Duration::from_secs(360))
            .build()?,
        task_semaphore: Arc::new(Semaphore::new(config.worker_concurrency)),
        config: config.clone(),
    };
    images::recover_tasks(&state)?;

    let static_service = ServeDir::new(&config.static_directory)
        .not_found_service(ServeFile::new(config.static_directory.join("index.html")));
    let app = Router::new()
        .route("/healthz", get(account::liveness))
        .route("/api/health", get(account::health))
        .route("/api/config/public", get(account::public_config))
        .route("/api/stats", get(account::public_stats))
        .route("/api/session", get(auth::session))
        .route("/api/account/profile", put(account::update_profile))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/announcements", get(account::list_announcements))
        .route(
            "/api/api-keys",
            get(auth::list_api_keys).post(auth::create_api_key),
        )
        .route("/api/api-keys/{id}", delete(auth::revoke_api_key))
        .route(
            "/api/providers",
            get(account::list_providers).post(account::create_provider),
        )
        .route(
            "/api/providers/{id}/activate",
            put(account::activate_provider),
        )
        .route("/api/providers/{id}", delete(account::delete_provider))
        .route("/api/usage", get(account::get_usage))
        .route(
            "/api/images",
            get(images::list_images).delete(images::clear_images),
        )
        .route("/api/images/generate", post(images::generate_image))
        .route(
            "/api/images/generate/async",
            post(images::generate_image_async),
        )
        .route("/api/images/edit", post(images::edit_image))
        .route("/api/images/edit/async", post(images::edit_image_async))
        .route(
            "/api/images/{id}/visibility",
            put(images::update_image_visibility),
        )
        .route("/api/images/{id}", delete(images::delete_image))
        .route("/api/images/{id}/file", get(images::private_image_file))
        .route("/api/image-tasks", get(images::list_active_image_tasks))
        .route("/api/image-tasks/{ids}", get(images::get_image_tasks))
        .route("/api/gallery", get(images::public_gallery))
        .route("/public/images/{id}", get(images::public_image_file))
        .route("/v1/images/generations", post(images::external_generate))
        .route("/v1/images/edits", post(images::external_edit))
        .route(
            "/v1/images/generations/async",
            post(images::external_generate_async),
        )
        .route("/v1/images/edits/async", post(images::external_edit_async))
        .route("/v1/tasks/{ids}", get(images::get_tasks))
        .route("/v1/tasks/confirm", post(images::confirm_tasks))
        .route("/v1/account/credits", get(account::external_credits))
        .route("/v1/account/usage", get(account::external_usage))
        .route("/api/{*path}", any(account::api_not_found))
        .fallback_service(static_service)
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "Lumora API started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
