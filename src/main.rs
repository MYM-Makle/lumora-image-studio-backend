mod account;
mod admin;
mod auth;
mod classification;
mod config;
mod db;
mod images;
mod model;
mod observability;
mod presence;
mod request;
mod retention;
mod security;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue, Method},
    middleware,
    routing::{any, delete, get, post, put},
    Router,
};
use reqwest::Client;
use tokio::sync::Semaphore;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};

use config::Config;
use db::{open_database, Database};
use presence::PresenceThrottle;

#[derive(Clone)]
pub struct AppState {
    db: Database,
    client: Client,
    config: Config,
    task_semaphore: Arc<Semaphore>,
    presence: PresenceThrottle,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    observability::init_tracing(config.production);
    observability::install_metrics()?;
    let db = open_database(&config.data_directory, &config.master_key)?;
    let state = AppState {
        db,
        client: Client::builder()
            .timeout(Duration::from_secs(360))
            .build()?,
        task_semaphore: Arc::new(Semaphore::new(config.worker_concurrency)),
        presence: PresenceThrottle::new(),
        config: config.clone(),
    };
    images::recover_tasks(&state)?;
    retention::spawn_daily(state.clone());

    let static_service = ServeDir::new(&config.static_directory)
        .fallback(ServeFile::new(config.static_directory.join("index.html")));
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("https://tauri.localhost"),
            HeaderValue::from_static("http://tauri.localhost"),
            HeaderValue::from_static("tauri://localhost"),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("x-lumora-device-id"),
            HeaderName::from_static("x-lumora-platform"),
            HeaderName::from_static("x-lumora-app-version"),
            HeaderName::from_static("x-lumora-client"),
        ])
        .expose_headers([request::REQUEST_ID_HEADER.clone()])
        .allow_credentials(true);
    let mut global_rate_builder = GovernorConfigBuilder::default();
    global_rate_builder.per_millisecond(500).burst_size(120);
    let mut global_rate_builder = global_rate_builder
        .key_extractor(request::TrustedClientIpKeyExtractor)
        .use_headers();
    let global_rate = global_rate_builder
        .finish()
        .expect("global rate limit configuration is valid");

    let mut write_rate_builder = GovernorConfigBuilder::default();
    write_rate_builder
        .per_second(2)
        .burst_size(30)
        .methods(vec![Method::POST, Method::PUT, Method::DELETE]);
    let mut write_rate_builder = write_rate_builder
        .key_extractor(request::TrustedClientIpKeyExtractor)
        .use_headers();
    let write_rate = write_rate_builder
        .finish()
        .expect("write rate limit configuration is valid");

    let global_limiter = global_rate.limiter().clone();
    let write_limiter = write_rate.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            global_limiter.retain_recent();
            write_limiter.retain_recent();
        }
    });

    let api_routes = Router::new()
        .route("/api/config/public", get(account::public_config))
        .route("/api/stats", get(account::public_stats))
        .route("/api/session", get(auth::session))
        .route("/api/account/profile", put(account::update_profile))
        .route("/api/auth/email-code", post(auth::send_email_code))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/activity/heartbeat", post(account::heartbeat))
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
        .route(
            "/api/images/{id}/publish",
            post(images::publish_local_image),
        )
        .route("/api/images/{id}/local", post(images::localize_image))
        .route("/api/images/{id}", delete(images::delete_image))
        .route("/api/images/{id}/file", get(images::private_image_file))
        .route(
            "/api/images/{id}/thumbnail",
            get(images::private_image_thumbnail),
        )
        .route(
            "/api/images/{id}/references/{index}",
            get(images::private_image_reference_file),
        )
        .route(
            "/api/image-tasks",
            get(images::list_active_image_tasks).delete(images::clear_failed_image_tasks),
        )
        .route(
            "/api/image-tasks/{id}/retry",
            post(images::retry_image_task),
        )
        .route(
            "/api/image-tasks/{ids}",
            get(images::get_image_tasks).delete(images::delete_failed_image_task),
        )
        .route(
            "/api/image-tasks/{id}/references/{index}",
            get(images::private_task_reference_file),
        )
        .route("/api/gallery", get(images::public_gallery))
        .route("/public/images/{id}", get(images::public_image_file))
        .route(
            "/public/images/{id}/thumbnail",
            get(images::public_image_thumbnail),
        )
        .route("/api/admin/session", get(admin::session))
        .route("/api/admin/overview", get(admin::overview))
        .route("/api/admin/users", get(admin::list_users))
        .route(
            "/api/admin/users/credits/bulk",
            post(admin::bulk_set_credits),
        )
        .route(
            "/api/admin/users/{id}",
            get(admin::get_user).put(admin::update_user),
        )
        .route("/api/admin/users/{id}/credits", post(admin::adjust_credits))
        .route("/api/admin/credit-ledger", get(admin::list_credit_ledger))
        .route("/api/admin/usage-logs", get(admin::list_usage_logs))
        .route("/api/admin/ip-location", get(admin::ip_location))
        .route("/api/admin/images/{id}/file", get(admin::image_file))
        .route(
            "/api/admin/settings",
            get(admin::get_settings).put(admin::update_settings),
        )
        .route(
            "/api/admin/api-keys/revoke-legacy",
            post(admin::revoke_legacy_api_keys),
        )
        .route(
            "/api/admin/providers",
            get(admin::list_providers).post(admin::create_provider),
        )
        .route(
            "/api/admin/providers/{id}/activate",
            put(admin::activate_provider),
        )
        .route("/api/admin/providers/{id}", delete(admin::delete_provider))
        .route("/api/admin/announcements", post(admin::create_announcement))
        .route(
            "/api/admin/announcements/{id}",
            put(admin::update_announcement).delete(admin::delete_announcement),
        )
        .route("/api/{*path}", any(account::api_not_found))
        .layer(middleware::from_fn(request::require_first_party_request));
    let external_routes = Router::new()
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
        .route("/v1/account/usage", get(account::external_usage));
    let limited_routes = api_routes
        .merge(external_routes)
        .layer(GovernorLayer::new(Arc::new(write_rate)).error_handler(request::rate_limit_response))
        .layer(
            GovernorLayer::new(Arc::new(global_rate)).error_handler(request::rate_limit_response),
        );
    let app = Router::new()
        .route("/healthz", get(account::liveness))
        .route("/api/health", get(account::health))
        .route("/metrics", get(observability::metrics))
        .merge(limited_routes)
        .fallback_service(static_service)
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(middleware::from_fn(request::observe_request))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "Lumora API started");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
