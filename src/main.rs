//! Binary entrypoint: load `.env`, init tracing, read config, and serve with graceful shutdown.

use anyhow::Context;
use overfwd::{Config, create_app};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load `.env` if present; real env vars still win over file values.
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env().context("failed to load configuration")?;
    let addr = format!("{}:{}", config.host, config.port);

    let app = create_app(config);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    tracing::info!("Listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("Shutdown complete");
    Ok(())
}

/// Initialize the tracing subscriber. Honors `RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Resolve once Ctrl-C is received, triggering axum's graceful shutdown.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %err, "failed to listen for shutdown signal");
        return;
    }
    tracing::info!("Received Ctrl-C, shutting down");
}
