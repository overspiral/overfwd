//! overfwd binary entrypoint (SPEC §4 Gateway).
//!
//! Loads [`overfwd::Config`] from the environment, builds the app router, and
//! serves it. Everything of substance lives in the library crate so it can be
//! unit- and integration-tested.

use std::process::ExitCode;

use overfwd::Config;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "overfwd=info,tower_http=info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(%err, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    let bind = config.bind;
    // Debug on Config redacts the api_key (see config.rs), so this is safe to log.
    tracing::info!(?config, "starting overfwd");

    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(%err, %bind, "failed to bind");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(%bind, "overfwd listening");
    if let Err(err) = axum::serve(listener, overfwd::app(config)).await {
        tracing::error!(%err, "server error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
