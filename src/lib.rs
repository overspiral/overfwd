//! overfwd — REST -> IMAP/SMTP bridge (v0 HTTP scaffold).
//!
//! The library exposes [`create_app`], which builds the axum [`Router`]. Keeping this
//! in the library (rather than `main.rs`) lets integration tests exercise the real
//! router over HTTP.

pub mod config;
pub mod error;
pub mod routes;

use std::sync::Arc;

use axum::Router;
use tower_http::trace::TraceLayer;

pub use config::Config;

/// Shared application state, cloned into every request via axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

/// Build the application router with all routes and middleware layered on.
pub fn create_app(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
    };

    Router::new()
        .merge(routes::health::router())
        .merge(routes::hello::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
