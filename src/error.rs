//! Application error type shared by handlers.
//!
//! v0 only carries an `Internal` variant, but this establishes the pattern the bridge
//! handlers will extend (per-status variants mapping to JSON error bodies).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Convenience alias so handlers can return `Result<T>`.
pub type Result<T> = std::result::Result<T, AppError>;

/// Errors returned from request handlers.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// An unexpected, unrecoverable error. Rendered as HTTP 500.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Log the full error; only surface a generic message for 5xx.
        if status.is_server_error() {
            tracing::error!(error = ?self, "request failed");
        }
        let message = if status.is_server_error() {
            "internal server error".to_string()
        } else {
            self.to_string()
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
