//! Root greeting endpoint — a simple sign of life for humans hitting `/`.

use axum::{Json, Router, routing::get};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
struct Greeting {
    name: &'static str,
    version: &'static str,
    message: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(hello))
}

async fn hello() -> Json<Greeting> {
    Json(Greeting {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        message: "overfwd — REST -> IMAP/SMTP bridge",
    })
}
