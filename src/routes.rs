//! The v1 REST facade (SPEC §6).
//!
//! Registers the three v1 actions and wraps them in the Axis-1 gateway-access
//! middleware. The handler bodies are stubs returning [`GatewayError::NotImplemented`]
//! (HTTP 501) until the IMAP/SMTP tasks fill them in.
//!
//! | Route                | Action   | Class | SPEC |
//! |----------------------|----------|-------|------|
//! | `POST /email/search` | `search` | read  | §6   |
//! | `POST /email/get`    | `get`    | read  | §6   |
//! | `POST /email/send`   | `send`   | write | §6   |

use axum::routing::post;
use axum::Router;

use crate::auth::require_gateway_access;
use crate::error::GatewayError;
use crate::AppState;

/// Build the application router for the given shared state (SPEC §6).
pub fn router(state: AppState) -> Router {
    let email = Router::new()
        .route("/search", post(search))
        .route("/get", post(get))
        .route("/send", post(send))
        // Axis-1 gateway-access gate wraps every /email route (SPEC §5).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_gateway_access,
        ));

    Router::new().nest("/email", email).with_state(state)
}

/// `POST /email/search` — search a mailbox (read). Stub (SPEC §6).
async fn search() -> GatewayError {
    GatewayError::NotImplemented("search is not implemented yet".to_string())
}

/// `POST /email/get` — fetch a message (read). Stub (SPEC §6).
async fn get() -> GatewayError {
    GatewayError::NotImplemented("get is not implemented yet".to_string())
}

/// `POST /email/send` — submit a message (write). Stub (SPEC §6).
async fn send() -> GatewayError {
    GatewayError::NotImplemented("send is not implemented yet".to_string())
}
