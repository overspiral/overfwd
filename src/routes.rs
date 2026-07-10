//! The v1 REST facade (SPEC §6).
//!
//! Registers the three v1 actions and wraps them in the Axis-1 gateway-access
//! middleware. `send` is live over SMTP; the read actions (`search`/`get`) are
//! still stubs returning [`GatewayError::NotImplemented`] (HTTP 501) until the IMAP
//! action task fills them in.
//!
//! | Route                | Action   | Class | SPEC |
//! |----------------------|----------|-------|------|
//! | `POST /email/search` | `search` | read  | §6   |
//! | `POST /email/get`    | `get`    | read  | §6   |
//! | `POST /email/send`   | `send`   | write | §6   |

use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::{require_gateway_access, MailboxCredential};
use crate::error::GatewayError;
use crate::send::{SendDisclosure, SendRequest, SendResponse};
use crate::smtp::{submit, SmtpSettings};
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

/// `POST /email/send` — build a message and submit it over SMTP (write; SPEC §4/§6).
///
/// Parses the Inline mailbox credential from the `X-Mailbox-*` headers and the
/// message from the JSON body, submits via [`crate::smtp::submit`], and returns the
/// To/From/Subject + clamped-Body disclosure. Provider failures surface as the
/// typed `auth_failure` / `host_unreachable` / `tls_failure` codes (SPEC §7).
///
/// **Redaction (SPEC §6):** the `X-Mailbox-Auth` `Basic` header is never echoed
/// into the response, the audit log, or an error — the password is a [`Secret`] and
/// every logged/returned field is drawn from the non-secret disclosure.
///
/// [`Secret`]: crate::auth::Secret
async fn send(
    headers: HeaderMap,
    body: Result<Json<SendRequest>, JsonRejection>,
) -> Result<Json<SendResponse>, GatewayError> {
    let credential = MailboxCredential::from_headers(&headers)?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    let message = request.into_message()?;
    let disclosure = SendDisclosure::for_message(&message);

    let security = SmtpSettings::from_env().security_for(&credential.smtp);
    submit(
        &credential.smtp,
        &credential.username,
        &credential.password,
        security,
        &message,
    )
    .await?;

    // Audit (SPEC §6): To/From/Subject only. The `X-Mailbox-Auth` Basic header and
    // the mailbox password never reach a log line — the password is a `Secret` and
    // we log only the non-secret disclosure fields.
    tracing::info!(
        from = %disclosure.from,
        to = ?disclosure.to,
        subject = %disclosure.subject,
        "send accepted by provider",
    );

    Ok(Json(SendResponse::accepted(disclosure)))
}
