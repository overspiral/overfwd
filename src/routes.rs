//! The v1 REST facade (SPEC §6).
//!
//! Registers the three v1 actions and wraps them in the Axis-1 gateway-access
//! middleware. All three are live: `search`/`get` translate to IMAP against the
//! caller's mailbox ([`crate::imap`]); `send` builds a message and submits it over
//! SMTP ([`crate::smtp`]).
//!
//! | Route                | Action   | Class | SPEC |
//! |----------------------|----------|-------|------|
//! | `POST /email/search` | `search` | read  | §6   |
//! | `POST /email/get`    | `get`    | read  | §6   |
//! | `POST /email/send`   | `send`   | write | §6   |
//!
//! **Reads are ordinary, auto-approvable reads** (SPEC §6): there is no per-fetch
//! approval gate — the only consent boundary is whether the caller holds a valid
//! mailbox credential at all, enforced by [`MailboxCredential::from_headers`]. Each
//! read translates its request schema into the IMAP primitives:
//! - `search` → SELECT + (UID) SEARCH + a light BODY.PEEK FETCH per hit, returning
//!   [`MessageSummary`] rows.
//! - `get` → SELECT + a single BODY.PEEK FETCH, parsed into a [`FullMessage`].

use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::{require_gateway_access, MailboxCredential};
use crate::error::GatewayError;
use crate::imap::{self, FullMessage, ImapSettings, MessageSummary};
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

/// Request schema for `POST /email/search` (SPEC §6).
///
/// `query` is a raw IMAP SEARCH key (`ALL`, `UNSEEN`, `SUBJECT "hi"`, …); it is the
/// caller's responsibility to form a valid key. `criteria` is accepted as an alias.
/// An absent `query` defaults to `ALL`. `folder` defaults to the mailbox's `INBOX`.
#[derive(Debug, Deserialize)]
struct SearchRequest {
    /// Mailbox to search; defaults to [`imap::DEFAULT_MAILBOX`] (`INBOX`).
    #[serde(default)]
    folder: Option<String>,
    /// Raw IMAP SEARCH key. Defaults to `ALL`; also accepted as `criteria`.
    #[serde(default = "default_search_query", alias = "criteria")]
    query: String,
    /// Cap on the number of summaries returned (newest first). `None` = no cap.
    #[serde(default)]
    limit: Option<usize>,
}

fn default_search_query() -> String {
    "ALL".to_string()
}

/// `POST /email/search` — search a mailbox (read, SPEC §6).
///
/// Translates to IMAP SELECT + SEARCH + a light FETCH, returning newest-first
/// [`MessageSummary`] rows clamped to `limit`. Missing mailbox headers, a malformed
/// body, and provider failures all surface as typed [`GatewayError`]s (SPEC §7).
async fn search(
    headers: HeaderMap,
    body: Result<Json<SearchRequest>, JsonRejection>,
) -> Result<Json<Vec<MessageSummary>>, GatewayError> {
    let credential = MailboxCredential::from_headers(&headers)?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    let settings = ImapSettings::from_env();
    let folder = request.folder.as_deref().unwrap_or(imap::DEFAULT_MAILBOX);
    let mut summaries = imap::search(&credential, &settings, folder, &request.query).await?;

    // The IMAP layer returns ascending UID (newest-last) and leaves ordering to us
    // (SPEC §4). Present newest-first, then clamp — so `limit` keeps the newest N.
    summaries.reverse();
    if let Some(limit) = request.limit {
        summaries.truncate(limit);
    }

    Ok(Json(summaries))
}

/// Request schema for `POST /email/get` (SPEC §6). `uid` is required.
#[derive(Debug, Deserialize)]
struct GetRequest {
    /// Mailbox holding the message; defaults to [`imap::DEFAULT_MAILBOX`] (`INBOX`).
    #[serde(default)]
    folder: Option<String>,
    /// The mailbox-unique id of the message to fetch (from a prior `search`).
    uid: u32,
}

/// `POST /email/get` — fetch one message (read, SPEC §6).
///
/// Translates to IMAP SELECT + a single FETCH, parsed into a [`FullMessage`]
/// (headers + text/html body). A `uid` with no matching message maps to
/// [`GatewayError::NotFound`] by the IMAP layer.
async fn get(
    headers: HeaderMap,
    body: Result<Json<GetRequest>, JsonRejection>,
) -> Result<Json<FullMessage>, GatewayError> {
    let credential = MailboxCredential::from_headers(&headers)?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    let settings = ImapSettings::from_env();
    let folder = request.folder.as_deref().unwrap_or(imap::DEFAULT_MAILBOX);
    let message = imap::get(&credential, &settings, folder, request.uid).await?;

    Ok(Json(message))
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
