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
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::auth::{require_gateway_access, InlineHeaders, MailboxCredential};
use crate::error::{ErrorResponse, GatewayError};
use crate::imap::{self, FullMessage, ImapSettings, MessageSummary};
use crate::send::{SendDisclosure, SendRequest, SendResponse};
use crate::smtp::{submit, SmtpSettings};
use crate::AppState;

/// Build the application router for the given shared state (SPEC §6).
///
/// The `/email` actions sit behind the Axis-1 gateway-access gate; the OpenAPI docs
/// ([`crate::openapi::openapi_router`]) are merged **outside** that gate so
/// `/openapi.json` and `/docs` are reachable without a gateway key (SPEC §5).
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

    let mut router = Router::new().nest("/email", email);

    // The MCP endpoint exposes the same three actions as JSON-RPC 2.0 tools, behind the
    // same Axis-1 gate as `/email` (SPEC §5). Off when `OVERFWD_ENABLE_MCP=false`.
    if state.config.enable_mcp {
        let mcp = Router::new()
            .route("/mcp", post(crate::mcp::mcp_endpoint))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_gateway_access,
            ));
        router = router.merge(mcp);
    }

    router
        .with_state(state)
        .merge(crate::openapi::openapi_router())
}

/// Request schema for `POST /email/search` (SPEC §6).
///
/// `query` is a raw IMAP SEARCH key (`ALL`, `UNSEEN`, `SUBJECT "hi"`, …); a bare
/// phrase like `John Smith` is rejected up front with a `bad_request` naming the fix —
/// see [`SearchRequest::validated_query`]. `criteria` is accepted as an alias.
/// A `query` that is absent, `null`, or blank means `ALL`. `folder` defaults to the
/// mailbox's `INBOX`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct SearchRequest {
    /// Mailbox to search; defaults to [`imap::DEFAULT_MAILBOX`] (`INBOX`).
    #[serde(default)]
    #[schema(example = "INBOX")]
    folder: Option<String>,
    /// Raw IMAP SEARCH key, e.g. `UNSEEN` or `FROM "John Smith"`. Absent, `null`, or
    /// blank means `ALL`; also accepted as `criteria`.
    #[serde(default, alias = "criteria")]
    #[schema(example = "UNSEEN")]
    query: Option<String>,
    /// Cap on the number of summaries returned (newest first). `None` = no cap.
    #[serde(default)]
    #[schema(example = 20)]
    limit: Option<usize>,
}

/// The IMAP SEARCH key meaning "every message in the mailbox".
const ALL_SEARCH_QUERY: &str = "ALL";

/// The SEARCH keys of RFC 3501 §6.4.4 — every word that may legally *begin* a search
/// key. Used only to catch the common "caller typed a bare phrase" mistake; the
/// server remains the authority on the rest of the grammar.
const SEARCH_KEYS: &[&str] = &[
    "ALL",
    "ANSWERED",
    "BCC",
    "BEFORE",
    "BODY",
    "CC",
    "DELETED",
    "DRAFT",
    "FLAGGED",
    "FROM",
    "HEADER",
    "KEYWORD",
    "LARGER",
    "NEW",
    "NOT",
    "OLD",
    "OLDER",
    "ON",
    "OR",
    "RECENT",
    "SEEN",
    "SENTBEFORE",
    "SENTON",
    "SENTSINCE",
    "SINCE",
    "SMALLER",
    "SUBJECT",
    "TEXT",
    "TO",
    "UID",
    "UNANSWERED",
    "UNDELETED",
    "UNDRAFT",
    "UNFLAGGED",
    "UNKEYWORD",
    "UNSEEN",
    "YOUNGER",
];

impl SearchRequest {
    /// The SEARCH key to send. An absent, `null`, or blank `query` all say the same
    /// thing — the caller wants everything — so they normalize to `ALL` rather than
    /// reaching IMAP as an empty (invalid) key.
    ///
    /// A non-blank query must *start* like a search key, otherwise the caller gets a
    /// [`GatewayError::BadRequest`] naming the problem and the fix. Without this a
    /// bare phrase comes back as an empty result set, indistinguishable from "nothing
    /// matched". Only the leading token is checked: validating the whole grammar here
    /// would reject legitimate-but-exotic queries (unquoted `HEADER` arguments, server
    /// extension keys), and a deeper mistake still surfaces as a `bad_request` when the
    /// server rejects it (see `map_command_err` in [`crate::imap`]).
    fn validated_query(&self) -> Result<&str, GatewayError> {
        let query = match self.query.as_deref().map(str::trim) {
            Some(query) if !query.is_empty() => query,
            _ => return Ok(ALL_SEARCH_QUERY),
        };

        let head = query.split_whitespace().next().unwrap_or(query);
        let is_key = SEARCH_KEYS.contains(&head.to_ascii_uppercase().as_str());
        // A bare sequence set (`1:*`, `4,9`) is a valid key, and a parenthesized group
        // hands the inner key to the server.
        let is_sequence_set = head
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | ':' | '*'));
        if is_key || is_sequence_set || head.starts_with('(') {
            return Ok(query);
        }

        Err(GatewayError::BadRequest(format!(
            "invalid criteria: {query:?} — bare words are not IMAP SEARCH keys. \
             Did you mean FROM {query:?} or TEXT {query:?}?"
        )))
    }
}

/// `POST /email/search` — search a mailbox (read, SPEC §6).
///
/// Translates to IMAP SELECT + SEARCH + a light FETCH, returning newest-first
/// [`MessageSummary`] rows clamped to `limit`. Missing mailbox headers, a malformed
/// body, and provider failures all surface as typed [`GatewayError`]s (SPEC §7).
#[utoipa::path(
    post,
    path = "/email/search",
    tag = "email",
    request_body = SearchRequest,
    security(
        ("gateway_api_key" = []),
        ("mailbox_auth" = []),
        ("mailbox_imap" = []),
        ("mailbox_smtp" = []),
    ),
    responses(
        (status = 200, description = "Newest-first message summaries (clamped to `limit`).", body = Vec<MessageSummary>),
        (status = 400, description = "`bad_request` — missing/malformed mailbox headers or JSON body, or a `query` that is not a valid IMAP SEARCH key.", body = ErrorResponse),
        (status = 401, description = "`unauthorized` — missing/invalid gateway bearer key (Axis-1).", body = ErrorResponse),
        (status = 404, description = "`not_found` — the requested mailbox does not exist.", body = ErrorResponse),
        (status = 502, description = "`auth_failure` / `host_unreachable` / `tls_failure` — the mailbox provider rejected the credential or was unreachable.", body = ErrorResponse),
    ),
)]
pub(crate) async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<SearchRequest>, JsonRejection>,
) -> Result<Json<Vec<MessageSummary>>, GatewayError> {
    let credential = InlineHeaders::parse(&headers)?
        .into_credential(&state.autoconfig, &state.endpoints)
        .await?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    Ok(Json(do_search(&credential, request).await?))
}

/// The `search` action's business core, shared by the REST handler and the MCP tool
/// (`crate::mcp`). Takes an already-resolved [`MailboxCredential`] so the caller owns
/// credential resolution (done once per HTTP request).
pub(crate) async fn do_search(
    credential: &MailboxCredential,
    request: SearchRequest,
) -> Result<Vec<MessageSummary>, GatewayError> {
    let settings = ImapSettings::from_env();
    let folder = request.folder.as_deref().unwrap_or(imap::DEFAULT_MAILBOX);
    let mut summaries =
        imap::search(credential, &settings, folder, request.validated_query()?).await?;

    // The IMAP layer returns ascending UID (newest-last) and leaves ordering to us
    // (SPEC §4). Present newest-first, then clamp — so `limit` keeps the newest N.
    summaries.reverse();
    if let Some(limit) = request.limit {
        summaries.truncate(limit);
    }

    Ok(summaries)
}

/// Request schema for `POST /email/get` (SPEC §6). `uid` is required.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct GetRequest {
    /// Mailbox holding the message; defaults to [`imap::DEFAULT_MAILBOX`] (`INBOX`).
    #[serde(default)]
    #[schema(example = "INBOX")]
    folder: Option<String>,
    /// The mailbox-unique id of the message to fetch (from a prior `search`).
    #[schema(example = 42)]
    uid: u32,
}

/// `POST /email/get` — fetch one message (read, SPEC §6).
///
/// Translates to IMAP SELECT + a single FETCH, parsed into a [`FullMessage`]
/// (headers + text/html body). A `uid` with no matching message maps to
/// [`GatewayError::NotFound`] by the IMAP layer.
#[utoipa::path(
    post,
    path = "/email/get",
    tag = "email",
    request_body = GetRequest,
    security(
        ("gateway_api_key" = []),
        ("mailbox_auth" = []),
        ("mailbox_imap" = []),
        ("mailbox_smtp" = []),
    ),
    responses(
        (status = 200, description = "The full message: headers plus decoded text/html bodies.", body = FullMessage),
        (status = 400, description = "`bad_request` — missing/malformed mailbox headers or JSON body.", body = ErrorResponse),
        (status = 401, description = "`unauthorized` — missing/invalid gateway bearer key (Axis-1).", body = ErrorResponse),
        (status = 404, description = "`not_found` — no message with that `uid` (or the mailbox is missing).", body = ErrorResponse),
        (status = 502, description = "`auth_failure` / `host_unreachable` / `tls_failure` — the mailbox provider rejected the credential or was unreachable.", body = ErrorResponse),
    ),
)]
pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<GetRequest>, JsonRejection>,
) -> Result<Json<FullMessage>, GatewayError> {
    let credential = InlineHeaders::parse(&headers)?
        .into_credential(&state.autoconfig, &state.endpoints)
        .await?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    Ok(Json(do_get(&credential, request).await?))
}

/// The `get` action's business core, shared by the REST handler and the MCP tool.
pub(crate) async fn do_get(
    credential: &MailboxCredential,
    request: GetRequest,
) -> Result<FullMessage, GatewayError> {
    let settings = ImapSettings::from_env();
    let folder = request.folder.as_deref().unwrap_or(imap::DEFAULT_MAILBOX);
    imap::get(credential, &settings, folder, request.uid).await
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
#[utoipa::path(
    post,
    path = "/email/send",
    tag = "email",
    request_body = SendRequest,
    security(
        ("gateway_api_key" = []),
        ("mailbox_auth" = []),
        ("mailbox_imap" = []),
        ("mailbox_smtp" = []),
    ),
    responses(
        (status = 200, description = "Accepted by the provider; echoes the To/From/Subject/body-preview disclosure (SPEC §6).", body = SendResponse),
        (status = 400, description = "`bad_request` — missing/malformed mailbox headers, empty `to`, or no body.", body = ErrorResponse),
        (status = 401, description = "`unauthorized` — missing/invalid gateway bearer key (Axis-1).", body = ErrorResponse),
        (status = 502, description = "`auth_failure` / `host_unreachable` / `tls_failure` — the SMTP provider rejected the credential or was unreachable.", body = ErrorResponse),
    ),
)]
pub(crate) async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<SendRequest>, JsonRejection>,
) -> Result<Json<SendResponse>, GatewayError> {
    let credential = InlineHeaders::parse(&headers)?
        .into_credential(&state.autoconfig, &state.endpoints)
        .await?;
    let Json(request) =
        body.map_err(|err| GatewayError::BadRequest(format!("invalid JSON request body: {err}")))?;

    Ok(Json(do_send(&credential, request).await?))
}

/// The `send` action's business core, shared by the REST handler and the MCP tool.
///
/// Keeps the audit `tracing::info!` line (SPEC §6: To/From/Subject only) so both the
/// REST route and the MCP tool log identically. The `X-Mailbox-Auth` Basic header and
/// the mailbox password never reach a log line — the password is a `Secret` and only
/// the non-secret disclosure fields are logged.
pub(crate) async fn do_send(
    credential: &MailboxCredential,
    request: SendRequest,
) -> Result<SendResponse, GatewayError> {
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

    tracing::info!(
        from = %disclosure.from,
        to = ?disclosure.to,
        subject = %disclosure.subject,
        "send accepted by provider",
    );

    Ok(SendResponse::accepted(disclosure))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> SearchRequest {
        serde_json::from_str(body).expect("body should deserialize")
    }

    /// The query a body would send to IMAP, panicking if it is rejected.
    fn query_of(body: &str) -> String {
        parse(body)
            .validated_query()
            .unwrap_or_else(|e| panic!("body {body} should be accepted, got: {e}"))
            .to_string()
    }

    #[test]
    fn absent_null_and_blank_query_all_mean_all() {
        // The three ways a caller says "no filter" — a templated client emitting `""`
        // or `null` for an unset field must not reach IMAP as an empty SEARCH key.
        for body in [
            r#"{}"#,
            r#"{"query":null}"#,
            r#"{"query":""}"#,
            r#"{"query":"   "}"#,
        ] {
            assert_eq!(query_of(body), "ALL", "body: {body}");
        }
    }

    #[test]
    fn a_real_query_is_passed_through_trimmed() {
        assert_eq!(query_of(r#"{"query":"UNSEEN"}"#), "UNSEEN");
        assert_eq!(query_of(r#"{"query":"  UNSEEN  "}"#), "UNSEEN");
        assert_eq!(query_of(r#"{"query":"SUBJECT \"hi\""}"#), r#"SUBJECT "hi""#);
    }

    #[test]
    fn criteria_alias_still_works() {
        assert_eq!(query_of(r#"{"criteria":"UNSEEN"}"#), "UNSEEN");
        assert_eq!(query_of(r#"{"criteria":""}"#), "ALL");
    }

    #[test]
    fn valid_criteria_are_accepted() {
        // Keyword case is the server's business, sequence sets and parenthesized
        // groups are keys too, and only the leading token is inspected — so an
        // exotic-but-legal tail must not be rejected here.
        for query in [
            "UNSEEN",
            "unseen",
            r#"FROM "John Smith""#,
            r#"SUBJECT "hi""#,
            "1:* NOT DELETED",
            "(OR SEEN UNSEEN)",
            "HEADER X-Spam-Flag YES",
            "SINCE 1-Jul-2025",
        ] {
            let request = SearchRequest {
                folder: None,
                query: Some(query.to_string()),
                limit: None,
            };
            assert_eq!(
                request.validated_query().expect("should be accepted"),
                query
            );
        }
    }

    #[test]
    fn bare_words_are_rejected_with_a_fix_suggestion() {
        // The mistake this guards: a bare phrase is a legal-looking body that IMAP
        // answers with a rejection, which used to reach the caller as "no results".
        for body in [r#"{"query":"John Smith"}"#, r#"{"criteria":"John Smith"}"#] {
            let err = parse(body)
                .validated_query()
                .expect_err("bare words should be rejected");
            assert_eq!(err.code(), "bad_request", "body: {body}");
            let message = err.message();
            assert!(
                message.contains(r#""John Smith""#),
                "message should quote the offending criteria, got: {message}"
            );
            assert!(
                message.contains(r#"FROM "John Smith""#)
                    && message.contains(r#"TEXT "John Smith""#),
                "message should name the fix, got: {message}"
            );
        }
    }
}
