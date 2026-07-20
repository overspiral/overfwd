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
//! - `search` → SELECT + (UID) SEARCH + a light BODY.PEEK FETCH of the newest `limit`
//!   hits, returning a [`SearchResponse`] envelope of [`MessageSummary`] rows. Its
//!   filter comes either from the structured `from`/`subject`/`text`/`since` params,
//!   compiled and quoted here, or from a raw IMAP `query` — never both (see
//!   [`SearchRequest`]). `limit` defaults to [`DEFAULT_SEARCH_LIMIT`] and is capped at
//!   [`MAX_SEARCH_LIMIT`]; when more matched than fit, `truncated` says so rather than
//!   leaving the caller to guess.
//! - `get` → SELECT + a single BODY.PEEK FETCH, parsed into a [`FullMessage`].

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
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
/// There are **two filter modes**, and a request may use only one of them:
///
/// 1. **Structured** — `from` / `subject` / `text` / `since`. The gateway compiles them
///    into a correctly quoted IMAP SEARCH key, ANDed together. This is the mode a caller
///    who doesn't speak IMAP should reach for: `{"from": "John Smith"}` just works.
/// 2. **Raw** — `query` (alias `criteria`), an IMAP SEARCH key (`UNSEEN`,
///    `OR SEEN FLAGGED`, `HEADER X-Spam-Flag YES`, …) passed through after a light
///    sanity check ([`SearchRequest::validated_query`]). The escape hatch for the parts
///    of the grammar the structured params don't reach.
///
/// Supplying both is a [`GatewayError::BadRequest`] rather than a silent pick: the caller
/// must be able to tell which filter actually ran. Absent, `null`, and blank all mean
/// *unset* for every filter field, so a blank `query` beside a `from` is not a conflict,
/// and a request with no filter at all means `ALL`. `folder` defaults to `INBOX`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct SearchRequest {
    /// Mailbox to search; defaults to [`imap::DEFAULT_MAILBOX`] (`INBOX`).
    #[serde(default)]
    #[schema(example = "INBOX")]
    folder: Option<String>,
    /// Substring-match the `From` header, e.g. `John Smith` or `john@example.com`.
    /// Quoting and escaping are handled for you. Cannot be combined with `query`.
    #[serde(default)]
    #[schema(example = "John Smith")]
    from: Option<String>,
    /// Substring-match the `Subject` header. Cannot be combined with `query`.
    #[serde(default)]
    #[schema(example = "invoice")]
    subject: Option<String>,
    /// Substring-match anywhere in the message — headers *and* body (IMAP `TEXT`).
    /// Cannot be combined with `query`.
    #[serde(default)]
    #[schema(example = "lunch")]
    text: Option<String>,
    /// Only messages received on or after this date. Accepts `2025-07-01` or the IMAP
    /// form `1-Jul-2025`. Cannot be combined with `query`.
    #[serde(default)]
    #[schema(example = "2025-07-01")]
    since: Option<String>,
    /// Raw IMAP SEARCH key, e.g. `UNSEEN` or `FROM "John Smith"` — the escape hatch for
    /// the full grammar. Absent, `null`, or blank means `ALL`; also accepted as
    /// `criteria`. Cannot be combined with the structured params above.
    #[serde(default, alias = "criteria")]
    #[schema(example = "UNSEEN")]
    query: Option<String>,
    /// Cap on the number of summaries returned (newest first). Absent means
    /// [`DEFAULT_SEARCH_LIMIT`]; anything above [`MAX_SEARCH_LIMIT`] is clamped to it.
    /// `0` is honoured literally — it returns no rows, only the `total`.
    #[serde(default)]
    #[schema(example = 10, minimum = 0)]
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

/// How many summaries a caller gets when it does not ask for a `limit`.
///
/// A default at all (rather than "everything") matters because every returned row costs
/// a full `BODY.PEEK[]` fetch and parse against the provider — an unbounded search is an
/// unbounded round-trip.
pub const DEFAULT_SEARCH_LIMIT: usize = 10;

/// The ceiling on `limit`, whatever the caller asks for.
///
/// An over-cap `limit` is clamped rather than rejected: a caller passing a large number
/// means "give me lots", and failing that request helps no one. The clamp is never
/// silent — [`SearchResponse::truncated`] reports it on the wire.
pub const MAX_SEARCH_LIMIT: usize = 50;

/// Month names in the IMAP `date-text` form (RFC 3501 §9), indexed by month - 1.
const IMAP_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Wrap `value` as an IMAP quoted string (RFC 3501 §4.3): `\` and `"` are the only two
/// characters that need escaping inside one.
///
/// Non-ASCII is emitted as raw UTF-8. The grammar formally wants a `CHARSET` clause or a
/// literal for that, but every server we target (GreenMail, Dovecot, Gmail) matches raw
/// UTF-8 in a quoted string, while an unsupported `CHARSET` key is answered with a flat
/// `BAD` — best-effort beats reliably broken. CR/LF are rejected by [`structured_value`]
/// before reaching here, so no escaping decision can smuggle one through.
fn quote_imap(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if c == '\\' || c == '"' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// A structured param's value, trimmed, or `None` if it is absent/blank (same "unset"
/// rule the raw `query` uses).
///
/// A control character is refused outright: a bare CR/LF inside a quoted string would
/// end the IMAP command line and let a caller-supplied value inject a second command
/// into the session's protocol stream.
fn structured_value<'a>(
    field: &str,
    value: Option<&'a String>,
) -> Result<Option<&'a str>, GatewayError> {
    let value = match value.map(|v| v.trim()) {
        Some(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };

    if value.chars().any(char::is_control) {
        return Err(GatewayError::BadRequest(format!(
            "invalid `{field}`: control characters are not allowed in a search value"
        )));
    }

    Ok(Some(value))
}

/// Normalize a caller's date to the IMAP `d-Mmm-yyyy` form (RFC 3501 §9).
///
/// Accepts ISO `2025-07-01` — what a caller naturally writes, and what an agent emits
/// from a date picker — and the IMAP form `1-Jul-2025` itself, so a caller who already
/// knows the protocol isn't forced back to the raw `query`. The day is *not* zero-padded.
fn imap_date(value: &str) -> Result<String, GatewayError> {
    let bad = || {
        GatewayError::BadRequest(format!(
            "invalid `since`: {value:?} — expected a date like \"2025-07-01\" or \"1-Jul-2025\""
        ))
    };

    let parts: Vec<&str> = value.split('-').collect();
    let [first, month, last] = parts[..] else {
        return Err(bad());
    };

    // ISO `YYYY-MM-DD` is distinguished from IMAP `d-Mmm-yyyy` by which end holds the
    // 4-digit year; the month is numeric in the first and alphabetic in the second.
    let (year, month, day) = if first.len() == 4 {
        let month = month.parse::<usize>().map_err(|_| bad())?;
        (first, month, last)
    } else {
        let month = IMAP_MONTHS
            .iter()
            .position(|m| m.eq_ignore_ascii_case(month))
            .ok_or_else(bad)?
            + 1;
        (last, month, first)
    };

    let day: u32 = day.parse().map_err(|_| bad())?;
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }

    Ok(format!("{day}-{}-{year}", IMAP_MONTHS[month - 1]))
}

impl SearchRequest {
    /// The SEARCH key this request compiles to — the single entry point [`do_search`] uses.
    ///
    /// Structured params and a raw `query` are mutually exclusive (see [`SearchRequest`]);
    /// supplying both is a `bad_request` rather than a silent choice, because whichever
    /// half we dropped would be invisible to the caller. With neither, the request means
    /// `ALL`.
    ///
    /// Structured params bypass [`Self::validated_query`]: that check exists to catch a
    /// caller hand-writing the grammar, and the key here is generated, not typed.
    fn search_key(&self) -> Result<String, GatewayError> {
        let structured: Vec<(&str, &str)> = [
            ("from", structured_value("from", self.from.as_ref())?),
            (
                "subject",
                structured_value("subject", self.subject.as_ref())?,
            ),
            ("text", structured_value("text", self.text.as_ref())?),
            ("since", structured_value("since", self.since.as_ref())?),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|value| (field, value)))
        .collect();

        let raw_query = match self.query.as_deref().map(str::trim) {
            Some(query) if !query.is_empty() => Some(query),
            _ => None,
        };

        if !structured.is_empty() {
            if raw_query.is_some() {
                let named = structured
                    .iter()
                    .map(|(field, _)| *field)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(GatewayError::BadRequest(format!(
                    "`query` cannot be combined with the structured params ({named}) — \
                     use one or the other. `query` takes the full IMAP SEARCH grammar; \
                     the structured params are ANDed together and quoted for you."
                )));
            }

            // Adjacent SEARCH keys are ANDed by IMAP. Emitted in declaration order so the
            // key is deterministic for a given request.
            let keys: Vec<String> = structured
                .iter()
                .map(|(field, value)| match *field {
                    "from" => Ok(format!("FROM {}", quote_imap(value))),
                    "subject" => Ok(format!("SUBJECT {}", quote_imap(value))),
                    "text" => Ok(format!("TEXT {}", quote_imap(value))),
                    _ => Ok(format!("SINCE {}", imap_date(value)?)),
                })
                .collect::<Result<_, GatewayError>>()?;
            return Ok(keys.join(" "));
        }

        self.validated_query().map(str::to_string)
    }

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

    /// How many summaries to actually fetch: the caller's `limit`, defaulted when
    /// absent and clamped to [`MAX_SEARCH_LIMIT`].
    fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .min(MAX_SEARCH_LIMIT)
    }
}

/// Response body for `POST /email/search` (SPEC §6).
///
/// An envelope rather than a bare array so truncation can never be silent: a caller
/// holding 10 rows can tell "that was everything" from "there were 400 and you have the
/// newest 10". The same shape reaches MCP agents, which have no response headers to read
/// (see [`crate::mcp`]).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SearchResponse {
    /// Newest-first summaries, at most the effective `limit` of them.
    results: Vec<MessageSummary>,
    /// How many messages the IMAP SEARCH matched, before `limit` was applied.
    #[schema(example = 137)]
    total: usize,
    /// `true` when more messages matched than `results` carries — the list was cut.
    #[schema(example = true)]
    truncated: bool,
}

impl SearchResponse {
    /// Wrap what the IMAP layer fetched, deriving `truncated` from the pre-limit match
    /// count. The single home of that rule — [`do_search`] and its tests both come
    /// through here, so a test cannot pass by re-implementing the comparison.
    fn from_results(found: imap::SearchResults) -> Self {
        SearchResponse {
            truncated: found.total > found.summaries.len(),
            total: found.total,
            results: found.summaries,
        }
    }
}

/// `POST /email/search` — search a mailbox (read, SPEC §6).
///
/// Translates to IMAP SELECT + SEARCH + a light FETCH of the newest `limit` matches,
/// returning a [`SearchResponse`] envelope: newest-first [`MessageSummary`] rows plus
/// the pre-limit `total` and a `truncated` flag. Missing mailbox headers, a malformed
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
        (status = 200, description = "Newest-first message summaries (clamped to `limit`, default 10, max 50), with the pre-limit `total` and a `truncated` flag.", body = SearchResponse),
        (status = 400, description = "`bad_request` — missing/malformed mailbox headers or JSON body, a `query` that is not a valid IMAP SEARCH key, an unparseable `since`, or a `query` combined with the structured params.", body = ErrorResponse),
        (status = 401, description = "`unauthorized` — missing/invalid gateway bearer key (Axis-1).", body = ErrorResponse),
        (status = 404, description = "`not_found` — the requested mailbox does not exist.", body = ErrorResponse),
        (status = 502, description = "`auth_failure` / `host_unreachable` / `tls_failure` — the mailbox provider rejected the credential or was unreachable.", body = ErrorResponse),
    ),
)]
pub(crate) async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<SearchRequest>, JsonRejection>,
) -> Result<Json<SearchResponse>, GatewayError> {
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
) -> Result<SearchResponse, GatewayError> {
    let settings = ImapSettings::from_env();
    let folder = request.folder.as_deref().unwrap_or(imap::DEFAULT_MAILBOX);

    // The IMAP layer applies the limit to the fetch itself and hands back newest-first
    // summaries plus the pre-limit match count, so the clamp costs no extra round-trip.
    let found = imap::search(
        credential,
        &settings,
        folder,
        &request.search_key()?,
        request.effective_limit(),
    )
    .await?;

    Ok(SearchResponse::from_results(found))
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

    /// The SEARCH key a body compiles to, panicking if it is rejected.
    fn query_of(body: &str) -> String {
        parse(body)
            .search_key()
            .unwrap_or_else(|e| panic!("body {body} should be accepted, got: {e}"))
    }

    /// The error a body is rejected with, panicking if it is accepted.
    fn error_of(body: &str) -> GatewayError {
        parse(body)
            .search_key()
            .expect_err(&format!("body {body} should be rejected"))
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
            let body = serde_json::json!({ "query": query }).to_string();
            assert_eq!(query_of(&body), query);
        }
    }

    #[test]
    fn bare_words_are_rejected_with_a_fix_suggestion() {
        // The mistake this guards: a bare phrase is a legal-looking body that IMAP
        // answers with a rejection, which used to reach the caller as "no results".
        for body in [r#"{"query":"John Smith"}"#, r#"{"criteria":"John Smith"}"#] {
            let err = error_of(body);
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

    #[test]
    fn default_limit_applies_when_absent() {
        // No `limit` must not mean "every match": each row is a full BODY.PEEK[] fetch.
        for body in [r#"{}"#, r#"{"query":"UNSEEN"}"#, r#"{"limit":null}"#] {
            assert_eq!(
                parse(body).effective_limit(),
                DEFAULT_SEARCH_LIMIT,
                "body: {body}"
            );
        }
    }

    #[test]
    fn each_structured_param_compiles_to_its_key() {
        // The motivating case: `{"from": "John Smith"}` is what a caller reaches for,
        // and it must become the quoted key they would otherwise have had to write.
        assert_eq!(query_of(r#"{"from":"John Smith"}"#), r#"FROM "John Smith""#);
        assert_eq!(query_of(r#"{"subject":"invoice"}"#), r#"SUBJECT "invoice""#);
        assert_eq!(query_of(r#"{"text":"lunch"}"#), r#"TEXT "lunch""#);
    }

    #[test]
    fn since_accepts_iso_and_imap_dates() {
        // Both spellings land on the IMAP form, day unpadded: an agent emitting an ISO
        // date and a caller who already knows the protocol get the same search.
        for body in [r#"{"since":"2025-07-01"}"#, r#"{"since":"1-Jul-2025"}"#] {
            assert_eq!(query_of(body), "SINCE 1-Jul-2025", "body: {body}");
        }
        assert_eq!(query_of(r#"{"since":"2025-12-25"}"#), "SINCE 25-Dec-2025");
        // Month case is ours to normalize, not the caller's to get right.
        assert_eq!(query_of(r#"{"since":"9-mar-2024"}"#), "SINCE 9-Mar-2024");
    }

    #[test]
    fn structured_params_are_anded_in_declaration_order() {
        // Adjacent keys are IMAP's AND. Order is fixed so the emitted key is stable for
        // a given request regardless of JSON field order.
        assert_eq!(
            query_of(r#"{"since":"2025-07-01","text":"c","subject":"b","from":"a"}"#),
            r#"FROM "a" SUBJECT "b" TEXT "c" SINCE 1-Jul-2025"#
        );
        assert_eq!(
            query_of(r#"{"from":"John Smith","since":"2025-07-01"}"#),
            r#"FROM "John Smith" SINCE 1-Jul-2025"#
        );
    }

    #[test]
    fn values_are_quoted_and_escaped() {
        // Spaces are the whole reason quoting exists; an embedded quote or backslash
        // would otherwise terminate the string and corrupt the command.
        assert_eq!(query_of(r#"{"from":"John Smith"}"#), r#"FROM "John Smith""#);
        assert_eq!(
            query_of(r#"{"subject":"say \"hi\" now"}"#),
            r#"SUBJECT "say \"hi\" now""#
        );
        assert_eq!(
            query_of(r#"{"text":"back\\slash"}"#),
            r#"TEXT "back\\slash""#
        );
        // Non-ASCII travels as raw UTF-8 — no CHARSET clause, no mangling.
        assert_eq!(
            query_of(r#"{"from":"Ángel Martín"}"#),
            r#"FROM "Ángel Martín""#
        );
    }

    #[test]
    fn control_characters_in_a_value_are_rejected() {
        // A bare CRLF inside a quoted string ends the command line: without this the
        // value could inject a second IMAP command into the session.
        for body in [
            r#"{"from":"a\r\nLOGOUT"}"#,
            r#"{"subject":"a\nb"}"#,
            r#"{"text":"a\tb"}"#,
        ] {
            let err = error_of(body);
            assert_eq!(err.code(), "bad_request", "body: {body}");
            assert!(
                err.message().contains("control characters"),
                "message should name the problem, got: {}",
                err.message()
            );
        }
    }

    #[test]
    fn explicit_limit_under_cap_is_honoured() {
        assert_eq!(parse(r#"{"limit":5}"#).effective_limit(), 5);
        // The cap itself is allowed — the boundary is inclusive.
        let at_cap = format!(r#"{{"limit":{MAX_SEARCH_LIMIT}}}"#);
        assert_eq!(parse(&at_cap).effective_limit(), MAX_SEARCH_LIMIT);
        // Zero is a literal request for no rows (a "just give me the total" probe),
        // not a stand-in for "unset".
        assert_eq!(parse(r#"{"limit":0}"#).effective_limit(), 0);
    }

    #[test]
    fn explicit_limit_over_cap_clamps() {
        let over_cap = format!(r#"{{"limit":{}}}"#, MAX_SEARCH_LIMIT + 1);
        assert_eq!(parse(&over_cap).effective_limit(), MAX_SEARCH_LIMIT);
        assert_eq!(
            parse(r#"{"limit":500}"#).effective_limit(),
            MAX_SEARCH_LIMIT
        );
        assert_eq!(
            parse(r#"{"limit":18446744073709551615}"#).effective_limit(),
            MAX_SEARCH_LIMIT
        );
    }

    /// A stub summary; only `uid` matters for the envelope's shape.
    fn summary(uid: u32) -> MessageSummary {
        MessageSummary {
            uid,
            from: None,
            to: None,
            subject: None,
            date: None,
            snippet: None,
        }
    }

    /// Build the wire body the way `do_search` does — through the production
    /// [`SearchResponse::from_results`], so the truncation rule under test is the real
    /// one rather than a copy of it re-derived in the test.
    fn envelope(summaries: Vec<MessageSummary>, total: usize) -> serde_json::Value {
        let response = SearchResponse::from_results(imap::SearchResults { summaries, total });
        serde_json::to_value(&response).expect("envelope serialises")
    }

    #[test]
    fn truncation_marker_is_set_when_more_matched_than_returned() {
        // The whole point of the envelope: 2 rows out of 137 matches must say so.
        let json = envelope(vec![summary(9), summary(8)], 137);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["total"], 137);
        assert_eq!(
            json["results"].as_array().map(Vec::len),
            Some(2),
            "results must be an array under that exact key"
        );
        // The rows themselves survive the wrapping, newest-first as the IMAP layer left
        // them — an envelope that dropped or reordered them would still pass the
        // counts above.
        assert_eq!(json["results"][0]["uid"], 9);
        assert_eq!(json["results"][1]["uid"], 8);
    }

    #[test]
    fn truncation_marker_is_clear_when_everything_fit() {
        let json = envelope(vec![summary(2), summary(1)], 2);
        assert_eq!(json["truncated"], false);
        assert_eq!(json["total"], 2);

        // The empty search is not "truncated" either.
        let json = envelope(Vec::new(), 0);
        assert_eq!(json["truncated"], false);
        assert_eq!(json["total"], 0);
        assert_eq!(json["results"].as_array().map(Vec::len), Some(0));
    }

    /// The `limit == 0` probe is the one case where zero rows coexists with a non-zero
    /// total, so it must still be reported as truncated.
    #[test]
    fn zero_limit_probe_is_truncated_when_matches_exist() {
        let json = envelope(Vec::new(), 44);
        assert_eq!(json["total"], 44);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["results"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn blank_structured_params_mean_unset() {
        // Same "absent, null, or blank all mean unset" rule the raw query follows — a
        // templated client emitting "" must not produce `FROM ""`, which matches nothing.
        for body in [
            r#"{"from":""}"#,
            r#"{"from":null,"subject":"   "}"#,
            r#"{"from":"","subject":"","text":"","since":""}"#,
        ] {
            assert_eq!(query_of(body), "ALL", "body: {body}");
        }
        // …and a blank one alongside a real one simply drops out.
        assert_eq!(query_of(r#"{"from":"a","subject":""}"#), r#"FROM "a""#);
        assert_eq!(query_of(r#"{"from":"  a  "}"#), r#"FROM "a""#);
    }

    #[test]
    fn query_combined_with_structured_params_is_rejected() {
        // Picking one silently would leave the caller unable to tell which filter ran.
        for (body, expected_fields) in [
            (r#"{"query":"UNSEEN","from":"a"}"#, "from"),
            (r#"{"criteria":"UNSEEN","since":"2025-07-01"}"#, "since"),
            (r#"{"query":"UNSEEN","from":"a","text":"b"}"#, "from, text"),
        ] {
            let err = error_of(body);
            assert_eq!(err.code(), "bad_request", "body: {body}");
            let message = err.message();
            assert!(
                message.contains(expected_fields),
                "message should name the structured params ({expected_fields}), got: {message}"
            );
            assert!(
                message.contains("`query`"),
                "message should name the other half, got: {message}"
            );
        }
    }

    #[test]
    fn a_blank_query_beside_a_structured_param_is_not_a_conflict() {
        // A client that always sends the field, empty when unset, is not making a
        // choice — it has no query at all, so there is nothing to conflict with.
        for body in [
            r#"{"query":"","from":"John Smith"}"#,
            r#"{"query":null,"from":"John Smith"}"#,
            r#"{"criteria":"   ","from":"John Smith"}"#,
        ] {
            assert_eq!(query_of(body), r#"FROM "John Smith""#, "body: {body}");
        }
    }

    #[test]
    fn an_unparseable_since_is_rejected_naming_both_formats() {
        for body in [
            r#"{"since":"last week"}"#,
            r#"{"since":"2025-13-01"}"#,
            r#"{"since":"32-Jul-2025"}"#,
            r#"{"since":"2025-07-01T00:00:00Z"}"#,
            r#"{"since":"01/07/2025"}"#,
            r#"{"since":"1-Foo-2025"}"#,
            r#"{"since":"1-Jul-25"}"#,
        ] {
            let err = error_of(body);
            assert_eq!(err.code(), "bad_request", "body: {body}");
            let message = err.message();
            assert!(
                message.contains("2025-07-01") && message.contains("1-Jul-2025"),
                "message should name both accepted formats, got: {message}"
            );
        }
    }
}
