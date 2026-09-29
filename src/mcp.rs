//! MCP server surface: the three v1 actions as JSON-RPC 2.0 tools (SPEC §5/§6).
//!
//! This exposes `search`/`get`/`send` to Model Context Protocol clients over a single
//! `POST /mcp` endpoint, so an agent can consume the gateway as an MCP server. It is a
//! **consumption surface** over the existing REST actions — not agent orchestration
//! (SPEC non-goals) — and reuses the exact same business logic ([`crate::routes::do_search`]
//! / [`do_get`](crate::routes::do_get) / [`do_send`](crate::routes::do_send)) and the
//! same two auth axes as the REST facade, so there is zero behavioral drift.
//!
//! ## Transport
//!
//! MCP Streamable HTTP in **stateless JSON mode**: every call is a self-contained POST
//! that returns `application/json` (never SSE), and no `Mcp-Session-Id` is issued. This
//! matches overfwd's stateless, no-creds-at-rest posture — each POST re-parses the
//! Axis-2 headers, does the work, and forgets everything.
//!
//! ## The two auth axes (SPEC §5), unchanged
//!
//! - **Axis 1 — gateway access:** `POST /mcp` sits behind the same
//!   [`require_gateway_access`](crate::auth::require_gateway_access) gate as `/email`,
//!   so a configured gateway carries `Authorization: Bearer <api_key>` on every POST.
//! - **Axis 2 — mailbox credential:** each `tools/call` reads the `X-Mailbox-*` headers
//!   from its POST and resolves them via the same
//!   [`InlineHeaders::parse`](crate::auth::InlineHeaders::parse) →
//!   [`into_credential`](crate::auth::InlineHeaders::into_credential) path. The
//!   `initialize` / `tools/list` / `ping` methods do not touch a mailbox, so a client
//!   may probe them without mailbox headers.
//!
//! ## Method coverage
//!
//! A tools-only server: `initialize`, `notifications/initialized` (a notification — no
//! response), `ping`, `tools/list`, `tools/call`. `resources/*`, `prompts/*`,
//! `completion/*`, and `logging/*` are intentionally unimplemented — spec-legal since
//! the `initialize` result advertises only the `tools` capability.
//!
//! ## Body size
//!
//! `email_send` can carry inline attachments, so `POST /mcp` accepts the same raised
//! body limit as `POST /email/send` ([`crate::routes::send_body_limit`], 16 MiB by
//! default). Every tool shares the one endpoint, so the transport cannot tell a
//! `send` from a `search` before reading the body. The trade-off: any caller past the
//! Axis-1 gate can make the gateway buffer up to that limit, and only *after*
//! parsing is a payload over the ordinary 2 MiB refused unless it consists solely of
//! `email_send` calls. Every other tool stays bounded in what it will *act on*, but
//! not in what the endpoint will read. The limit tracks `OVERFWD_MAX_ATTACHMENT_BYTES`,
//! so a deployment that sets it to `0` (no attachments) brings `/mcp` back to ~2.7 MiB.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use utoipa::PartialSchema;

use crate::auth::{InlineHeaders, MailboxCredential};
use crate::error::GatewayError;
use crate::routes::{do_get, do_search, do_send, GetRequest, SearchRequest, DEFAULT_BODY_LIMIT};
use crate::send::{AttachmentLimits, SendRequest};
use crate::AppState;

/// The MCP protocol revision this server implements. Bump alongside
/// [`SUPPORTED_VERSIONS`] when tracking a new spec revision.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol revisions we accept during `initialize` negotiation. When the client asks
/// for one of these we echo it back; otherwise we answer with [`MCP_PROTOCOL_VERSION`]
/// and let the client decide whether to proceed.
const SUPPORTED_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

// JSON-RPC 2.0 standard error codes (https://www.jsonrpc.org/specification#error_object).
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// A single JSON-RPC 2.0 request (or notification, when `id` is absent). `params` is
/// kept as a raw [`Value`] so each method parses its own arguments lazily.
#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// A single JSON-RPC 2.0 response. Exactly one of `result`/`error` is populated.
#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Serialize)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// `tools/call` params: the tool `name` and its `arguments` object.
#[derive(Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default = "empty_object")]
    arguments: Value,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

fn ok_response(id: Value, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn error_response(
    id: Value,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
            data,
        }),
    }
}

/// `POST /mcp` — the MCP JSON-RPC 2.0 endpoint (SPEC §6).
///
/// Accepts a single request object or a batch array. Returns `application/json` with a
/// single response, an array of responses, or — when the payload carried only
/// notifications — `202 Accepted` with an empty body. A malformed body is reported as a
/// JSON-RPC `-32700` parse error (HTTP 200), since JSON-RPC transports errors in the
/// body, not via HTTP status. The exception is an oversized body, which gets HTTP
/// `413` (carrying a JSON-RPC `-32600` body): it is a transport limit, not a message
/// the server read — see the module docs on body size.
pub(crate) async fn mcp_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let bytes = match body {
        Ok(bytes) => bytes,
        Err(err) if err.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return too_large(format!("request body too large: {}", err.body_text()));
        }
        Err(err) => return parse_error(format!("parse error: {err}")),
    };
    if !is_json_content_type(&headers) {
        return parse_error(
            "parse error: expected a request with `Content-Type: application/json`".to_string(),
        );
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(err) => return parse_error(format!("parse error: {err}")),
    };
    if bytes.len() > DEFAULT_BODY_LIMIT && !is_send_only(&value) {
        return too_large(format!(
            "request body too large: only `email_send` calls may exceed {DEFAULT_BODY_LIMIT} bytes"
        ));
    }
    drop(bytes);

    match value {
        Value::Array(items) => {
            if items.is_empty() {
                let resp = error_response(
                    Value::Null,
                    INVALID_REQUEST,
                    "invalid request: empty batch",
                    None,
                );
                return Json(resp).into_response();
            }
            let mut responses = Vec::new();
            for item in items {
                if let Some(resp) = handle_one(&state, &headers, item).await {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                // A batch of only notifications gets no response body.
                StatusCode::ACCEPTED.into_response()
            } else {
                Json(responses).into_response()
            }
        }
        Value::Object(_) => match handle_one(&state, &headers, value).await {
            Some(resp) => Json(resp).into_response(),
            None => StatusCode::ACCEPTED.into_response(),
        },
        _ => {
            let resp = error_response(
                Value::Null,
                INVALID_REQUEST,
                "invalid request: expected a JSON-RPC object or batch array",
                None,
            );
            Json(resp).into_response()
        }
    }
}

fn parse_error(message: String) -> Response {
    Json(error_response(Value::Null, PARSE_ERROR, message, None)).into_response()
}

fn too_large(message: String) -> Response {
    let resp = error_response(Value::Null, INVALID_REQUEST, message, None);
    (StatusCode::PAYLOAD_TOO_LARGE, Json(resp)).into_response()
}

/// Whether the request declares a JSON body: `application/json` or an
/// `application/*+json` type, parameters (`; charset=utf-8`) allowed — the rule
/// axum's own `Json` extractor applies.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

/// Whether a payload is nothing but `email_send` tool calls — the one tool allowed a
/// body past [`DEFAULT_BODY_LIMIT`], because it is the one that carries attachments.
fn is_send_only(value: &Value) -> bool {
    let is_send_call = |item: &Value| {
        item.get("method").and_then(Value::as_str) == Some("tools/call")
            && item.pointer("/params/name").and_then(Value::as_str) == Some("email_send")
    };
    match value {
        Value::Array(items) => !items.is_empty() && items.iter().all(is_send_call),
        item => is_send_call(item),
    }
}

/// Handle one JSON-RPC message. Returns `None` for notifications (no `id`) and for
/// messages we cannot parse that lack an `id` — both of which get no response.
async fn handle_one(state: &AppState, headers: &HeaderMap, value: Value) -> Option<RpcResponse> {
    // Only the id is copied out up front — the message itself is moved into the
    // parse, so an `email_send` carrying megabytes of attachments is never cloned.
    let id = value.get("id").cloned();
    let request: RpcRequest = match serde_json::from_value(value) {
        Ok(req) => req,
        Err(err) => {
            // Only answer if the client supplied an id; a malformed notification is
            // silently dropped (JSON-RPC notifications never get a response).
            let id = id?;
            return Some(error_response(
                id,
                INVALID_REQUEST,
                format!("invalid request: {err}"),
                None,
            ));
        }
    };

    if request.jsonrpc != "2.0" {
        return request
            .id
            .map(|id| error_response(id, INVALID_REQUEST, "jsonrpc must be \"2.0\"", None));
    }

    match request.method.as_str() {
        "initialize" => request
            .id
            .map(|id| ok_response(id, initialize_result(request.params.as_ref()))),
        "ping" => request.id.map(|id| ok_response(id, json!({}))),
        "tools/list" => request.id.map(|id| ok_response(id, tools_list())),
        "tools/call" => match request.id {
            // A `tools/call` without an id is malformed (a call must be answerable).
            Some(id) => Some(tools_call(state, headers, request.params, id).await),
            None => None,
        },
        // Notifications (e.g. `notifications/initialized`) get no response.
        method if method.starts_with("notifications/") => None,
        other => request.id.map(|id| {
            error_response(
                id,
                METHOD_NOT_FOUND,
                format!("method not found: {other}"),
                None,
            )
        }),
    }
}

/// The `initialize` result: advertise the tools capability and negotiate the protocol
/// version (echo the client's when supported, else our latest).
fn initialize_result(params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str());
    let protocol = match requested {
        Some(v) if SUPPORTED_VERSIONS.contains(&v) => v,
        _ => MCP_PROTOCOL_VERSION,
    };
    json!({
        "protocolVersion": protocol,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "overfwd",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

/// The `tools/list` result. Each tool's `inputSchema` is the JSON Schema utoipa already
/// derives for the REST request type, so the MCP schema cannot drift from what the
/// action actually accepts.
fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "email_search",
                "description": "Search a mailbox folder via IMAP. Filter with the \
                    structured params — `from`, `subject`, `text` (headers and body), \
                    `since` (\"2025-07-01\") — which are ANDed together and quoted for \
                    you: {\"from\": \"John Smith\"} works as written. For anything they \
                    don't cover, `query` takes a raw IMAP SEARCH key instead (e.g. \
                    \"UNSEEN\", \"OR SEEN FLAGGED\"); it cannot be combined with them. \
                    With no filter, searches everything. Returns \
                    {\"results\": [...newest-first summaries...], \"total\": <matches \
                    before the limit>, \"truncated\": <bool>}. `limit` defaults to 10 \
                    and is capped at 50, so a large mailbox is always cut: when \
                    `truncated` is true, `results` is only the newest slice of `total` \
                    matches — narrow the search or page by UID rather than assuming you \
                    have seen everything.",
                "inputSchema": input_schema::<SearchRequest>(),
                "annotations": { "readOnlyHint": true },
            },
            {
                "name": "email_get",
                "description": "Fetch one message by its mailbox-unique `uid` (from a \
                    prior email_search): headers plus decoded text/html body.",
                "inputSchema": input_schema::<GetRequest>(),
                "annotations": { "readOnlyHint": true },
            },
            {
                "name": "email_send",
                "description": "Build a message and submit it over the caller's SMTP \
                    mailbox. Files go in `attachments` as \
                    [{\"filename\", \"content_type\", \"content_base64\"}] — at most 20, \
                    10 MiB decoded in total by default. Returns the To/From/Subject, a \
                    clamped body preview, and each attachment's filename and size.",
                "inputSchema": input_schema::<SendRequest>(),
                "annotations": { "readOnlyHint": false },
            },
        ]
    })
}

/// Serialize a utoipa-derived schema into an MCP `inputSchema` (a JSON Schema object).
fn input_schema<T: PartialSchema>() -> Value {
    serde_json::to_value(T::schema()).expect("utoipa schema serializes to JSON")
}

/// Dispatch a `tools/call`: resolve the mailbox credential, deserialize the arguments,
/// and run the same business core as the REST handler.
///
/// Protocol-level problems (missing/invalid mailbox headers, unknown tool, or
/// un-deserializable arguments) surface as a JSON-RPC `-32602` error. Provider-side
/// failures from the action itself surface as a `CallToolResult` with `isError: true`
/// (the JSON-RPC call still succeeds) — the MCP-idiomatic way to report a tool error an
/// agent can reason about.
async fn tools_call(
    state: &AppState,
    headers: &HeaderMap,
    params: Option<Value>,
    id: Value,
) -> RpcResponse {
    let credential = match resolve_credential(state, headers).await {
        Ok(cred) => cred,
        Err(err) => return gateway_protocol_error(id, &err),
    };

    let params = match params {
        Some(p) => p,
        None => return error_response(id, INVALID_PARAMS, "missing params for tools/call", None),
    };
    let call: ToolCallParams = match serde_json::from_value(params) {
        Ok(call) => call,
        Err(err) => {
            return error_response(id, INVALID_PARAMS, format!("invalid params: {err}"), None)
        }
    };

    match call.name.as_str() {
        "email_search" => match parse_arguments::<SearchRequest>(&call.name, call.arguments) {
            Ok(req) => tool_response(id, do_search(&credential, req).await),
            Err(resp) => error_response(id, INVALID_PARAMS, resp, None),
        },
        "email_get" => match parse_arguments::<GetRequest>(&call.name, call.arguments) {
            Ok(req) => tool_response(id, do_get(&credential, req).await),
            Err(resp) => error_response(id, INVALID_PARAMS, resp, None),
        },
        "email_send" => match parse_arguments::<SendRequest>(&call.name, call.arguments) {
            Ok(req) => {
                let limits =
                    AttachmentLimits::with_max_total_bytes(state.config.max_attachment_bytes);
                tool_response(id, do_send(&credential, req, &limits).await)
            }
            Err(resp) => error_response(id, INVALID_PARAMS, resp, None),
        },
        other => error_response(id, INVALID_PARAMS, format!("unknown tool: {other}"), None),
    }
}

/// Resolve the Axis-2 mailbox credential from this POST's headers — the exact path the
/// REST handlers use.
async fn resolve_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<MailboxCredential, GatewayError> {
    InlineHeaders::parse(headers)?
        .into_credential(&state.autoconfig, &state.endpoints)
        .await
}

fn parse_arguments<T: serde::de::DeserializeOwned>(
    tool: &str,
    arguments: Value,
) -> Result<T, String> {
    serde_json::from_value(arguments).map_err(|err| format!("invalid arguments for {tool}: {err}"))
}

/// Wrap a business-core `Result` into a JSON-RPC success whose result is a
/// `CallToolResult` — successful payload as text content, or `isError: true` carrying
/// the stable `{ code, message }` envelope on a provider failure.
fn tool_response<T: Serialize>(id: Value, outcome: Result<T, GatewayError>) -> RpcResponse {
    match outcome {
        Ok(value) => {
            let payload = serde_json::to_value(&value).unwrap_or(Value::Null);
            ok_response(id, tool_success(payload))
        }
        Err(err) => ok_response(id, tool_error(&err)),
    }
}

fn tool_success(payload: Value) -> Value {
    json!({
        "content": [ { "type": "text", "text": payload.to_string() } ],
        "isError": false,
    })
}

fn tool_error(err: &GatewayError) -> Value {
    // Reuse the gateway's stable wire body. `message()` never carries the `Basic`
    // value or the mailbox password (SPEC §6), so no secret can leak here.
    let body = json!({ "code": err.code(), "message": err.message() });
    json!({
        "content": [ { "type": "text", "text": body.to_string() } ],
        "isError": true,
    })
}

/// Map a credential-resolution [`GatewayError`] onto a JSON-RPC `-32602` (it is an
/// argument/credential problem detected before the tool ran), carrying the stable code
/// in `data` for machine consumption.
fn gateway_protocol_error(id: Value, err: &GatewayError) -> RpcResponse {
    error_response(
        id,
        INVALID_PARAMS,
        err.message().to_string(),
        Some(json!({ "code": err.code() })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_input_schema_documents_attachments_inline() {
        let schema = input_schema::<SendRequest>();
        let attachments = &schema["properties"]["attachments"];
        assert_eq!(attachments["type"], "array", "{attachments}");
        let item = &attachments["items"];
        assert!(
            !schema.to_string().contains("$ref"),
            "the MCP inputSchema must be self-contained: {schema}"
        );
        for field in ["filename", "content_type", "content_base64"] {
            assert!(item["properties"][field].is_object(), "{field}: {item}");
        }
        let required: Vec<&str> = item["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(required, ["filename", "content_type", "content_base64"]);
    }

    #[test]
    fn only_pure_send_payloads_count_as_send_only() {
        let send =
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"email_send"}});
        let search =
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"email_search"}});
        assert!(is_send_only(&send));
        assert!(is_send_only(&json!([send.clone(), send.clone()])));
        assert!(!is_send_only(&search));
        assert!(!is_send_only(&json!([send, search])));
        assert!(!is_send_only(&json!([])));
        assert!(!is_send_only(&json!({"method":"initialize"})));
    }
}
