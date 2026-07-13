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

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use utoipa::PartialSchema;

use crate::auth::{InlineHeaders, MailboxCredential};
use crate::error::GatewayError;
use crate::routes::{do_get, do_search, do_send, GetRequest, SearchRequest};
use crate::send::SendRequest;
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
/// body, not via HTTP status.
pub(crate) async fn mcp_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(value) = match body {
        Ok(json) => json,
        Err(err) => {
            let resp = error_response(
                Value::Null,
                PARSE_ERROR,
                format!("parse error: {err}"),
                None,
            );
            return Json(resp).into_response();
        }
    };

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

/// Handle one JSON-RPC message. Returns `None` for notifications (no `id`) and for
/// messages we cannot parse that lack an `id` — both of which get no response.
async fn handle_one(state: &AppState, headers: &HeaderMap, value: Value) -> Option<RpcResponse> {
    let request: RpcRequest = match serde_json::from_value(value.clone()) {
        Ok(req) => req,
        Err(err) => {
            // Only answer if the client supplied an id; a malformed notification is
            // silently dropped (JSON-RPC notifications never get a response).
            let id = value.get("id").cloned()?;
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
                "description": "Search a mailbox folder via IMAP using a raw IMAP SEARCH \
                    key (e.g. \"ALL\", \"UNSEEN\", \"SUBJECT \\\"hi\\\"\"). Returns \
                    newest-first message summaries, clamped to `limit`.",
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
                    mailbox. Returns the To/From/Subject and a clamped body preview.",
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
            Ok(req) => tool_response(id, do_send(&credential, req).await),
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
        .into_credential(&state.autoconfig)
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
