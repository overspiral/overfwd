//! Integration tests for the MCP endpoint (`POST /mcp`, SPEC §5/§6).
//!
//! Drives the router in-process with `tower::ServiceExt::oneshot` — no live mail and no
//! bound socket. The non-ignored tests exercise the JSON-RPC protocol surface and the
//! request-validation paths that are rejected *before* any IMAP/SMTP connection (missing
//! credential, unknown tool, malformed arguments); the live happy path lives in the
//! `#[ignore]`d GreenMail test at the bottom.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use overfwd::auth::{H_MAILBOX_AUTH, H_MAILBOX_IMAP, H_MAILBOX_SMTP};
use overfwd::{app, Config};
use serde_json::json;
use tower::ServiceExt;

fn config(require_api_key: bool, api_key: Option<&str>) -> Config {
    Config {
        bind: "0.0.0.0:8000".parse().unwrap(),
        require_api_key,
        api_key: api_key.map(|k| overfwd::auth::Secret::new(k.to_string())),
        enable_mcp: true,
    }
}

fn config_mcp_disabled() -> Config {
    Config {
        enable_mcp: false,
        ..config(false, None)
    }
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// A `POST /mcp` carrying the given JSON-RPC body and no mailbox headers.
fn rpc(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A `POST /mcp` with a valid Inline mailbox credential and both host headers present
/// (so credential resolution takes the fast path — no autoconfig, no network).
fn rpc_with_mailbox(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0") // test:test
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// --- Protocol handshake ----------------------------------------------------------

#[tokio::test]
async fn initialize_advertises_tools_capability() {
    let request = rpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {} }
    }));
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 1);
    assert_eq!(json["result"]["protocolVersion"], "2025-06-18");
    assert!(json["result"]["capabilities"]["tools"].is_object());
    assert_eq!(json["result"]["serverInfo"]["name"], "overfwd");
}

/// A client asking for an older supported revision gets it echoed back.
#[tokio::test]
async fn initialize_negotiates_a_supported_older_version() {
    let request = rpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2024-11-05" }
    }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["result"]["protocolVersion"], "2024-11-05");
}

/// An unknown requested version falls back to our latest.
#[tokio::test]
async fn initialize_falls_back_on_unknown_version() {
    let request = rpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "1999-01-01" }
    }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["result"]["protocolVersion"], "2025-06-18");
}

/// A notification (no `id`) gets no response body: HTTP 202, empty.
#[tokio::test]
async fn initialized_notification_gets_no_response() {
    let request = rpc(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn ping_returns_empty_result() {
    let request = rpc(json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["id"], 7);
    assert_eq!(json["result"], json!({}));
}

// --- tools/list ------------------------------------------------------------------

#[tokio::test]
async fn tools_list_exposes_the_three_actions_with_real_schemas() {
    let request = rpc(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;

    let tools = json["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["email_search", "email_get", "email_send"]);

    for tool in tools {
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "tool {}",
            tool["name"]
        );
    }

    // The schema is the utoipa-derived one: `email_get.uid` is required.
    let get = tools.iter().find(|t| t["name"] == "email_get").unwrap();
    let required = get["inputSchema"]["required"].as_array().unwrap();
    assert!(
        required.iter().any(|v| v == "uid"),
        "email_get schema should require uid: {get}"
    );

    // Read/write class is surfaced as an annotation.
    let send = tools.iter().find(|t| t["name"] == "email_send").unwrap();
    assert_eq!(send["annotations"]["readOnlyHint"], false);
    let search = tools.iter().find(|t| t["name"] == "email_search").unwrap();
    assert_eq!(search["annotations"]["readOnlyHint"], true);
}

// --- tools/call protocol errors (rejected before any IMAP/SMTP connection) -------

/// A `tools/call` with no mailbox headers fails credential resolution → `-32602`,
/// carrying the stable gateway code in `data`.
#[tokio::test]
async fn tools_call_without_mailbox_headers_is_invalid_params() {
    let request = rpc(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": "email_search", "arguments": {} }
    }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["data"]["code"], "bad_request");
}

#[tokio::test]
async fn tools_call_unknown_tool_is_invalid_params() {
    let request = rpc_with_mailbox(json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": { "name": "email_delete", "arguments": {} }
    }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["error"]["code"], -32602);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("email_delete"));
}

#[tokio::test]
async fn tools_call_malformed_arguments_is_invalid_params() {
    // uid must be an integer; a string fails deserialization before any IMAP call.
    let request = rpc_with_mailbox(json!({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": { "name": "email_get", "arguments": { "uid": "not-a-number" } }
    }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["error"]["code"], -32602);
}

// --- JSON-RPC envelope errors ----------------------------------------------------

#[tokio::test]
async fn unknown_method_is_method_not_found() {
    let request = rpc(json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/list" }));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["error"]["code"], -32601);
}

#[tokio::test]
async fn non_json_body_is_parse_error() {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Content-Type", "application/json")
        .body(Body::from("this is not json"))
        .unwrap();
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    assert_eq!(json["error"]["code"], -32700);
    assert_eq!(json["id"], serde_json::Value::Null);
}

#[tokio::test]
async fn batch_returns_one_response_per_request() {
    let request = rpc(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping" }
    ]));
    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;
    let responses = json.as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["result"], json!({}));
}

#[tokio::test]
async fn batch_of_only_notifications_gets_no_body() {
    let request = rpc(json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized" },
        { "jsonrpc": "2.0", "method": "notifications/cancelled" }
    ]));
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(body_bytes(response).await.is_empty());
}

// --- Axis-1 gateway-access gate (SPEC §5) ----------------------------------------

#[tokio::test]
async fn mcp_requires_bearer_when_api_key_enforced() {
    let request = rpc(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }));
    let response = app(config(true, Some("the-key")))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["code"], "unauthorized");
}

#[tokio::test]
async fn mcp_accepts_correct_bearer() {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Authorization", "Bearer the-key")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }).to_string(),
        ))
        .unwrap();
    let response = app(config(true, Some("the-key")))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["result"]["serverInfo"]["name"],
        "overfwd"
    );
}

#[tokio::test]
async fn mcp_endpoint_absent_when_disabled() {
    let request = rpc(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }));
    let response = app(config_mcp_disabled()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- GreenMail end-to-end --------------------------------------------------------

/// End-to-end `tools/call email_send` against the shared GreenMail stack, asserting the
/// tool succeeds and the credential is not leaked. `#[ignore]`d like the other GreenMail
/// tests (CI does not boot the mail server):
///
/// ```sh
/// make mail-up
/// cargo test --test mcp -- --ignored
/// ```
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn tools_call_email_send_delivers_without_leaking_the_credential() {
    let request = rpc_with_mailbox(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "email_send",
            "arguments": {
                "from": "test@localhost",
                "to": ["alice@localhost"],
                "bcc": ["blind@localhost"],
                "subject": "mcp send",
                "text": "sent through the mcp tool"
            }
        }
    }));

    let json = body_json(app(config(false, None)).oneshot(request).await.unwrap()).await;

    let result = &json["result"];
    assert_eq!(result["isError"], false);

    // The tool's text content carries the same SendResponse the REST route returns.
    let text = result["content"][0]["text"].as_str().unwrap();
    let disclosed: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(disclosed["sent"], true);
    assert_eq!(disclosed["disclosure"]["from"], "test@localhost");
    assert_eq!(disclosed["disclosure"]["subject"], "mcp send");

    // Redaction (SPEC §6): neither the Basic value nor the blind recipient may appear.
    let rendered = json.to_string();
    assert!(
        !rendered.contains("dGVzdDp0ZXN0"),
        "auth header leaked: {rendered}"
    );
    assert!(
        !rendered.contains("blind@localhost"),
        "bcc leaked: {rendered}"
    );
}
