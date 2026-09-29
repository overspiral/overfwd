//! Integration tests for the HTTP spine (SPEC §5–7).
//!
//! Drives the router in-process with `tower::ServiceExt::oneshot` — no live mail
//! and no bound socket needed. All three actions are live, so the non-ignored tests
//! here exercise the request-validation paths that are rejected *before* any IMAP or
//! SMTP connection is attempted (missing credential, malformed body, missing field);
//! the live happy paths live in the `#[ignore]`d GreenMail tests (this file's `send`
//! test plus `tests/routes_e2e.rs` for the reads).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use overfwd::auth::{H_MAILBOX_AUTH, H_MAILBOX_IMAP, H_MAILBOX_SMTP};
use overfwd::{app, Config};
use tower::ServiceExt;

fn config(require_api_key: bool, api_key: Option<&str>) -> Config {
    Config {
        bind: "0.0.0.0:8000".parse().unwrap(),
        require_api_key,
        api_key: api_key.map(|k| overfwd::auth::Secret::new(k.to_string())),
        enable_mcp: true,
        block_private_endpoints: false,
        max_attachment_bytes: overfwd::config::DEFAULT_MAX_ATTACHMENT_BYTES,
    }
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn post(path: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn json_post(path: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn unknown_route_is_404() {
    let response = app(config(false, None))
        .oneshot(post("/email/nope"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Read routes: request validation (rejected before any IMAP connection) -------

/// A read route with no mailbox headers is rejected with a typed `bad_request`
/// before any IMAP connection is attempted (SPEC §5 Axis 2, §7). This exercises the
/// wiring without needing a live mail server.
#[tokio::test]
async fn read_routes_without_mailbox_headers_are_bad_request() {
    // `/email/search` — all body fields default, so it is the credential that is
    // missing; `/email/get` additionally requires a `uid` in the body.
    let cases = [
        ("/email/search", json_post("/email/search", "{}")),
        ("/email/get", json_post("/email/get", r#"{"uid":1}"#)),
    ];
    for (name, request) in cases {
        let response = app(config(false, None)).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(body_json(response).await["code"], "bad_request", "{name}");
    }
}

/// A malformed JSON body yields the gateway's typed `bad_request`, not axum's
/// untyped `Json` rejection (SPEC §7). Mailbox headers are present so the failure is
/// unambiguously the body, not the credential.
#[tokio::test]
async fn invalid_json_body_is_typed_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from("not json"))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

/// A `query` that is not an IMAP SEARCH key is refused with a typed `bad_request`
/// before any IMAP connection is attempted — the caller must be able to tell "your
/// syntax was wrong" from "nothing matched" (SPEC §7).
#[tokio::test]
async fn search_with_bare_word_criteria_is_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"query":"John Smith"}"#))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = body_json(response).await;
    assert_eq!(body["code"], "bad_request");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains(r#"FROM "John Smith""#),
        "message should name the fix, got: {message}"
    );
}

/// A raw `query` combined with the structured params is refused before any IMAP call:
/// silently honouring one half would leave the caller unable to tell which filter ran.
#[tokio::test]
async fn search_with_query_and_structured_params_is_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"query":"UNSEEN","from":"John Smith"}"#))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = body_json(response).await;
    assert_eq!(body["code"], "bad_request");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("`query`") && message.contains("from"),
        "message should name both halves of the conflict, got: {message}"
    );
}

/// An unparseable `since` is caught here rather than becoming an opaque server
/// rejection — the caller gets the two accepted date formats named.
#[tokio::test]
async fn search_with_unparseable_since_is_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"since":"last week"}"#))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = body_json(response).await;
    assert_eq!(body["code"], "bad_request");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("2025-07-01") && message.contains("1-Jul-2025"),
        "message should name both accepted formats, got: {message}"
    );
}

/// `/email/get` without the required `uid` is a typed `bad_request` (SPEC §6, §7),
/// even when a valid mailbox credential is present — no IMAP call is attempted.
#[tokio::test]
async fn get_without_uid_is_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/get")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

// --- Axis-1 gateway-access gate (SPEC §5) ---------------------------------------

#[tokio::test]
async fn api_key_not_enforced_when_toggle_off() {
    // require_api_key=false → the gate is a no-op. With no mailbox headers the
    // request reaches the handler and is rejected there for the *credential*
    // (bad_request), proving the gate did not reject it (which would be 401).
    let response = app(config(false, None))
        .oneshot(post("/email/search"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn api_key_enforced_rejects_missing_bearer() {
    let response = app(config(true, Some("the-key")))
        .oneshot(post("/email/search"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["code"], "unauthorized");
}

#[tokio::test]
async fn api_key_enforced_rejects_wrong_bearer() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header("Authorization", "Bearer wrong-key")
        .body(Body::empty())
        .unwrap();
    let response = app(config(true, Some("the-key")))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_enforced_accepts_correct_bearer() {
    // Correct key → passes the Axis-1 gate. With no mailbox headers the handler then
    // rejects for the missing credential (bad_request) — a 400 (not 401) proves the
    // gate accepted the key, without opening a live IMAP connection.
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header("Authorization", "Bearer the-key")
        .body(Body::empty())
        .unwrap();
    let response = app(config(true, Some("the-key")))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

// --- Send route: request validation (rejected before submit) --------------------

/// A `POST /email/send` carrying valid Inline mailbox headers and the given JSON
/// body. The SMTP target points at a dead port so any test that *reaches* the
/// network fails fast — but every test below is designed to be rejected during
/// request validation, before `submit` is ever called.
fn send_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/email/send")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0") // test:test
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn send_without_mailbox_headers_is_bad_request() {
    // No X-Mailbox-* headers → credential parsing fails before anything else.
    let request = Request::builder()
        .method("POST")
        .uri("/email/send")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"from":"a@x","to":["b@y"],"subject":"s","text":"t"}"#,
        ))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn send_without_a_body_field_is_bad_request() {
    // Neither `text` nor `html` → rejected before submit.
    let response = app(config(false, None))
        .oneshot(send_request(r#"{"from":"a@x","to":["b@y"],"subject":"s"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn send_with_no_recipients_is_bad_request() {
    let response = app(config(false, None))
        .oneshot(send_request(
            r#"{"from":"a@x","to":[],"subject":"s","text":"t"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn send_accepts_a_comma_separated_recipient_string() {
    // `to` as a bare string parses (the failure below is about the *body*, not the
    // recipients), so a caller need not wrap a single address in an array.
    let response = app(config(false, None))
        .oneshot(send_request(
            r#"{"from":"a@x","to":"b@y, c@z","subject":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(json["code"], "bad_request");
    let message = json["message"].as_str().unwrap();
    assert!(
        message.contains("body"),
        "expected the body-required error, got: {message}"
    );
}

#[tokio::test]
async fn send_with_an_empty_recipient_string_is_bad_request() {
    let response = app(config(false, None))
        .oneshot(send_request(
            r#"{"from":"a@x","to":"  ","subject":"s","text":"t"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn send_with_malformed_json_is_bad_request() {
    let response = app(config(false, None))
        .oneshot(send_request("this is not json"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

// --- Body limits -------------------------------------------------------------------

const MIB: usize = 1024 * 1024;

/// A `send` body of roughly `size` bytes that parses but is rejected in validation
/// (`to` is empty), so a test can tell "the transport accepted it" (400 about
/// recipients) from "the transport refused it" (413) without any SMTP traffic.
fn padded_send_body(size: usize) -> String {
    format!(
        r#"{{"from":"a@x","to":[],"subject":"s","text":"{}"}}"#,
        "a".repeat(size)
    )
}

fn send_request_owned(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/email/send")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn send_accepts_bodies_between_the_default_and_send_limits() {
    for size in [3 * MIB, 15 * MIB] {
        let response = app(config(false, None))
            .oneshot(send_request_owned(padded_send_body(size)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "size {size}");
        let json = body_json(response).await;
        let message = json["message"].as_str().unwrap();
        assert!(
            message.contains("recipient"),
            "a {size}-byte body should reach validation, got: {message}"
        );
    }
}

#[tokio::test]
async fn send_accepts_a_full_default_attachment_allowance() {
    // 10 MiB decoded = ~13.3 MiB of base64: must fit the transport limit.
    let content = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 10 * MIB]);
    let body = format!(
        r#"{{"from":"a@x","to":[],"subject":"s","text":"t","attachments":[{{"filename":"f.bin","content_type":"application/octet-stream","content_base64":"{content}"}}]}}"#
    );
    let response = app(config(false, None))
        .oneshot(send_request_owned(body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert!(
        json["message"].as_str().unwrap().contains("recipient"),
        "{json}"
    );
}

#[tokio::test]
async fn send_over_the_body_limit_is_413() {
    let response = app(config(false, None))
        .oneshot(send_request_owned(padded_send_body(17 * MIB)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(response).await["code"], "payload_too_large");
}

#[tokio::test]
async fn the_send_limit_grows_with_the_attachment_cap() {
    let big = Config {
        max_attachment_bytes: 20 * MIB,
        ..config(false, None)
    };
    let response = app(big)
        .oneshot(send_request_owned(padded_send_body(17 * MIB)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn other_routes_keep_the_default_body_limit() {
    let body = format!(r#"{{"query":"{}"}}"#, "a".repeat(3 * MIB));
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(response).await["code"], "payload_too_large");
}

/// End-to-end happy path for `POST /email/send` against the shared GreenMail stack.
///
/// `#[ignore]`d like the other GreenMail tests (CI does not boot the mail server):
///
/// ```sh
/// make mail-up
/// cargo test --test routes -- --ignored
/// ```
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn send_delivers_and_discloses_without_leaking_the_credential() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/send")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0") // test:test
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"from":"test@localhost","to":["alice@localhost"],"bcc":["blind@localhost"],"subject":"routed send","text":"through the send route"}"#,
        ))
        .unwrap();

    let response = app(config(false, None)).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["sent"], true);
    assert_eq!(json["disclosure"]["from"], "test@localhost");
    assert_eq!(json["disclosure"]["to"][0], "alice@localhost");
    assert_eq!(json["disclosure"]["subject"], "routed send");
    assert_eq!(json["disclosure"]["body_preview"], "through the send route");

    // Redaction (SPEC §6): neither the Basic value nor the blind recipient may
    // appear anywhere in the disclosed response.
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

/// `POST /email/send` with an inline attachment against the shared GreenMail stack:
/// the JSON wire shape decodes, submits, and discloses name + size but not content.
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn send_with_an_attachment_discloses_name_and_size_only() {
    let content = base64::engine::general_purpose::STANDARD.encode(b"ATTACHMENT-CONTENT");
    let body = format!(
        r#"{{"from":"test@localhost","to":"alice@localhost","subject":"routed attachment","text":"see attached","attachments":[{{"filename":"../notes.txt","content_type":"text/plain","content_base64":"{content}"}}]}}"#
    );
    let response = app(config(false, None))
        .oneshot(send_request_owned(body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(
        json["disclosure"]["attachments"],
        serde_json::json!([{ "filename": "..notes.txt", "size_bytes": 18 }])
    );
    let rendered = json.to_string();
    assert!(!rendered.contains("ATTACHMENT-CONTENT"), "{rendered}");
    assert!(!rendered.contains(&content), "{rendered}");
}
