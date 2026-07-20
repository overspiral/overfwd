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
