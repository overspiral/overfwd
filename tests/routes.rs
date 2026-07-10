//! Integration tests for the HTTP spine (SPEC §5–7).
//!
//! Drives the router in-process with `tower::ServiceExt::oneshot` — no live mail
//! and no bound socket needed.

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

#[tokio::test]
async fn stub_routes_return_501_with_typed_error() {
    // `send` is live now; only the read actions remain stubs.
    for path in ["/email/search", "/email/get"] {
        let response = app(config(false, None)).oneshot(post(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        let json = body_json(response).await;
        assert_eq!(json["code"], "not_implemented", "{path}");
        assert!(json["message"].is_string(), "{path}");
    }
}

#[tokio::test]
async fn unknown_route_is_404() {
    let response = app(config(false, None))
        .oneshot(post("/email/nope"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_key_not_enforced_when_toggle_off() {
    // No Authorization header, require_api_key=false → passes gate, reaches 501 stub.
    let response = app(config(false, None))
        .oneshot(post("/email/search"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
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
async fn send_with_malformed_json_is_bad_request() {
    let response = app(config(false, None))
        .oneshot(send_request("this is not json"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}

#[tokio::test]
async fn api_key_enforced_accepts_correct_bearer() {
    // Correct key → passes the Axis-1 gate; then hits the not-yet-implemented stub.
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header("Authorization", "Bearer the-key")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0")
        .header(H_MAILBOX_IMAP, "localhost:3143")
        .header(H_MAILBOX_SMTP, "localhost:3025")
        .body(Body::empty())
        .unwrap();
    let response = app(config(true, Some("the-key")))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
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
