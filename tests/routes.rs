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
    for path in ["/email/search", "/email/get", "/email/send"] {
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
