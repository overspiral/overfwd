//! End-to-end tests for the two `read` HTTP routes against the shared GreenMail
//! stack (SPEC §6). These drive the *whole* router — Axis-1 gate, header parsing,
//! request schema, IMAP translation, and JSON response — in-process via
//! `tower::ServiceExt::oneshot`, so they cover the wiring the unit tests can't.
//!
//! `#[ignore]`d so `cargo test` stays green without a mail server. Run them once
//! GreenMail is up:
//!
//! ```sh
//! make mail-up
//! cargo test --test routes_e2e -- --ignored
//! ```
//!
//! Like `imap_e2e`, each test `APPEND`s a message with a unique subject to `INBOX`
//! (via the IMAP primitives — SMTP is a separate task) so runs stay independent on
//! the shared, un-reset stack. The seeded account is `test:test` on plaintext IMAP
//! `3143`; plaintext keeps TLS config out of the picture.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use overfwd::auth::{
    HostPort, MailboxCredential, Secret, H_MAILBOX_AUTH, H_MAILBOX_IMAP, H_MAILBOX_SMTP,
};
use overfwd::imap::{connect, login, TlsMode, DEFAULT_MAILBOX};
use overfwd::{app, Config};
use tower::ServiceExt;

const HOST: &str = "localhost";
const IMAP_PORT: u16 = 3143;
const SMTP_PORT: u16 = 3025;

/// A require-api-key-off gateway config (Inline self-host posture, SPEC §10).
fn gateway_config() -> Config {
    Config {
        bind: "0.0.0.0:8000".parse().unwrap(),
        require_api_key: false,
        api_key: None,
        enable_mcp: true,
    }
}

fn cred() -> MailboxCredential {
    MailboxCredential {
        username: "test".to_string(),
        password: Secret::new("test".to_string()),
        imap: HostPort {
            host: HOST.to_string(),
            port: IMAP_PORT,
        },
        smtp: HostPort {
            host: HOST.to_string(),
            port: SMTP_PORT,
        },
    }
}

/// A distinct, greppable subject per test so runs don't collide on the shared stack.
fn unique_subject(tag: &str) -> String {
    format!("overfwd-routes-e2e-{tag}-{}", std::process::id())
}

fn sample_message(subject: &str) -> String {
    format!(
        "From: Alice Example <alice@example.com>\r\n\
To: test@localhost\r\n\
Subject: {subject}\r\n\
Date: Tue, 1 Jul 2025 09:30:00 +0000\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Body for {subject}: are you free for lunch tomorrow at noon?\r\n"
    )
}

/// APPEND a message straight to `INBOX` over IMAP (SMTP is a separate task).
async fn append_message(raw: &str) {
    let c = cred();
    let client = connect(&c.imap, TlsMode::for_port(c.imap.port), true)
        .await
        .expect("connect");
    let mut session = login(client, &c.username, c.password.expose())
        .await
        .expect("login");
    session
        .append(DEFAULT_MAILBOX, None, None, raw.as_bytes())
        .await
        .expect("append");
    let _ = session.logout().await;
}

/// The three Inline mailbox headers for the seeded `test` account (SPEC §5).
fn mailbox_headers(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    let basic = base64::engine::general_purpose::STANDARD.encode("test:test");
    builder
        .header(H_MAILBOX_AUTH, format!("Basic {basic}"))
        .header(H_MAILBOX_IMAP, format!("{HOST}:{IMAP_PORT}"))
        .header(H_MAILBOX_SMTP, format!("{HOST}:{SMTP_PORT}"))
}

fn read_request(path: &str, json: String) -> Request<Body> {
    mailbox_headers(
        Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json"),
    )
    .body(Body::from(json))
    .unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_then_get_round_trips_over_http() {
    // Rely on MAIL_TLS_INSECURE being irrelevant on plaintext 3143; the env is left
    // as-is (ImapSettings default is secure, unused for a plain connection).
    let subject = unique_subject("roundtrip");
    append_message(&sample_message(&subject)).await;

    // search: the SUBJECT key should surface our just-appended message.
    let query = format!(r#"{{"query":"SUBJECT \"{subject}\""}}"#);
    let response = app(gateway_config())
        .oneshot(read_request("/email/search", query))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let summaries = body_json(response).await;
    let hit = summaries
        .as_array()
        .expect("search returns a JSON array")
        .iter()
        .find(|m| m["subject"] == subject)
        .expect("our subject present in results");
    assert_eq!(hit["from"], "Alice Example <alice@example.com>");
    assert!(hit["snippet"].as_str().unwrap().contains("lunch tomorrow"));
    let uid = hit["uid"].as_u64().expect("uid present");

    // get: the same uid returns the full parsed message (headers + text body).
    let get_body = format!(r#"{{"uid":{uid}}}"#);
    let response = app(gateway_config())
        .oneshot(read_request("/email/get", get_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let full = body_json(response).await;
    assert_eq!(full["uid"], uid);
    assert_eq!(full["subject"], subject);
    assert!(full["text_body"]
        .as_str()
        .unwrap()
        .contains("lunch tomorrow"));
    // `raw` is `#[serde(skip)]`, so it must not appear on the wire (SPEC §6).
    assert!(full.get("raw").is_none(), "raw must not serialise");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_limit_clamps_results() {
    // Append two distinct messages sharing a subject prefix, then search with a
    // limit of 1 and assert exactly one summary comes back.
    let subject = unique_subject("limit");
    append_message(&sample_message(&format!("{subject}-a"))).await;
    append_message(&sample_message(&format!("{subject}-b"))).await;

    let query = format!(r#"{{"query":"SUBJECT \"{subject}\"","limit":1}}"#);
    let response = app(gateway_config())
        .oneshot(read_request("/email/search", query))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let summaries = body_json(response).await;
    assert_eq!(
        summaries.as_array().map(Vec::len),
        Some(1),
        "limit=1 should return exactly one summary"
    );
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn get_unknown_uid_is_not_found() {
    // A high but syntactically valid UID (UIDs are 1..=u32::MAX) that no message
    // occupies: the FETCH returns nothing, which `get` maps to the typed `not_found`
    // (SPEC §7). UID 0 is avoided — it is invalid syntax and can draw a `BAD`.
    let response = app(gateway_config())
        .oneshot(read_request(
            "/email/get",
            r#"{"uid":4000000000}"#.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["code"], "not_found");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_unknown_folder_is_not_found() {
    let response = app(gateway_config())
        .oneshot(read_request(
            "/email/search",
            r#"{"folder":"No-Such-Folder","query":"ALL"}"#.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["code"], "not_found");
}
