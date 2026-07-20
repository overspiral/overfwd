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
use overfwd::routes::{DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT};
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
        block_private_endpoints: false,
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

/// APPEND `count` messages sharing `subject` as a prefix, over a single session.
///
/// The limit/cap tests need to seed past `MAX_SEARCH_LIMIT`; doing that through
/// [`append_message`] would open and tear down one IMAP connection per message.
async fn append_batch(subject: &str, count: usize) {
    let c = cred();
    let client = connect(&c.imap, TlsMode::for_port(c.imap.port), true)
        .await
        .expect("connect");
    let mut session = login(client, &c.username, c.password.expose())
        .await
        .expect("login");
    for i in 0..count {
        let raw = sample_message(&format!("{subject}-{i}"));
        session
            .append(DEFAULT_MAILBOX, None, None, raw.as_bytes())
            .await
            .expect("append");
    }
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
    let body = body_json(response).await;
    let hit = body["results"]
        .as_array()
        .expect("search returns a `results` array")
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

/// Search for `subject` with an optional `limit`, returning the response envelope.
async fn search_envelope(subject: &str, limit: Option<usize>) -> serde_json::Value {
    let limit = match limit {
        Some(n) => format!(r#","limit":{n}"#),
        None => String::new(),
    };
    let query = format!(r#"{{"query":"SUBJECT \"{subject}\""{limit}}}"#);
    let response = app(gateway_config())
        .oneshot(read_request("/email/search", query))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

fn result_count(envelope: &serde_json::Value) -> usize {
    envelope["results"]
        .as_array()
        .expect("search returns a `results` array")
        .len()
}

/// Run a structured search and return the `results` rows.
async fn structured_results(body: serde_json::Value) -> Vec<serde_json::Value> {
    let response = app(gateway_config())
        .oneshot(read_request("/email/search", body.to_string()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "body: {body}");
    body_json(response).await["results"]
        .as_array()
        .expect("search returns a `results` array")
        .clone()
}

/// The structured params are the affordance a caller reaches for first: `{"from": …}`
/// must find the message without anyone hand-writing IMAP syntax, and combining params
/// must narrow (AND), not widen (OR).
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn structured_params_search_and_and_together() {
    let subject = unique_subject("structured");
    append_message(&sample_message(&subject)).await;

    // Each param alone finds it, and so does the conjunction — including `since`, which
    // matches on the server's INTERNALDATE (the APPEND happened just now, so any past
    // date qualifies).
    //
    // `from` is spelled as the address, not the display name: GreenMail's FROM matches
    // only the address part of the header, where RFC 3501 (and Dovecot/Gmail) match the
    // whole header including `Alice Example`. Asserting on the display name here would
    // test the fake server's limitation, not our compiler.
    for body in [
        serde_json::json!({ "subject": subject }),
        serde_json::json!({ "from": "alice@example.com", "subject": subject }),
        serde_json::json!({ "text": "lunch tomorrow", "subject": subject }),
        serde_json::json!({ "subject": subject, "since": "2020-01-01" }),
    ] {
        let results = structured_results(body.clone()).await;
        assert!(
            results.iter().any(|m| m["subject"] == subject),
            "structured search should find our message (body: {body})"
        );
    }

    // A non-matching `from` beside the matching `subject` must yield nothing: adjacent
    // keys are ANDed, so one miss kills the match. This is what distinguishes a real
    // conjunction from a "match any param" search.
    let results = structured_results(
        serde_json::json!({ "subject": subject, "from": "nobody@example.invalid" }),
    )
    .await;
    assert!(
        !results.iter().any(|m| m["subject"] == subject),
        "params are ANDed, so a non-matching `from` must exclude the message"
    );
}

/// A value with spaces and embedded quotes is quoted and escaped server-side — the
/// caller never has to know the IMAP string grammar.
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn structured_values_with_spaces_and_quotes_are_quoted() {
    let subject = format!("{} say \"hi\" now", unique_subject("quoting"));
    append_message(&sample_message(&subject)).await;

    let results = structured_results(serde_json::json!({ "subject": subject })).await;
    assert!(
        results.iter().any(|m| m["subject"] == subject),
        "a subject containing spaces and double quotes should still match"
    );
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_limit_clamps_results_and_marks_truncation() {
    // Three messages share a subject prefix; asking for one must return one — and say
    // so, rather than leaving the caller to believe it saw the whole match set. `total`
    // counts *matches*, not returned rows, which is what makes the flag actionable.
    let subject = unique_subject("limit");
    append_batch(&subject, 3).await;

    let envelope = search_envelope(&subject, Some(1)).await;
    assert_eq!(result_count(&envelope), 1, "limit=1 returns one summary");
    assert_eq!(envelope["total"], 3, "total counts every match");
    assert_eq!(envelope["truncated"], true);
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_under_limit_is_not_marked_truncated() {
    // The companion case: when everything fit, `truncated` must be false and `total`
    // must agree with the row count — otherwise the flag would be noise.
    let subject = unique_subject("untruncated");
    append_message(&sample_message(&subject)).await;

    let envelope = search_envelope(&subject, Some(DEFAULT_SEARCH_LIMIT)).await;
    assert_eq!(result_count(&envelope), 1);
    assert_eq!(envelope["total"], 1);
    assert_eq!(envelope["truncated"], false);
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_limit_over_cap_is_clamped_not_rejected() {
    // Seed *more than the cap* under one subject: a smaller corpus would make the
    // "at most MAX_SEARCH_LIMIT rows" assertion vacuously true and the test would pass
    // just as happily with no cap at all.
    let subject = unique_subject("over-cap");
    let seeded = MAX_SEARCH_LIMIT + 3;
    append_batch(&subject, seeded).await;

    let envelope = search_envelope(&subject, Some(5000)).await;
    assert_eq!(
        result_count(&envelope),
        MAX_SEARCH_LIMIT,
        "an over-cap limit must clamp to exactly the cap"
    );
    assert_eq!(
        envelope["total"], seeded,
        "total still reports every match, uncapped"
    );
    assert_eq!(
        envelope["truncated"], true,
        "clamping to the cap is truncation and must be advertised"
    );
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_without_limit_applies_the_default() {
    // An absent `limit` does not mean "every match": the route's default applies. Seed
    // past the default so the bound is actually exercised rather than coincidental.
    let subject = unique_subject("default-limit");
    let seeded = DEFAULT_SEARCH_LIMIT + 2;
    append_batch(&subject, seeded).await;

    let envelope = search_envelope(&subject, None).await;
    assert_eq!(
        result_count(&envelope),
        DEFAULT_SEARCH_LIMIT,
        "an unqualified search is bounded by the default limit"
    );
    assert_eq!(envelope["total"], seeded);
    assert_eq!(envelope["truncated"], true);
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn broad_search_without_limit_stays_bounded() {
    // The same default, over the whole shared mailbox rather than a seeded subject —
    // the shape a real caller hits when it just asks for "everything".
    let response = app(gateway_config())
        .oneshot(read_request(
            "/email/search",
            r#"{"query":"ALL"}"#.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let envelope = body_json(response).await;
    assert!(
        result_count(&envelope) <= DEFAULT_SEARCH_LIMIT,
        "the default limit should bound an unqualified search, got {}",
        result_count(&envelope)
    );
    // `total` is the pre-limit match count, so it is never smaller than what we got.
    let total = envelope["total"].as_u64().expect("total present") as usize;
    assert!(total >= result_count(&envelope));
    assert_eq!(envelope["truncated"], total > result_count(&envelope));
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn empty_query_searches_everything() {
    // A blank `query` is how templated clients and MCP agents spell "no filter": it
    // must normalize to the IMAP `ALL` key, not reach the provider as an empty (and
    // invalid) SEARCH key — which the server would answer with `BAD`, surfacing here as
    // a 5xx rather than a 200 with matches.
    //
    // The assertion is on `total` (the pre-limit match count), not on finding a
    // specific message in `results`: sibling tests on this shared, un-reset mailbox
    // seed past the default limit, so whether any one message falls inside the
    // newest-N window is not this test's business. Exact `ALL` equivalence is pinned
    // without a server by `absent_null_and_blank_query_all_mean_all` in `src/routes.rs`.
    let subject = unique_subject("empty-query");
    append_message(&sample_message(&subject)).await;

    // `limit: 0` keeps this to SEARCH alone — no bodies fetched just to count.
    for body in [
        r#"{"query":"","limit":0}"#,
        r#"{"query":"   ","limit":0}"#,
        r#"{"query":null,"limit":0}"#,
        r#"{"limit":0}"#,
    ] {
        let response = app(gateway_config())
            .oneshot(read_request("/email/search", body.to_string()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "body: {body}");
        let response_body = body_json(response).await;
        assert!(
            response_body["total"].as_u64().expect("total present") >= 1,
            "an unfiltered search should match the mail we just appended (body: {body})"
        );
    }
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
