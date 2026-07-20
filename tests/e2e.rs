//! End-to-end suite closing overfwd **v0** (SPEC §4–§7): the whole REST → IMAP/SMTP
//! path exercised against the shared **GreenMail** stack (`docs/testing.md`, `compose.yml`).
//!
//! Unlike the per-module `#[ignore]`d GreenMail tests (`imap_e2e`, `smtp_greenmail`,
//! `routes_e2e`), this suite is a **plain `cargo test`** citizen: every test probes
//! the stack's readiness endpoint first and, when it is unreachable, prints a clear
//! `SKIP …` line and returns. So `cargo test` stays green on a box with no
//! Docker/podman (CI) while the same command runs the full suite once the stack is up:
//!
//! ```sh
//! make mail-up                     # start the shared stack (idempotent)
//! cargo test --test e2e -- --nocapture   # --nocapture surfaces the SKIP lines
//! ```
//!
//! ## What it covers
//!
//! - **Round-trip through the HTTP surface:** `POST /email/send` a message as `test`,
//!   then confirm it arrived with `POST /email/search` + `POST /email/get` (SPEC §6),
//!   with an independent cross-check against GreenMail's management API on `:8080`.
//! - **`send` bodies:** `text` and `html` (SPEC §6 body variants).
//! - **The typed error model (SPEC §7):** a bad mailbox credential → `auth_failure`,
//!   a wrong host/port → `host_unreachable`, a missing uid → `not_found`.
//! - **Secrecy invariant (SPEC §6):** the `X-Mailbox-Auth` `Basic` value never appears
//!   in the response body *or* the audit log (captured via a scoped tracing subscriber).
//! - **Transport:** the plaintext ports throughout, plus a full implicit-TLS
//!   (skip-verify) round-trip over SMTPS `:3465` + IMAPS `:3993`.
//!
//! ## Isolation on the shared stack
//!
//! The GreenMail stack is **shared across worktrees** (`docs/testing.md`), so this suite
//! never issues a global `POST /api/service/reset` from a test body — that would wipe
//! a sibling run's mail mid-flight. It isolates instead with a **unique subject per
//! test** (the docs/testing.md-sanctioned alternative). `make mail-reset` remains the operator
//! step *between* whole runs.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use overfwd::auth::{
    HostPort, MailboxCredential, Secret, H_MAILBOX_AUTH, H_MAILBOX_IMAP, H_MAILBOX_SMTP,
};
use overfwd::imap::{self, ImapSettings, MessageSummary, DEFAULT_MAILBOX};
use overfwd::smtp::{submit, OutgoingBody, OutgoingMessage, SmtpSecurity};
use overfwd::{app, Config};

const HOST: &str = "localhost";
const IMAP_PLAIN: u16 = 3143;
const IMAP_TLS: u16 = 3993;
const SMTP_PLAIN: u16 = 3025;
const SMTP_TLS: u16 = 3465;
const MGMT_PORT: u16 = 8080;
/// `base64("test:test")` — the seeded mailbox's `Basic` value, and the exact token
/// the secrecy invariant (SPEC §6) forbids from logs and responses.
const AUTH_B64: &str = "dGVzdDp0ZXN0";
/// How long to wait for SMTP→IMAP delivery before declaring a round-trip failed.
const POLL_ATTEMPTS: usize = 40;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

// --- Reachability gate ----------------------------------------------------------

/// Skip the enclosing `#[tokio::test]` (returning early, so it still counts as
/// passed) when the shared GreenMail stack is not reachable — keeping `cargo test`
/// green without Docker/podman. The message is visible under `--nocapture`.
macro_rules! require_stack {
    () => {
        if !stack_ready().await {
            eprintln!(
                "SKIP {}: GreenMail stack not reachable at http://localhost:{MGMT_PORT} \
                 — start it with `make mail-up`. This e2e test is skipped so unit tests \
                 still run without Docker/podman.",
                module_path!(),
            );
            return;
        }
    };
}

/// `true` once GreenMail's management API answers readiness (SPEC — `docs/testing.md`).
/// A single container hosts SMTP/IMAP and the API, so this gate covers the whole stack.
async fn stack_ready() -> bool {
    matches!(
        mgmt_request("GET", "/api/service/readiness").await,
        Some((200, body)) if body.contains("Service running")
    )
}

/// A tiny dependency-free HTTP/1.0 client for GreenMail's management API on `:8080`
/// (`docs/testing.md`). Returns `(status, body)`, or `None` if the endpoint is unreachable.
/// HTTP/1.0 + `Connection: close` lets us read to EOF without parsing `Content-Length`.
async fn mgmt_request(method: &str, path: &str) -> Option<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let connect = tokio::net::TcpStream::connect(("127.0.0.1", MGMT_PORT));
    let mut stream = tokio::time::timeout(Duration::from_secs(2), connect)
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{MGMT_PORT}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .ok()?
        .ok()?;

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Some((status, body.to_string()))
}

/// Independent, non-IMAP cross-check: poll GreenMail's management mailbox dump for
/// `subject`. Confirms the send truly landed in the provider, not just that our own
/// IMAP read path agrees with our own write path.
async fn mgmt_has_subject(login: &str, subject: &str) -> bool {
    for _ in 0..POLL_ATTEMPTS {
        if let Some((200, body)) = mgmt_request("GET", &format!("/api/user/{login}/messages")).await
        {
            if body.contains(subject) {
                return true;
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

// --- HTTP-route helpers ---------------------------------------------------------

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

/// A distinct, greppable subject per test so runs stay independent on the shared,
/// un-reset stack (`docs/testing.md`). The pid varies per run, so leftovers never collide.
fn unique(tag: &str) -> String {
    format!("overfwd-v0-e2e-{tag}-{}", std::process::id())
}

/// Build a `POST` to a `/email/*` route carrying the three Inline mailbox headers
/// (SPEC §5): `Basic auth_b64` plus the IMAP/SMTP `host:port` targets.
fn route_request(
    path: &str,
    imap_port: u16,
    smtp_port: u16,
    auth_b64: &str,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(H_MAILBOX_AUTH, format!("Basic {auth_b64}"))
        .header(H_MAILBOX_IMAP, format!("{HOST}:{imap_port}"))
        .header(H_MAILBOX_SMTP, format!("{HOST}:{smtp_port}"))
        .body(Body::from(body))
        .unwrap()
}

/// Drive the whole router in-process for one request, returning `(status, json)`.
async fn call(request: Request<Body>) -> (StatusCode, Value) {
    let response = app(gateway_config()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

/// Poll `POST /email/search` (plaintext IMAP) until a summary with `subject` appears,
/// then return that summary as JSON. Panics if it never arrives within the budget.
async fn search_for_subject(subject: &str) -> Value {
    let query = json!({ "query": format!("SUBJECT \"{subject}\"") }).to_string();
    for _ in 0..POLL_ATTEMPTS {
        let (status, body) = call(route_request(
            "/email/search",
            IMAP_PLAIN,
            SMTP_PLAIN,
            AUTH_B64,
            query.clone(),
        ))
        .await;
        assert_eq!(status, StatusCode::OK, "search failed: {body}");
        if let Some(hit) = body
            .as_array()
            .and_then(|rows| rows.iter().find(|m| m["subject"] == subject))
        {
            return hit.clone();
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("message with subject {subject} never appeared via /email/search");
}

// --- Module-layer helpers (implicit-TLS round-trip) -----------------------------

/// An Inline credential for the seeded `test` account, IMAP pointed at `imap_port`.
fn cred(imap_port: u16, smtp_port: u16) -> MailboxCredential {
    MailboxCredential {
        username: "test".to_string(),
        password: Secret::new("test".to_string()),
        imap: HostPort {
            host: HOST.to_string(),
            port: imap_port,
        },
        smtp: HostPort {
            host: HOST.to_string(),
            port: smtp_port,
        },
    }
}

/// Poll `imap::search` until a summary with `subject` appears (used for the TLS
/// round-trip, which drives the module layer directly with an explicit insecure
/// setting rather than the env-driven route path).
async fn module_search_for_subject(
    c: &MailboxCredential,
    settings: &ImapSettings,
    subject: &str,
) -> MessageSummary {
    let query = format!("SUBJECT \"{subject}\"");
    for _ in 0..POLL_ATTEMPTS {
        let summaries = imap::search(c, settings, DEFAULT_MAILBOX, &query)
            .await
            .expect("imap search");
        if let Some(hit) = summaries
            .into_iter()
            .find(|m| m.subject.as_deref() == Some(subject))
        {
            return hit;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("message with subject {subject} never appeared via IMAPS search");
}

// --- Log capture (secrecy invariant) --------------------------------------------

/// A `Vec<u8>` sink behind a shared lock, usable as a `tracing` `MakeWriter`.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static LOG_SINK: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

/// Install (once) a process-global tracing subscriber that captures all log output
/// into an in-memory buffer, and return that buffer. Idempotent: repeated calls
/// reuse the same sink. Every send handler logs its audit line here, so the secrecy
/// assertion can prove the `Basic` value never reached a log.
fn install_log_capture() -> Arc<Mutex<Vec<u8>>> {
    LOG_SINK
        .get_or_init(|| {
            let sink = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .with_writer(BufWriter(sink.clone()))
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .finish();
            // Ignore an error: another test binary may already hold the global default.
            let _ = tracing::subscriber::set_global_default(subscriber);
            sink
        })
        .clone()
}

fn captured_logs(sink: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&sink.lock().unwrap()).into_owned()
}

// --- Tests ----------------------------------------------------------------------

/// The v0 headline: send a `text` message as `test`, confirm it via the mgmt API
/// (independent of IMAP) and via the `search` + `get` read routes (SPEC §6).
#[tokio::test]
async fn roundtrip_text_over_plain() {
    require_stack!();
    let subject = unique("text");
    let body = format!("plain body for {subject}: lunch tomorrow at noon?");

    let (status, resp) = call(route_request(
        "/email/send",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({
            "from": "test@localhost",
            "to": ["test@localhost"],
            "subject": subject,
            "text": body,
        })
        .to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "send: {resp}");
    assert_eq!(resp["sent"], true);
    assert_eq!(resp["disclosure"]["subject"], subject);

    // Independent cross-check: the provider itself reports the message (non-IMAP path).
    assert!(
        mgmt_has_subject("test", &subject).await,
        "message not visible via the GreenMail management API"
    );

    // search: the SUBJECT key surfaces our message.
    let hit = search_for_subject(&subject).await;
    assert!(
        hit["from"].as_str().unwrap().contains("test@localhost"),
        "unexpected from: {}",
        hit["from"]
    );
    assert!(hit["snippet"].as_str().unwrap().contains("lunch tomorrow"));
    let uid = hit["uid"].as_u64().expect("uid present");

    // get: the same uid returns the full parsed message.
    let (status, full) = call(route_request(
        "/email/get",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({ "uid": uid }).to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "get: {full}");
    assert_eq!(full["uid"], uid);
    assert_eq!(full["subject"], subject);
    assert!(full["text_body"]
        .as_str()
        .unwrap()
        .contains("lunch tomorrow"));
    // `raw` is `#[serde(skip)]`, so it must never appear on the wire (SPEC §6).
    assert!(full.get("raw").is_none(), "raw must not serialise");
}

/// `send` with an `html` body round-trips: the HTML part is preserved and readable
/// back through `get` (SPEC §6 body variants).
#[tokio::test]
async fn roundtrip_html_over_plain() {
    require_stack!();
    let subject = unique("html");
    let marker = format!("html-marker-{}", std::process::id());
    let html = format!("<html><body><h1>Hi</h1><p>{marker}</p></body></html>");

    let (status, resp) = call(route_request(
        "/email/send",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({
            "from": "test@localhost",
            "to": ["test@localhost"],
            "subject": subject,
            "html": html,
        })
        .to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "send: {resp}");
    assert_eq!(resp["sent"], true);

    let hit = search_for_subject(&subject).await;
    let uid = hit["uid"].as_u64().expect("uid present");

    let (status, full) = call(route_request(
        "/email/get",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({ "uid": uid }).to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "get: {full}");
    assert_eq!(full["subject"], subject);
    assert!(
        full["html_body"]
            .as_str()
            .unwrap_or_default()
            .contains(&marker),
        "html body not preserved: {}",
        full["html_body"]
    );
}

/// A full round-trip over the **implicit-TLS** ports with skip-verify: submit over
/// SMTPS `:3465`, read back over IMAPS `:3993`. GreenMail's built-in cert is
/// self-signed, so both legs run `insecure` (SPEC §4). Driven at the module layer to
/// keep the env-driven `MAIL_TLS_INSECURE` toggle out of the shared test process.
#[tokio::test]
async fn roundtrip_over_implicit_tls() {
    require_stack!();
    let subject = unique("tls");
    let body = format!("tls body for {subject}: lunch tomorrow at noon?");

    submit(
        &HostPort {
            host: HOST.to_string(),
            port: SMTP_TLS,
        },
        "test",
        &Secret::new("test".to_string()),
        SmtpSecurity::ImplicitTls { insecure: true },
        &OutgoingMessage {
            from: "test@localhost".to_string(),
            to: vec!["test@localhost".to_string()],
            cc: vec![],
            bcc: vec![],
            subject: subject.clone(),
            body: OutgoingBody::Text(body.clone()),
        },
    )
    .await
    .expect("GreenMail should accept the message over SMTPS :3465");

    let c = cred(IMAP_TLS, SMTP_TLS);
    let settings = ImapSettings { tls_insecure: true };
    let hit = module_search_for_subject(&c, &settings, &subject).await;

    let full = imap::get(&c, &settings, DEFAULT_MAILBOX, hit.uid)
        .await
        .expect("get over IMAPS");
    assert_eq!(full.subject.as_deref(), Some(subject.as_str()));
    assert!(full
        .text_body
        .as_deref()
        .unwrap()
        .contains("lunch tomorrow"));
}

/// Error model (SPEC §7): a rejected mailbox password surfaces as `auth_failure` /
/// `502` through the read route — the provider is healthy, the credential is not.
#[tokio::test]
async fn bad_credential_is_auth_failure() {
    require_stack!();
    let bad = base64::engine::general_purpose::STANDARD.encode("test:wrong-password");
    let (status, body) = call(route_request(
        "/email/search",
        IMAP_PLAIN,
        SMTP_PLAIN,
        &bad,
        json!({ "query": "ALL" }).to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["code"], "auth_failure");
}

/// Error model (SPEC §7): an IMAP target with nothing listening maps to
/// `host_unreachable` / `502`. `:3999` is closed in the GreenMail stack.
#[tokio::test]
async fn wrong_host_port_is_host_unreachable() {
    require_stack!();
    let (status, body) = call(route_request(
        "/email/search",
        3999,
        SMTP_PLAIN,
        AUTH_B64,
        json!({ "query": "ALL" }).to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["code"], "host_unreachable");
}

/// Error model (SPEC §7): a syntactically valid uid that no message occupies maps to
/// `not_found` / `404`. UID `0` is avoided (invalid syntax → could draw a `BAD`).
#[tokio::test]
async fn missing_uid_is_not_found() {
    require_stack!();
    let (status, body) = call(route_request(
        "/email/get",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({ "uid": 4_000_000_000u64 }).to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");
}

/// Secrecy invariant (SPEC §6): the `X-Mailbox-Auth` `Basic` value must never appear
/// in the response body or the audit log. We capture the handler's tracing output and
/// assert the base64 token is absent from both — and confirm the send *was* logged
/// (its subject is present), so the assertion is not vacuous.
#[tokio::test]
async fn basic_auth_never_appears_in_logs_or_output() {
    require_stack!();
    let sink = install_log_capture();
    let subject = unique("redact");

    let (status, resp) = call(route_request(
        "/email/send",
        IMAP_PLAIN,
        SMTP_PLAIN,
        AUTH_B64,
        json!({
            "from": "test@localhost",
            "to": ["test@localhost"],
            "subject": subject,
            "text": "redaction check",
        })
        .to_string(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "send: {resp}");

    // Output: the disclosed response must not carry the Basic value.
    let rendered = resp.to_string();
    assert!(
        !rendered.contains(AUTH_B64),
        "auth header leaked into the response: {rendered}"
    );

    // Logs: the audit line logs to/from/subject but never the credential.
    let logs = captured_logs(&sink);
    assert!(
        logs.contains(&subject),
        "expected the send to be logged (capture is working)"
    );
    assert!(
        !logs.contains(AUTH_B64) && !logs.contains("Basic dGVzdDp0ZXN0"),
        "auth header leaked into the audit log"
    );
}
