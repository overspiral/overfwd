//! End-to-end IMAP tests against the shared GreenMail stack (SPEC §4).
//!
//! These are `#[ignore]`d so `cargo test` stays green without a mail server. Run
//! them once GreenMail is up:
//!
//! ```sh
//! make mail-up                 # start the shared stack
//! cargo test --test imap_e2e -- --ignored
//! ```
//!
//! Each test is self-contained on the IMAP side: it `APPEND`s a unique message to
//! `INBOX`, then drives the module's public `search`/`get` functions and asserts on
//! the parsed result. Using a per-test unique subject keeps runs independent of
//! leftover mail (the shared stack is not reset between worktrees).
//!
//! GreenMail's seeded account is `test:test` (login id, not the email); its TLS
//! ports use a self-signed cert, so these tests set `tls_insecure`.

use overfwd::auth::{HostPort, MailboxCredential, Secret};
use overfwd::imap::{self, connect, login, uid_search, ImapSettings, TlsMode, DEFAULT_MAILBOX};
use overfwd::pool::{ImapPool, PoolConfig};

const HOST: &str = "localhost";
const PLAIN_PORT: u16 = 3143;
const TLS_PORT: u16 = 3993;

/// A generous `limit` for tests that care about the search *working*, not about
/// clamping — comfortably above what any single test appends. Truncation behaviour is
/// covered at the route layer (`tests/routes_e2e.rs`) where the policy actually lives.
const LIMIT: usize = 50;

/// An Inline credential for the seeded `test` account, IMAP pointed at `port`.
fn cred(port: u16) -> MailboxCredential {
    MailboxCredential {
        username: "test".to_string(),
        password: Secret::new("test".to_string()),
        imap: HostPort {
            host: HOST.to_string(),
            port,
        },
        // SMTP target is unused by the read path but the struct requires it.
        smtp: HostPort {
            host: HOST.to_string(),
            port: 3025,
        },
    }
}

fn insecure() -> ImapSettings {
    ImapSettings { tls_insecure: true }
}

/// A distinct, greppable subject per test so runs don't collide on the shared stack.
fn unique_subject(tag: &str) -> String {
    // No wall clock available in this harness; use the OS pid + a tag for uniqueness.
    format!("overfwd-e2e-{tag}-{}", std::process::id())
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

/// APPEND a message directly via IMAP (keeps the test independent of SMTP, which is
/// a separate task). Returns nothing; the message is then found via SEARCH.
async fn append_message(c: &MailboxCredential, s: &ImapSettings, raw: &str) {
    let tls = TlsMode::for_port(c.imap.port);
    let client = connect(&c.imap, tls, s.tls_insecure)
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

async fn run_search_and_get(port: u16) {
    let c = cred(port);
    let s = insecure();
    let subject = unique_subject(if port == TLS_PORT { "tls" } else { "plain" });

    append_message(&c, &s, &sample_message(&subject)).await;

    // search: the SUBJECT key should find exactly our just-appended message.
    let query = format!("SUBJECT \"{subject}\"");
    let summaries = imap::search(&c, &s, DEFAULT_MAILBOX, &query, LIMIT)
        .await
        .expect("search");
    assert!(
        !summaries.summaries.is_empty(),
        "search found no message for subject {subject}"
    );
    let hit = summaries
        .summaries
        .iter()
        .find(|m| m.subject.as_deref() == Some(subject.as_str()))
        .expect("our subject present in results");
    assert_eq!(
        hit.from.as_deref(),
        Some("Alice Example <alice@example.com>")
    );
    assert!(hit.snippet.as_deref().unwrap().contains("lunch tomorrow"));

    // get: fetching the same uid returns the full parsed message.
    let full = imap::get(&c, &s, DEFAULT_MAILBOX, hit.uid)
        .await
        .expect("get");
    assert_eq!(full.uid, hit.uid);
    assert_eq!(full.subject.as_deref(), Some(subject.as_str()));
    assert!(full
        .text_body
        .as_deref()
        .unwrap()
        .contains("lunch tomorrow"));
    assert!(!full.raw.is_empty(), "raw bytes retained");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_and_get_over_plaintext() {
    run_search_and_get(PLAIN_PORT).await;
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn search_and_get_over_implicit_tls() {
    run_search_and_get(TLS_PORT).await;
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn bad_credential_maps_to_auth_failure() {
    let mut c = cred(PLAIN_PORT);
    c.password = Secret::new("wrong-password".to_string());
    let err = imap::search(&c, &insecure(), DEFAULT_MAILBOX, "ALL", LIMIT)
        .await
        .expect_err("login should be rejected");
    assert_eq!(err.code(), "auth_failure", "got: {err}");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn wrong_port_maps_to_host_unreachable() {
    // 3999 has nothing listening on it in the GreenMail stack.
    let c = cred(3999);
    let err = imap::search(&c, &insecure(), DEFAULT_MAILBOX, "ALL", LIMIT)
        .await
        .expect_err("connect should fail");
    assert_eq!(err.code(), "host_unreachable", "got: {err}");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn unknown_mailbox_maps_to_not_found() {
    let c = cred(PLAIN_PORT);
    let err = imap::search(&c, &insecure(), "No-Such-Folder", "ALL", LIMIT)
        .await
        .expect_err("select of a missing mailbox should fail");
    assert_eq!(err.code(), "not_found", "got: {err}");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn secure_tls_rejects_self_signed_cert() {
    // With tls_insecure=false, verification is real: GreenMail's built-in
    // self-signed cert must fail the handshake → tls_failure. This also proves the
    // insecure flag is what's letting the other TLS tests through, not a no-op path.
    let c = cred(TLS_PORT);
    let secure = ImapSettings {
        tls_insecure: false,
    };
    let err = imap::search(&c, &secure, DEFAULT_MAILBOX, "ALL", LIMIT)
        .await
        .expect_err("self-signed cert should be rejected");
    assert_eq!(err.code(), "tls_failure", "got: {err}");
}

/// Pooled reads reuse a warm connection: after the first `search_pooled` returns a
/// session to the pool, the second one takes that warm session (validated with NOOP)
/// instead of logging in afresh — while still returning identical results.
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn pooled_search_reuses_warm_connection() {
    let c = cred(PLAIN_PORT);
    let s = insecure();
    let subject = unique_subject("pool-reuse");
    append_message(&c, &s, &sample_message(&subject)).await;
    let query = format!("SUBJECT \"{subject}\"");

    let pool = ImapPool::new(PoolConfig::default());
    assert_eq!(pool.idle_count(), 0, "pool starts empty");

    // First call: cache miss → fresh login, then the healthy session is pooled.
    let first = imap::search_pooled(&pool, &c, &s, DEFAULT_MAILBOX, &query, LIMIT)
        .await
        .expect("first pooled search");
    assert!(
        !first.summaries.is_empty(),
        "first search found our message"
    );
    assert_eq!(pool.idle_count(), 1, "healthy session returned to the pool");

    // Second call: cache hit → the warm session is reused and returned again.
    let second = imap::search_pooled(&pool, &c, &s, DEFAULT_MAILBOX, &query, LIMIT)
        .await
        .expect("second pooled search");
    assert_eq!(
        first.summaries.len(),
        second.summaries.len(),
        "reused connection yields the same results"
    );
    assert_eq!(pool.idle_count(), 1, "session pooled again after reuse");

    // get_pooled shares the same warm session.
    let uid = second.summaries[0].uid;
    let full = imap::get_pooled(&pool, &c, &s, DEFAULT_MAILBOX, uid)
        .await
        .expect("pooled get");
    assert_eq!(full.uid, uid);
    assert_eq!(pool.idle_count(), 1);
}

/// A disabled pool (`max_idle == 0`) never retains a connection: every call falls
/// back to a fresh per-request login, and the results are still correct (SPEC §4 —
/// per-request login is the fallback).
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn disabled_pool_falls_back_to_per_request_login() {
    let c = cred(PLAIN_PORT);
    let s = insecure();

    let pool = ImapPool::new(PoolConfig::disabled());
    assert!(!pool.is_enabled());

    let summaries = imap::search_pooled(&pool, &c, &s, DEFAULT_MAILBOX, "ALL", LIMIT)
        .await
        .expect("search with pooling disabled");
    // The read still works; nothing is retained.
    let _ = summaries;
    assert_eq!(pool.idle_count(), 0, "disabled pool retains nothing");
}

/// A transport failure must not poison the pool: a `search_pooled` against a dead
/// port errors as `host_unreachable` and leaves the pool empty (the suspect
/// connection, if any, is discarded rather than returned).
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn pooled_search_on_dead_port_leaves_pool_empty() {
    // 3999 has nothing listening on it in the GreenMail stack.
    let c = cred(3999);
    let pool = ImapPool::new(PoolConfig::default());
    let err = imap::search_pooled(&pool, &c, &insecure(), DEFAULT_MAILBOX, "ALL", LIMIT)
        .await
        .expect_err("connect should fail");
    assert_eq!(err.code(), "host_unreachable", "got: {err}");
    assert_eq!(pool.idle_count(), 0, "nothing pooled on transport failure");
}

/// Lower-level primitive check: connect + login + UID SEARCH ALL succeeds and the
/// unified stream type covers TLS. Kept minimal — the higher-level tests exercise
/// the parse path.
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn primitives_connect_login_search() {
    let c = cred(TLS_PORT);
    let s = insecure();
    let client = connect(&c.imap, TlsMode::ImplicitTls, s.tls_insecure)
        .await
        .expect("connect tls");
    let mut session = login(client, &c.username, c.password.expose())
        .await
        .expect("login");
    imap::select(&mut session, DEFAULT_MAILBOX)
        .await
        .expect("select");
    // SEARCH ALL must not error (result set may be empty or not).
    let _uids = uid_search(&mut session, "ALL").await.expect("uid_search");
    let _ = session.logout().await;
}
