//! End-to-end SMTP submission tests against the shared GreenMail stack (SPEC §4).
//!
//! These require the shared mail server to be running, so they are `#[ignore]`d by
//! default (CI does not start GreenMail). They still compile under
//! `cargo clippy --all-targets`, keeping them from bit-rotting. To run them:
//!
//! ```sh
//! make mail-up
//! cargo test --test smtp_greenmail -- --ignored
//! ```
//!
//! Ports and credentials mirror `compose.yml` / `.env` (login `test`, pass `test`,
//! plaintext `:3025`, implicit-TLS `:3465`, self-signed cert → `insecure`).

use overfwd::auth::{HostPort, Secret};
use overfwd::smtp::{submit, OutgoingBody, OutgoingMessage, SmtpSecurity};

fn message() -> OutgoingMessage {
    OutgoingMessage {
        from: "test@localhost".to_string(),
        to: vec!["alice@localhost".to_string()],
        cc: vec![],
        bcc: vec![],
        subject: "overfwd smtp e2e".to_string(),
        body: OutgoingBody::Text("Sent through the overfwd SMTP module.".to_string()),
    }
}

fn smtp(port: u16) -> HostPort {
    HostPort {
        host: "localhost".to_string(),
        port,
    }
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn plaintext_submission_is_accepted() {
    submit(
        &smtp(3025),
        "test",
        &Secret::new("test".to_string()),
        SmtpSecurity::Plaintext,
        &message(),
    )
    .await
    .expect("GreenMail should accept the message on :3025");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn implicit_tls_submission_is_accepted() {
    // GreenMail's SMTPS cert is self-signed → verification must be skipped.
    submit(
        &smtp(3465),
        "test",
        &Secret::new("test".to_string()),
        SmtpSecurity::ImplicitTls { insecure: true },
        &message(),
    )
    .await
    .expect("GreenMail should accept the message over implicit TLS on :3465");
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn wrong_password_is_auth_failure() {
    let err = submit(
        &smtp(3025),
        "test",
        &Secret::new("wrong-password".to_string()),
        SmtpSecurity::Plaintext,
        &message(),
    )
    .await
    .expect_err("a bad password must be rejected");
    assert_eq!(err.code(), "auth_failure", "{err}");
    assert!(
        !err.message().contains("wrong-password"),
        "the password must never appear in the error: {err}"
    );
}

#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn closed_port_is_host_unreachable() {
    // Nothing listens on :3999 — connection refused maps to host_unreachable.
    let err = submit(
        &smtp(3999),
        "test",
        &Secret::new("test".to_string()),
        SmtpSecurity::Plaintext,
        &message(),
    )
    .await
    .expect_err("an unreachable endpoint must error");
    assert_eq!(err.code(), "host_unreachable", "{err}");
}
