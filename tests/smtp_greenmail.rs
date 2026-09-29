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

use mail_parser::{MessageParser, MimeHeaders};
use overfwd::auth::{HostPort, MailboxCredential, Secret};
use overfwd::imap::{self, ImapSettings, DEFAULT_MAILBOX};
use overfwd::smtp::{submit, OutgoingAttachment, OutgoingBody, OutgoingMessage, SmtpSecurity};

fn message() -> OutgoingMessage {
    OutgoingMessage {
        from: "test@localhost".to_string(),
        to: vec!["alice@localhost".to_string()],
        cc: vec![],
        bcc: vec![],
        subject: "overfwd smtp e2e".to_string(),
        body: OutgoingBody::Text("Sent through the overfwd SMTP module.".to_string()),
        attachments: vec![],
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

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// Deterministic, awkward bytes: every byte value, CR/LF/bare-LF runs, a lone `.`
/// line (SMTP dot-stuffing), and ~1 MiB of pseudo-random filler so the base64 body
/// spans many lines.
fn awkward_bytes() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..=255u8).collect();
    bytes.extend_from_slice(b"\r\n.\r\nbare\nlf\n\r\r\n");
    let mut state: u32 = 0x1234_5678;
    for _ in 0..(1024 * 1024) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push(state as u8);
    }
    bytes
}

/// Send a message with two attachments through `:3025`, fetch it back over IMAP as
/// the recipient, and check each attachment's name, type, and bytes (by SHA-256).
#[tokio::test]
#[ignore = "requires the shared GreenMail stack: make mail-up"]
async fn attachments_round_trip_byte_exact_over_imap() {
    let subject = format!("overfwd-e2e-attachments-{}", std::process::id());
    let binary = awkward_bytes();
    let text = b"line one\nline two\r\ntrailing space \n".to_vec();

    let message = OutgoingMessage {
        subject: subject.clone(),
        body: OutgoingBody::Both {
            text: "see attached".to_string(),
            html: "<p>see attached</p>".to_string(),
        },
        bcc: vec!["test@localhost".to_string()],
        attachments: vec![
            OutgoingAttachment {
                filename: "blob.bin".to_string(),
                content_type: "application/octet-stream".to_string(),
                bytes: binary.clone(),
            },
            OutgoingAttachment {
                filename: "notes ñ.txt".to_string(),
                content_type: "text/plain".to_string(),
                bytes: text.clone(),
            },
        ],
        ..message()
    };
    submit(
        &smtp(3025),
        "test",
        &Secret::new("test".to_string()),
        SmtpSecurity::Plaintext,
        &message,
    )
    .await
    .expect("GreenMail should accept the message");

    // Read it back as the recipient (GreenMail login `alice:alice`).
    let alice = MailboxCredential {
        username: "alice".to_string(),
        password: Secret::new("alice".to_string()),
        imap: HostPort {
            host: "localhost".to_string(),
            port: 3143,
        },
        smtp: smtp(3025),
    };
    let settings = ImapSettings { tls_insecure: true };
    let found = imap::search(
        &alice,
        &settings,
        DEFAULT_MAILBOX,
        &format!("SUBJECT \"{subject}\""),
        1,
    )
    .await
    .expect("search");
    let uid = found.summaries.first().expect("message delivered").uid;
    let fetched = imap::get(&alice, &settings, DEFAULT_MAILBOX, uid)
        .await
        .expect("get");

    let raw = String::from_utf8_lossy(&fetched.raw);
    assert!(
        !raw.to_ascii_lowercase().contains("\nbcc:"),
        "no Bcc header may reach the recipient"
    );
    assert_eq!(fetched.text_body.as_deref(), Some("see attached"));

    let parsed = MessageParser::default().parse(&fetched.raw).expect("parse");
    let attachments: Vec<(String, String, Vec<u8>)> = parsed
        .attachments()
        .map(|part| {
            let ct = part.content_type().expect("content type");
            (
                part.attachment_name().unwrap_or_default().to_string(),
                format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or_default()),
                part.contents().to_vec(),
            )
        })
        .collect();
    assert_eq!(attachments.len(), 2);

    assert_eq!(attachments[0].0, "blob.bin");
    assert_eq!(attachments[0].1, "application/octet-stream");
    assert_eq!(
        sha256(&attachments[0].2),
        sha256(&binary),
        "binary bytes differ"
    );

    assert_eq!(attachments[1].0, "notes ñ.txt");
    assert_eq!(attachments[1].1, "text/plain");
    assert_eq!(
        sha256(&attachments[1].2),
        sha256(&text),
        "text bytes differ"
    );
}
