//! SMTP submission (SPEC §4 — "SMTP submit | `lettre`").
//!
//! One deep function, [`submit`], turns a typed [`OutgoingMessage`] into an
//! RFC-conformant MIME message (built with `mail-builder`) and hands it to the
//! provider's SMTP endpoint (via `lettre`). It is the whole of the `send` action's
//! provider-facing work; wiring the `POST /email/send` route and its JSON schema is
//! a separate task (this module deliberately knows nothing about HTTP).
//!
//! ## What it covers
//!
//! - **Transport security.** Plaintext (GreenMail `:3025`, real-world `:25`) and
//!   implicit TLS / SMTPS (GreenMail `:3465`, real-world `:465`), chosen by
//!   [`SmtpSecurity`]. STARTTLS-on-587 is out of scope for now.
//! - **Self-signed certs.** [`SmtpSecurity::ImplicitTls`] carries an `insecure`
//!   flag that skips certificate *and* hostname verification — required for
//!   GreenMail's built-in self-signed cert (`.env` `MAIL_TLS_INSECURE`). It is a
//!   deliberate, per-target opt-in, never the default.
//! - **Error mapping.** `lettre` failures collapse onto the bounded
//!   [`GatewayError`] set (SPEC §7): TLS negotiation → `tls_failure`, a credential
//!   rejection → `auth_failure`, an unreachable/unresponsive host → `host_unreachable`.
//!
//! **Secrecy invariant (SPEC §6):** the password is read from [`Secret`] only to
//! hand `lettre` its `Credentials`; it is never placed into an error message. The
//! non-secret host/port *is* included in errors to aid debugging.

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::response::{Category, Code};
use lettre::transport::smtp::Error as SmtpError;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_builder::MessageBuilder;

use crate::auth::{HostPort, Secret};
use crate::error::GatewayError;

/// Environment flag: skip TLS certificate verification (self-signed providers such
/// as the GreenMail e2e stack). Off by default — real providers get real
/// verification. Mirrors the IMAP client's flag of the same name.
const ENV_TLS_INSECURE: &str = "MAIL_TLS_INSECURE";

/// How to secure the connection to the SMTP endpoint.
///
/// The mailbox wire contract (SPEC §5) carries only a non-secret `host:port` in
/// `X-Mailbox-Smtp`; whether that endpoint speaks plaintext or implicit TLS is a
/// decision the caller makes (commonly from the port — see
/// [`SmtpSecurity::for_submission_port`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Plaintext SMTP — no TLS (GreenMail `:3025`, local relays on `:25`).
    /// `lettre` still performs `AUTH` over the cleartext channel if the server
    /// advertises it, which is how GreenMail authenticates on `:3025`.
    Plaintext,
    /// Implicit TLS on connect (SMTPS — GreenMail `:3465`, real-world `:465`).
    ///
    /// `insecure` skips certificate and hostname verification. It exists for
    /// self-signed test servers (GreenMail, `.env` `MAIL_TLS_INSECURE=true`) and
    /// must stay `false` against real providers.
    ImplicitTls { insecure: bool },
}

impl SmtpSecurity {
    /// Convention-based default for a submission port.
    ///
    /// The standard implicit-TLS submission port `465` (and GreenMail's `3465`)
    /// gets [`SmtpSecurity::ImplicitTls`]; everything else is treated as
    /// [`SmtpSecurity::Plaintext`]. `tls_insecure` is only consulted for the TLS
    /// case and comes from deployment config (`.env` `MAIL_TLS_INSECURE`).
    ///
    /// This is a courtesy for the caller (the `send` action); a caller that knows
    /// its provider's posture can construct the variant directly instead.
    pub fn for_submission_port(port: u16, tls_insecure: bool) -> Self {
        match port {
            465 | 3465 => SmtpSecurity::ImplicitTls {
                insecure: tls_insecure,
            },
            _ => SmtpSecurity::Plaintext,
        }
    }
}

/// Runtime transport tuning for SMTP submission, sourced from the environment.
///
/// Mirrors the IMAP client's `ImapSettings`: kept separate from the gateway's own
/// [`crate::Config`] on purpose — this is provider-transport tuning, not the
/// gateway's own posture (bind, api_key). The `send` action reads one per request.
#[derive(Debug, Clone)]
pub struct SmtpSettings {
    /// When `true`, implicit-TLS handshakes accept any server certificate (SPEC §4
    /// — GreenMail's built-in self-signed cert). Driven by `MAIL_TLS_INSECURE`.
    pub tls_insecure: bool,
}

impl SmtpSettings {
    /// Read settings from the process environment. `MAIL_TLS_INSECURE` is a
    /// permissive boolean (`1/true/yes/on`); anything else (or unset) is `false`.
    pub fn from_env() -> Self {
        let tls_insecure = std::env::var(ENV_TLS_INSECURE)
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        SmtpSettings { tls_insecure }
    }

    /// Choose the transport security for a submission target. The `X-Mailbox-Smtp`
    /// wire value is a bare `host:port` with no scheme (SPEC §5), so security is
    /// inferred from the port via [`SmtpSecurity::for_submission_port`].
    pub fn security_for(&self, smtp: &HostPort) -> SmtpSecurity {
        SmtpSecurity::for_submission_port(smtp.port, self.tls_insecure)
    }
}

/// The body of an outgoing message.
///
/// Modelled as an enum so "no body at all" is unrepresentable: every message
/// carries at least a text or an HTML part (or both, as `multipart/alternative`).
#[derive(Debug, Clone)]
pub enum OutgoingBody {
    /// A `text/plain` body only.
    Text(String),
    /// A `text/html` body only.
    Html(String),
    /// Both, emitted as `multipart/alternative` (text first, then HTML).
    Both { text: String, html: String },
}

/// A typed outgoing message, before it becomes MIME (SPEC §4/§6 `send`).
///
/// Addresses are bare `local@domain` strings; the caller (the `send` action) is
/// responsible for the JSON schema, and this module validates address syntax when
/// building the envelope.
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    /// Envelope + header `From`.
    pub from: String,
    /// Primary recipients (`To`). Must be non-empty.
    pub to: Vec<String>,
    /// Carbon-copy recipients (`Cc`). May be empty.
    pub cc: Vec<String>,
    /// Blind-carbon-copy recipients (`Bcc`). May be empty. These are `RCPT TO`'d
    /// like any recipient but are **never** written into a header — a `Bcc` header
    /// would defeat the point. See [`build_envelope`] / [`build_mime`].
    pub bcc: Vec<String>,
    /// The `Subject` header.
    pub subject: String,
    /// The message body.
    pub body: OutgoingBody,
}

/// Build `message` and submit it to `smtp`, authenticating as `username`/`password`
/// over the chosen `security` (SPEC §4).
///
/// Returns `Ok(())` once the provider has accepted the message (SMTP `250`). All
/// failures map onto [`GatewayError`] (SPEC §7); none leak the password.
pub async fn submit(
    smtp: &HostPort,
    username: &str,
    password: &Secret,
    security: SmtpSecurity,
    message: &OutgoingMessage,
) -> Result<(), GatewayError> {
    let envelope = build_envelope(message)?;
    let raw = build_mime(message)?;
    let mailer = build_transport(smtp, username, password, security)?;

    mailer
        .send_raw(&envelope, &raw)
        .await
        .map_err(|err| map_smtp_error(smtp, err))?;
    Ok(())
}

/// Render the typed message into RFC-conformant MIME bytes with `mail-builder`.
///
/// `mail-builder` supplies `Date`, `Message-ID`, and `MIME-Version` automatically.
fn build_mime(message: &OutgoingMessage) -> Result<Vec<u8>, GatewayError> {
    let to: Vec<&str> = message.to.iter().map(String::as_str).collect();

    let mut builder = MessageBuilder::new()
        .from(message.from.as_str())
        .to(to)
        .subject(message.subject.as_str());

    if !message.cc.is_empty() {
        let cc: Vec<&str> = message.cc.iter().map(String::as_str).collect();
        builder = builder.cc(cc);
    }

    // `bcc` is intentionally *not* written as a header: a `Bcc` header would leak
    // the blind recipients to everyone. They reach the mail via the envelope's
    // `RCPT TO` only (see `build_envelope`).

    builder = match &message.body {
        OutgoingBody::Text(text) => builder.text_body(text.as_str()),
        OutgoingBody::Html(html) => builder.html_body(html.as_str()),
        OutgoingBody::Both { text, html } => {
            builder.text_body(text.as_str()).html_body(html.as_str())
        }
    };

    builder
        .write_to_vec()
        .map_err(|err| GatewayError::BadRequest(format!("could not build the MIME message: {err}")))
}

/// Build the SMTP envelope (`MAIL FROM` / `RCPT TO`) from the message.
///
/// The envelope recipient list is `to` **plus** `cc` **plus** `bcc` — all must
/// receive the message even though only `To`/`Cc` addresses appear in a header
/// (`bcc` is deliberately blind — see [`build_mime`]). Any malformed address is a
/// [`GatewayError::BadRequest`] naming the offending value (addresses are non-secret).
fn build_envelope(message: &OutgoingMessage) -> Result<Envelope, GatewayError> {
    let from = parse_address("from", &message.from)?;

    let mut recipients =
        Vec::with_capacity(message.to.len() + message.cc.len() + message.bcc.len());
    for addr in message
        .to
        .iter()
        .chain(message.cc.iter())
        .chain(message.bcc.iter())
    {
        recipients.push(parse_address("recipient", addr)?);
    }

    Envelope::new(Some(from), recipients).map_err(|err| {
        // Envelope::new only fails when there are no recipients.
        GatewayError::BadRequest(format!("invalid SMTP envelope: {err}"))
    })
}

fn parse_address(role: &str, value: &str) -> Result<Address, GatewayError> {
    value
        .parse::<Address>()
        .map_err(|_| GatewayError::BadRequest(format!("invalid {role} address: {value}")))
}

/// Construct the `lettre` transport for the target and chosen security.
fn build_transport(
    smtp: &HostPort,
    username: &str,
    password: &Secret,
    security: SmtpSecurity,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, GatewayError> {
    // `expose()` is confined to this line: the password goes straight into
    // `lettre`'s Credentials and is never formatted anywhere (SPEC §6).
    let credentials = Credentials::new(username.to_owned(), password.expose().to_owned());

    // `builder_dangerous` starts from `Tls::None` (plaintext); we upgrade to a TLS
    // wrapper only for the implicit-TLS case.
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp.host.as_str())
        .port(smtp.port)
        .credentials(credentials);

    if let SmtpSecurity::ImplicitTls { insecure } = security {
        let tls = TlsParameters::builder(smtp.host.clone())
            .dangerous_accept_invalid_certs(insecure)
            .dangerous_accept_invalid_hostnames(insecure)
            .build()
            .map_err(|err| {
                GatewayError::TlsFailure(format!(
                    "could not configure TLS for the SMTP provider {}:{}: {err}",
                    smtp.host, smtp.port
                ))
            })?;
        builder = builder.tls(Tls::Wrapper(tls));
    }

    Ok(builder.build())
}

/// Collapse a `lettre` SMTP error onto the bounded gateway error set (SPEC §7).
///
/// - a TLS-layer failure → `tls_failure`
/// - a negative reply carrying an authentication code → `auth_failure`
/// - anything else (connection refused, DNS/timeout, or an unclassified negative
///   reply) → `host_unreachable`, an "the provider side failed" catch-all whose
///   message carries the server's own reply text
///
/// `lettre` errors never contain the credential, so embedding the error is safe.
fn map_smtp_error(smtp: &HostPort, err: SmtpError) -> GatewayError {
    if err.is_tls() {
        return GatewayError::TlsFailure(format!(
            "TLS negotiation with the SMTP provider {}:{} failed: {err}",
            smtp.host, smtp.port
        ));
    }

    if let Some(code) = err.status() {
        if is_auth_code(code) {
            return GatewayError::AuthFailure(format!(
                "the SMTP provider rejected the mailbox credential: {err}"
            ));
        }
        return GatewayError::HostUnreachable(format!(
            "the SMTP provider {}:{} rejected the submission: {err}",
            smtp.host, smtp.port
        ));
    }

    GatewayError::HostUnreachable(format!(
        "could not reach the SMTP provider {}:{}: {err}",
        smtp.host, smtp.port
    ))
}

/// Whether an SMTP reply code denotes an authentication/authorization failure.
///
/// Covers the RFC 4954 auth replies (`432`, `454`, `530`, `534`, `535`, `538`) and,
/// as a backstop, any `x3z` "unspecified-3" code — the band those auth replies live
/// in. GreenMail rejects a bad password with `535`.
fn is_auth_code(code: Code) -> bool {
    matches!(u16::from(code), 432 | 454 | 530 | 534 | 535 | 538)
        || code.category == Category::Unspecified3
}

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::transport::smtp::response::{Detail, Severity};

    fn msg(body: OutgoingBody) -> OutgoingMessage {
        OutgoingMessage {
            from: "test@localhost".to_string(),
            to: vec!["alice@localhost".to_string()],
            cc: vec![],
            bcc: vec![],
            subject: "Hello".to_string(),
            body,
        }
    }

    #[test]
    fn text_message_has_expected_headers_and_body() {
        let raw = build_mime(&msg(OutgoingBody::Text("plain body".to_string()))).unwrap();
        let rendered = String::from_utf8(raw).unwrap();
        assert!(rendered.contains("From: <test@localhost>"), "{rendered}");
        assert!(rendered.contains("To: <alice@localhost>"), "{rendered}");
        assert!(rendered.contains("Subject: Hello"), "{rendered}");
        assert!(rendered.contains("plain body"), "{rendered}");
        // mail-builder fills these in for us.
        assert!(rendered.contains("Date: "), "{rendered}");
        assert!(rendered.contains("Message-ID: "), "{rendered}");
    }

    #[test]
    fn cc_is_emitted_as_a_header() {
        let mut m = msg(OutgoingBody::Text("body".to_string()));
        m.cc = vec!["carol@localhost".to_string()];
        let rendered = String::from_utf8(build_mime(&m).unwrap()).unwrap();
        assert!(rendered.contains("Cc: <carol@localhost>"), "{rendered}");
    }

    #[test]
    fn both_bodies_produce_multipart_alternative() {
        let raw = build_mime(&msg(OutgoingBody::Both {
            text: "the text part".to_string(),
            html: "<p>the html part</p>".to_string(),
        }))
        .unwrap();
        let rendered = String::from_utf8(raw).unwrap();
        assert!(rendered.contains("multipart/alternative"), "{rendered}");
        assert!(rendered.contains("the text part"), "{rendered}");
        assert!(rendered.contains("the html part"), "{rendered}");
    }

    #[test]
    fn envelope_includes_cc_recipients() {
        let mut m = msg(OutgoingBody::Text("body".to_string()));
        m.to = vec!["a@localhost".to_string(), "b@localhost".to_string()];
        m.cc = vec!["c@localhost".to_string()];

        let envelope = build_envelope(&m).unwrap();
        let recipients: Vec<String> = envelope.to().iter().map(|a| a.to_string()).collect();
        assert_eq!(recipients.len(), 3, "to + cc must all be RCPT TO'd");
        assert!(
            recipients.contains(&"c@localhost".to_string()),
            "{recipients:?}"
        );
    }

    #[test]
    fn envelope_includes_bcc_recipients() {
        let mut m = msg(OutgoingBody::Text("body".to_string()));
        m.cc = vec!["c@localhost".to_string()];
        m.bcc = vec!["d@localhost".to_string()];

        let envelope = build_envelope(&m).unwrap();
        let recipients: Vec<String> = envelope.to().iter().map(|a| a.to_string()).collect();
        assert_eq!(recipients.len(), 3, "to + cc + bcc must all be RCPT TO'd");
        assert!(
            recipients.contains(&"d@localhost".to_string()),
            "bcc must be RCPT TO'd: {recipients:?}"
        );
    }

    #[test]
    fn bcc_is_never_written_as_a_header() {
        let mut m = msg(OutgoingBody::Text("body".to_string()));
        m.bcc = vec!["secret-bcc@localhost".to_string()];
        let rendered = String::from_utf8(build_mime(&m).unwrap()).unwrap();
        assert!(
            !rendered.contains("secret-bcc@localhost"),
            "the Bcc recipient must not leak into any header: {rendered}"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("bcc:"),
            "no Bcc header may be emitted: {rendered}"
        );
    }

    #[test]
    fn security_for_infers_from_smtp_port() {
        let insecure = SmtpSettings { tls_insecure: true };
        let secure = SmtpSettings {
            tls_insecure: false,
        };
        let hp = |port| HostPort {
            host: "localhost".to_string(),
            port,
        };
        assert_eq!(secure.security_for(&hp(3025)), SmtpSecurity::Plaintext);
        assert_eq!(
            insecure.security_for(&hp(3465)),
            SmtpSecurity::ImplicitTls { insecure: true }
        );
        assert_eq!(
            secure.security_for(&hp(465)),
            SmtpSecurity::ImplicitTls { insecure: false }
        );
    }

    #[test]
    fn malformed_address_is_bad_request() {
        let mut m = msg(OutgoingBody::Text("body".to_string()));
        m.to = vec!["not-an-email".to_string()];
        assert_eq!(build_envelope(&m).unwrap_err().code(), "bad_request");
    }

    #[test]
    fn for_submission_port_maps_tls_ports() {
        assert_eq!(
            SmtpSecurity::for_submission_port(465, false),
            SmtpSecurity::ImplicitTls { insecure: false }
        );
        assert_eq!(
            SmtpSecurity::for_submission_port(3465, true),
            SmtpSecurity::ImplicitTls { insecure: true }
        );
        assert_eq!(
            SmtpSecurity::for_submission_port(3025, true),
            SmtpSecurity::Plaintext
        );
    }

    fn code(s: Severity, c: Category, d: Detail) -> Code {
        Code::new(s, c, d)
    }

    #[test]
    fn auth_codes_are_recognised() {
        // 535 Authentication credentials invalid — what GreenMail returns.
        assert!(is_auth_code(code(
            Severity::PermanentNegativeCompletion,
            Category::Unspecified3,
            Detail::Five
        )));
        // 530 Authentication required.
        assert!(is_auth_code(code(
            Severity::PermanentNegativeCompletion,
            Category::Unspecified3,
            Detail::Zero
        )));
    }

    #[test]
    fn non_auth_codes_are_not_auth() {
        // 550 mailbox unavailable — a rejection, but not an auth failure.
        assert!(!is_auth_code(code(
            Severity::PermanentNegativeCompletion,
            Category::MailSystem,
            Detail::Zero
        )));
        // 250 OK is obviously not an auth failure.
        assert!(!is_auth_code(code(
            Severity::PositiveCompletion,
            Category::MailSystem,
            Detail::Zero
        )));
    }
}
