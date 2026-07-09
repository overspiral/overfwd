//! The two independent auth axes (SPEC §5).
//!
//! - **Axis 1 — Gateway access.** [`require_gateway_access`] checks
//!   `Authorization: Bearer <api_key>` against the single static configured key,
//!   enforced only when `require_api_key` is set.
//! - **Axis 2 — Mailbox credential (Inline only).** [`MailboxCredential`] parses the
//!   `X-Mailbox-*` headers into a struct. Portfolio (`X-Mailbox-Account`) and
//!   Session sources are out of scope here (SPEC §5, §11).
//!
//! `Authorization` is reserved for the gateway key; the mailbox concern lives
//! entirely in `X-Mailbox-*`, so the two axes never collide (SPEC §5).
//!
//! **Secrecy invariant:** the `X-Mailbox-Auth` `Basic` value (and the derived
//! password) is never logged or echoed into an error body (SPEC §6). Passwords are
//! held in [`Secret`], whose `Debug`/`Display` redact.

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;

use crate::error::GatewayError;
use crate::AppState;

/// Header carrying the Inline mailbox credential: `Basic base64(user:pass)` (SPEC §5).
pub const H_MAILBOX_AUTH: &str = "X-Mailbox-Auth";
/// Header carrying the non-secret IMAP target: `host:port` (SPEC §5).
pub const H_MAILBOX_IMAP: &str = "X-Mailbox-Imap";
/// Header carrying the non-secret SMTP target: `host:port` (SPEC §5).
pub const H_MAILBOX_SMTP: &str = "X-Mailbox-Smtp";

/// A redacting wrapper for secret strings (mailbox password, gateway api_key).
///
/// `Debug` and `Display` both print a fixed placeholder so a secret can never
/// slip into a log line or error body (SPEC §6). Read the value with
/// [`Secret::expose`] only at the point of use.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// Reveal the underlying secret. Call sites should keep the result short-lived
    /// and never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***redacted***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***redacted***")
    }
}

/// A non-secret provider target: `host:port` (SPEC §5 — travels as config, not a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    /// Parse a `host:port` header value. The host must be non-empty and the port a
    /// valid `u16`. On failure returns [`GatewayError::BadRequest`] naming the header
    /// but never echoing a secret (these values are non-secret anyway).
    pub fn parse(header: &str, raw: &str) -> Result<Self, GatewayError> {
        let raw = raw.trim();
        let (host, port) = raw.rsplit_once(':').ok_or_else(|| {
            GatewayError::BadRequest(format!("{header} must be in host:port form"))
        })?;
        if host.is_empty() {
            return Err(GatewayError::BadRequest(format!(
                "{header} is missing a host"
            )));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| GatewayError::BadRequest(format!("{header} has an invalid port")))?;
        Ok(HostPort {
            host: host.to_string(),
            port,
        })
    }
}

/// An Inline mailbox credential parsed from the `X-Mailbox-*` headers (SPEC §5 Axis 2).
///
/// A single credential covers **both** IMAP and SMTP (SPEC §5). The `password` is
/// held in [`Secret`]; `Debug` on this struct redacts it, so the original `Basic`
/// value can't be reconstructed from a log line (SPEC §6).
#[derive(Clone)]
pub struct MailboxCredential {
    /// The mailbox login id (the part before `:` in the decoded `Basic` value).
    pub username: String,
    /// The mailbox password — never logged.
    pub password: Secret,
    /// Non-secret IMAP target for reads (`search`, `get`).
    pub imap: HostPort,
    /// Non-secret SMTP target for writes (`send`).
    pub smtp: HostPort,
}

impl std::fmt::Debug for MailboxCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxCredential")
            .field("username", &self.username)
            .field("password", &self.password)
            .field("imap", &self.imap)
            .field("smtp", &self.smtp)
            .finish()
    }
}

impl MailboxCredential {
    /// Parse the Inline credential from request headers (SPEC §5 Axis 2, §6 wire layout).
    ///
    /// Requires all three of `X-Mailbox-Auth`, `X-Mailbox-Imap`, `X-Mailbox-Smtp`.
    /// Any missing/malformed header yields [`GatewayError::BadRequest`]. Errors never
    /// include the `Basic` value.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, GatewayError> {
        let auth = required_str(headers, H_MAILBOX_AUTH)?;
        let (username, password) = parse_basic(&auth)?;

        let imap = HostPort::parse(H_MAILBOX_IMAP, &required_str(headers, H_MAILBOX_IMAP)?)?;
        let smtp = HostPort::parse(H_MAILBOX_SMTP, &required_str(headers, H_MAILBOX_SMTP)?)?;

        Ok(MailboxCredential {
            username,
            password,
            imap,
            smtp,
        })
    }
}

/// Read a required header as a `&str`, erroring if absent or non-ASCII.
fn required_str(headers: &HeaderMap, name: &str) -> Result<String, GatewayError> {
    let value = headers
        .get(name)
        .ok_or_else(|| GatewayError::BadRequest(format!("missing {name} header")))?;
    value
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| GatewayError::BadRequest(format!("{name} is not valid ASCII")))
}

/// Parse a `Basic base64(user:pass)` value into `(username, Secret(password))`.
///
/// Deliberately generic on error — it must never echo the (secret) header value
/// back to the caller or into a log (SPEC §6).
fn parse_basic(value: &str) -> Result<(String, Secret), GatewayError> {
    let malformed = || GatewayError::BadRequest(format!("{H_MAILBOX_AUTH} is malformed"));

    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
        .ok_or_else(malformed)?
        .trim();

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| malformed())?;
    let decoded = String::from_utf8(decoded).map_err(|_| malformed())?;

    let (user, pass) = decoded.split_once(':').ok_or_else(malformed)?;
    if user.is_empty() {
        return Err(malformed());
    }
    Ok((user.to_string(), Secret::new(pass.to_string())))
}

/// Axis-1 gateway-access middleware (SPEC §5).
///
/// When `require_api_key` is `false`, this is a pass-through (valid self-host
/// posture, SPEC §10). When `true`, the request must carry
/// `Authorization: Bearer <api_key>` matching the single configured key, else
/// [`GatewayError::Unauthorized`].
pub async fn require_gateway_access(
    State(config): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    if !config.require_api_key {
        return Ok(next.run(request).await);
    }

    let expected = config
        .api_key
        .as_ref()
        // Config::from_env guarantees this is Some when require_api_key is true.
        .ok_or_else(|| GatewayError::Unauthorized("gateway api_key required".to_string()))?;

    let presented = bearer_token(request.headers()).ok_or_else(|| {
        GatewayError::Unauthorized("missing or malformed bearer token".to_string())
    })?;

    if presented == expected.expose() {
        Ok(next.run(request).await)
    } else {
        Err(GatewayError::Unauthorized("invalid api_key".to_string()))
    }
}

/// Extract the `<token>` from an `Authorization: Bearer <token>` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pass: &str) -> String {
        let raw = format!("{user}:{pass}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    #[test]
    fn parse_basic_roundtrips_user_and_pass() {
        let (user, pass) = parse_basic(&basic("test", "s3cr3t")).unwrap();
        assert_eq!(user, "test");
        assert_eq!(pass.expose(), "s3cr3t");
    }

    #[test]
    fn parse_basic_allows_colon_in_password() {
        let (user, pass) = parse_basic(&basic("test", "a:b:c")).unwrap();
        assert_eq!(user, "test");
        assert_eq!(pass.expose(), "a:b:c");
    }

    #[test]
    fn parse_basic_rejects_garbage_without_echoing_it() {
        let err = parse_basic("Basic !!!not-base64!!!").unwrap_err();
        assert_eq!(err.code(), "bad_request");
        assert!(
            !err.message().contains("not-base64"),
            "error leaked the header value: {}",
            err.message()
        );
    }

    #[test]
    fn parse_basic_requires_scheme() {
        assert_eq!(
            parse_basic("dGVzdDp0ZXN0").unwrap_err().code(),
            "bad_request"
        );
    }

    #[test]
    fn secret_debug_and_display_redact() {
        let s = Secret::new("hunter2".to_string());
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(!format!("{s}").contains("hunter2"));
    }

    #[test]
    fn credential_debug_redacts_password() {
        let cred = MailboxCredential {
            username: "test".to_string(),
            password: Secret::new("hunter2".to_string()),
            imap: HostPort {
                host: "localhost".to_string(),
                port: 3143,
            },
            smtp: HostPort {
                host: "localhost".to_string(),
                port: 3025,
            },
        };
        let rendered = format!("{cred:?}");
        assert!(rendered.contains("test"), "username should be visible");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the password: {rendered}"
        );
    }

    #[test]
    fn host_port_parses() {
        let hp = HostPort::parse(H_MAILBOX_IMAP, "localhost:3143").unwrap();
        assert_eq!(hp.host, "localhost");
        assert_eq!(hp.port, 3143);
    }

    #[test]
    fn host_port_rejects_missing_port() {
        assert_eq!(
            HostPort::parse(H_MAILBOX_IMAP, "localhost")
                .unwrap_err()
                .code(),
            "bad_request"
        );
    }

    #[test]
    fn host_port_rejects_bad_port() {
        assert_eq!(
            HostPort::parse(H_MAILBOX_IMAP, "localhost:notaport")
                .unwrap_err()
                .code(),
            "bad_request"
        );
    }

    #[test]
    fn from_headers_requires_all_three() {
        let mut headers = HeaderMap::new();
        headers.insert(H_MAILBOX_AUTH, basic("test", "test").parse().unwrap());
        // Missing IMAP/SMTP → bad_request.
        assert_eq!(
            MailboxCredential::from_headers(&headers)
                .unwrap_err()
                .code(),
            "bad_request"
        );

        headers.insert(H_MAILBOX_IMAP, "localhost:3143".parse().unwrap());
        headers.insert(H_MAILBOX_SMTP, "localhost:3025".parse().unwrap());
        let cred = MailboxCredential::from_headers(&headers).unwrap();
        assert_eq!(cred.username, "test");
        assert_eq!(cred.imap.port, 3143);
        assert_eq!(cred.smtp.port, 3025);
    }

    #[test]
    fn bearer_token_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer abc123".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc123"));

        headers.insert(AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
