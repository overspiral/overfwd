//! The two independent auth axes (SPEC §5).
//!
//! - **Axis 1 — Gateway access.** [`require_gateway_access`] checks
//!   `Authorization: Bearer <api_key>` against the single static configured key,
//!   enforced only when `require_api_key` is set.
//! - **Axis 2 — Mailbox credential (Inline only).** [`InlineHeaders::parse`] reads the
//!   `X-Mailbox-*` headers; [`InlineHeaders::into_credential`] then resolves them into
//!   a [`MailboxCredential`], deriving any absent host target from the user's domain
//!   via [`crate::autoconfig`]. Portfolio (`X-Mailbox-Account`) and Session sources are
//!   out of scope here (SPEC §5, §11).
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

use crate::autoconfig::Autoconfig;
use crate::error::GatewayError;
use crate::AppState;

/// Header carrying the Inline mailbox credential: `Basic base64(user:pass)` (SPEC §5).
pub const H_MAILBOX_AUTH: &str = "X-Mailbox-Auth";
/// Header carrying the non-secret IMAP target: `host:port` (SPEC §5).
pub const H_MAILBOX_IMAP: &str = "X-Mailbox-Imap";
/// Header carrying the non-secret SMTP target: `host:port` (SPEC §5).
pub const H_MAILBOX_SMTP: &str = "X-Mailbox-Smtp";
/// Optional header naming the domain to autoconfigure from when the `X-Mailbox-Imap`
/// / `X-Mailbox-Smtp` targets are absent. Overrides the domain otherwise taken from
/// the mailbox username's `@` — and lets a short login-id (no `@`) autoconfigure.
pub const H_MAILBOX_DOMAIN: &str = "X-Mailbox-Domain";

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

/// A fully-resolved Inline mailbox credential (SPEC §5 Axis 2).
///
/// Produced by [`InlineHeaders::into_credential`] once both host targets are known
/// (supplied on the wire or filled from autoconfiguration). A single credential covers
/// **both** IMAP and SMTP (SPEC §5). The `password` is held in [`Secret`]; `Debug` on
/// this struct redacts it, so the original `Basic` value can't be reconstructed from a
/// log line (SPEC §6).
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

/// The Inline mailbox headers as parsed off the wire, **before** autoconfiguration.
///
/// `X-Mailbox-Auth` is always required; the host targets are optional and, when
/// absent, filled from the user's domain by [`InlineHeaders::into_credential`]
/// (SPEC §5). Keeping the parse (pure, sync) separate from the resolve (async,
/// possibly network) keeps the fast path — both headers present — allocation- and
/// I/O-free, and makes the resolve independently testable.
#[derive(Clone)]
pub struct InlineHeaders {
    /// Mailbox login id (part before `:` in the decoded `Basic` value).
    pub username: String,
    /// Mailbox password — never logged.
    pub password: Secret,
    /// IMAP target, if `X-Mailbox-Imap` was present.
    pub imap: Option<HostPort>,
    /// SMTP target, if `X-Mailbox-Smtp` was present.
    pub smtp: Option<HostPort>,
    /// Explicit autoconfig domain from `X-Mailbox-Domain`, if present.
    pub domain: Option<String>,
}

impl std::fmt::Debug for InlineHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineHeaders")
            .field("username", &self.username)
            .field("password", &self.password)
            .field("imap", &self.imap)
            .field("smtp", &self.smtp)
            .field("domain", &self.domain)
            .finish()
    }
}

impl InlineHeaders {
    /// Parse the Inline headers (SPEC §5 Axis 2, §6 wire layout).
    ///
    /// `X-Mailbox-Auth` is required; `X-Mailbox-Imap`, `X-Mailbox-Smtp`, and
    /// `X-Mailbox-Domain` are optional (a present-but-malformed one still errors).
    /// Errors never include the `Basic` value.
    pub fn parse(headers: &HeaderMap) -> Result<Self, GatewayError> {
        let auth = required_str(headers, H_MAILBOX_AUTH)?;
        let (username, password) = parse_basic(&auth)?;

        let imap = optional_host_port(headers, H_MAILBOX_IMAP)?;
        let smtp = optional_host_port(headers, H_MAILBOX_SMTP)?;
        let domain = optional_str(headers, H_MAILBOX_DOMAIN)?
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());

        Ok(InlineHeaders {
            username,
            password,
            imap,
            smtp,
            domain,
        })
    }

    /// The autoconfig domain: the explicit `X-Mailbox-Domain` override, else the
    /// username's `@domain`. `None` when neither is available.
    fn autoconfig_domain(&self) -> Option<String> {
        self.domain.clone().or_else(|| {
            self.username
                .rsplit_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
                .filter(|d| !d.is_empty())
        })
    }

    /// Resolve into a complete [`MailboxCredential`], filling any absent host target
    /// from autoconfiguration (SPEC §5).
    ///
    /// Fast path: when both host headers are present, no lookup happens. Otherwise the
    /// domain (override or username `@domain`) drives [`Autoconfig::resolve`]; an
    /// explicitly-supplied header always wins over the resolved value. Yields
    /// [`GatewayError::BadRequest`] when there is no domain to resolve (or autoconfig
    /// is disabled), and [`GatewayError::AutoconfigFailed`] when the lookup finds no
    /// usable endpoint for the needed side.
    pub async fn into_credential(
        self,
        autoconfig: &Autoconfig,
    ) -> Result<MailboxCredential, GatewayError> {
        // Fast path — nothing to resolve.
        if let (Some(imap), Some(smtp)) = (self.imap.clone(), self.smtp.clone()) {
            return Ok(MailboxCredential {
                username: self.username,
                password: self.password,
                imap,
                smtp,
            });
        }

        if !autoconfig.enabled() {
            return Err(GatewayError::BadRequest(missing_target_message()));
        }

        let domain = self.autoconfig_domain().ok_or_else(|| {
            GatewayError::BadRequest(format!(
                "{missing}; cannot autoconfigure without a domain — supply the host header(s) or {H_MAILBOX_DOMAIN}",
                missing = missing_target_message(),
            ))
        })?;

        // Pass a full address to provider-hosted autoconfig only when we can form one.
        let email = if self.username.contains('@') {
            Some(self.username.clone())
        } else {
            self.domain
                .as_ref()
                .map(|d| format!("{}@{}", self.username, d))
        };

        let servers = autoconfig.resolve(&domain, email.as_deref()).await?;

        let imap = self.imap.clone().or(servers.imap).ok_or_else(|| {
            GatewayError::AutoconfigFailed(format!("no IMAP endpoint resolved for '{domain}'"))
        })?;
        let smtp = self.smtp.clone().or(servers.smtp).ok_or_else(|| {
            GatewayError::AutoconfigFailed(format!("no SMTP endpoint resolved for '{domain}'"))
        })?;

        Ok(MailboxCredential {
            username: self.username,
            password: self.password,
            imap,
            smtp,
        })
    }
}

fn missing_target_message() -> String {
    format!("missing {H_MAILBOX_IMAP} and/or {H_MAILBOX_SMTP} header")
}

/// Read a required header as a `String`, erroring if absent or non-ASCII.
fn required_str(headers: &HeaderMap, name: &str) -> Result<String, GatewayError> {
    let value = headers
        .get(name)
        .ok_or_else(|| GatewayError::BadRequest(format!("missing {name} header")))?;
    value
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| GatewayError::BadRequest(format!("{name} is not valid ASCII")))
}

/// Read an optional header as a `String`, erroring only if present-but-non-ASCII.
fn optional_str(headers: &HeaderMap, name: &str) -> Result<Option<String>, GatewayError> {
    match headers.get(name) {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .map(|s| Some(s.to_string()))
            .map_err(|_| GatewayError::BadRequest(format!("{name} is not valid ASCII"))),
    }
}

/// Parse an optional `host:port` header (absent → `None`; malformed → error).
fn optional_host_port(headers: &HeaderMap, name: &str) -> Result<Option<HostPort>, GatewayError> {
    match optional_str(headers, name)? {
        None => Ok(None),
        Some(raw) => Ok(Some(HostPort::parse(name, &raw)?)),
    }
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

    // Strip a trailing newline from the decoded credential. It is never part of a
    // real credential (a newline can't be typed into a password field or an HTTP
    // header, and IMAP/SMTP auth rejects control chars) — its only source is
    // `base64 <file>` including the file's trailing `\n`. Only `\r`/`\n` are
    // trimmed, deliberately not spaces/tabs, which could be genuine password bytes.
    let decoded = decoded.trim_end_matches(['\r', '\n']);

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
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    if !state.config.require_api_key {
        return Ok(next.run(request).await);
    }

    let expected = state
        .config
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
    fn parse_basic_strips_trailing_newline_from_credential() {
        // `base64 <file>` includes the file's trailing newline; it must not leak
        // into the password. Covers bare LF and CRLF.
        for (encoded, why) in [("test:s3cr3t\n", "LF"), ("test:s3cr3t\r\n", "CRLF")] {
            let header = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(encoded)
            );
            let (user, pass) = parse_basic(&header).unwrap();
            assert_eq!(user, "test", "{why}");
            assert_eq!(
                pass.expose(),
                "s3cr3t",
                "{why}: trailing newline not stripped"
            );
        }
    }

    #[test]
    fn parse_basic_keeps_trailing_space_and_interior_newline() {
        // A trailing space could be a genuine password byte — do not trim it. An
        // interior newline is preserved; only a trailing one is an encoding artifact.
        let (_, pass) = parse_basic(&basic("test", "s3cr3t ")).unwrap();
        assert_eq!(pass.expose(), "s3cr3t ");
        let (_, pass) = parse_basic(&basic("test", "a\nb")).unwrap();
        assert_eq!(pass.expose(), "a\nb");
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

    use crate::autoconfig::testing;

    /// Build headers with the auth header plus any extra (name, value) pairs.
    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        use axum::http::HeaderName;
        let mut headers = HeaderMap::new();
        headers.insert(H_MAILBOX_AUTH, basic("test", "test").parse().unwrap());
        for (name, value) in pairs {
            let name: HeaderName = name.parse().unwrap();
            headers.insert(name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn parse_makes_host_headers_optional() {
        let headers = headers_with(&[]);
        let parsed = InlineHeaders::parse(&headers).unwrap();
        assert_eq!(parsed.username, "test");
        assert!(parsed.imap.is_none());
        assert!(parsed.smtp.is_none());
        assert!(parsed.domain.is_none());
    }

    #[test]
    fn parse_still_rejects_a_malformed_host_header() {
        // Present-but-malformed IMAP header is a bad_request even though it's optional.
        let headers = headers_with(&[(H_MAILBOX_IMAP, "localhost")]);
        assert_eq!(
            InlineHeaders::parse(&headers).unwrap_err().code(),
            "bad_request"
        );
    }

    #[tokio::test]
    async fn both_headers_present_resolves_without_lookup() {
        let headers = headers_with(&[
            (H_MAILBOX_IMAP, "localhost:3143"),
            (H_MAILBOX_SMTP, "localhost:3025"),
        ]);
        // A disabled resolver proves the fast path never consults autoconfig.
        let cred = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::disabled())
            .await
            .unwrap();
        assert_eq!(cred.imap.port, 3143);
        assert_eq!(cred.smtp.port, 3025);
    }

    #[tokio::test]
    async fn missing_target_without_a_domain_is_bad_request() {
        // Username `test` has no `@` and no X-Mailbox-Domain → nothing to autoconfigure.
        let headers = headers_with(&[]);
        let err = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::empty())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "bad_request");
    }

    #[tokio::test]
    async fn autoconfig_fills_both_targets_from_username_domain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            H_MAILBOX_AUTH,
            basic("jane@fastmail.com", "pw").parse().unwrap(),
        );
        let cred = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::ispdb("fastmail.com", testing::FASTMAIL_XML))
            .await
            .unwrap();
        assert_eq!(cred.imap.host, "imap.fastmail.com");
        assert_eq!(cred.imap.port, 993);
        assert_eq!(cred.smtp.port, 465);
    }

    #[tokio::test]
    async fn domain_header_enables_a_short_login_id() {
        // Login id `test` (no `@`) autoconfigures via the explicit domain header.
        let headers = headers_with(&[(H_MAILBOX_DOMAIN, "fastmail.com")]);
        let cred = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::ispdb("fastmail.com", testing::FASTMAIL_XML))
            .await
            .unwrap();
        assert_eq!(cred.imap.host, "imap.fastmail.com");
    }

    #[tokio::test]
    async fn an_explicit_host_header_overrides_autoconfig() {
        let mut headers = HeaderMap::new();
        headers.insert(
            H_MAILBOX_AUTH,
            basic("jane@fastmail.com", "pw").parse().unwrap(),
        );
        headers.insert(H_MAILBOX_IMAP, "imap.override.test:1993".parse().unwrap());
        let cred = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::ispdb("fastmail.com", testing::FASTMAIL_XML))
            .await
            .unwrap();
        // IMAP from the header, SMTP filled from autoconfig.
        assert_eq!(cred.imap.host, "imap.override.test");
        assert_eq!(cred.imap.port, 1993);
        assert_eq!(cred.smtp.host, "smtp.fastmail.com");
    }

    #[tokio::test]
    async fn disabled_autoconfig_keeps_missing_target_a_bad_request() {
        let mut headers = HeaderMap::new();
        headers.insert(
            H_MAILBOX_AUTH,
            basic("jane@fastmail.com", "pw").parse().unwrap(),
        );
        let err = InlineHeaders::parse(&headers)
            .unwrap()
            .into_credential(&testing::disabled())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "bad_request");
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
