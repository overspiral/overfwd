//! IMAP client (SPEC §4).
//!
//! The provider-facing read side of the gateway. This module opens a fresh
//! connection to the mailbox's IMAP endpoint (from `X-Mailbox-Imap`), logs in with
//! the Inline credential, and exposes the `LOGIN / SELECT / SEARCH / FETCH`
//! primitives the `search` and `get` actions need. Fetched messages are parsed with
//! `mail-parser` into typed [`MessageSummary`] / [`FullMessage`] forms.
//!
//! ## Scope (this task)
//!
//! - Connect to GreenMail plain `3143` and implicit-TLS `3993`; TLS skips
//!   certificate verification when `MAIL_TLS_INSECURE` is set (self-signed certs).
//! - Reusable async primitives returning typed results (uids, raw bytes).
//! - `mail-parser` summaries + full form.
//! - Connection / login / TLS failures mapped onto the Foundation [`GatewayError`]
//!   codes (`auth_failure`, `host_unreachable`, `not_found`, `tls_failure`).
//!
//! Deliberately **not** here (separate tasks, SPEC §4/§6): the HTTP routes/schemas
//! and SMTP submit. The poolless [`search`]/[`get`] open a fresh connection per call
//! and log out — the correct stateless fallback (SPEC §4). Their pooled counterparts
//! [`search_pooled`]/[`get_pooled`] reuse a warm session from the [`crate::pool`]
//! when one exists and fall back to that same per-request login when it does not.
//!
//! ## Choosing TLS
//!
//! The `X-Mailbox-Imap` wire value is a bare `host:port` with no scheme (SPEC §5),
//! so the transport is inferred from the port: the IANA implicit-TLS IMAP port
//! `993` (and GreenMail's `3993` mirror) use TLS, everything else is plaintext.
//! See [`TlsMode::for_port`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_imap::types::Uid;
use async_imap::{Client, Session};
use futures_util::TryStreamExt;
use mail_parser::{Address, MessageParser};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use utoipa::ToSchema;

use crate::auth::{HostPort, MailboxCredential};
use crate::error::GatewayError;
use crate::pool::ImapPool;

/// Environment flag: skip TLS certificate verification (self-signed providers such
/// as the GreenMail e2e stack). Off by default — real providers get real verification.
const ENV_TLS_INSECURE: &str = "MAIL_TLS_INSECURE";

/// The default mailbox a read operation targets when none is named.
pub const DEFAULT_MAILBOX: &str = "INBOX";

/// FETCH data items that pull the whole raw message plus its UID, **without**
/// setting `\Seen` (`.PEEK`). `mail-parser` then does the RFC-conformant parse.
const FETCH_RAW_QUERY: &str = "(UID BODY.PEEK[])";

/// Runtime knobs for the IMAP client, sourced from the environment.
///
/// Kept separate from the Foundation [`crate::Config`] on purpose: `Config` models
/// the gateway's own posture (bind, api_key), whereas this is provider-transport
/// tuning. The actions task threads an `ImapSettings` in per call (or caches one).
#[derive(Debug, Clone)]
pub struct ImapSettings {
    /// When `true`, TLS handshakes accept any server certificate (SPEC §4 —
    /// GreenMail's built-in self-signed cert). Driven by `MAIL_TLS_INSECURE`.
    pub tls_insecure: bool,
}

impl ImapSettings {
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
        ImapSettings { tls_insecure }
    }
}

/// The transport to use for an IMAP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plaintext TCP (e.g. GreenMail `3143`, standard `143`). No STARTTLS here.
    Plain,
    /// Implicit TLS from the first byte (e.g. GreenMail `3993`, standard `993`).
    ImplicitTls,
}

impl TlsMode {
    /// Infer the transport from the IMAP port. `993` is the IANA implicit-TLS IMAP
    /// port; `3993` is GreenMail's mirror of it. Everything else is treated as
    /// plaintext. This is the only signal available — the wire format carries no
    /// scheme (SPEC §5).
    pub fn for_port(port: u16) -> TlsMode {
        match port {
            993 | 3993 => TlsMode::ImplicitTls,
            _ => TlsMode::Plain,
        }
    }
}

/// A concrete stream that is either plaintext or TLS, so both transports produce a
/// single `Session<MaybeTlsStream>` type. `async-imap` needs one concrete stream
/// type; this enum unifies them (the standard "maybe-TLS" pattern).
#[derive(Debug)]
pub enum MaybeTlsStream {
    /// Plaintext TCP.
    Plain(TcpStream),
    /// TLS over TCP. Boxed because `TlsStream` is much larger than a bare socket.
    Tls(Box<TlsStream<TcpStream>>),
}

// Both inner streams are `Unpin`, so `MaybeTlsStream` is too and we can project
// through `get_mut()` without `unsafe`.
impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// An unauthenticated IMAP client over the unified stream.
pub type ImapClient = Client<MaybeTlsStream>;
/// An authenticated IMAP session over the unified stream — the handle the
/// SELECT/SEARCH/FETCH primitives operate on.
pub type ImapSession = Session<MaybeTlsStream>;

/// A raw fetched message: its UID plus the full RFC822 bytes (`BODY[]`).
#[derive(Debug, Clone)]
pub struct RawMessage {
    /// The mailbox-unique id of the message.
    pub uid: u32,
    /// The full raw message, header + body, as returned by `BODY.PEEK[]`.
    pub raw: Vec<u8>,
}

/// A lightweight message summary for `search` results (SPEC §6).
///
/// Every field beyond `uid` is best-effort: a message that fails to parse still
/// yields a summary carrying its `uid` with the rest `None`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MessageSummary {
    /// Mailbox-unique id — the handle `get` uses to fetch the full message.
    #[schema(example = 42)]
    pub uid: u32,
    /// `From` as a display string (`Name <addr>` or bare `addr`).
    pub from: Option<String>,
    /// `To` as a display string, recipients comma-joined.
    pub to: Option<String>,
    /// Decoded `Subject`.
    pub subject: Option<String>,
    /// `Date` normalised to RFC 3339.
    pub date: Option<String>,
    /// A short plain-text preview of the body.
    pub snippet: Option<String>,
}

/// A full message for `get` (SPEC §6): the summary fields plus decoded bodies and
/// the original raw bytes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FullMessage {
    /// Mailbox-unique id.
    #[schema(example = 42)]
    pub uid: u32,
    /// `From` display string.
    pub from: Option<String>,
    /// `To` display string.
    pub to: Option<String>,
    /// Decoded `Subject`.
    pub subject: Option<String>,
    /// `Date` normalised to RFC 3339.
    pub date: Option<String>,
    /// Decoded `text/plain` body, if any.
    pub text_body: Option<String>,
    /// Decoded `text/html` body, if any.
    pub html_body: Option<String>,
    /// The full raw RFC822 message, so a caller can re-parse or archive verbatim.
    #[serde(skip)]
    pub raw: Vec<u8>,
}

// ---------------------------------------------------------------------------
// High-level entry points — what the search/get actions call.
// ---------------------------------------------------------------------------

/// `search`: connect, log in, select `mailbox`, run the IMAP SEARCH `query`, and
/// return a summary per matching message (SPEC §6 read).
///
/// `query` is a raw IMAP SEARCH key (e.g. `ALL`, `SUBJECT "hi"`, `UNSEEN`); the
/// actions task builds it from the request schema. `mailbox` defaults to
/// [`DEFAULT_MAILBOX`] at the call site. The connection is opened fresh and closed
/// on return (no pool yet, SPEC §4).
pub async fn search(
    cred: &MailboxCredential,
    settings: &ImapSettings,
    mailbox: &str,
    query: &str,
) -> Result<Vec<MessageSummary>, GatewayError> {
    let mut session = connect_and_login(cred, settings).await?;
    let result = search_on(&mut session, mailbox, query).await;
    logout(session).await;
    result
}

/// `get`: connect, log in, select `mailbox`, and fetch the single message with
/// `uid`, parsed into a [`FullMessage`] (SPEC §6 read).
///
/// A `uid` with no matching message maps to [`GatewayError::NotFound`].
pub async fn get(
    cred: &MailboxCredential,
    settings: &ImapSettings,
    mailbox: &str,
    uid: u32,
) -> Result<FullMessage, GatewayError> {
    let mut session = connect_and_login(cred, settings).await?;
    let result = get_on(&mut session, mailbox, uid).await;
    logout(session).await;
    result
}

/// Run SEARCH + FETCH on an already-selected session. Split out so both the public
/// [`search`] and tests can drive it without re-opening a connection.
async fn search_on(
    session: &mut ImapSession,
    mailbox: &str,
    query: &str,
) -> Result<Vec<MessageSummary>, GatewayError> {
    select(session, mailbox).await?;
    let mut uids = uid_search(session, query).await?;
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    // Stable, newest-last order; the actions task can reverse/paginate later.
    uids.sort_unstable();
    let raws = uid_fetch_raw(session, &uids).await?;
    Ok(raws.iter().map(|m| parse_summary(m.uid, &m.raw)).collect())
}

/// Fetch a single message by UID on an already-connected session.
async fn get_on(
    session: &mut ImapSession,
    mailbox: &str,
    uid: u32,
) -> Result<FullMessage, GatewayError> {
    select(session, mailbox).await?;
    let raws = uid_fetch_raw(session, &[uid]).await?;
    let msg = raws
        .into_iter()
        .next()
        .ok_or_else(|| GatewayError::NotFound(format!("no message with uid {uid}")))?;
    Ok(parse_full(msg.uid, &msg.raw))
}

// ---------------------------------------------------------------------------
// Pooled entry points — reuse a warm session when one is available, else fall back
// to a fresh per-request LOGIN (SPEC §4 "Connection pooling").
// ---------------------------------------------------------------------------

/// `search`, amortized: like [`search`] but acquires a warm session from `pool`
/// when one exists (else logs in fresh), and returns the session to the pool for
/// reuse when it is still healthy.
pub async fn search_pooled(
    pool: &ImapPool,
    cred: &MailboxCredential,
    settings: &ImapSettings,
    mailbox: &str,
    query: &str,
) -> Result<Vec<MessageSummary>, GatewayError> {
    let mut session = acquire(pool, cred, settings).await?;
    let result = search_on(&mut session, mailbox, query).await;
    release(pool, cred, session, &result).await;
    result
}

/// `get`, amortized: the pooled counterpart of [`get`] (see [`search_pooled`]).
pub async fn get_pooled(
    pool: &ImapPool,
    cred: &MailboxCredential,
    settings: &ImapSettings,
    mailbox: &str,
    uid: u32,
) -> Result<FullMessage, GatewayError> {
    let mut session = acquire(pool, cred, settings).await?;
    let result = get_on(&mut session, mailbox, uid).await;
    release(pool, cred, session, &result).await;
    result
}

/// Obtain a logged-in session for `cred`: a warm one from the pool if available,
/// otherwise a fresh [`connect_and_login`]. The pool already validates warmth with a
/// `NOOP`, so the returned session is ready for `SELECT`.
async fn acquire(
    pool: &ImapPool,
    cred: &MailboxCredential,
    settings: &ImapSettings,
) -> Result<ImapSession, GatewayError> {
    if let Some(session) = pool.take_warm(cred).await {
        return Ok(session);
    }
    connect_and_login(cred, settings).await
}

/// Decide the fate of `session` after an operation. A transport failure
/// (`host_unreachable` / `tls_failure`) means the connection is suspect, so it is
/// closed rather than pooled; on success — or a benign application error such as a
/// missing mailbox/message — the connection is healthy and returned for reuse.
async fn release<T>(
    pool: &ImapPool,
    cred: &MailboxCredential,
    session: ImapSession,
    result: &Result<T, GatewayError>,
) {
    match result {
        Err(e) if is_transport_error(e) => logout(session).await,
        _ => pool.give_back(cred, session).await,
    }
}

/// Whether an error implies the underlying connection is no longer trustworthy and
/// must not be returned to the pool.
fn is_transport_error(err: &GatewayError) -> bool {
    matches!(
        err,
        GatewayError::HostUnreachable(_) | GatewayError::TlsFailure(_)
    )
}

// ---------------------------------------------------------------------------
// Reusable primitives — LOGIN / SELECT / SEARCH / FETCH.
// ---------------------------------------------------------------------------

/// Open a connection to `cred.imap` and log in with the Inline credential,
/// returning an authenticated [`ImapSession`]. TLS is inferred from the port
/// ([`TlsMode::for_port`]).
pub async fn connect_and_login(
    cred: &MailboxCredential,
    settings: &ImapSettings,
) -> Result<ImapSession, GatewayError> {
    let tls = TlsMode::for_port(cred.imap.port);
    let client = connect(&cred.imap, tls, settings.tls_insecure).await?;
    login(client, &cred.username, cred.password.expose()).await
}

/// Open a raw IMAP connection (TCP, optionally wrapped in TLS) and consume the
/// server greeting, yielding an unauthenticated [`ImapClient`].
///
/// TCP failures map to [`GatewayError::HostUnreachable`]; TLS handshake failures to
/// [`GatewayError::TlsFailure`].
pub async fn connect(
    target: &HostPort,
    tls: TlsMode,
    tls_insecure: bool,
) -> Result<ImapClient, GatewayError> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| {
            GatewayError::HostUnreachable(format!(
                "cannot reach IMAP {}:{}: {e}",
                target.host, target.port
            ))
        })?;

    let stream = match tls {
        TlsMode::Plain => MaybeTlsStream::Plain(tcp),
        TlsMode::ImplicitTls => {
            let tls_stream = tls_handshake(tcp, &target.host, tls_insecure).await?;
            MaybeTlsStream::Tls(Box::new(tls_stream))
        }
    };

    let mut client = Client::new(stream);
    // The server sends an untagged greeting on connect; consume it before commands.
    client
        .read_response()
        .await
        .ok_or_else(|| GatewayError::HostUnreachable("IMAP server closed before greeting".into()))?
        .map_err(|e| GatewayError::HostUnreachable(format!("IMAP greeting failed: {e}")))?;

    Ok(client)
}

/// Perform the TLS handshake over an established TCP stream.
async fn tls_handshake(
    tcp: TcpStream,
    host: &str,
    insecure: bool,
) -> Result<TlsStream<TcpStream>, GatewayError> {
    let config = tls_client_config(insecure)?;
    let connector = TlsConnector::from(config);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| GatewayError::TlsFailure(format!("invalid TLS server name '{host}': {e}")))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| GatewayError::TlsFailure(format!("TLS handshake with {host} failed: {e}")))
}

/// Build a rustls client config. `insecure` swaps the real trust-anchor verifier
/// for an accept-all verifier (GreenMail self-signed, SPEC §4). The crypto
/// provider is pinned to `ring` via `builder_with_provider`, so no process-global
/// default provider needs installing.
fn tls_client_config(insecure: bool) -> Result<Arc<rustls::ClientConfig>, GatewayError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| GatewayError::TlsFailure(format!("TLS configuration failed: {e}")))?;

    let config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::AcceptAllVerifier::new(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// LOGIN: authenticate the client, consuming it and returning a [`Session`].
///
/// A rejected credential (server `NO`/`BAD`) maps to [`GatewayError::AuthFailure`];
/// an I/O failure mid-login to [`GatewayError::HostUnreachable`].
pub async fn login(
    client: ImapClient,
    username: &str,
    password: &str,
) -> Result<ImapSession, GatewayError> {
    client
        .login(username, password)
        .await
        .map_err(|(err, _client)| map_login_err(err))
}

/// SELECT a mailbox on the session. A missing mailbox (server `NO`) maps to
/// [`GatewayError::NotFound`].
pub async fn select(session: &mut ImapSession, mailbox: &str) -> Result<(), GatewayError> {
    session
        .select(mailbox)
        .await
        .map(|_mbox| ())
        .map_err(|e| map_select_err(e, mailbox))
}

/// UID SEARCH: return the UIDs matching a raw IMAP search `query`.
///
/// UIDs (not sequence numbers) are used throughout so results stay stable across
/// the connectionless, stateless request model (SPEC §4).
pub async fn uid_search(session: &mut ImapSession, query: &str) -> Result<Vec<u32>, GatewayError> {
    let uids: std::collections::HashSet<Uid> =
        session.uid_search(query).await.map_err(map_command_err)?;
    Ok(uids.into_iter().collect())
}

/// UID FETCH the full raw bytes of each requested UID (`BODY.PEEK[]`, no `\Seen`).
///
/// Returns one [`RawMessage`] per message the server returned with a UID and a
/// body; UIDs with no match are simply absent (the caller decides if that's a
/// [`GatewayError::NotFound`]).
pub async fn uid_fetch_raw(
    session: &mut ImapSession,
    uids: &[u32],
) -> Result<Vec<RawMessage>, GatewayError> {
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let set = uids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let stream = session
        .uid_fetch(&set, FETCH_RAW_QUERY)
        .await
        .map_err(map_command_err)?;
    let fetches: Vec<_> = stream.try_collect().await.map_err(map_command_err)?;

    Ok(fetches
        .into_iter()
        .filter_map(|f| match (f.uid, f.body()) {
            (Some(uid), Some(body)) => Some(RawMessage {
                uid,
                raw: body.to_vec(),
            }),
            _ => None,
        })
        .collect())
}

/// Best-effort LOGOUT. Failures are ignored: the connection is discarded on return
/// anyway (no pool), and a failed logout must not mask the operation's real result.
async fn logout(mut session: ImapSession) {
    let _ = session.logout().await;
}

// ---------------------------------------------------------------------------
// Parsing (mail-parser).
// ---------------------------------------------------------------------------

/// Parse raw bytes into a [`MessageSummary`]. Infallible: an unparseable message
/// still yields a summary carrying its `uid` with the other fields `None`.
pub fn parse_summary(uid: u32, raw: &[u8]) -> MessageSummary {
    match MessageParser::default().parse(raw) {
        Some(msg) => MessageSummary {
            uid,
            from: msg.from().and_then(render_address),
            to: msg.to().and_then(render_address),
            subject: msg.subject().map(str::to_string),
            date: msg.date().map(|d| d.to_rfc3339()),
            snippet: msg
                .body_preview(200)
                .map(|c| c.trim().to_string())
                .filter(|s| !s.is_empty()),
        },
        None => MessageSummary {
            uid,
            from: None,
            to: None,
            subject: None,
            date: None,
            snippet: None,
        },
    }
}

/// Parse raw bytes into a [`FullMessage`]. Infallible in the same way as
/// [`parse_summary`]; the raw bytes are always retained.
pub fn parse_full(uid: u32, raw: &[u8]) -> FullMessage {
    match MessageParser::default().parse(raw) {
        Some(msg) => FullMessage {
            uid,
            from: msg.from().and_then(render_address),
            to: msg.to().and_then(render_address),
            subject: msg.subject().map(str::to_string),
            date: msg.date().map(|d| d.to_rfc3339()),
            // Scan for genuine text/html parts. `body_text`/`body_html` deliberately
            // cross-convert (a plain-text part is offered as HTML and vice-versa), so
            // using them here would make `html_body` non-`None` for a plain-text mail.
            text_body: first_part_text(&msg),
            html_body: first_part_html(&msg),
            raw: raw.to_vec(),
        },
        None => FullMessage {
            uid,
            from: None,
            to: None,
            subject: None,
            date: None,
            text_body: None,
            html_body: None,
            raw: raw.to_vec(),
        },
    }
}

/// The first genuine `text/plain` part's decoded contents, if any.
fn first_part_text(msg: &mail_parser::Message<'_>) -> Option<String> {
    msg.parts.iter().find_map(|p| match &p.body {
        mail_parser::PartType::Text(t) => Some(t.to_string()),
        _ => None,
    })
}

/// The first genuine `text/html` part's decoded contents, if any. A plain-text-only
/// message has no such part, so this is `None` (unlike `Message::body_html`).
fn first_part_html(msg: &mail_parser::Message<'_>) -> Option<String> {
    msg.parts.iter().find_map(|p| match &p.body {
        mail_parser::PartType::Html(h) => Some(h.to_string()),
        _ => None,
    })
}

/// Render an address header as a display string: `Name <addr>` when a display name
/// is present, otherwise the bare address. Groups are flattened; entries with no
/// address are dropped. Returns `None` if nothing renderable remains.
fn render_address(addr: &Address<'_>) -> Option<String> {
    let parts: Vec<String> = addr
        .iter()
        .filter_map(|a| {
            let email = a.address()?;
            Some(match a.name() {
                Some(name) if !name.trim().is_empty() => format!("{} <{email}>", name.trim()),
                _ => email.to_string(),
            })
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Error mapping onto the Foundation GatewayError set (SPEC §7).
// ---------------------------------------------------------------------------

use async_imap::error::Error as ImapError;

/// Map a LOGIN failure. A protocol `NO`/`BAD` means the provider rejected the
/// credential → `auth_failure`; an I/O error means we lost the link → `host_unreachable`.
fn map_login_err(err: ImapError) -> GatewayError {
    match err {
        ImapError::Io(e) => {
            GatewayError::HostUnreachable(format!("IMAP connection lost during login: {e}"))
        }
        ImapError::ConnectionLost => {
            GatewayError::HostUnreachable("IMAP connection lost during login".into())
        }
        // No/Bad/Parse/Validate on LOGIN all mean the credential was not accepted.
        _ => GatewayError::AuthFailure("IMAP login rejected".into()),
    }
}

/// Map a SELECT failure. A `NO` means the mailbox does not exist → `not_found`;
/// transport errors → `host_unreachable`.
fn map_select_err(err: ImapError, mailbox: &str) -> GatewayError {
    match err {
        ImapError::No(_) => GatewayError::NotFound(format!("mailbox '{mailbox}' not found")),
        ImapError::Io(e) => {
            GatewayError::HostUnreachable(format!("IMAP error selecting '{mailbox}': {e}"))
        }
        ImapError::ConnectionLost => GatewayError::HostUnreachable("IMAP connection lost".into()),
        other => {
            GatewayError::HostUnreachable(format!("IMAP error selecting '{mailbox}': {other}"))
        }
    }
}

/// Map a SEARCH/FETCH failure. A `NO`/`BAD`/`Validate` means the server rejected the
/// arguments we were given — by this point the mailbox itself is known to exist (SELECT
/// already succeeded, see [`map_select_err`]), so the fault is the caller's criteria →
/// `bad_request`. Transport errors → `host_unreachable`.
fn map_command_err(err: ImapError) -> GatewayError {
    match err {
        ImapError::No(m) | ImapError::Bad(m) => {
            GatewayError::BadRequest(format!("IMAP rejected the command: {m}"))
        }
        ImapError::Validate(e) => {
            GatewayError::BadRequest(format!("invalid character in IMAP command: {e}"))
        }
        ImapError::Io(e) => GatewayError::HostUnreachable(format!("IMAP command failed: {e}")),
        ImapError::ConnectionLost => GatewayError::HostUnreachable("IMAP connection lost".into()),
        other => GatewayError::HostUnreachable(format!("IMAP command failed: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: Alice Example <alice@example.com>\r\n\
To: Bob <bob@example.com>\r\n\
Subject: Lunch tomorrow?\r\n\
Date: Tue, 1 Jul 2025 09:30:00 +0000\r\n\
Message-ID: <abc@example.com>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hey Bob, are you free for lunch tomorrow at noon?\r\n";

    /// A server rejection of SEARCH/FETCH is the caller's syntax problem, not the
    /// network's: SELECT has already proven the mailbox exists, so `NO` and `BAD` both
    /// mean "these arguments are wrong". Only genuine transport faults stay 502.
    #[test]
    fn command_rejection_is_bad_request_and_transport_faults_are_not() {
        for err in [
            ImapError::No("SEARCH failed".into()),
            ImapError::Bad("Invalid search criteria".into()),
        ] {
            let mapped = map_command_err(err);
            assert_eq!(mapped.code(), "bad_request", "got: {mapped}");
        }

        assert_eq!(
            map_command_err(ImapError::ConnectionLost).code(),
            "host_unreachable"
        );
        assert_eq!(
            map_command_err(ImapError::Io(std::io::Error::other("boom"))).code(),
            "host_unreachable"
        );
    }

    #[test]
    fn tls_mode_inferred_from_port() {
        assert_eq!(TlsMode::for_port(993), TlsMode::ImplicitTls);
        assert_eq!(TlsMode::for_port(3993), TlsMode::ImplicitTls);
        assert_eq!(TlsMode::for_port(143), TlsMode::Plain);
        assert_eq!(TlsMode::for_port(3143), TlsMode::Plain);
    }

    #[test]
    fn settings_default_is_secure() {
        // Unset env → verification stays on. (We read the process env; in the test
        // binary MAIL_TLS_INSECURE is normally absent.)
        std::env::remove_var(ENV_TLS_INSECURE);
        assert!(!ImapSettings::from_env().tls_insecure);
    }

    #[test]
    fn parse_summary_extracts_headers_and_snippet() {
        let s = parse_summary(42, SAMPLE);
        assert_eq!(s.uid, 42);
        assert_eq!(s.from.as_deref(), Some("Alice Example <alice@example.com>"));
        assert_eq!(s.to.as_deref(), Some("Bob <bob@example.com>"));
        assert_eq!(s.subject.as_deref(), Some("Lunch tomorrow?"));
        assert!(s.date.as_deref().unwrap().starts_with("2025-07-01"));
        assert!(s.snippet.as_deref().unwrap().contains("lunch tomorrow"));
    }

    #[test]
    fn parse_full_extracts_body_and_retains_raw() {
        let m = parse_full(7, SAMPLE);
        assert_eq!(m.uid, 7);
        assert_eq!(m.subject.as_deref(), Some("Lunch tomorrow?"));
        assert!(m.text_body.as_deref().unwrap().contains("free for lunch"));
        assert!(m.html_body.is_none());
        assert_eq!(m.raw, SAMPLE);
    }

    #[test]
    fn parse_summary_is_infallible_on_garbage() {
        let s = parse_summary(1, b"\x00\x01 not a message");
        assert_eq!(s.uid, 1);
        // No headers parsed, but we still get a summary with the uid.
        assert!(s.subject.is_none());
    }

    #[test]
    fn full_message_serialises_without_raw() {
        // `raw` is `#[serde(skip)]` so it never bloats/binary-poisons a JSON body.
        let m = parse_full(3, SAMPLE);
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["uid"], 3);
        assert!(json.get("raw").is_none(), "raw must not serialise");
        assert_eq!(json["subject"], "Lunch tomorrow?");
    }
}

/// The dangerous accept-all certificate verifier used only when `tls_insecure` is
/// set (SPEC §4 — GreenMail's self-signed cert). It short-circuits chain
/// verification but still validates handshake **signatures** via the crypto
/// provider, so the TLS session itself remains cryptographically sound.
mod danger {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Accepts any server certificate chain. Constructed only on the insecure path.
    #[derive(Debug)]
    pub struct AcceptAllVerifier(Arc<CryptoProvider>);

    impl AcceptAllVerifier {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            AcceptAllVerifier(provider)
        }
    }

    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // Deliberately trust any presented chain (self-signed providers).
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
