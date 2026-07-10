//! # overfwd — Mailbox Gateway
//!
//! A stateless REST facade over remote IMAP/SMTP mailboxes. This crate is the
//! **spine** of the gateway: configuration, the two-axis auth model, the typed
//! error model, and route registration. The provider-facing IMAP/SMTP work and
//! the real action bodies land in later tasks; this crate deliberately keeps the
//! surface Inline-only (SPEC §5).
//!
//! ## Map of types → SPEC sections
//!
//! | Type / item                    | SPEC reference | Role |
//! |--------------------------------|----------------|------|
//! | [`config::Config`]             | §5, §10        | Env-driven server config: bind address and the `require_api_key` toggle + static gateway key. |
//! | [`auth::require_gateway_access`] | §5 Axis 1    | `Authorization: Bearer <api_key>` gateway-access gate, enforced only when `require_api_key`. |
//! | [`auth::MailboxCredential`]    | §5 Axis 2 (Inline) | Parsed `X-Mailbox-Auth` / `X-Mailbox-Imap` / `X-Mailbox-Smtp`. The `Basic` value is never logged. |
//! | [`auth::Secret`]               | §5, §6         | Redacting wrapper so mailbox passwords never reach logs or disclosures. |
//! | [`error::GatewayError`]        | §7             | Bounded, machine-readable error codes mapped to HTTP status + a stable `{ code, message }` body. |
//! | [`smtp::submit`]               | §4, §7         | Build a message (`mail-builder`) and submit it over SMTP (`lettre`), mapping transport failures onto [`GatewayError`]. |
//! | [`send::SendRequest`]          | §6             | The `POST /email/send` JSON schema, its validation into an `OutgoingMessage`, and the redaction-safe To/From/Subject disclosure. |
//! | [`routes::router`]             | §6             | `POST /email/{search,get,send}` — `send` is live over SMTP; `search`/`get` are `not_implemented` stubs. |
//!
//! Out of scope for this task (SPEC §5, §11): Portfolio/Session credential
//! sources, multi-injection, live IMAP/SMTP, the connection pool, and attachments.

pub mod auth;
pub mod config;
pub mod error;
pub mod imap;
pub mod routes;
pub mod send;
pub mod smtp;

use std::sync::Arc;

use axum::Router;

pub use config::Config;
pub use error::GatewayError;

/// Shared application state handed to handlers and middleware.
///
/// Just the immutable [`Config`] today; a connection pool and (optionally) a
/// Portfolio credential store hang off here in later tasks (SPEC §4).
pub type AppState = Arc<Config>;

/// Build the full application [`Router`] for the given config.
///
/// The `/email/*` routes are wrapped with the Axis-1 gateway-access middleware
/// ([`auth::require_gateway_access`]); the middleware is a no-op when
/// `require_api_key` is false (SPEC §5, §10 self-host).
pub fn app(config: Config) -> Router {
    let state: AppState = Arc::new(config);
    routes::router(state)
}
