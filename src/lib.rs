//! # overfwd — Mailbox Gateway
//!
//! A stateless REST facade over remote IMAP/SMTP mailboxes. This crate is the
//! **spine** of the gateway: configuration, the two-axis auth model, the typed
//! error model, route registration, and the three v1 actions — `search`/`get` over
//! IMAP and `send` over SMTP. The connection pool lands in a later task; this crate
//! deliberately keeps the surface Inline-only (SPEC §5).
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
//! | [`imap`]                       | §4, §6         | Provider-facing IMAP client backing the two `read` actions (`search`/`get`). |
//! | [`smtp::submit`]               | §4, §7         | Build a message (`mail-builder`) and submit it over SMTP (`lettre`), mapping transport failures onto [`GatewayError`]. |
//! | [`send::SendRequest`]          | §6             | The `POST /email/send` JSON schema, its validation into an `OutgoingMessage`, and the redaction-safe To/From/Subject disclosure. |
//! | [`pool::ImapPool`]             | §4             | Ephemeral in-memory, per-credential, bounded/LRU/TTL'd cache of warm IMAP sessions; per-request login is the fallback. |
//! | [`routes::router`]             | §6             | `POST /email/{search,get,send}` — all live: `search`/`get` over IMAP, `send` over SMTP. |
//! | [`openapi::ApiDoc`]            | §6, §7         | Code-derived OpenAPI 3.1 document, served at `/openapi.json` + Swagger UI at `/docs` (both outside the Axis-1 gate). |
//!
//! Out of scope here (SPEC §5, §11): Portfolio/Session credential sources,
//! multi-injection, and attachments.

pub mod auth;
pub mod config;
pub mod error;
pub mod imap;
pub mod openapi;
pub mod pool;
pub mod routes;
pub mod send;
pub mod smtp;

use std::sync::Arc;

use axum::Router;

pub use config::Config;
pub use error::GatewayError;
pub use pool::{ImapPool, PoolConfig};

/// Shared application state handed to handlers and middleware.
///
/// Just the immutable [`Config`] today; a connection pool and (optionally) a
/// Portfolio credential store hang off here in later tasks (SPEC §4). Per-request
/// provider tuning (`ImapSettings` / `SmtpSettings`) is read from the environment
/// inside each handler rather than stored here.
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
