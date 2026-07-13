//! Code-derived OpenAPI 3.1 document and the routes that serve it (SPEC §6/§7).
//!
//! The spec is assembled by [`utoipa`] from the real handler signatures
//! (`#[utoipa::path]` on [`crate::routes`]) and the real request/response types
//! (`#[derive(ToSchema)]`), so it is generated from the code and cannot drift from
//! what the gateway actually accepts and returns. Nothing here is hand-authored
//! JSON.
//!
//! ## The two auth axes (SPEC §5), as security schemes
//!
//! Both axes are documented as OpenAPI security schemes on every `/email` operation
//! (see [`SecurityAddon`]):
//!
//! - **Axis 1 — gateway access:** `Authorization: Bearer <api_key>` (HTTP bearer,
//!   scheme `gateway_api_key`). Enforced only when the gateway is configured with
//!   `require_api_key`.
//! - **Axis 2 — Inline mailbox credential:** request headers carried as `apiKey`
//!   schemes — `X-Mailbox-Auth: Basic base64(user:pass)` (`mailbox_auth`, required),
//!   `X-Mailbox-Imap: host:port` (`mailbox_imap`) and `X-Mailbox-Smtp: host:port`
//!   (`mailbox_smtp`). The two host headers are **optional**: when absent, `host:port`
//!   is derived from the user's domain via autoconfiguration, optionally steered by
//!   `X-Mailbox-Domain` (`mailbox_domain`) — see SPEC §5.
//!
//! ## Serving
//!
//! [`openapi_router`] exposes `GET /openapi.json` (the raw spec) and `GET /docs`
//! (interactive Swagger UI). Both live **outside** the Axis-1 gate so the docs are
//! reachable without a gateway key.
//!
//! The MCP endpoint at `POST /mcp` (see [`crate::mcp`]) is JSON-RPC 2.0, not REST, and
//! is deliberately **not** part of this OpenAPI document; it reuses the same request
//! schemas (`SearchRequest`/`GetRequest`/`SendRequest`) to derive its tool inputs.

use axum::routing::get;
use axum::{Json, Router};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

/// The generated OpenAPI 3.1 document for the v1 REST facade.
///
/// `paths` pulls in the three annotated handlers; `components(schemas(...))` pulls
/// in every request/response type by its `ToSchema` derive; `modifiers` layers on
/// the two-axis security schemes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "overfwd — Mailbox Gateway",
        description = "A stateless REST facade over remote IMAP/SMTP mailboxes. \
            Two independent auth axes apply to every `/email` action: an \
            `Authorization: Bearer <api_key>` gateway key (Axis 1) and the Inline \
            mailbox credential carried in `X-Mailbox-Auth` / `X-Mailbox-Imap` / \
            `X-Mailbox-Smtp` (Axis 2). The host headers are optional — when absent \
            the IMAP/SMTP target is autoconfigured from the user's domain (SPEC §5).",
        version = env!("CARGO_PKG_VERSION"),
        license(name = "MIT"),
    ),
    paths(
        crate::routes::search,
        crate::routes::get,
        crate::routes::send,
    ),
    components(schemas(
        crate::routes::SearchRequest,
        crate::routes::GetRequest,
        crate::send::SendRequest,
        crate::send::SendResponse,
        crate::send::SendDisclosure,
        crate::imap::MessageSummary,
        crate::imap::FullMessage,
        crate::error::ErrorResponse,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "email", description = "v1 mailbox actions: search, get, send (SPEC §6)."),
    ),
)]
pub struct ApiDoc;

/// Registers the two-axis auth as OpenAPI security schemes (SPEC §5). Applied via
/// the `modifiers(&SecurityAddon)` hook because security schemes are cross-cutting
/// and can't be expressed on an individual `#[utoipa::path]`.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);

        // Axis 1 — gateway access.
        components.add_security_scheme(
            "gateway_api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Axis-1 gateway access: `Authorization: Bearer <api_key>`. \
                         Enforced only when the gateway is configured with \
                         `require_api_key`.",
                    ))
                    .build(),
            ),
        );

        // Axis 2 — Inline mailbox credential, as three request headers.
        components.add_security_scheme(
            "mailbox_auth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Mailbox-Auth",
                "Axis-2 mailbox credential: `Basic base64(user:pass)`. The `Basic` \
                 value is never logged or echoed into a response (SPEC §6).",
            ))),
        );
        components.add_security_scheme(
            "mailbox_imap",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Mailbox-Imap",
                "Axis-2 IMAP target for reads (`search`/`get`): a bare `host:port` \
                 (no scheme; TLS is inferred from the port). Optional — when absent, \
                 the target is autoconfigured from the user's domain (SPEC §5).",
            ))),
        );
        components.add_security_scheme(
            "mailbox_smtp",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Mailbox-Smtp",
                "Axis-2 SMTP target for writes (`send`): a bare `host:port` (no \
                 scheme; TLS is inferred from the port). Optional — when absent, the \
                 target is autoconfigured from the user's domain (SPEC §5).",
            ))),
        );
        components.add_security_scheme(
            "mailbox_domain",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Mailbox-Domain",
                "Optional domain to autoconfigure the IMAP/SMTP target from when the \
                 host headers are absent. Overrides the domain otherwise taken from \
                 the mailbox username's `@` (SPEC §5).",
            ))),
        );
    }
}

/// The router serving the generated spec and Swagger UI, deliberately kept
/// **outside** the Axis-1 gate (SPEC §5) so the docs are reachable without a
/// gateway key.
///
/// - `GET /openapi.json` — the raw OpenAPI 3.1 document.
/// - `GET /docs` — interactive Swagger UI (it loads the spec from
///   `/docs/openapi.json`, which it serves itself; the canonical public copy is the
///   `/openapi.json` route above).
pub fn openapi_router() -> Router {
    Router::new()
        .route("/openapi.json", get(openapi_json))
        .merge(SwaggerUi::new("/docs").url("/docs/openapi.json", ApiDoc::openapi()))
}

/// Serve the generated document as JSON.
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
