//! Typed error model (SPEC §7).
//!
//! A bounded set of machine-readable error codes a caller can gate / approve /
//! branch on. Each variant maps to a **stable** string code (never change these —
//! callers match on them across gateway versions and instances) and an HTTP
//! status. The wire body is always `{ "code": ..., "message": ... }`.
//!
//! SPEC §7 mandates at least: `auth_failure`, `host_unreachable`, `not_found`,
//! `tls_failure`. `bad_request` and `unauthorized` cover the gateway's own request
//! validation and Axis-1 access. `not_implemented` backs the v1 route stubs until
//! the real IMAP/SMTP bodies land. `autoconfig_failed` covers the domain→provider
//! autoconfiguration path (missing host headers resolved from the user's domain).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// The gateway's bounded, typed error set (SPEC §7).
///
/// The `String` payload is a human-readable message. It MUST NOT contain secrets:
/// in particular the `X-Mailbox-Auth` `Basic` value is never placed here (SPEC §6).
#[derive(Debug, Clone)]
pub enum GatewayError {
    /// Malformed/invalid request the gateway rejected before acting. → 400
    BadRequest(String),
    /// Axis-1 gateway access denied: missing/invalid `Authorization` bearer. → 401
    Unauthorized(String),
    /// The mailbox credential was rejected by the provider (bad user/pass). → 502
    AuthFailure(String),
    /// The provider IMAP/SMTP host is unreachable (down, or wrong host/port). → 502
    HostUnreachable(String),
    /// A mailbox or message was not found. → 404
    NotFound(String),
    /// TLS negotiation with the provider failed. → 502
    TlsFailure(String),
    /// The `X-Mailbox-Imap`/`-Smtp` host headers were absent and the provider
    /// target could not be resolved from the user's domain via autoconfiguration
    /// (no config published, lookup failed, or no implicit-TLS endpoint offered).
    /// A caller can recover by supplying the host headers explicitly. → 502
    AutoconfigFailed(String),
    /// The action is registered but not yet implemented (v1 stubs). → 501
    NotImplemented(String),
}

impl GatewayError {
    /// The stable, machine-readable code (SPEC §7). **Never change these strings.**
    pub fn code(&self) -> &'static str {
        match self {
            GatewayError::BadRequest(_) => "bad_request",
            GatewayError::Unauthorized(_) => "unauthorized",
            GatewayError::AuthFailure(_) => "auth_failure",
            GatewayError::HostUnreachable(_) => "host_unreachable",
            GatewayError::NotFound(_) => "not_found",
            GatewayError::TlsFailure(_) => "tls_failure",
            GatewayError::AutoconfigFailed(_) => "autoconfig_failed",
            GatewayError::NotImplemented(_) => "not_implemented",
        }
    }

    /// The HTTP status this error maps to.
    ///
    /// Upstream provider failures (`auth_failure`, `host_unreachable`,
    /// `tls_failure`) surface as `502 Bad Gateway`: the gateway itself is healthy;
    /// the mailbox provider is what rejected or was unreachable.
    pub fn status(&self) -> StatusCode {
        match self {
            GatewayError::BadRequest(_) => StatusCode::BAD_REQUEST,
            GatewayError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            GatewayError::AuthFailure(_) => StatusCode::BAD_GATEWAY,
            GatewayError::HostUnreachable(_) => StatusCode::BAD_GATEWAY,
            GatewayError::NotFound(_) => StatusCode::NOT_FOUND,
            GatewayError::TlsFailure(_) => StatusCode::BAD_GATEWAY,
            GatewayError::AutoconfigFailed(_) => StatusCode::BAD_GATEWAY,
            GatewayError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// The human-readable message payload.
    pub fn message(&self) -> &str {
        match self {
            GatewayError::BadRequest(m)
            | GatewayError::Unauthorized(m)
            | GatewayError::AuthFailure(m)
            | GatewayError::HostUnreachable(m)
            | GatewayError::NotFound(m)
            | GatewayError::TlsFailure(m)
            | GatewayError::AutoconfigFailed(m)
            | GatewayError::NotImplemented(m) => m,
        }
    }
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for GatewayError {}

/// The stable JSON error body (SPEC §7): `{ "code": ..., "message": ... }`.
///
/// This is the single wire shape every [`GatewayError`] serialises to, so the
/// OpenAPI schema derived here (via [`ToSchema`]) is the real response envelope and
/// cannot drift from what the gateway actually returns. `code` is one of the stable
/// strings from [`GatewayError::code`]; `message` is human-readable and never
/// carries a secret (SPEC §6).
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Stable, machine-readable code — one of `bad_request`, `unauthorized`,
    /// `auth_failure`, `host_unreachable`, `not_found`, `tls_failure`,
    /// `autoconfig_failed`, `not_implemented` (SPEC §7).
    #[schema(example = "not_found")]
    pub code: String,
    /// Human-readable detail. Never contains the `X-Mailbox-Auth` value or a
    /// mailbox password (SPEC §6).
    #[schema(example = "mailbox 'INBOX' not found")]
    pub message: String,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            code: self.code().to_string(),
            message: self.message().to_string(),
        };
        (self.status(), Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_distinct() {
        // Locks the wire codes: a change here is a breaking API change (SPEC §7).
        let cases = [
            (GatewayError::BadRequest(String::new()), "bad_request", 400),
            (
                GatewayError::Unauthorized(String::new()),
                "unauthorized",
                401,
            ),
            (
                GatewayError::AuthFailure(String::new()),
                "auth_failure",
                502,
            ),
            (
                GatewayError::HostUnreachable(String::new()),
                "host_unreachable",
                502,
            ),
            (GatewayError::NotFound(String::new()), "not_found", 404),
            (GatewayError::TlsFailure(String::new()), "tls_failure", 502),
            (
                GatewayError::AutoconfigFailed(String::new()),
                "autoconfig_failed",
                502,
            ),
            (
                GatewayError::NotImplemented(String::new()),
                "not_implemented",
                501,
            ),
        ];
        for (err, code, status) in cases {
            assert_eq!(err.code(), code);
            assert_eq!(err.status().as_u16(), status, "code {code}");
        }
    }
}
