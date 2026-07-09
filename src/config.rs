//! Configuration for the overfwd server, loaded from environment variables.
//!
//! `.env` is loaded (via `dotenvy`) before `from_env` runs. The mail settings mirror
//! the connection contract in `.env` so the future IMAP/SMTP bridge can consume them
//! without any restructuring — v0 only reads them into the `Config`.

use std::env;

/// Top-level server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the HTTP listener to.
    pub host: String,
    /// Port to bind the HTTP listener to.
    pub port: u16,
    /// Upstream mail server connection details (unused in v0, ready for the bridge).
    pub mail: MailConfig,
    /// GreenMail management REST API base URL.
    pub greenmail_api: String,
}

/// SMTP/IMAP connection contract, sourced from the `MAIL_*` env vars.
#[derive(Debug, Clone)]
pub struct MailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls_port: u16,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_tls_port: u16,
    /// Login id (short form) used for SMTP AUTH / IMAP LOGIN — not the email address.
    pub user: String,
    pub pass: String,
    /// The actual email address for envelope From/To.
    pub address: String,
    /// GreenMail's TLS ports use a self-signed cert; clients must skip verification.
    pub tls_insecure: bool,
}

/// Errors that can occur while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid value for {var}: {source}")]
    InvalidPort {
        var: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("invalid value for {var}: expected `true` or `false`, got `{value}`")]
    InvalidBool { var: &'static str, value: String },
}

impl Config {
    /// Build a `Config` from the process environment, applying defaults for anything unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            host: env::var("OVERFWD_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            // Default 3000 avoids GreenMail's management API on 8080.
            port: parse_port("OVERFWD_PORT", 3000)?,
            mail: MailConfig::from_env()?,
            greenmail_api: env::var("GREENMAIL_API")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        })
    }
}

impl MailConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            smtp_host: env::var("MAIL_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            smtp_port: parse_port("MAIL_SMTP_PORT", 3025)?,
            smtp_tls_port: parse_port("MAIL_SMTP_TLS_PORT", 3465)?,
            imap_host: env::var("MAIL_IMAP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            imap_port: parse_port("MAIL_IMAP_PORT", 3143)?,
            imap_tls_port: parse_port("MAIL_IMAP_TLS_PORT", 3993)?,
            user: env::var("MAIL_USER").unwrap_or_else(|_| "test".to_string()),
            pass: env::var("MAIL_PASS").unwrap_or_else(|_| "test".to_string()),
            address: env::var("MAIL_ADDRESS").unwrap_or_else(|_| "test@localhost".to_string()),
            tls_insecure: parse_bool("MAIL_TLS_INSECURE", true)?,
        })
    }
}

/// Parse a port env var, falling back to `default` when unset/empty.
fn parse_port(var: &'static str, default: u16) -> Result<u16, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse()
            .map_err(|source| ConfigError::InvalidPort { var, source }),
        _ => Ok(default),
    }
}

/// Parse a boolean env var (`true`/`false`, case-insensitive), falling back to `default`.
fn parse_bool(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.trim().is_empty() => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidBool { var, value: v }),
        },
        _ => Ok(default),
    }
}
