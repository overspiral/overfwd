//! Server configuration, read from the environment (SPEC §5 Axis 1, §10 Deployment).
//!
//! Two knobs matter for the spine:
//! - **bind address/port** — MUST be configurable and MUST NOT default to `8080`
//!   (that port is GreenMail's management API in this repo's e2e stack).
//! - **`require_api_key`** — the Axis-1 gateway-access toggle: on for hosted/Cloud,
//!   optional for self-host.

use std::net::SocketAddr;

use crate::auth::Secret;

/// Default listen address. Port `8000` is chosen deliberately to avoid `8080`,
/// which the shared GreenMail e2e stack uses for its management REST API.
const DEFAULT_BIND: &str = "0.0.0.0:8000";

/// Environment variable names, kept together so they are easy to audit.
const ENV_BIND: &str = "OVERFWD_BIND";
const ENV_REQUIRE_API_KEY: &str = "OVERFWD_REQUIRE_API_KEY";
const ENV_API_KEY: &str = "OVERFWD_API_KEY";
const ENV_ENABLE_MCP: &str = "OVERFWD_ENABLE_MCP";

/// Immutable, process-wide server configuration (SPEC §5, §10).
#[derive(Clone)]
pub struct Config {
    /// Socket the HTTP server binds to.
    pub bind: SocketAddr,
    /// Axis-1 gateway-access toggle. When `false`, the bearer check is skipped
    /// (valid self-host posture, SPEC §10).
    pub require_api_key: bool,
    /// The single static gateway api_key (SPEC §5 Axis 1). Present iff
    /// `require_api_key` is `true`; wrapped in [`Secret`] so it never logs.
    pub api_key: Option<Secret>,
    /// Whether to serve the MCP endpoint at `POST /mcp` (SPEC §5). Defaults to `true`;
    /// the endpoint sits behind the same Axis-1 gateway-access gate as `/email`, so
    /// enabling it adds no unauthenticated surface. Set `OVERFWD_ENABLE_MCP=false` to
    /// run a pure-REST deployment.
    pub enable_mcp: bool,
}

/// Errors from loading [`Config`] out of the environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{ENV_BIND}='{value}' is not a valid host:port address: {source}")]
    InvalidBind {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error("{var}='{value}' is not a valid boolean (use true/false)")]
    InvalidBool { var: &'static str, value: String },
    #[error(
        "{ENV_REQUIRE_API_KEY}=true but {ENV_API_KEY} is unset — refusing to start a gateway \
         that requires a key it does not have"
    )]
    MissingApiKey,
}

impl Config {
    /// Load configuration from the process environment, applying defaults.
    ///
    /// Fails fast (rather than at first request) when the config is internally
    /// inconsistent — e.g. `require_api_key=true` with no key configured.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_raw = env_or(ENV_BIND, DEFAULT_BIND);
        let bind = bind_raw
            .parse::<SocketAddr>()
            .map_err(|source| ConfigError::InvalidBind {
                value: bind_raw.clone(),
                source,
            })?;

        let require_api_key = match std::env::var(ENV_REQUIRE_API_KEY) {
            Ok(v) => parse_bool(&v).ok_or(ConfigError::InvalidBool {
                var: ENV_REQUIRE_API_KEY,
                value: v,
            })?,
            Err(_) => false,
        };

        let api_key = std::env::var(ENV_API_KEY)
            .ok()
            .filter(|k| !k.is_empty())
            .map(Secret::new);

        if require_api_key && api_key.is_none() {
            return Err(ConfigError::MissingApiKey);
        }

        let enable_mcp = match std::env::var(ENV_ENABLE_MCP) {
            Ok(v) => parse_bool(&v).ok_or(ConfigError::InvalidBool {
                var: ENV_ENABLE_MCP,
                value: v,
            })?,
            Err(_) => true,
        };

        Ok(Self {
            bind,
            require_api_key,
            api_key,
            enable_mcp,
        })
    }
}

/// Redacts the api_key so a `{:?}` of `Config` (e.g. in a startup log) can't leak it.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("require_api_key", &self.require_api_key)
            .field("api_key", &self.api_key)
            .field("enable_mcp", &self.enable_mcp)
            .finish()
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse a permissive boolean: `true/false`, `1/0`, `yes/no`, `on/off` (case-insensitive).
fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_accepts_common_spellings() {
        for t in ["true", "TRUE", "1", "yes", "on", " On "] {
            assert_eq!(parse_bool(t), Some(true), "{t}");
        }
        for f in ["false", "FALSE", "0", "no", "off"] {
            assert_eq!(parse_bool(f), Some(false), "{f}");
        }
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn default_bind_is_not_the_greenmail_mgmt_port() {
        let bind: SocketAddr = DEFAULT_BIND.parse().unwrap();
        assert_ne!(bind.port(), 8080, "must not clash with GreenMail mgmt API");
    }

    #[test]
    fn debug_redacts_api_key() {
        let cfg = Config {
            bind: DEFAULT_BIND.parse().unwrap(),
            require_api_key: true,
            api_key: Some(Secret::new("super-secret-key".to_string())),
            enable_mcp: true,
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("super-secret-key"),
            "Debug leaked the api_key: {rendered}"
        );
    }
}
