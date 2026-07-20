//! Endpoint address policy — the SSRF guard on caller-supplied provider targets
//! (SPEC §5, §10).
//!
//! [`crate::autoconfig`] already defends the *derived* path: [`is_public_domain`]
//! rejects IP literals and non-DNS names before any HTTP request, and the live
//! fetcher's DNS resolver drops non-public addresses on every hop. But an
//! **explicit** `X-Mailbox-Imap` / `X-Mailbox-Smtp` header bypasses all of that —
//! [`HostPort::parse`](crate::auth::HostPort::parse) only checks "non-empty host,
//! valid `u16` port", and `imap.rs`/`smtp.rs` then dial whatever they were handed.
//!
//! Single-tenant that is a feature: the local GreenMail stack in `compose.yml` is
//! reached as `localhost:3143`. Multi-tenant it means any caller can aim a shared
//! gateway at an arbitrary TCP endpoint reachable from the container — including
//! the cloud metadata endpoint at `169.254.169.254` and anything on the
//! deployment's private network.
//!
//! [`EndpointGuard`] closes that, **opt-in and off by default** so self-hosters and
//! the e2e stack keep working unchanged. Turn it on with
//! `OVERFWD_BLOCK_PRIVATE_ENDPOINTS=true` (see [`crate::config::Config`]) for a
//! shared deployment.
//!
//! ## What is refused
//!
//! [`is_forbidden_ip`] is the single address predicate for the whole crate — the
//! same one the autoconfig fetcher's DNS resolver applies — covering loopback,
//! RFC1918, link-local (`169.254/16`, the metadata endpoint), CGNAT, multicast,
//! broadcast, unspecified, IPv6 loopback/link-local/unique-local, and
//! IPv4-mapped-IPv6 forms of all of the above.
//!
//! The check runs on the **resolved** address, not just the literal: a hostname
//! whose `A` record is `10.0.0.5` is the interesting attack. Every returned address
//! is checked and *any* non-public answer rejects the endpoint, so an attacker
//! cannot hide a private address behind a multi-answer record set.
//!
//! ## Known residual — TOCTOU
//!
//! The guard resolves the host, then `imap.rs`/`smtp.rs` resolve it again when they
//! connect. A DNS record that changes between the two lookups (classic DNS
//! rebinding) is **not** caught. Closing it means threading a pre-resolved
//! `SocketAddr` through both clients, and `lettre`'s builder does not take one — so
//! it is deliberately documented rather than solved. The guard still raises the bar
//! from "type an IP in a header" to "run rebinding infrastructure".
//!
//! [`is_public_domain`]: crate::autoconfig::is_public_domain

use std::net::{IpAddr, ToSocketAddrs};

use crate::auth::HostPort;
use crate::autoconfig::BoxFuture;
use crate::error::GatewayError;

/// Addresses the gateway must never be tricked into connecting to.
///
/// Shared by [`EndpointGuard`] (explicit `X-Mailbox-*` targets) and the autoconfig
/// fetcher's `SafeDnsResolver` (every HTTP hop of the ladder), so both paths agree
/// on what "non-public" means.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 100.64.0.0/10 CGNAT (RFC 6598).
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
                // 0.0.0.0/8 "this network".
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local fc00::/7.
                || (seg[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Hostname → addresses, behind a trait so the guard's policy is testable without
/// DNS (mirroring [`crate::autoconfig`]'s `HttpFetcher` / `SrvResolver`).
pub trait AddrResolver: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>>;
}

/// The production resolver: the system resolver via `getaddrinfo`, off the async
/// worker threads. This is the same lookup `TcpStream::connect` will perform.
pub struct SystemResolver;

impl AddrResolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
        let host = host.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                // Port is irrelevant to A/AAAA resolution; 0 is a placeholder.
                let addrs = (host.as_str(), 0u16).to_socket_addrs()?;
                Ok(addrs.map(|sa| sa.ip()).collect())
            })
            .await
            .map_err(std::io::Error::other)?
        })
    }
}

/// The opt-in public-address check applied to a provider `host:port` target.
///
/// Disabled by default ([`EndpointGuard::disabled`]) — every check passes and no
/// DNS traffic is emitted, so a self-host deployment pointing at `localhost:3143`
/// behaves exactly as before. Enabled, [`EndpointGuard::check`] rejects any target
/// that is, or resolves to, a non-public address.
pub struct EndpointGuard {
    enabled: bool,
    resolver: Box<dyn AddrResolver>,
}

impl EndpointGuard {
    /// Build a guard with an injected resolver. `enabled == false` short-circuits
    /// every check.
    pub fn new(enabled: bool, resolver: Box<dyn AddrResolver>) -> Self {
        EndpointGuard { enabled, resolver }
    }

    /// The production guard: system DNS, gated on the config flag.
    pub fn from_config(enabled: bool) -> Self {
        EndpointGuard::new(enabled, Box::new(SystemResolver))
    }

    /// A permanently-off guard — the default posture, and what tests that do not
    /// exercise this policy should use.
    pub fn disabled() -> Self {
        EndpointGuard::new(false, Box::new(SystemResolver))
    }

    /// Whether the policy is being enforced.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Reject `target` if it is, or resolves to, a non-public address.
    ///
    /// `source` names where the target came from — a header name
    /// (`X-Mailbox-Imap`) or an autoconfig provenance label — and appears in the
    /// error so the caller can tell which endpoint was refused. Targets are
    /// non-secret, so the host may be echoed; no credential ever reaches here.
    ///
    /// Returns [`GatewayError::BadRequest`] for a blocked address (deliberately a
    /// different code from `host_unreachable`, so a caller can distinguish "policy
    /// refused this" from "the host is down") and
    /// [`GatewayError::HostUnreachable`] when the name does not resolve at all.
    pub async fn check(&self, source: &str, target: &HostPort) -> Result<(), GatewayError> {
        if !self.enabled {
            return Ok(());
        }

        let host = target.host.trim().trim_end_matches('.');
        // `[::1]:993` parses into the bracketed literal `[::1]`; unwrap it before
        // trying to read it as an address.
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);

        // An IP literal needs no lookup — judge it directly.
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return if is_forbidden_ip(ip) {
                Err(blocked(source, host))
            } else {
                Ok(())
            };
        }

        // Names that never denote a public host, refused without a lookup (a
        // split-horizon resolver could otherwise answer with a routable address).
        let lower = bare.to_ascii_lowercase();
        if lower == "localhost"
            || lower.ends_with(".localhost")
            || lower.ends_with(".local")
            || lower.ends_with(".internal")
        {
            return Err(blocked(source, host));
        }

        let addrs = self.resolver.lookup(bare).await.map_err(|e| {
            GatewayError::HostUnreachable(format!("cannot resolve {source} host '{host}': {e}"))
        })?;
        if addrs.is_empty() {
            return Err(GatewayError::HostUnreachable(format!(
                "{source} host '{host}' has no addresses"
            )));
        }
        // Reject if ANY answer is non-public: a record set mixing a public and a
        // private address would otherwise be a free rebinding primitive.
        if addrs.iter().copied().any(is_forbidden_ip) {
            return Err(blocked(source, host));
        }
        Ok(())
    }
}

/// The refusal. Names the endpoint and the knob, echoes no credential.
fn blocked(source: &str, host: &str) -> GatewayError {
    GatewayError::BadRequest(format!(
        "{source} host '{host}' is not a public address; this gateway refuses loopback, \
         private, link-local, and CGNAT endpoints (OVERFWD_BLOCK_PRIVATE_ENDPOINTS)"
    ))
}

/// In-memory resolver fake, shared by this module's tests and `auth.rs`'s.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;

    /// A resolver answering from a fixed table; unknown hosts fail to resolve.
    pub struct FakeResolver {
        answers: HashMap<String, Vec<IpAddr>>,
    }

    impl AddrResolver for FakeResolver {
        fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
            let answer = self.answers.get(&host.to_ascii_lowercase()).cloned();
            Box::pin(async move {
                answer.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no such host")
                })
            })
        }
    }

    /// An enforcing guard whose DNS answers come from `(host, &[ip])` pairs.
    pub fn enforcing(answers: &[(&str, &[&str])]) -> EndpointGuard {
        let answers = answers
            .iter()
            .map(|(host, ips)| {
                (
                    host.to_ascii_lowercase(),
                    ips.iter().map(|ip| ip.parse().unwrap()).collect(),
                )
            })
            .collect();
        EndpointGuard::new(true, Box::new(FakeResolver { answers }))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::enforcing;
    use super::*;

    fn hp(host: &str) -> HostPort {
        HostPort {
            host: host.to_string(),
            port: 993,
        }
    }

    /// Every literal an attacker would reach for, refused with `bad_request`.
    #[tokio::test]
    async fn enforcing_rejects_non_public_literals() {
        let guard = enforcing(&[]);
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            // The cloud metadata endpoint — the reason this flag exists.
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            let err = guard.check("X-Mailbox-Imap", &hp(host)).await.unwrap_err();
            assert_eq!(err.code(), "bad_request", "{host} was not refused");
            assert!(
                err.message().contains("X-Mailbox-Imap"),
                "{host}: error does not name the header: {}",
                err.message()
            );
        }
    }

    #[tokio::test]
    async fn enforcing_rejects_internal_names_without_a_lookup() {
        // No table entries: reaching the resolver at all would be a `host_unreachable`.
        let guard = enforcing(&[]);
        for host in ["localhost", "greenmail.local", "db.internal", "LOCALHOST"] {
            let err = guard.check("X-Mailbox-Smtp", &hp(host)).await.unwrap_err();
            assert_eq!(err.code(), "bad_request", "{host} was not refused");
        }
    }

    /// The interesting attack: a perfectly ordinary name whose A record is private.
    #[tokio::test]
    async fn enforcing_rejects_a_name_resolving_to_a_private_address() {
        let guard = enforcing(&[("evil.example.com", &["10.0.0.5"])]);
        let err = guard
            .check("X-Mailbox-Imap", &hp("evil.example.com"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "bad_request");
    }

    /// A mixed record set must not let the private answer through.
    #[tokio::test]
    async fn enforcing_rejects_when_any_answer_is_private() {
        let guard = enforcing(&[("mixed.example.com", &["93.184.216.34", "169.254.169.254"])]);
        let err = guard
            .check("X-Mailbox-Imap", &hp("mixed.example.com"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "bad_request");
    }

    #[tokio::test]
    async fn enforcing_accepts_a_public_host_and_literal() {
        let guard = enforcing(&[("imap.fastmail.com", &["103.168.172.45"])]);
        guard
            .check("X-Mailbox-Imap", &hp("imap.fastmail.com"))
            .await
            .unwrap();
        guard
            .check("X-Mailbox-Imap", &hp("93.184.216.34"))
            .await
            .unwrap();
    }

    /// An unresolvable name is "unreachable", not "refused" — the two stay distinct.
    #[tokio::test]
    async fn unresolvable_host_is_host_unreachable_not_bad_request() {
        let guard = enforcing(&[]);
        let err = guard
            .check("X-Mailbox-Imap", &hp("nope.example.com"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "host_unreachable");
    }

    /// The default posture: everything the enforcing guard refuses is allowed, and
    /// no lookup is attempted (an empty fake table would otherwise error).
    #[tokio::test]
    async fn disabled_guard_allows_everything() {
        let guard = EndpointGuard::disabled();
        assert!(!guard.enabled());
        for host in ["localhost", "127.0.0.1", "169.254.169.254", "::1"] {
            guard.check("X-Mailbox-Imap", &hp(host)).await.unwrap();
        }
    }
}
