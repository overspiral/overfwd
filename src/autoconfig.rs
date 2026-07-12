//! Email autoconfiguration — derive the provider `host:port` from the user's domain
//! when the `X-Mailbox-Imap` / `X-Mailbox-Smtp` headers are absent (SPEC §5, §8).
//!
//! A caller normally supplies the non-secret provider target explicitly. This module
//! is the fallback: given the mailbox **domain**, it resolves the IMAP and SMTP
//! endpoints the way a mail client (Thunderbird) does, over a bounded ladder:
//!
//! 1. Provider-hosted `https://autoconfig.<domain>/mail/config-v1.1.xml`.
//! 2. Well-known `https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`.
//! 3. The Thunderbird ISPDB `https://autoconfig.thunderbird.net/v1.1/<domain>`.
//! 4. RFC 6186 DNS SRV (`_imaps._tcp` / `_submissions._tcp` / …).
//! 5. MX → map the exchanger's registrable domain back onto the ISPDB (step 3).
//!
//! Only the SPEC §8 "standard-IMAP long tail" is in scope; Gmail/Outlook are not.
//!
//! ## Transport constraint
//!
//! The downstream IMAP/SMTP clients infer TLS purely from the port and support
//! **implicit TLS only** (IMAP `993`, SMTP `465`) — no STARTTLS (`imap.rs`
//! `TlsMode::for_port`, `smtp.rs` `SmtpSecurity::for_submission_port`). So this
//! module **prefers the SSL/implicit-TLS endpoint** from every source; a
//! STARTTLS-only provider is returned with a warning and will not work until
//! STARTTLS support lands (a deliberate follow-up).
//!
//! ## Testability
//!
//! The network lives behind two small traits, [`HttpFetcher`] and [`SrvResolver`],
//! so the ladder logic in [`Autoconfig::resolve`] is exercised with in-memory fakes
//! (see the tests) and the live `reqwest`/`hickory` impls are injected in production
//! by [`Autoconfig::from_env`].
//!
//! ## SSRF
//!
//! The domain is caller-influenced, so the server would otherwise fetch attacker-named
//! URLs. Two defenses: [`is_public_domain`] rejects IP literals / `localhost` / non-DNS
//! names before any request, and the live fetcher's DNS resolver ([`SafeDnsResolver`])
//! refuses to connect to loopback/private/link-local addresses on every hop.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::auth::HostPort;
use crate::error::GatewayError;

/// The constant Thunderbird ISPDB base (step 3 / step 5 of the ladder).
const ISPDB_BASE: &str = "https://autoconfig.thunderbird.net/v1.1";

/// A boxed, `Send` future — the return shape for the object-safe network traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Environment variable names, kept together for auditing (mirrors `config.rs`).
const ENV_ENABLE: &str = "OVERFWD_AUTOCONFIG_ENABLE";
const ENV_TIMEOUT_SECS: &str = "OVERFWD_AUTOCONFIG_TIMEOUT_SECS";
const ENV_CACHE_TTL_SECS: &str = "OVERFWD_AUTOCONFIG_CACHE_TTL_SECS";

/// Runtime knobs for autoconfiguration, sourced from the environment.
#[derive(Debug, Clone)]
pub struct AutoconfigSettings {
    /// Master switch. When `false`, a missing host header stays a `bad_request`
    /// (today's behavior) and no outbound autoconfig traffic is ever emitted.
    pub enabled: bool,
    /// Per-attempt HTTP/DNS timeout.
    pub timeout: Duration,
    /// How long a **successful** resolution is cached in-memory (never persisted).
    pub pos_ttl: Duration,
    /// How long a **failed** resolution is negatively cached (kept short so a
    /// provider that starts publishing autoconfig is picked up soon after).
    pub neg_ttl: Duration,
}

impl Default for AutoconfigSettings {
    fn default() -> Self {
        AutoconfigSettings {
            enabled: true,
            timeout: Duration::from_secs(5),
            pos_ttl: Duration::from_secs(3600),
            neg_ttl: Duration::from_secs(300),
        }
    }
}

impl AutoconfigSettings {
    /// Read settings from the process environment, applying defaults.
    ///
    /// `OVERFWD_AUTOCONFIG_ENABLE` is a permissive boolean (`1/true/yes/on`);
    /// anything else keeps the default (enabled). The two durations are seconds;
    /// a non-numeric or zero value falls back to the default.
    pub fn from_env() -> Self {
        let defaults = AutoconfigSettings::default();
        let enabled = std::env::var(ENV_ENABLE)
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(defaults.enabled);
        AutoconfigSettings {
            enabled,
            timeout: secs_or(ENV_TIMEOUT_SECS, defaults.timeout),
            pos_ttl: secs_or(ENV_CACHE_TTL_SECS, defaults.pos_ttl),
            neg_ttl: defaults.neg_ttl,
        }
    }
}

fn secs_or(key: &str, default: Duration) -> Duration {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(default)
}

/// A resolved provider target. Either field may be `None` when a source only yields
/// one side (e.g. a bare `_imaps._tcp` SRV record); the caller in `auth.rs` fills
/// only the header(s) it is actually missing and errors if the needed one is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailServers {
    /// IMAP endpoint (implicit-TLS preferred).
    pub imap: Option<HostPort>,
    /// SMTP submission endpoint (implicit-TLS preferred).
    pub smtp: Option<HostPort>,
}

impl MailServers {
    fn is_complete(&self) -> bool {
        self.imap.is_some() && self.smtp.is_some()
    }

    fn is_empty(&self) -> bool {
        self.imap.is_none() && self.smtp.is_none()
    }

    /// Fill any gap in `self` from `other` (first source to name a side wins).
    fn merge_from(&mut self, other: MailServers) {
        if self.imap.is_none() {
            self.imap = other.imap;
        }
        if self.smtp.is_none() {
            self.smtp = other.smtp;
        }
    }
}

/// One DNS SRV record: a target host and port (RFC 6186 mail SRV records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub host: String,
    pub port: u16,
}

/// Fetch autoconfig XML over HTTP. The live impl is [`SafeHttpFetcher`]; tests inject
/// a fake. `Ok(Some(body))` on a 2xx XML response, `Ok(None)` on a non-2xx (e.g. 404),
/// `Err` on a transport failure — the ladder treats both non-success cases as "try
/// the next rung".
pub trait HttpFetcher: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Option<String>, GatewayError>>;
}

/// Resolve mail SRV and MX records. The live impl wraps `hickory-resolver`; tests
/// inject a fake. Lookups return an empty vec (never an error) so an absent record is
/// indistinguishable from a resolver hiccup — either way the ladder moves on.
pub trait SrvResolver: Send + Sync {
    /// SRV records for `name` (e.g. `_imaps._tcp.example.com`), by priority.
    fn srv<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Vec<SrvRecord>>;
    /// MX exchanger hostnames for `domain`, by preference.
    fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<String>>;
}

struct CacheEntry {
    expires: Instant,
    value: Option<MailServers>,
}

/// The autoconfiguration resolver: the ladder, an in-memory TTL cache, and the
/// injected network backends. Construct the live form with [`Autoconfig::from_env`].
pub struct Autoconfig {
    http: Box<dyn HttpFetcher>,
    dns: Box<dyn SrvResolver>,
    settings: AutoconfigSettings,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl Autoconfig {
    /// Build a resolver from explicit parts (used by tests and by `from_env`).
    pub fn new(
        http: Box<dyn HttpFetcher>,
        dns: Box<dyn SrvResolver>,
        settings: AutoconfigSettings,
    ) -> Self {
        Autoconfig {
            http,
            dns,
            settings,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether autoconfiguration is enabled (mirrors `AutoconfigSettings::enabled`).
    pub fn enabled(&self) -> bool {
        self.settings.enabled
    }

    /// Resolve `domain` to its IMAP/SMTP endpoints, consulting the cache first.
    ///
    /// `email` (when known) is passed to provider-hosted autoconfig as
    /// `?emailaddress=`. Returns [`GatewayError::AutoconfigFailed`] when the domain is
    /// not a public hostname or the whole ladder yields nothing.
    pub async fn resolve(
        &self,
        domain: &str,
        email: Option<&str>,
    ) -> Result<MailServers, GatewayError> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !is_public_domain(&domain) {
            return Err(GatewayError::AutoconfigFailed(format!(
                "'{domain}' is not a resolvable public mail domain"
            )));
        }

        if let Some(hit) = self.cache_get(&domain) {
            return hit.ok_or_else(|| autoconfig_miss(&domain));
        }

        let resolved = self.run_ladder(&domain, email).await;
        let value = if resolved.is_empty() {
            None
        } else {
            Some(resolved)
        };
        self.cache_put(&domain, value.clone());
        value.ok_or_else(|| autoconfig_miss(&domain))
    }

    /// Walk the ladder, merging partial results until both sides are known or the
    /// rungs are exhausted. Per-rung errors are swallowed (logged) — only a fully
    /// empty result is a failure.
    async fn run_ladder(&self, domain: &str, email: Option<&str>) -> MailServers {
        let mut acc = MailServers::default();

        // Rungs 1–3: Mozilla autoconfig XML over HTTPS.
        for url in http_config_urls(domain, email) {
            if acc.is_complete() {
                break;
            }
            match self.http.get(&url).await {
                Ok(Some(body)) => {
                    if let Some(found) = parse_autoconfig(&body) {
                        acc.merge_from(found);
                    }
                }
                Ok(None) => {}
                Err(err) => tracing::debug!(%url, %err, "autoconfig fetch failed; trying next"),
            }
        }

        // Rung 4: RFC 6186 DNS SRV. Prefer implicit-TLS records (`_imaps` / `_submissions`).
        if !acc.is_complete() {
            acc.merge_from(self.srv_lookup(domain).await);
        }

        // Rung 5: MX → registrable domain → ISPDB.
        if !acc.is_complete() {
            if let Some(found) = self.mx_to_ispdb(domain).await {
                acc.merge_from(found);
            }
        }

        acc
    }

    async fn srv_lookup(&self, domain: &str) -> MailServers {
        // Implicit-TLS first (usable downstream); plaintext/STARTTLS SRV as a warned
        // fallback only if no implicit-TLS record exists.
        let imap = match first(self.dns.srv(&format!("_imaps._tcp.{domain}")).await) {
            Some(r) => Some(HostPort {
                host: r.host,
                port: r.port,
            }),
            None => first(self.dns.srv(&format!("_imap._tcp.{domain}")).await).map(|r| {
                warn_starttls("IMAP", &r.host);
                HostPort {
                    host: r.host,
                    port: r.port,
                }
            }),
        };
        let smtp = match first(self.dns.srv(&format!("_submissions._tcp.{domain}")).await) {
            Some(r) => Some(HostPort {
                host: r.host,
                port: r.port,
            }),
            None => first(self.dns.srv(&format!("_submission._tcp.{domain}")).await).map(|r| {
                warn_starttls("SMTP", &r.host);
                HostPort {
                    host: r.host,
                    port: r.port,
                }
            }),
        };
        MailServers { imap, smtp }
    }

    async fn mx_to_ispdb(&self, domain: &str) -> Option<MailServers> {
        let exchanger = first(self.dns.mx(domain).await)?;
        let mx_domain = registrable_domain(&exchanger);
        if mx_domain == domain || !is_public_domain(&mx_domain) {
            return None;
        }
        let url = format!("{ISPDB_BASE}/{mx_domain}");
        match self.http.get(&url).await {
            Ok(Some(body)) => parse_autoconfig(&body),
            _ => None,
        }
    }

    fn cache_get(&self, domain: &str) -> Option<Option<MailServers>> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.get(domain)?;
        if entry.expires > Instant::now() {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    fn cache_put(&self, domain: &str, value: Option<MailServers>) {
        let ttl = if value.is_some() {
            self.settings.pos_ttl
        } else {
            self.settings.neg_ttl
        };
        let entry = CacheEntry {
            expires: Instant::now() + ttl,
            value,
        };
        self.cache.lock().unwrap().insert(domain.to_string(), entry);
    }
}

fn autoconfig_miss(domain: &str) -> GatewayError {
    GatewayError::AutoconfigFailed(format!(
        "no mail autoconfiguration found for domain '{domain}'; supply X-Mailbox-Imap/-Smtp explicitly"
    ))
}

fn first<T>(mut v: Vec<T>) -> Option<T> {
    if v.is_empty() {
        None
    } else {
        Some(v.swap_remove(0))
    }
}

fn warn_starttls(protocol: &str, host: &str) {
    tracing::warn!(
        %protocol, %host,
        "autoconfig found only a non-implicit-TLS endpoint; downstream supports implicit TLS only \
         (993/465) — this target may not connect until STARTTLS support lands"
    );
}

/// The three HTTP autoconfig URLs, in Thunderbird's precedence order.
fn http_config_urls(domain: &str, email: Option<&str>) -> Vec<String> {
    let query = email
        .filter(|e| e.contains('@'))
        .map(|e| format!("?emailaddress={e}"))
        .unwrap_or_default();
    vec![
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml{query}"),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml{query}"),
        format!("{ISPDB_BASE}/{domain}"),
    ]
}

/// The naive registrable domain: the last two labels of a hostname. Good enough to
/// map an MX exchanger (`mx1.messagingengine.com`) to a provider key
/// (`messagingengine.com`) for the ISPDB — the PSL is out of scope here.
fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        host
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// Reject anything that is not a plausible public DNS mail domain **before** any
/// network request — the first line of SSRF defense (the domain is caller-supplied).
pub fn is_public_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    // An IP literal is never a mail domain and is the obvious SSRF vector.
    if domain.parse::<IpAddr>().is_ok() {
        return false;
    }
    let lower = domain.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

// ---------------------------------------------------------------------------------
// Autoconfig XML model (Mozilla `clientConfig`, config-v1.1). Only the incoming IMAP
// and outgoing SMTP host/port/socketType are needed.
// ---------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ClientConfig {
    #[serde(rename = "emailProvider")]
    email_provider: EmailProvider,
}

#[derive(Debug, Deserialize)]
struct EmailProvider {
    #[serde(rename = "incomingServer", default)]
    incoming: Vec<XmlServer>,
    #[serde(rename = "outgoingServer", default)]
    outgoing: Vec<XmlServer>,
}

#[derive(Debug, Deserialize)]
struct XmlServer {
    #[serde(rename = "@type", default)]
    kind: String,
    hostname: Option<String>,
    port: Option<u16>,
    #[serde(rename = "socketType", default)]
    socket_type: Option<String>,
}

/// Parse an autoconfig `clientConfig` document into a [`MailServers`], preferring the
/// implicit-TLS (`SSL`) endpoint for each side. Returns `None` if the XML does not
/// parse or names neither an IMAP nor an SMTP server.
fn parse_autoconfig(xml: &str) -> Option<MailServers> {
    let config: ClientConfig = quick_xml::de::from_str(xml).ok()?;
    let imap = pick_server(&config.email_provider.incoming, "imap");
    let smtp = pick_server(&config.email_provider.outgoing, "smtp");
    let servers = MailServers { imap, smtp };
    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

/// Choose the best server of `kind` from a list: prefer an `SSL` (implicit-TLS)
/// entry; otherwise take the first usable one and warn (STARTTLS/plain is not usable
/// downstream yet).
fn pick_server(servers: &[XmlServer], kind: &str) -> Option<HostPort> {
    let candidates: Vec<&XmlServer> = servers
        .iter()
        .filter(|s| s.kind.eq_ignore_ascii_case(kind))
        .filter(|s| s.hostname.as_deref().is_some_and(|h| !h.is_empty()) && s.port.is_some())
        .collect();

    let ssl = candidates.iter().find(|s| {
        s.socket_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("SSL"))
    });

    let chosen = match ssl {
        Some(s) => Some(*s),
        None => {
            if let Some(s) = candidates.first() {
                warn_starttls(
                    &kind.to_ascii_uppercase(),
                    s.hostname.as_deref().unwrap_or(""),
                );
                Some(*s)
            } else {
                None
            }
        }
    }?;

    Some(HostPort {
        host: chosen.hostname.clone()?,
        port: chosen.port?,
    })
}

impl Autoconfig {
    /// Build the live resolver: a `reqwest` fetcher with an SSRF-filtering DNS
    /// resolver and a `hickory` SRV/MX resolver, both bounded by the configured
    /// timeout. Reads knobs from the environment.
    pub fn from_env() -> Self {
        let settings = AutoconfigSettings::from_env();
        let http: Box<dyn HttpFetcher> = Box::new(live::SafeHttpFetcher::new(settings.timeout));
        let dns: Box<dyn SrvResolver> = Box::new(live::HickorySrvResolver::new(settings.timeout));
        Autoconfig::new(http, dns, settings)
    }
}

/// In-memory network fakes and constructors, shared by this module's tests and the
/// `auth.rs` tests (which exercise the header→credential resolve path).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A fake HTTP backend mapping exact URLs to XML bodies, counting every call.
    #[derive(Default)]
    pub struct FakeHttp {
        pub responses: HashMap<String, String>,
        pub calls: Arc<AtomicUsize>,
    }

    impl FakeHttp {
        pub fn with(url: &str, body: &str) -> Self {
            let mut responses = HashMap::new();
            responses.insert(url.to_string(), body.to_string());
            FakeHttp {
                responses,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl HttpFetcher for FakeHttp {
        fn get<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Option<String>, GatewayError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let body = self.responses.get(url).cloned();
            Box::pin(async move { Ok(body) })
        }
    }

    #[derive(Default)]
    pub struct FakeSrv {
        pub srv: HashMap<String, Vec<SrvRecord>>,
        pub mx: HashMap<String, Vec<String>>,
    }

    impl SrvResolver for FakeSrv {
        fn srv<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Vec<SrvRecord>> {
            let recs = self.srv.get(name).cloned().unwrap_or_default();
            Box::pin(async move { recs })
        }
        fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<String>> {
            let recs = self.mx.get(domain).cloned().unwrap_or_default();
            Box::pin(async move { recs })
        }
    }

    pub fn ac(http: FakeHttp, dns: FakeSrv) -> Autoconfig {
        Autoconfig::new(Box::new(http), Box::new(dns), AutoconfigSettings::default())
    }

    /// A resolver that serves `xml` for `domain` via the ISPDB rung; every other
    /// domain (and every SRV/MX lookup) misses.
    pub fn ispdb(domain: &str, xml: &str) -> Autoconfig {
        ac(
            FakeHttp::with(&format!("{ISPDB_BASE}/{domain}"), xml),
            FakeSrv::default(),
        )
    }

    /// A resolver with no data — every lookup misses (autoconfig enabled).
    pub fn empty() -> Autoconfig {
        ac(FakeHttp::default(), FakeSrv::default())
    }

    /// A resolver with autoconfig disabled (the master switch is off).
    pub fn disabled() -> Autoconfig {
        Autoconfig::new(
            Box::new(FakeHttp::default()),
            Box::new(FakeSrv::default()),
            AutoconfigSettings {
                enabled: false,
                ..AutoconfigSettings::default()
            },
        )
    }

    /// A minimal SSL-everywhere autoconfig document for `fastmail.com`.
    pub const FASTMAIL_XML: &str = r#"<?xml version="1.0"?>
        <clientConfig version="1.1">
          <emailProvider id="fastmail.com">
            <incomingServer type="imap">
              <hostname>imap.fastmail.com</hostname>
              <port>993</port>
              <socketType>SSL</socketType>
            </incomingServer>
            <outgoingServer type="smtp">
              <hostname>smtp.fastmail.com</hostname>
              <port>465</port>
              <socketType>SSL</socketType>
            </outgoingServer>
          </emailProvider>
        </clientConfig>"#;
}

#[cfg(test)]
mod tests {
    use super::testing::{ac, FakeHttp, FakeSrv, FASTMAIL_XML};
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn parse_prefers_ssl_endpoint() {
        let xml = r#"<clientConfig version="1.1"><emailProvider id="x">
            <incomingServer type="imap">
              <hostname>imap.x.test</hostname><port>143</port><socketType>STARTTLS</socketType>
            </incomingServer>
            <incomingServer type="imap">
              <hostname>imap.x.test</hostname><port>993</port><socketType>SSL</socketType>
            </incomingServer>
            <outgoingServer type="smtp">
              <hostname>smtp.x.test</hostname><port>465</port><socketType>SSL</socketType>
            </outgoingServer>
          </emailProvider></clientConfig>"#;
        let servers = parse_autoconfig(xml).unwrap();
        assert_eq!(
            servers.imap.unwrap().port,
            993,
            "must pick the SSL entry, not STARTTLS"
        );
        assert_eq!(servers.smtp.unwrap().port, 465);
    }

    #[test]
    fn parse_falls_back_to_starttls_when_no_ssl() {
        let xml = r#"<clientConfig version="1.1"><emailProvider id="x">
            <incomingServer type="imap">
              <hostname>imap.x.test</hostname><port>143</port><socketType>STARTTLS</socketType>
            </incomingServer>
          </emailProvider></clientConfig>"#;
        let servers = parse_autoconfig(xml).unwrap();
        assert_eq!(servers.imap.unwrap().port, 143);
        assert!(servers.smtp.is_none());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_autoconfig("not xml at all").is_none());
        assert!(
            parse_autoconfig("<clientConfig><emailProvider id=\"x\"/></clientConfig>").is_none()
        );
    }

    #[tokio::test]
    async fn resolves_from_provider_hosted_xml() {
        let url =
            "https://autoconfig.fastmail.com/mail/config-v1.1.xml?emailaddress=jane@fastmail.com";
        let ac = ac(FakeHttp::with(url, FASTMAIL_XML), FakeSrv::default());
        let servers = ac
            .resolve("fastmail.com", Some("jane@fastmail.com"))
            .await
            .unwrap();
        assert_eq!(servers.imap.unwrap().host, "imap.fastmail.com");
        assert_eq!(servers.smtp.unwrap().port, 465);
    }

    #[tokio::test]
    async fn falls_back_to_ispdb_when_provider_silent() {
        let url = format!("{ISPDB_BASE}/fastmail.com");
        let ac = ac(FakeHttp::with(&url, FASTMAIL_XML), FakeSrv::default());
        // No email → no ?emailaddress= and provider/well-known return nothing.
        let servers = ac.resolve("fastmail.com", None).await.unwrap();
        assert_eq!(servers.imap.unwrap().host, "imap.fastmail.com");
    }

    #[tokio::test]
    async fn falls_back_to_srv() {
        let mut dns = FakeSrv::default();
        dns.srv.insert(
            "_imaps._tcp.example.com".to_string(),
            vec![SrvRecord {
                host: "imap.example.com".to_string(),
                port: 993,
            }],
        );
        dns.srv.insert(
            "_submissions._tcp.example.com".to_string(),
            vec![SrvRecord {
                host: "smtp.example.com".to_string(),
                port: 465,
            }],
        );
        let ac = ac(FakeHttp::default(), dns);
        let servers = ac.resolve("example.com", None).await.unwrap();
        assert_eq!(servers.imap.unwrap().host, "imap.example.com");
        assert_eq!(servers.smtp.unwrap().port, 465);
    }

    #[tokio::test]
    async fn falls_back_to_mx_then_ispdb() {
        let mut dns = FakeSrv::default();
        dns.mx.insert(
            "customdomain.test".to_string(),
            vec!["mx1.messagingengine.com".to_string()],
        );
        let ispdb = format!("{ISPDB_BASE}/messagingengine.com");
        let ac = ac(FakeHttp::with(&ispdb, FASTMAIL_XML), dns);
        let servers = ac.resolve("customdomain.test", None).await.unwrap();
        assert_eq!(servers.imap.unwrap().host, "imap.fastmail.com");
    }

    #[tokio::test]
    async fn exhausted_ladder_is_autoconfig_failed() {
        let ac = ac(FakeHttp::default(), FakeSrv::default());
        let err = ac.resolve("nowhere.test", None).await.unwrap_err();
        assert_eq!(err.code(), "autoconfig_failed");
    }

    #[tokio::test]
    async fn positive_result_is_cached() {
        let url = format!("{ISPDB_BASE}/fastmail.com");
        let http = FakeHttp::with(&url, FASTMAIL_XML);
        let calls = http.calls.clone();
        let ac = ac(http, FakeSrv::default());

        ac.resolve("fastmail.com", None).await.unwrap();
        let after_first = calls.load(Ordering::SeqCst);
        ac.resolve("fastmail.com", None).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_first,
            "second resolve must be served from cache — no new fetches"
        );
    }

    #[tokio::test]
    async fn negative_result_is_cached() {
        let http = FakeHttp::default();
        let calls = http.calls.clone();
        let ac = ac(http, FakeSrv::default());
        assert!(ac.resolve("nowhere.test", None).await.is_err());
        let after_first = calls.load(Ordering::SeqCst);
        assert!(ac.resolve("nowhere.test", None).await.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_first,
            "miss must be cached too"
        );
    }

    #[tokio::test]
    async fn rejects_ssrf_domains_before_any_fetch() {
        let http = FakeHttp::default();
        let calls = http.calls.clone();
        let ac = ac(http, FakeSrv::default());
        for bad in [
            "localhost",
            "127.0.0.1",
            "10.0.0.5",
            "foo.internal",
            "[::1]",
        ] {
            let err = ac.resolve(bad, None).await.unwrap_err();
            assert_eq!(err.code(), "autoconfig_failed", "{bad} must be rejected");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no network for rejected domains"
        );
    }

    #[test]
    fn public_domain_validation() {
        assert!(is_public_domain("fastmail.com"));
        assert!(is_public_domain("mail.example.co.uk"));
        assert!(!is_public_domain("localhost"));
        assert!(!is_public_domain("nodot"));
        assert!(!is_public_domain("127.0.0.1"));
        assert!(!is_public_domain("::1"));
        assert!(!is_public_domain("host.internal"));
        assert!(!is_public_domain("-bad.example.com"));
        assert!(!is_public_domain(""));
    }

    #[test]
    fn registrable_domain_takes_last_two_labels() {
        assert_eq!(
            registrable_domain("mx1.messagingengine.com"),
            "messagingengine.com"
        );
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.c.d.test."), "d.test");
    }

    #[test]
    fn config_urls_include_email_only_when_present() {
        let with = http_config_urls("d.test", Some("u@d.test"));
        assert!(with[0].ends_with("?emailaddress=u@d.test"));
        let without = http_config_urls("d.test", None);
        assert!(without[0].ends_with("config-v1.1.xml"));
        // ISPDB rung never carries the email query.
        assert_eq!(without[2], format!("{ISPDB_BASE}/d.test"));
    }
}

/// Live network backends (`reqwest` + `hickory-resolver`). Kept in a submodule so the
/// pure ladder logic above stays free of transport detail and easy to test with fakes.
mod live {
    use std::error::Error;
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use hickory_resolver::TokioAsyncResolver;
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};

    use super::{BoxFuture, GatewayError, HttpFetcher, SrvRecord, SrvResolver};

    /// Cap on an autoconfig response body — the documents are a few KB; anything
    /// larger is treated as a non-answer (defense against a hostile endpoint).
    const MAX_BODY: usize = 256 * 1024;

    /// Install `ring` as the process-wide rustls crypto provider exactly once. The
    /// `reqwest` `*-no-provider` feature relies on a process default being present;
    /// pinning it to `ring` keeps the build off aws-lc-rs / a C toolchain (matching
    /// the rest of the TLS stack).
    fn install_ring_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// `reqwest`-backed HTTP fetcher used in production.
    pub(super) struct SafeHttpFetcher {
        client: Option<reqwest::Client>,
    }

    impl SafeHttpFetcher {
        pub(super) fn new(timeout: Duration) -> Self {
            install_ring_provider();
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(timeout)
                .user_agent("overfwd-autoconfig")
                // A hostile provider could redirect; the SSRF DNS filter runs on
                // every hop, so cap the count rather than chase arbitrarily.
                .redirect(reqwest::redirect::Policy::limited(3))
                .dns_resolver(Arc::new(SafeDnsResolver))
                .build()
                .ok();
            SafeHttpFetcher { client }
        }
    }

    impl HttpFetcher for SafeHttpFetcher {
        fn get<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Option<String>, GatewayError>> {
            Box::pin(async move {
                let client = self.client.as_ref().ok_or_else(|| {
                    GatewayError::AutoconfigFailed("autoconfig HTTP client unavailable".to_string())
                })?;
                let mut resp =
                    client.get(url).send().await.map_err(|e| {
                        GatewayError::AutoconfigFailed(format!("fetch failed: {e}"))
                    })?;
                if !resp.status().is_success() {
                    return Ok(None);
                }
                if resp
                    .content_length()
                    .is_some_and(|len| len as usize > MAX_BODY)
                {
                    return Ok(None);
                }
                let mut body: Vec<u8> = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(|e| GatewayError::AutoconfigFailed(format!("read failed: {e}")))?
                {
                    if body.len() + chunk.len() > MAX_BODY {
                        return Ok(None);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(String::from_utf8(body).ok())
            })
        }
    }

    /// A `reqwest` DNS resolver that drops loopback/private/link-local addresses, so
    /// the fetcher can never be steered at an internal service by a caller-chosen
    /// domain (SSRF), including across redirects.
    struct SafeDnsResolver;

    impl Resolve for SafeDnsResolver {
        fn resolve(&self, name: Name) -> Resolving {
            Box::pin(async move {
                let host = name.as_str().to_string();
                let filtered = tokio::task::spawn_blocking(move || {
                    // Port is irrelevant to A/AAAA resolution; 0 is a placeholder.
                    let addrs = (host.as_str(), 0u16).to_socket_addrs()?;
                    let kept: Vec<SocketAddr> =
                        addrs.filter(|sa| !is_forbidden_ip(sa.ip())).collect();
                    Ok::<_, std::io::Error>(kept)
                })
                .await;

                match filtered {
                    Ok(Ok(addrs)) if !addrs.is_empty() => {
                        let iter: Addrs = Box::new(addrs.into_iter());
                        Ok(iter)
                    }
                    Ok(Ok(_)) => {
                        let e: Box<dyn Error + Send + Sync> =
                            "refusing to connect to a non-public address".into();
                        Err(e)
                    }
                    Ok(Err(e)) => Err(Box::new(e) as Box<dyn Error + Send + Sync>),
                    Err(e) => Err(Box::new(e) as Box<dyn Error + Send + Sync>),
                }
            })
        }
    }

    /// Addresses the gateway must never be tricked into connecting to.
    fn is_forbidden_ip(ip: IpAddr) -> bool {
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

    /// `hickory-resolver`-backed SRV/MX lookups used in production.
    pub(super) struct HickorySrvResolver {
        resolver: TokioAsyncResolver,
    }

    impl HickorySrvResolver {
        pub(super) fn new(timeout: Duration) -> Self {
            let (config, mut opts) = hickory_resolver::system_conf::read_system_conf()
                .unwrap_or_else(|_| {
                    (
                        hickory_resolver::config::ResolverConfig::cloudflare(),
                        hickory_resolver::config::ResolverOpts::default(),
                    )
                });
            opts.timeout = timeout;
            opts.attempts = 1;
            HickorySrvResolver {
                resolver: TokioAsyncResolver::tokio(config, opts),
            }
        }
    }

    impl SrvResolver for HickorySrvResolver {
        fn srv<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Vec<SrvRecord>> {
            Box::pin(async move {
                match self.resolver.srv_lookup(name).await {
                    Ok(lookup) => lookup
                        .iter()
                        .filter_map(|srv| {
                            let host = srv.target().to_utf8();
                            let host = host.trim_end_matches('.').to_string();
                            // A single "." target means "service not provided" (RFC 2782).
                            if host.is_empty() {
                                None
                            } else {
                                Some(SrvRecord {
                                    host,
                                    port: srv.port(),
                                })
                            }
                        })
                        .collect(),
                    Err(_) => vec![],
                }
            })
        }

        fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<String>> {
            Box::pin(async move {
                match self.resolver.mx_lookup(domain).await {
                    Ok(lookup) => {
                        let mut records: Vec<(u16, String)> = lookup
                            .iter()
                            .map(|mx| {
                                let host =
                                    mx.exchange().to_utf8().trim_end_matches('.').to_string();
                                (mx.preference(), host)
                            })
                            .filter(|(_, host)| !host.is_empty())
                            .collect();
                        // Lowest preference value first (most-preferred exchanger).
                        records.sort_by_key(|(pref, _)| *pref);
                        records.into_iter().map(|(_, host)| host).collect()
                    }
                    Err(_) => vec![],
                }
            })
        }
    }
}
