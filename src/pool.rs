//! Ephemeral in-memory IMAP connection pool (SPEC §4 "Connection pooling").
//!
//! A logged-in IMAP connection is expensive: TCP, an optional TLS handshake, and a
//! `LOGIN` round-trip before the first useful command. Under the stateless request
//! model every `search`/`get` would otherwise pay that cost afresh. This pool
//! amortizes it by keeping a small set of **warm, already-authenticated** sessions
//! around for a short while and handing one back when the next request presents the
//! same credential.
//!
//! ## What it is — and deliberately is not
//!
//! - **Purely in-memory.** Idle sessions live in a process-local [`std::sync::Mutex`];
//!   nothing is written anywhere. On restart the pool is empty. This keeps the
//!   zero-persistence promise (SPEC §2, §4) honest: no credential and no mail — and
//!   now no *connection* — outlives the process.
//! - **Best-effort, per instance.** Under a serverless lifecycle an instance may be
//!   frozen or reaped between requests, so a warm connection is a lucky bonus, never
//!   a guarantee. **Per-request `LOGIN`/`SELECT` is the correct fallback** whenever
//!   no warm connection exists ([`crate::imap::search_pooled`] does exactly this).
//! - **No external store.** No Redis, no database, no cross-instance sharing — that
//!   would reintroduce the very statefulness overfwd exists to avoid (SPEC §1, §10).
//!
//! ## Shape
//!
//! - **Keyed per credential** by [`PoolKey`] — `host:port` + login + an *opaque*
//!   SHA-256 handle over the password. The raw password is never a map key, and a
//!   rotated password yields a different key (so a stale session is never reused for
//!   a new secret).
//! - **Bounded** by a global idle-connection cap; the oldest idle session is evicted
//!   **LRU** when the cap is exceeded, so memory stays bounded regardless of how many
//!   distinct credentials pass through.
//! - **Short TTL.** An idle session older than the TTL is discarded rather than
//!   reused, bounding how long a connection (and the server resources behind it) is
//!   held, and sidestepping servers that silently drop long-idle IMAP connections.
//!
//! Both the cap and the TTL are configurable via the environment ([`PoolConfig`]);
//! setting the cap to `0` disables pooling entirely (every request logs in fresh).

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::auth::MailboxCredential;
use crate::imap::ImapSession;

/// Env var: maximum number of idle connections held across *all* credentials.
/// `0` disables pooling. Defaults to [`DEFAULT_MAX_IDLE`].
const ENV_MAX_IDLE: &str = "OVERFWD_POOL_MAX_IDLE";
/// Env var: how long (seconds) an idle connection may be reused before it is
/// discarded. Defaults to [`DEFAULT_IDLE_TTL_SECS`].
const ENV_IDLE_TTL_SECS: &str = "OVERFWD_POOL_IDLE_TTL_SECS";

/// Default global idle-connection cap. Small: the pool is an amortization aid, not a
/// large steady-state connection reservoir, and a shared instance may see many
/// distinct credentials.
const DEFAULT_MAX_IDLE: usize = 32;
/// Default idle TTL. Short, per SPEC §4: long enough to amortize a burst of requests
/// for one mailbox, short enough that connections and server resources aren't held.
const DEFAULT_IDLE_TTL_SECS: u64 = 60;

/// Upper bound on how long a courtesy `LOGOUT` (on evicted/expired sessions) or a
/// liveness `NOOP` may block. A dead connection should fail fast; this stops a
/// half-open socket from hanging the request that triggered the cleanup.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Tunables for the connection pool, sourced from the environment.
///
/// Kept separate from [`crate::Config`] (the gateway's own posture) and
/// [`crate::imap::ImapSettings`] (TLS transport tuning): this is purely about how
/// aggressively warm connections are cached.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum idle connections held across all credentials. `0` disables pooling.
    pub max_idle: usize,
    /// Maximum age of an idle connection before it is discarded rather than reused.
    pub idle_ttl: Duration,
}

impl PoolConfig {
    /// Read pool tunables from the process environment, applying defaults.
    ///
    /// A present-but-unparseable value falls back to the default and logs a warning
    /// rather than failing startup: an operator's typo in an optimization knob must
    /// not take the gateway down (unlike [`crate::Config`], which fails fast on
    /// values that would make the server behave *incorrectly*).
    pub fn from_env() -> Self {
        let max_idle = parse_env(ENV_MAX_IDLE, DEFAULT_MAX_IDLE);
        let idle_ttl_secs = parse_env(ENV_IDLE_TTL_SECS, DEFAULT_IDLE_TTL_SECS);
        PoolConfig {
            max_idle,
            idle_ttl: Duration::from_secs(idle_ttl_secs),
        }
    }

    /// A configuration with pooling switched off (every request logs in fresh).
    pub fn disabled() -> Self {
        PoolConfig {
            max_idle: 0,
            idle_ttl: Duration::ZERO,
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            max_idle: DEFAULT_MAX_IDLE,
            idle_ttl: Duration::from_secs(DEFAULT_IDLE_TTL_SECS),
        }
    }
}

/// Parse an env var into a `FromStr` value, falling back to `default` (with a warning)
/// when the value is present but unparseable, and silently when it is absent.
fn parse_env<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    match std::env::var(name) {
        Ok(raw) => match raw.trim().parse::<T>() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("{name}='{raw}' is not a valid value; using the default instead");
                default
            }
        },
        Err(_) => default,
    }
}

/// The opaque per-credential pool key (SPEC §4).
///
/// Equality (and therefore reuse) requires the IMAP `host:port`, the login, **and**
/// the password to all match. `host`/`port`/`username` are non-secret and kept in the
/// clear; the password contributes only as a SHA-256 [`secret_digest`](Self), so the
/// raw secret is never a plaintext map key. A changed password produces a different
/// digest, and thus a different key — a session authenticated with the old secret is
/// never handed to a request presenting a new one.
#[derive(Clone, PartialEq, Eq)]
pub struct PoolKey {
    host: String,
    port: u16,
    username: String,
    secret_digest: [u8; 32],
}

impl PoolKey {
    /// Derive the key from an Inline mailbox credential. Reads target the IMAP
    /// endpoint, so the key is scoped to `cred.imap` (not SMTP).
    pub fn from_cred(cred: &MailboxCredential) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, cred.password.expose().as_bytes());
        let mut secret_digest = [0u8; 32];
        secret_digest.copy_from_slice(digest.as_ref());
        PoolKey {
            host: cred.imap.host.clone(),
            port: cred.imap.port,
            username: cred.username.clone(),
            secret_digest,
        }
    }
}

/// Redacts the password digest so a `{:?}` of the key can never become an offline
/// dictionary-attack oracle against the mailbox password. The non-secret target and
/// login are shown, matching [`crate::auth::MailboxCredential`]'s `Debug`.
impl std::fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolKey")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("secret_digest", &"***redacted***")
            .finish()
    }
}

/// The ephemeral IMAP connection pool.
///
/// Cheap to `clone` conceptually via `Arc` at the call site; the pool itself is meant
/// to be held once behind the shared application state and shared by reference.
pub struct ImapPool {
    inner: Mutex<Reservoir<ImapSession>>,
    config: PoolConfig,
}

impl ImapPool {
    /// Build a pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        ImapPool {
            inner: Mutex::new(Reservoir::new()),
            config,
        }
    }

    /// Build a pool configured from the environment ([`PoolConfig::from_env`]).
    pub fn from_env() -> Self {
        ImapPool::new(PoolConfig::from_env())
    }

    /// Whether pooling is active. When `false`, [`take_warm`](Self::take_warm) always
    /// misses and [`give_back`](Self::give_back) closes the session immediately.
    pub fn is_enabled(&self) -> bool {
        self.config.max_idle > 0
    }

    /// The current number of idle connections held. Primarily for tests and metrics.
    pub fn idle_count(&self) -> usize {
        self.lock().len()
    }

    /// Try to take a warm, **live** session for `cred`, or `None` on a miss.
    ///
    /// On a hit the candidate is validated with a `NOOP` before being returned: a
    /// server may have dropped a long-idle connection, and handing a caller a dead
    /// session would turn a cache hit into a spurious error. A candidate that fails
    /// the `NOOP` (or times out) is discarded and treated as a miss, so the caller
    /// falls back to a fresh `LOGIN` — the correct fallback (SPEC §4). Any expired
    /// sessions swept while searching are closed politely.
    pub async fn take_warm(&self, cred: &MailboxCredential) -> Option<ImapSession> {
        if !self.is_enabled() {
            return None;
        }
        let key = PoolKey::from_cred(cred);
        let now = Instant::now();
        let (candidate, expired) = {
            let mut res = self.lock();
            res.take(&key, now, self.config.idle_ttl)
        };
        close_all(expired).await;

        let mut session = candidate?;
        match tokio::time::timeout(IO_TIMEOUT, session.noop()).await {
            Ok(Ok(())) => Some(session),
            // Dead or unresponsive — drop it and let the caller log in fresh.
            _ => {
                close(session).await;
                None
            }
        }
    }

    /// Return a healthy session to the pool for later reuse (best-effort).
    ///
    /// If pooling is disabled the session is logged out instead. Inserting may push
    /// the pool over its cap or reveal expired entries; any such sessions are evicted
    /// **LRU-first** and closed politely, outside the lock. Callers must only return
    /// sessions they believe are healthy — a session that just hit a transport error
    /// should be closed by the caller, not returned here (see
    /// [`crate::imap::search_pooled`]).
    pub async fn give_back(&self, cred: &MailboxCredential, session: ImapSession) {
        if !self.is_enabled() {
            close(session).await;
            return;
        }
        let key = PoolKey::from_cred(cred);
        let now = Instant::now();
        let evicted = {
            let mut res = self.lock();
            res.put(
                key,
                session,
                now,
                self.config.idle_ttl,
                self.config.max_idle,
            )
        };
        close_all(evicted).await;
    }

    /// Lock the reservoir, recovering from a poisoned mutex. A panic while another
    /// request held the lock must not permanently break pooling for every subsequent
    /// request; the idle set is just a cache, safe to keep using.
    fn lock(&self) -> std::sync::MutexGuard<'_, Reservoir<ImapSession>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Politely `LOGOUT` a session, bounded by [`IO_TIMEOUT`]. Errors and timeouts are
/// ignored: the session is being discarded regardless, and a failed close must not
/// surface as a request error.
async fn close(mut session: ImapSession) {
    let _ = tokio::time::timeout(IO_TIMEOUT, session.logout()).await;
}

/// Close a batch of discarded sessions.
async fn close_all(sessions: Vec<ImapSession>) {
    for session in sessions {
        close(session).await;
    }
}

// ---------------------------------------------------------------------------
// Reservoir — the storage/eviction core, generic over the connection type so its
// LRU/TTL/capacity behaviour is unit-testable without a live IMAP server.
// ---------------------------------------------------------------------------

/// A bounded, LRU, TTL'd set of idle connections keyed by [`PoolKey`].
///
/// Ordering invariant: `entries` runs **front = least-recently-used** to
/// **back = most-recently-used**. A returned connection is pushed to the back; the
/// front is evicted first. Generic over `T` purely so tests can exercise the policy
/// with cheap stand-in "connections".
struct Reservoir<T> {
    entries: VecDeque<Entry<T>>,
}

/// One idle connection plus the bookkeeping the reservoir needs.
struct Entry<T> {
    key: PoolKey,
    conn: T,
    /// When the connection was last returned to the pool; TTL is measured from here.
    stored_at: Instant,
}

impl<T> Reservoir<T> {
    fn new() -> Self {
        Reservoir {
            entries: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Take the most-recently-used live entry matching `key`, if any.
    ///
    /// Expired entries (older than `ttl`) are swept out first and returned for
    /// closing, so a stale connection is never handed back and dead entries don't
    /// accumulate. Returns `(hit, expired)`.
    fn take(&mut self, key: &PoolKey, now: Instant, ttl: Duration) -> (Option<T>, Vec<T>) {
        let expired = self.drain_expired(now, ttl);
        // Search from the back so the freshest matching connection is reused.
        let idx = self.entries.iter().rposition(|e| &e.key == key);
        let hit = idx.and_then(|i| self.entries.remove(i)).map(|e| e.conn);
        (hit, expired)
    }

    /// Insert `conn` as most-recently-used, enforcing the TTL and the global cap.
    ///
    /// Returns every connection that must be closed: any expired entries swept in
    /// passing, plus the LRU entries evicted to bring the pool back within
    /// `max_idle`. With `max_idle == 0` the just-inserted connection is itself
    /// evicted, so a disabled pool never retains anything.
    fn put(
        &mut self,
        key: PoolKey,
        conn: T,
        now: Instant,
        ttl: Duration,
        max_idle: usize,
    ) -> Vec<T> {
        let mut dead = self.drain_expired(now, ttl);
        self.entries.push_back(Entry {
            key,
            conn,
            stored_at: now,
        });
        while self.entries.len() > max_idle {
            if let Some(evicted) = self.entries.pop_front() {
                dead.push(evicted.conn);
            } else {
                break;
            }
        }
        dead
    }

    /// Remove and return every entry whose age is `>= ttl`. Relative order of the
    /// survivors is preserved (so the LRU..MRU invariant holds).
    fn drain_expired(&mut self, now: Instant, ttl: Duration) -> Vec<T> {
        let mut dead = Vec::new();
        let mut i = 0;
        while i < self.entries.len() {
            if now.saturating_duration_since(self.entries[i].stored_at) >= ttl {
                // remove shifts later elements down; don't advance `i`.
                if let Some(e) = self.entries.remove(i) {
                    dead.push(e.conn);
                }
            } else {
                i += 1;
            }
        }
        dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{HostPort, Secret};

    fn cred(host: &str, port: u16, user: &str, pass: &str) -> MailboxCredential {
        MailboxCredential {
            username: user.to_string(),
            password: Secret::new(pass.to_string()),
            imap: HostPort {
                host: host.to_string(),
                port,
            },
            smtp: HostPort {
                host: host.to_string(),
                port: 3025,
            },
        }
    }

    fn key(host: &str, port: u16, user: &str, pass: &str) -> PoolKey {
        PoolKey::from_cred(&cred(host, port, user, pass))
    }

    // ---- PoolKey identity ----

    #[test]
    fn key_matches_for_identical_credentials() {
        assert_eq!(
            key("mail.example.com", 993, "alice", "s3cr3t"),
            key("mail.example.com", 993, "alice", "s3cr3t"),
        );
    }

    #[test]
    fn key_differs_when_password_changes() {
        // A rotated password must not reuse a session authed with the old one.
        assert_ne!(
            key("mail.example.com", 993, "alice", "old-pass"),
            key("mail.example.com", 993, "alice", "new-pass"),
        );
    }

    #[test]
    fn key_differs_across_login_host_and_port() {
        let base = key("mail.example.com", 993, "alice", "pw");
        assert_ne!(base, key("mail.example.com", 993, "bob", "pw"));
        assert_ne!(base, key("other.example.com", 993, "alice", "pw"));
        assert_ne!(base, key("mail.example.com", 143, "alice", "pw"));
    }

    #[test]
    fn key_debug_redacts_password_digest_but_shows_target() {
        let rendered = format!("{:?}", key("mail.example.com", 993, "alice", "hunter2"));
        assert!(rendered.contains("mail.example.com"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        // Neither the password nor its raw digest bytes should be present.
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    // ---- Reservoir policy (generic over a stand-in connection = i32) ----

    const TTL: Duration = Duration::from_secs(60);
    const BIG: usize = 100;

    fn kx(n: u16) -> PoolKey {
        key("h", n, "u", "p")
    }

    #[test]
    fn miss_on_empty_and_on_unknown_key() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let now = Instant::now();
        let (hit, dead) = r.take(&kx(1), now, TTL);
        assert!(hit.is_none());
        assert!(dead.is_empty());
    }

    #[test]
    fn put_then_take_roundtrips_by_key() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let now = Instant::now();
        assert!(r.put(kx(1), 111, now, TTL, BIG).is_empty());
        assert!(r.put(kx(2), 222, now, TTL, BIG).is_empty());
        assert_eq!(r.len(), 2);

        let (hit, _) = r.take(&kx(2), now, TTL);
        assert_eq!(hit, Some(222));
        // Taking removes it; the other key is untouched.
        assert_eq!(r.len(), 1);
        let (hit1, _) = r.take(&kx(1), now, TTL);
        assert_eq!(hit1, Some(111));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn take_returns_most_recently_used_for_a_key() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let now = Instant::now();
        // Two connections for the SAME credential; MRU (returned last) comes out first.
        r.put(kx(1), 1, now, TTL, BIG);
        r.put(kx(1), 2, now, TTL, BIG);
        let (hit, _) = r.take(&kx(1), now, TTL);
        assert_eq!(hit, Some(2));
        let (hit, _) = r.take(&kx(1), now, TTL);
        assert_eq!(hit, Some(1));
    }

    #[test]
    fn cap_evicts_least_recently_used_first() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let now = Instant::now();
        let max = 2;
        assert!(r.put(kx(1), 1, now, TTL, max).is_empty());
        assert!(r.put(kx(2), 2, now, TTL, max).is_empty());
        // Third insert exceeds the cap → evict the LRU (the first, value 1).
        let evicted = r.put(kx(3), 3, now, TTL, max);
        assert_eq!(evicted, vec![1]);
        assert_eq!(r.len(), 2);
        // The survivors are 2 and 3.
        assert_eq!(r.take(&kx(1), now, TTL).0, None);
        assert_eq!(r.take(&kx(2), now, TTL).0, Some(2));
        assert_eq!(r.take(&kx(3), now, TTL).0, Some(3));
    }

    #[test]
    fn zero_cap_never_retains() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let now = Instant::now();
        let evicted = r.put(kx(1), 42, now, TTL, 0);
        assert_eq!(evicted, vec![42], "the just-inserted conn is evicted");
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn expired_entries_are_swept_on_take() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let t0 = Instant::now();
        r.put(kx(1), 1, t0, TTL, BIG);
        r.put(kx(2), 2, t0, TTL, BIG);
        // Well past the TTL: both are expired and swept, none returned as a hit.
        let later = t0 + TTL + Duration::from_secs(1);
        let (hit, mut dead) = r.take(&kx(1), later, TTL);
        assert_eq!(hit, None);
        dead.sort_unstable();
        assert_eq!(dead, vec![1, 2]);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn expired_entries_are_swept_on_put() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let t0 = Instant::now();
        r.put(kx(1), 1, t0, TTL, BIG);
        let later = t0 + TTL + Duration::from_secs(1);
        // Inserting later sweeps the stale entry and keeps only the fresh one.
        let dead = r.put(kx(2), 2, later, TTL, BIG);
        assert_eq!(dead, vec![1]);
        assert_eq!(r.len(), 1);
        assert_eq!(r.take(&kx(2), later, TTL).0, Some(2));
    }

    #[test]
    fn entry_just_under_ttl_is_still_reusable() {
        let mut r: Reservoir<i32> = Reservoir::new();
        let t0 = Instant::now();
        r.put(kx(1), 7, t0, TTL, BIG);
        // One second short of the TTL → still live.
        let almost = t0 + TTL - Duration::from_secs(1);
        assert_eq!(r.take(&kx(1), almost, TTL).0, Some(7));
    }

    // ---- ImapPool config gating ----

    #[test]
    fn disabled_pool_reports_not_enabled() {
        let pool = ImapPool::new(PoolConfig::disabled());
        assert!(!pool.is_enabled());
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn enabled_pool_reports_enabled() {
        let pool = ImapPool::new(PoolConfig::default());
        assert!(pool.is_enabled());
    }
}
