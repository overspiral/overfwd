# Changelog

## [0.2.0](https://github.com/overspiral/overfwd/compare/v0.1.0...v0.2.0) (2026-07-13)


### Features

* **autoconfig:** resolve via MX provider's own autoconfig, not just ISPDB ([#19](https://github.com/overspiral/overfwd/issues/19)) ([0de5da5](https://github.com/overspiral/overfwd/commit/0de5da5a9ba9c4ff310bde7f3744d637727d3db2))


### Bug Fixes

* **auth:** strip trailing newline from decoded X-Mailbox-Auth credential ([#20](https://github.com/overspiral/overfwd/issues/20)) ([f0af0d6](https://github.com/overspiral/overfwd/commit/f0af0d6186233034c72615e4b652b5c5c436fca8))

## 0.1.0 (2026-07-13)

Initial release of **overfwd** — a stateless REST facade over remote IMAP/SMTP
mailboxes. A single small Rust binary that lets any HTTP client send and
read/search mail across arbitrary standard-IMAP providers. It holds no
credentials and no mail at rest: it is a pure function of the request plus the
presented mailbox credential.

### Features

* **HTTP gateway:** inline-only [axum](https://github.com/tokio-rs/axum) server with structured logging, env-based config, and graceful shutdown ([46145ee](https://github.com/overspiral/overfwd/commit/46145ee)).
* **Read mail:** `POST /email/search` and `POST /email/get`, backed by a dedicated IMAP client module ([8ece4e7](https://github.com/overspiral/overfwd/commit/8ece4e7), [5dea0d5](https://github.com/overspiral/overfwd/commit/5dea0d5)).
* **Send mail:** `POST /email/send`, backed by an SMTP submission module ([3246f90](https://github.com/overspiral/overfwd/commit/3246f90), [528960c](https://github.com/overspiral/overfwd/commit/528960c)).
* **Connection pooling:** ephemeral in-memory IMAP connection pool, keyed by an opaque SHA-256 handle so the raw mailbox password is never used as a map key ([f202cf0](https://github.com/overspiral/overfwd/commit/f202cf0)).
* **Autoconfiguration:** derives the IMAP/SMTP host:port from the user's domain when `X-Mailbox-*` host headers are absent, via Mozilla-style autoconfig XML over HTTPS with an RFC 6186 DNS SRV / MX fallback; the fetch is SSRF-guarded against private/loopback targets ([57f9a13](https://github.com/overspiral/overfwd/commit/57f9a13)).
* **OpenAPI:** code-derived OpenAPI 3.1 document (generated from the real request/response types via utoipa, so it can't drift from the handlers) served alongside a Swagger UI ([4656524](https://github.com/overspiral/overfwd/commit/4656524)).
* **Pure-Rust TLS:** rustls + ring throughout (IMAP, SMTP, and HTTP client), keeping the build free of a system OpenSSL dependency.

### Testing & Tooling

* End-to-end suite exercising the read/send/autoconfig flows against a shared GreenMail IMAP/SMTP server ([f024946](https://github.com/overspiral/overfwd/commit/f024946), [e43d196](https://github.com/overspiral/overfwd/commit/e43d196)).
* GitHub Actions CI (`fmt · clippy · build · test`) with an aggregate `ci-ok` gate ([f80e5af](https://github.com/overspiral/overfwd/commit/f80e5af)).

### Documentation

* Product README, LICENSE, `SPEC.md`, and testing docs ([d6e146a](https://github.com/overspiral/overfwd/commit/d6e146a), [ca4c517](https://github.com/overspiral/overfwd/commit/ca4c517)).
