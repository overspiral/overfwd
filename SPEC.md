# overfwd — Specification

A standalone, multi-tenant **Mailbox Gateway**: a small Rust service that presents a REST
facade over remote IMAP/SMTP mailboxes. It lets any HTTP client **send** and **read/search**
mail across arbitrary standard-IMAP providers, translating REST calls into IMAP/SMTP against
the end user's own mailbox.

overfwd is **purely a stateless translation layer**. In its default mode it holds no
credentials and no mail at rest — it is a pure function of `(request + presented credential)`.
It does not orchestrate agents, store messages, own inboxes, or ingest inbound events. It
answers one question: "given this mailbox credential, run this mail operation and return the
result."

The gateway's mandate is to disrupt EmailEngine / Nylas / Unipile: a single small binary,
MIT-licensed, zero-persistence by default, with no per-account server-side state.

overfwd is developed as an independent open-source project (`overspiral/overfwd`). Overslash
is one consumer among others, and consumes it as an ordinary third-party HTTP service.

---

## 1. Problem Statement

Programmatic access to arbitrary email mailboxes is either stateful, cloud-only, or expensive:

1. **EmailEngine** — self-hostable, but **stateful** (Redis + its own encrypted store of every
   account's credentials), Node runtime, a **$995/yr commercial license**, and account-pinned.
2. **Nylas / Unipile** — **cloud-only**; **credentials and mail content flow through a third
   party**; per-connected-account pricing; vendor lock-in; no real self-host story.
3. **Rolling your own** — every integrator re-implements IMAP `LOGIN/SELECT/SEARCH/FETCH` and
   SMTP submit, plus provider quirks, error mapping, and connection reuse.

overfwd extracts this into one stateless binary with a clean REST surface, so a caller presents
a mailbox credential per request and gets send/read/search — with nothing persisted.

---

## 2. Goals and Non-Goals

### Goals

1. **REST facade over IMAP/SMTP** — a stable surface (`search`, `get`, `send` to start) with
   clean request/response schemas, so callers never speak raw IMAP/SMTP or JMAP.
2. **Zero-persistence by default** — in Inline mode the gateway stores no credentials and no
   mail. "Your secrets never touch our disk."
3. **Bring-your-own-secrets** — the mailbox credential is presented per request from the
   caller's own vault; the gateway uses it and forgets it.
4. **Standard-IMAP long tail, provider-agnostic** — Migadu, Fastmail, iCloud, Zoho, Proton
   Bridge, corporate Dovecot/Cyrus, etc., reachable with a presented credential.
5. **Single small Rust binary** — low footprint, no Redis/DB required for the core path.
6. **Stateless horizontal scale** — any instance serves any request; no account-pinned state.
7. **Multi-tenant, shared deployment** — one shared gateway serves many tenants; tenancy is a
   deployment topology, not a code difference. Per-instance deployment is also supported.
8. **Privacy→convenience ladder** — Inline (stateless) → Session (ephemeral) → Portfolio
   (managed), in one binary, meeting integrators wherever they sit on the privacy curve.
9. **Permissive OSS license (MIT)** — vs EmailEngine's paid license.
10. **Runs identically standalone and embedded** — no dependency on any consumer to boot.

### Non-Goals

1. **No agent's own inbox** — no programmatic inbox creation/hosting. (Deferred track.)
2. **No real-time inbound** — no "wake on new mail" push/event ingestion. The gateway is
   request/response only. (Deferred track — needs an inbound-event subsystem.)
3. **Not Gmail / Outlook** — Google and Microsoft require OAuth XOAUTH2 for IMAP; routing them
   through the gateway buys nothing over their native REST APIs and loses fidelity (labels,
   threads, search operators). Big-two mail belongs on native REST, not this gateway.
4. **No message store, no mail at rest** — the gateway proxies; it does not archive.
5. **Not a JMAP proxy** — JMAP is not used, even internally. The wire contract is a REST facade
   defined by this spec.
6. **Not an agent framework, orchestrator, or general API gateway.**

---

## 3. Terminology

**Mailbox Gateway** — the *role*: a service presenting a REST facade over a remote IMAP/SMTP
mailbox, translating REST into IMAP/SMTP against the end user's provider. In Inline mode it
holds no credentials and no mail at rest.
_Avoid_: "JMAP proxy" (JMAP was dropped), "mail relay" / "SMTP relay" (it reads too).

**overfwd** — the concrete OSS implementation of the Mailbox Gateway: a standalone,
MIT-licensed Rust project (`overspiral/overfwd`).

**Inline / Portfolio / Session** — the three *credential sources* (see §5). Inline is the
zero-persistence default and the only mode Overslash uses.

---

## 4. Architecture

| Component | Tech | Purpose |
|-----------|------|---------|
| **Gateway** | Rust | HTTP server exposing the REST facade; IMAP/SMTP client; connection pool |
| **IMAP client** | `async-imap` | `LOGIN / SELECT / SEARCH / FETCH / APPEND` against the provider |
| **SMTP submit** | `lettre` | Message submission |
| **Parsing / building** | `mail-parser` + `mail-builder` (Stalwart) | RFC-conformant, zero-copy parse and construction |
| **Credential store** (optional) | encrypted store | Backs Portfolio/Session modes only; **disabled** in zero-persistence deployments |

The `send + read` surface is deliberately small: IMAP `LOGIN/SELECT/SEARCH/FETCH/APPEND` plus
SMTP submit. Implemented from scratch as a thin gateway — **no JMAP**.

**Stateless.** No account-pinned state; any instance serves any request. This fits both
per-instance deployment and a shared horizontally-scaled pool.

### Connection pooling

**Ephemeral in-memory connection pooling** amortizes IMAP `LOGIN`/`SELECT` cost across
requests, regardless of mode:

- Short TTL, per-credential, bounded, LRU.
- Purely in-memory — **lost on restart**, never persisted. Zero-persistence stays honest.
- Best-effort per instance under serverless lifecycles; **per-request login is the correct
  fallback** when no warm connection exists.

---

## 5. Credential & Auth Model

Two **independent** axes: access to the gateway, and the mailbox credential itself.

### Axis 1 — Gateway access

`api_key` presented as `Authorization: Bearer <api_key>`. Server config `require_api_key`
(on for hosted/Cloud, optional for self-host). A scoped api_key sees only its N accounts.

`Authorization` is reserved for the gateway api_key. The mailbox concern lives entirely in
`X-Mailbox-*` headers — the two axes never collide.

### Axis 2 — Mailbox credential (one of three sources)

| Source | How presented | Persistence | Notes |
|--------|---------------|-------------|-------|
| **Inline** | `X-Mailbox-Auth: Basic base64(user:pass)` per request; host/port in non-secret `X-Mailbox-*` headers | **None** | The zero-persistence default. The **only** mode Overslash uses. |
| **Portfolio** | `X-Mailbox-Account: <account_id>` referencing a credential in the gateway's own encrypted store | Stored (encrypted) | Standalone-product only; **disabled** in hosted/Cloud zero-persistence deployments. |
| **Session** | `session_token` handle minted by `create_session` (a TTL'd ghost Portfolio account) | Ephemeral | No creds at rest; a scoped, expiring handle. |

A single mailbox credential covers **both** SMTP and IMAP (commonly a shared user/app-password,
e.g. Migadu). The mailbox host/port are **non-secret** and travel as config, not as a secret.

### Wire layout

```
Authorization: Bearer <api_key>              # gateway access (axis 1)
X-Mailbox-Auth:  Basic base64(user:pass)     # mailbox credential — Inline (axis 2)
X-Mailbox-Imap:  <host>:<port>               # non-secret provider target (optional — see below)
X-Mailbox-Smtp:  <host>:<port>               # non-secret provider target (optional — see below)
X-Mailbox-Domain: <domain>                   # optional: domain to autoconfigure from
# — or, in Portfolio mode, instead of X-Mailbox-Auth/Imap/Smtp: —
X-Mailbox-Account: <account_id>
```

**Autoconfiguration fallback.** `X-Mailbox-Imap` / `X-Mailbox-Smtp` are optional. When a
host header is absent, the gateway derives `host:port` from the user's **domain** via email
autoconfiguration (Mozilla autoconfig — provider-hosted, `.well-known`, and the Thunderbird
ISPDB — then RFC 6186 DNS SRV / MX), the way a mail client does. The domain is taken from the
mailbox username's `@`, or from an explicit `X-Mailbox-Domain` (which also lets a short
login-id with no `@` autoconfigure). An explicitly-supplied host header always wins over the
resolved value. Results are cached in-memory only (never persisted — zero-persistence stays
honest). Only the §8 standard-IMAP long tail is in scope; the resolver prefers implicit-TLS
endpoints (IMAP `993` / SMTP `465`). When no target can be resolved the request fails with the
`autoconfig_failed` code (§7); when there is no domain to resolve at all it stays a
`bad_request`. Autoconfiguration is on by default and can be disabled by config.

**Endpoint address policy (SSRF).** The autoconfiguration path is SSRF-defended by
construction: only plausible public DNS domains are looked up, and the fetcher's resolver
refuses non-public addresses on every hop. An **explicit** `X-Mailbox-Imap` / `X-Mailbox-Smtp`
carries no such guarantee — a self-hosted gateway is *meant* to be pointed at
`localhost:3143`. On a **shared, multi-tenant** deployment that same freedom is an SSRF
primitive aimed at the deployment's private network and the cloud metadata endpoint
(`169.254.169.254`). Set `block_private_endpoints` (`OVERFWD_BLOCK_PRIVATE_ENDPOINTS=true`,
§10) to refuse any target that **is, or resolves to**, a loopback, RFC1918, link-local, CGNAT,
IPv6 unique-local/link-local, or unspecified address, plus the `localhost` / `.local` /
`.internal` names. Every address a name resolves to is checked, and any non-public answer
rejects the endpoint. Autoconfig-derived targets go through the same gate — nothing else
validates the `hostname` inside a hostile provider's `clientConfig` XML. Refusals are
`bad_request` (§7) naming the endpoint — deliberately distinct from `host_unreachable`, so a
consumer can tell "policy refused this" from "the provider is down". The flag defaults to
**off**, keeping self-host and the e2e stack unchanged. Known residual: the guard resolves,
then the IMAP/SMTP client resolves again, so DNS rebinding between the two lookups is not
caught.

A consumer that fronts many tenants (e.g. Overslash) can use a **single static gateway
api_key** for its own identity; its tenancy is carried per-request by the differing mailbox
credential, so **the gateway never sees the consumer's tenants**.

---

## 6. REST Facade

### v1 actions

| Action | Method | Class | Behaviour |
|--------|--------|-------|-----------|
| `search` | `POST /email/search` | **read** | Search a mailbox; auto-approvable. |
| `get` | `POST /email/get` | **read** | Fetch a message; auto-approvable. |
| `send` | `POST /email/send` | **write** | Submit a message. Gated for callers that gate writes. |

**Reads are ordinary `read`** and auto-approvable. The consent boundary is *whether the mailbox
owner granted read permission at all* — not a per-fetch approval.

**`search` is bounded, and says so.** Every returned row costs a full `BODY.PEEK[]` fetch and
parse, so `limit` defaults to **10** and is hard-capped at **50**; an over-cap request is clamped,
not rejected. Because a bounded read can silently mislead a caller into thinking it saw
everything, `search` answers with an envelope rather than a bare array:

```json
{ "results": [ …newest-first summaries… ], "total": 137, "truncated": true }
```

`total` is the pre-limit match count (free — UID SEARCH returns it without fetching a body) and
`truncated` is `true` whenever more matched than `results` carries. The envelope — rather than a
response header — is what the MCP tool result carries too, so an agent consuming `email_search`
gets the same truncation signal a REST caller does.

**`search` filtering** has two mutually exclusive modes. The **structured** params `from`,
`subject`, `text` and `since` are compiled server-side into a correctly quoted IMAP SEARCH key and
ANDed together — the default affordance for a caller that doesn't speak IMAP. The **raw** `query`
(alias `criteria`) takes an IMAP SEARCH key directly, as the escape hatch for the rest of the
grammar. Supplying both is a `bad_request`: whichever half the gateway dropped would be invisible
to the caller. Supplying neither means `ALL`.

**`send` disclosure** (for callers that surface approvals): the request discloses To / From /
Subject plus a clamped Body; the `Basic` auth header is **redacted** from any disclosure/audit.

### MCP surface

The same three actions are also exposed as **Model Context Protocol tools** at `POST /mcp`
(JSON-RPC 2.0, MCP Streamable HTTP in stateless JSON mode), so an agent can consume the gateway
as an MCP server. This is a *consumption surface* over the existing actions, not agent
orchestration (§2 Non-Goals). Tools: `email_search`, `email_get`, `email_send`; their input
schemas are the same code-derived JSON Schemas as the REST request bodies, so they cannot drift.

Both auth axes (§5) are unchanged and travel as HTTP headers on every POST: the gateway key as
`Authorization: Bearer` (Axis 1, same gate as `/email`), the mailbox credential as `X-Mailbox-*`
(Axis 2, read per `tools/call`). The server is stateless — no `Mcp-Session-Id`, nothing kept
between requests. Provider failures surface as a tool result with `isError: true` carrying the
stable `{ code, message }` envelope (§7); malformed calls / missing credentials surface as
JSON-RPC errors. The endpoint is on by default and disabled with `OVERFWD_ENABLE_MCP=false`
(§10). It advertises only the `tools` capability (a strict subset of MCP; no resources/prompts).

### Later additions (not v1)

- `get_attachment` — binary payloads, with a `prefer_stream` option for large attachments.
- `list_folders`.
- `create_session` — mint a Session credential (Portfolio-backed deployments only).

---

## 7. Error Model

Bounded, typed, machine-readable error codes a caller can gate/approve/branch on. At minimum:

- **auth failure** (bad mailbox credential)
- **host unreachable** (provider IMAP/SMTP down or wrong host/port)
- **mailbox / message not found**
- **TLS failure**
- **autoconfig failed** (host headers absent and no provider target resolvable from the domain)

Codes are stable across gateway instances and versions.

---

## 8. Coverage Boundary

**In scope:** the **standard-IMAP long tail** — any provider reachable with a presented
credential (Migadu, Fastmail, iCloud, Zoho, Proton Bridge, corporate Dovecot/Cyrus, …).

**Out of scope, by design:** Gmail and Microsoft Outlook/M365. They require OAuth XOAUTH2 for
IMAP; native REST (Gmail API, Microsoft Graph) is strictly better for them. The gateway does
**not** cover the big two.

---

## 9. Templating (single generic template)

The gateway is consumed through **one generic template** (working name `email` /
`mailbox-gateway`), instantiated by:

- a **gateway URL**,
- a **`user:pass` secret** name (the secret holds **only** `user:pass` — nothing
  provider-specific), and
- **non-secret host/port** config for the provider.

Nothing provider-specific lives in the template. Turnkey per-provider variants
(Migadu/Fastmail/…) are **optional forks** of this generic template with host/port pre-filled —
a consumer-side convenience, not a gateway concern.

---

## 10. Deployment

- **Hosted (Cloud Run)** — one shared, stateless service. The Portfolio credential store is
  **disabled**; in-memory pools are best-effort per instance under the serverless lifecycle,
  with per-request login as the fallback. Fly/GCE are unjustified without per-tenant state.
  A shared deployment SHOULD set `OVERFWD_BLOCK_PRIVATE_ENDPOINTS=true` (§5): reachable by
  every tenant, an explicit endpoint header is otherwise an SSRF primitive. Running without a
  VPC connector is containment, not a substitute — the metadata endpoint stays reachable.
- **Standalone** — the overfwd Docker image. Self-host may run with `require_api_key=false`
  (Inline only needs the `base64` credential encoding on the caller side; multi-injection of a
  gateway api_key + mailbox creds on one request is a hosted-only concern), and leaves
  `block_private_endpoints` off so `localhost`/LAN mail servers stay reachable.

| Axis                       | Self-host default | Shared / multi-tenant |
|----------------------------|-------------------|-----------------------|
| `require_api_key`          | `false`           | `true` (+ `api_key`)  |
| `block_private_endpoints`  | `false`           | `true`                |

---

## 11. Roadmap / Deferred Tracks

Deliberate deferrals, not omissions:

- **Own-inbox** — programmatic inbox creation/hosting.
- **Real-time inbound** — "wake on new mail"; needs an inbound-event ingestion subsystem.
- **Portfolio / Session modes** — standalone-product surfaces; can land after the Inline path.
- **Attachments** (`get_attachment`, `prefer_stream`) and **`list_folders`**.
- **Microsoft Graph** — a separate REST track for Outlook/M365, outside this gateway.

---

## Appendix — Design provenance

This spec is extracted from the settled design in
[`docs/design/email-integration.md`](docs/design/email-integration.md) (grilling session
2026-07-08/09). See [`docs/design/INDEX.md`](docs/design/INDEX.md) for the full design-doc set.
