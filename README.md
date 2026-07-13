# overfwd

A stateless REST facade over remote IMAP/SMTP mailboxes — a single small Rust
binary that lets any HTTP client **send** and **read/search** mail across
arbitrary standard-IMAP providers (Migadu, Fastmail, iCloud, Zoho, corporate
Dovecot/Cyrus, …). It holds no credentials and no mail at rest: it's a pure
function of `(request + presented mailbox credential)`.

See [`SPEC.md`](SPEC.md) for the full design.

## Run

```bash
cp .env.example .env      # configure listen address, endpoints, credentials
cargo run                 # reads config from the environment; listens on OVERFWD_BIND (default 0.0.0.0:8000)
cargo build --release     # optimized binary at target/release/overfwd
```

## Run with Docker

Multi-arch images (amd64 + arm64) are published to Docker Hub on every release:

```bash
docker run -p 8000:8000 angelmanuel/overfwd:latest
```

Configuration is entirely environment-driven — no config files. The common knobs:

| Variable                 | Default        | Purpose                                            |
|--------------------------|----------------|----------------------------------------------------|
| `OVERFWD_BIND`           | `0.0.0.0:8000` | Listen socket.                                     |
| `OVERFWD_REQUIRE_API_KEY`| `false`        | Require an `Authorization: Bearer` gateway key.    |
| `OVERFWD_API_KEY`        | —              | The gateway key (required when the above is true). |

```bash
docker run -p 8000:8000 \
  -e OVERFWD_REQUIRE_API_KEY=true \
  -e OVERFWD_API_KEY=your-secret-key \
  angelmanuel/overfwd:latest
```

The image runs as a non-root user on a minimal distroless base (no shell); the
unauthenticated `GET /openapi.json` route can serve as a liveness probe.

## Endpoints

| Method | Path            | Class | Behaviour            |
|--------|-----------------|-------|----------------------|
| `POST` | `/email/search` | read  | Search a mailbox     |
| `POST` | `/email/get`    | read  | Fetch a message      |
| `POST` | `/email/send`   | write | Submit a message     |
| `POST` | `/mcp`          | —     | MCP server (JSON-RPC 2.0) exposing the three actions as tools |

The mailbox credential travels per request in the `X-Mailbox-Auth` header; the
IMAP/SMTP targets are **autoconfigured from the mailbox domain**, so no explicit
server headers are needed for common providers. The gateway `api_key` (when
enabled) is `Authorization: Bearer …`. See [`SPEC.md` §5–§6](SPEC.md).

## MCP server

`overfwd` is also a [Model Context Protocol](https://modelcontextprotocol.io)
server: the same three actions are exposed as MCP **tools** (`email_search`,
`email_get`, `email_send`) over JSON-RPC 2.0 at `POST /mcp`, so an agent can drive
mailboxes directly. It speaks MCP Streamable HTTP in stateless JSON mode. Disable
it with `OVERFWD_ENABLE_MCP=false`.

The two auth axes are unchanged and both travel as HTTP headers on every request:

- **Gateway key (Axis 1):** `Authorization: Bearer <api_key>` — same gate as
  `/email`, active only when `OVERFWD_REQUIRE_API_KEY=true`.
- **Mailbox credential (Axis 2):** `X-Mailbox-Auth: Basic base64(user:pass)` (plus
  the optional `X-Mailbox-Imap` / `X-Mailbox-Smtp` / `X-Mailbox-Domain`) on each
  `tools/call`.

```bash
# Handshake, then list the tools
curl -sS http://localhost:8000/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
curl -sS http://localhost:8000/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# Call a tool (mailbox credential in the same headers as the REST API)
AUTH=$(printf 'you@example.com:app-password' | base64)
curl -sS http://localhost:8000/mcp \
  -H "X-Mailbox-Auth: Basic $AUTH" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"email_search","arguments":{"query":"UNSEEN","limit":10}}}'
```

Clients that only speak stdio (e.g. Claude Desktop) can bridge to the HTTP endpoint
with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote), which forwards the
`Authorization` and `X-Mailbox-*` headers:

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "overfwd": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "https://your-host/mcp",
        "--header", "Authorization: Bearer ${OVERFWD_API_KEY}",
        "--header", "X-Mailbox-Auth: Basic ${MAILBOX_BASIC}"
      ]
    }
  }
}
```

There is no OAuth flow — the mailbox credential is injected as static headers via
the bridge.

## Quick demo

The mailbox credential is `Basic base64(user:pass)`. Use a full email address as
the user so overfwd can autoconfigure the provider from its domain — no IMAP/SMTP
server headers required:

```bash
AUTH=$(printf 'you@example.com:app-password' | base64)

# Search the inbox for unread messages
curl -sS http://localhost:8000/email/search \
  -H "X-Mailbox-Auth: Basic $AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"query":"UNSEEN","limit":10}'

# Send a message
curl -sS http://localhost:8000/email/send \
  -H "X-Mailbox-Auth: Basic $AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"from":"you@example.com","to":["dest@example.com"],
       "subject":"Hello from overfwd","text":"Sent through the gateway."}'
```

## Test

```bash
cargo test
```

E2e tests run against a shared local GreenMail mail server — start it first with
`make mail-up`. See [`docs/testing.md`](docs/testing.md).

## License

MIT © 2026 Overspiral S.L. See [`LICENSE`](LICENSE).
