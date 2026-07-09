# overfwd

A REST → IMAP/SMTP bridge server (Rust). This repo currently contains the **e2e
test mail server**: a real IMAP + SMTP target the future bridge is tested against.

## Shared mail server (read this first)

E2e tests run against **[GreenMail](https://greenmail-mail-test.github.io/greenmail/)**,
a real SMTP + IMAP + POP3 server, in one container via `compose.yml`.

> **⚠️ One stack, shared across all worktrees.**
> We work in many git worktrees but they all use the **same** GreenMail instance.
> Start it **once** — from any worktree — with `make mail-up`. The Makefile pins
> a fixed project name (`overfwd-mail`, via `-p`) and the compose file pins a fixed
> container name and host ports, so running `up` again from another worktree is a
> **no-op**, not a port conflict.
> **Never** start a second stack per worktree. To isolate test runs, **reset
> state** (`make mail-reset`) or use distinct addresses/subjects per run.

### Start / stop / reset

```bash
make mail-up       # start (idempotent). Docker host: make mail-up COMPOSE="docker compose"
make mail-status   # container state + readiness
make mail-reset    # wipe all mailboxes without restarting
make mail-logs     # follow logs
make mail-down     # stop and remove the stack
```

### Ports (all on `localhost`)

| Protocol | Plain | TLS  |
|----------|-------|------|
| SMTP     | 3025  | 3465 |
| IMAP     | 3143  | 3993 |
| POP3     | 3110  | 3995 |
| REST API | 8080  | —    |

TLS ports (3465 / 3993) use GreenMail's **built-in self-signed certificate** — no
cert files to mount, but clients must **skip certificate verification** on them.

### Accounts

Preconfigured deterministic users. **SMTP AUTH / IMAP LOGIN use the login id (short
form), not the email address**; the password is the same for both:

| Login id | Password | Email address     |
|----------|----------|-------------------|
| `test`   | `test`   | `test@localhost`  |
| `alice`  | `alice`  | `alice@localhost` |

GreenMail also auto-creates a user on first access, so extra addresses need no restart.

### Management REST API (`http://localhost:8080`)

- `GET  /api/service/readiness` → `{"message":"Service running"}`
- `POST /api/service/reset` → wipe all state
- `GET  /api/configuration` → active server setups/ports
- `GET  /api/user`, `GET /api/mail` → inspect users and messages

## Configuration

Copy `.env.example` → `.env` in your worktree (`.env` is gitignored). It documents
the connection endpoints the bridge and its e2e tests consume.
