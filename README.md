# overfwd

A **REST → IMAP/SMTP bridge** (mail forwarding). This is the **v0 HTTP scaffold**: an async
[axum](https://github.com/tokio-rs/axum) server with health/hello routes, structured logging,
env-based config, and graceful shutdown. The IMAP/SMTP bridging logic is not implemented yet — the
config already carries the mail settings so it slots in without restructuring.

## Run

```sh
cargo run
# Listening on 127.0.0.1:3000

curl -s localhost:3000/health   # {"status":"ok"}
curl -s localhost:3000/         # {"name":"overfwd","version":"0.1.0","message":"..."}
```

Press `Ctrl-C` to shut down gracefully.

## Test

```sh
cargo test        # runs the /health integration test (spins up the router on an ephemeral port)
cargo fmt --check
cargo clippy
```

## Configuration

Copy `.env` into the worktree (it is gitignored). All values have sensible defaults, so the server
runs with no `.env` at all.

| Variable            | Default                  | Purpose                                            |
| ------------------- | ------------------------ | -------------------------------------------------- |
| `OVERFWD_HOST`      | `127.0.0.1`              | HTTP bind address                                  |
| `OVERFWD_PORT`      | `3000`                   | HTTP bind port (avoids GreenMail's `8080`)         |
| `RUST_LOG`          | `info`                   | Tracing filter (e.g. `overfwd=debug,tower_http=debug`) |
| `MAIL_SMTP_HOST`    | `localhost`              | SMTP host (outbound)                               |
| `MAIL_SMTP_PORT`    | `3025`                   | SMTP plain port                                    |
| `MAIL_SMTP_TLS_PORT`| `3465`                   | SMTP TLS port                                      |
| `MAIL_IMAP_HOST`    | `localhost`              | IMAP host (inbound)                                |
| `MAIL_IMAP_PORT`    | `3143`                   | IMAP plain port                                    |
| `MAIL_IMAP_TLS_PORT`| `3993`                   | IMAP TLS port                                      |
| `MAIL_USER`         | `test`                   | Login id (short form, not the email)               |
| `MAIL_PASS`         | `test`                   | Password                                           |
| `MAIL_ADDRESS`      | `test@localhost`         | Envelope From/To address                           |
| `MAIL_TLS_INSECURE` | `true`                   | Skip TLS verification (GreenMail self-signed cert) |
| `GREENMAIL_API`     | `http://localhost:8080`  | GreenMail management REST API                      |

## Layout

```
src/
├── main.rs        bootstrap: dotenv, tracing, config, serve + graceful shutdown
├── lib.rs         AppState + create_app(config) -> Router
├── config.rs      Config / MailConfig, loaded from env
├── error.rs       AppError + IntoResponse
└── routes/        one module per resource (health, hello)
tests/
└── health.rs      integration test over real HTTP
```
