//! End-to-end coverage for the autoconfiguration fallback (SPEC §5).
//!
//! When the `X-Mailbox-Imap` / `X-Mailbox-Smtp` host headers are absent, the gateway
//! derives the provider target from the user's domain. These tests drive the real
//! router in-process with an **injected** [`Autoconfig`] resolver — the public
//! `Autoconfig::new` + `routes::router` seam — so no live network and no GreenMail are
//! needed. (The live resolver's SSRF guard intentionally refuses loopback/private
//! targets, so a real stub server could not stand in for a provider anyway; the ladder
//! logic itself is unit-tested in `src/autoconfig.rs`.)

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use overfwd::auth::{H_MAILBOX_AUTH, H_MAILBOX_DOMAIN};
use overfwd::autoconfig::{
    Autoconfig, AutoconfigSettings, BoxFuture, HttpFetcher, SrvRecord, SrvResolver,
};
use overfwd::{AppState, Config, EndpointGuard, GatewayError};
use tower::ServiceExt;

/// An autoconfig document that points both servers at a closed loopback port, so a
/// read that *reaches* the resolved target fails fast with a refused connection
/// (`host_unreachable`) — proving the target came from autoconfiguration.
const XML_TO_CLOSED_PORT: &str = r#"<clientConfig version="1.1">
  <emailProvider id="example.com">
    <incomingServer type="imap">
      <hostname>127.0.0.1</hostname><port>1</port><socketType>SSL</socketType>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>127.0.0.1</hostname><port>1</port><socketType>SSL</socketType>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#;

/// A fake HTTP backend that answers every autoconfig URL with the same document.
struct StubHttp;
impl HttpFetcher for StubHttp {
    fn get<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Option<String>, GatewayError>> {
        Box::pin(async { Ok(Some(XML_TO_CLOSED_PORT.to_string())) })
    }
}

/// A DNS backend with no records (the HTTP rung answers first anyway).
struct NoDns;
impl SrvResolver for NoDns {
    fn srv<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Vec<SrvRecord>> {
        Box::pin(async { Vec::new() })
    }
    fn mx<'a>(&'a self, _domain: &'a str) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async { Vec::new() })
    }
}

/// Build the real router with an injected, offline autoconfig resolver.
fn stub_app() -> Router {
    let autoconfig = Autoconfig::new(
        Box::new(StubHttp),
        Box::new(NoDns),
        AutoconfigSettings::default(),
    );
    let state = AppState {
        config: Arc::new(Config {
            bind: "0.0.0.0:8000".parse().unwrap(),
            require_api_key: false,
            api_key: None,
            enable_mcp: true,
            block_private_endpoints: false,
        }),
        autoconfig: Arc::new(autoconfig),
        endpoints: Arc::new(EndpointGuard::disabled()),
    };
    overfwd::routes::router(state)
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// With the host headers absent but `X-Mailbox-Domain` present, the read resolves its
/// IMAP target from autoconfig and *attempts the connection* — reaching
/// `host_unreachable` (not `bad_request`) proves the credential was fully resolved.
#[tokio::test]
async fn absent_imap_header_is_resolved_from_the_domain_header() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0") // test:test (a short login id, no @)
        .header(H_MAILBOX_DOMAIN, "example.com")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = stub_app().oneshot(request).await.unwrap();
    // 502 host_unreachable: autoconfig filled 127.0.0.1:1 and the IMAP connection was
    // refused — i.e. we got past credential resolution into the provider call.
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_json(response).await["code"], "host_unreachable");
}

/// A full email address in the credential supplies the domain with no extra header.
#[tokio::test]
async fn absent_imap_header_is_resolved_from_the_username_domain() {
    // Basic base64("jane@example.com:pw").
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic amFuZUBleGFtcGxlLmNvbTpwdw==")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = stub_app().oneshot(request).await.unwrap();
    assert_eq!(body_json(response).await["code"], "host_unreachable");
}

/// No host headers, no domain, and a login id with no `@` → nothing to autoconfigure,
/// so the request stays a typed `bad_request` (today's behavior is preserved).
#[tokio::test]
async fn absent_host_headers_without_a_domain_is_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri("/email/search")
        .header(H_MAILBOX_AUTH, "Basic dGVzdDp0ZXN0") // test:test — no domain anywhere
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = stub_app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "bad_request");
}
