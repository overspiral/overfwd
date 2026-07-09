//! Integration test: spin up the real router on an ephemeral port and hit it over HTTP.

use overfwd::config::{Config, MailConfig};
use overfwd::create_app;

fn test_config() -> Config {
    Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        greenmail_api: "http://localhost:8080".to_string(),
        mail: MailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 3025,
            smtp_tls_port: 3465,
            imap_host: "localhost".to_string(),
            imap_port: 3143,
            imap_tls_port: 3993,
            user: "test".to_string(),
            pass: "test".to_string(),
            address: "test@localhost".to_string(),
            tls_insecure: true,
        },
    }
}

#[tokio::test]
async fn health_returns_ok() {
    let app = create_app(test_config());

    // Bind to an ephemeral port and serve in the background.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::get(format!("http://{addr}/health"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("invalid json");
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}
