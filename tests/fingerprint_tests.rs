//! Tests for proxy fingerprinting
//!
//! This module contains tests for:
//! - Proxy type identification from response headers
//! - Fingerprint result display formatting
//! - suggest_checks ordering for each proxy type
//! - Integration tests with mock servers

use smugglex::fingerprint::{FingerprintResult, ProxyType, fingerprint_target, suggest_checks};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ========== Proxy Detection via Mock Servers ==========

async fn start_mock_server(server_header: &str, extra_headers: &str) -> (String, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let response = format!(
        "HTTP/1.1 200 OK\r\nServer: {}\r\n{}Content-Length: 2\r\nConnection: close\r\n\r\nOK",
        server_header, extra_headers
    );

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    (host, port)
}

#[tokio::test]
async fn test_fingerprint_nginx_server() {
    let (host, port) = start_mock_server("nginx/1.24.0", "").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::Nginx);
    assert_eq!(result.server_header.as_deref(), Some("nginx/1.24.0"));
}

#[tokio::test]
async fn test_fingerprint_apache_server() {
    let (host, port) = start_mock_server("Apache/2.4.52", "").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::Apache);
}

#[tokio::test]
async fn test_fingerprint_cloudflare_via_cf_ray() {
    let (host, port) = start_mock_server("cloudflare", "CF-RAY: abc123-LAX\r\n").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::Cloudflare);
}

#[tokio::test]
async fn test_fingerprint_cloudfront_via_amz_header() {
    let (host, port) = start_mock_server("CloudFront", "X-Amz-Cf-Id: abc123\r\n").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::CloudFront);
}

#[tokio::test]
async fn test_fingerprint_varnish_via_x_varnish() {
    let (host, port) = start_mock_server("Varnish", "X-Varnish: 12345\r\n").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::Varnish);
}

#[tokio::test]
async fn test_fingerprint_unknown_server() {
    let (host, port) = start_mock_server("MyCustom/1.0", "").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert!(matches!(result.detected_proxy, ProxyType::Unknown(_)));
}

#[tokio::test]
async fn test_fingerprint_envoy() {
    let (host, port) = start_mock_server("envoy", "").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::Envoy);
}

#[tokio::test]
async fn test_fingerprint_haproxy() {
    let (host, port) = start_mock_server("HAProxy", "").await;
    let result = fingerprint_target(&host, port, "/", 5, false, false).await.unwrap();
    assert_eq!(result.detected_proxy, ProxyType::HAProxy);
}

// ========== suggest_checks Tests ==========

#[test]
fn test_suggest_checks_nginx_prioritizes_cl_te() {
    let fp = FingerprintResult {
        detected_proxy: ProxyType::Nginx,
        server_header: Some("nginx".to_string()),
        via_header: None,
        powered_by: None,
        raw_headers: HashMap::new(),
    };
    let checks = suggest_checks(&fp);
    assert_eq!(checks[0], "cl-te");
    assert!(checks.contains(&"cl-edge"));
}

#[test]
fn test_suggest_checks_haproxy_prioritizes_te_cl() {
    let fp = FingerprintResult {
        detected_proxy: ProxyType::HAProxy,
        server_header: None,
        via_header: None,
        powered_by: None,
        raw_headers: HashMap::new(),
    };
    let checks = suggest_checks(&fp);
    assert_eq!(checks[0], "te-cl");
}

#[test]
fn test_suggest_checks_cloudflare_prioritizes_te_te() {
    let fp = FingerprintResult {
        detected_proxy: ProxyType::Cloudflare,
        server_header: None,
        via_header: None,
        powered_by: None,
        raw_headers: HashMap::new(),
    };
    let checks = suggest_checks(&fp);
    assert_eq!(checks[0], "te-te");
}

#[test]
fn test_suggest_checks_returns_all_checks() {
    let fp = FingerprintResult {
        detected_proxy: ProxyType::Unknown("test".to_string()),
        server_header: None,
        via_header: None,
        powered_by: None,
        raw_headers: HashMap::new(),
    };
    let checks = suggest_checks(&fp);
    assert_eq!(checks.len(), 6);
    assert!(checks.contains(&"cl-te"));
    assert!(checks.contains(&"te-cl"));
    assert!(checks.contains(&"te-te"));
    assert!(checks.contains(&"h2c"));
    assert!(checks.contains(&"h2"));
    assert!(checks.contains(&"cl-edge"));
}
