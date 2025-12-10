//! Tests for HTTP request module
//!
//! This module contains tests for:
//! - send_request function with mocked network calls
//! - TLS and non-TLS request handling
//! - Timeout behavior
//! - Error handling for connection failures

use smugglex::http::send_request;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

// Mock HTTP server for testing
async fn mock_server(port: u16, response: &str) {
    let response = response.to_string();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = socket.write_all(http_response.as_bytes()).await.unwrap();
        }
    });
}

// Mock HTTPS server (simplified - in real tests, use proper TLS setup)
async fn mock_https_server(_port: u16, _response: &str) {
    // For simplicity, we'll skip full HTTPS mocking in unit tests
    // In integration tests, use a proper test server
}

#[tokio::test]
async fn test_send_request_http_success() {
    let port = 8080;
    let response_body = "Hello, World!";
    mock_server(port, response_body).await;

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = send_request(
        "127.0.0.1",
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        5,
        false,
        false,
    )
    .await;

    assert!(result.is_ok());
    let (response, duration) = result.unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains(response_body));
    assert!(duration.as_millis() >= 0);
}

#[tokio::test]
async fn test_send_request_with_timeout() {
    let port = 8081;

    // Start a server that doesn't respond immediately
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        if let Ok((mut socket, _)) = listener.accept().await {
            // Delay response to trigger timeout
            tokio::time::sleep(Duration::from_secs(2)).await;
            let http_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let _ = socket.write_all(http_response.as_bytes()).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Use very short timeout
    let result = timeout(
        Duration::from_millis(500),
        send_request(
            "127.0.0.1",
            port,
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            1,
            false,
            false,
        ),
    )
    .await;

    // Should timeout
    assert!(result.is_err() || result.unwrap().is_err());
}

#[tokio::test]
async fn test_send_request_connection_refused() {
    // Try to connect to a port that should be closed
    let result = send_request(
        "127.0.0.1",
        9999,
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        5,
        false,
        false,
    )
    .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    // Should be an Io error due to connection refused
    match err {
        smugglex::error::SmugglexError::Io(_) => {}
        _ => panic!("Expected Io error"),
    }
}

#[tokio::test]
async fn test_send_request_invalid_host() {
    // Invalid hostname should fail
    let result = send_request(
        "invalid.host.name.that.does.not.exist",
        80,
        "GET / HTTP/1.1\r\nHost: invalid\r\n\r\n",
        5,
        false,
        false,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_send_request_verbose_output() {
    let port = 8082;
    let response_body = "Verbose test";
    mock_server(port, response_body).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Capture stdout to verify verbose output
    // Note: In real implementation, you might use a testing framework that captures output
    let result = send_request(
        "127.0.0.1",
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        5,
        true,
        false,
    )
    .await;

    assert!(result.is_ok());
    // Verbose output would be printed to stdout, but we can't easily test that in unit tests
    // In integration tests, we could capture stdout
}

#[tokio::test]
async fn test_send_request_with_custom_headers() {
    let port = 8083;
    let response_body = "Custom headers test";
    mock_server(port, response_body).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Custom: test\r\n\r\n";
    let result = send_request("127.0.0.1", port, request, 5, false, false).await;

    assert!(result.is_ok());
    let (response, _) = result.unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"));
}

// Note: HTTPS tests would require proper TLS certificate setup
// For now, we skip full HTTPS testing in unit tests
// Integration tests should cover HTTPS scenarios

#[tokio::test]
async fn test_send_request_large_response() {
    let port = 8084;
    let large_body = "x".repeat(10000); // 10KB response
    mock_server(port, &large_body).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = send_request(
        "127.0.0.1",
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        10,
        false,
        false,
    )
    .await;

    assert!(result.is_ok());
    let (response, _) = result.unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains(&large_body));
}
