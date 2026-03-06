//! Mock proxy test infrastructure for testing fingerprint detection
//! and payload behavior against different proxy configurations.
//!
//! Provides pre-built profiles simulating common proxy/server behaviors
//! for use in integration tests.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// How the mock proxy handles Transfer-Encoding headers.
#[derive(Debug, Clone)]
pub enum TeHandling {
    /// Accept and process chunked encoding normally
    AcceptChunked,
    /// Ignore/strip the TE header from responses
    IgnoreTE,
    /// Normalize TE header (remove obfuscation)
    NormalizeTE,
}

/// How the mock proxy handles Content-Length headers.
#[derive(Debug, Clone)]
pub enum ClHandling {
    /// Use the first Content-Length header value
    UseFirst,
    /// Use the last Content-Length header value
    UseLast,
    /// Reject requests with duplicate Content-Length headers
    RejectDuplicate,
}

/// Configuration for a mock proxy server.
#[derive(Debug, Clone)]
pub struct MockProxyConfig {
    /// Server header value to return
    pub server_header: String,
    /// How to handle Transfer-Encoding
    pub te_handling: TeHandling,
    /// How to handle Content-Length
    pub cl_handling: ClHandling,
    /// Extra response headers (pre-formatted with \r\n)
    pub extra_response_headers: String,
}

impl MockProxyConfig {
    /// Nginx-like behavior: uses CL, normalizes TE
    pub fn nginx() -> Self {
        Self {
            server_header: "nginx/1.24.0".to_string(),
            te_handling: TeHandling::NormalizeTE,
            cl_handling: ClHandling::UseFirst,
            extra_response_headers: String::new(),
        }
    }

    /// Varnish-like behavior: accepts chunked, uses first CL
    pub fn varnish() -> Self {
        Self {
            server_header: "Varnish".to_string(),
            te_handling: TeHandling::AcceptChunked,
            cl_handling: ClHandling::UseFirst,
            extra_response_headers: "X-Varnish: 12345678\r\n".to_string(),
        }
    }

    /// CloudFront-like behavior
    pub fn cloudfront() -> Self {
        Self {
            server_header: "CloudFront".to_string(),
            te_handling: TeHandling::AcceptChunked,
            cl_handling: ClHandling::UseFirst,
            extra_response_headers: "X-Amz-Cf-Id: abc123\r\n".to_string(),
        }
    }

    /// Cloudflare-like behavior
    pub fn cloudflare() -> Self {
        Self {
            server_header: "cloudflare".to_string(),
            te_handling: TeHandling::NormalizeTE,
            cl_handling: ClHandling::RejectDuplicate,
            extra_response_headers: "CF-RAY: abc123-LAX\r\nCF-Cache-Status: DYNAMIC\r\n".to_string(),
        }
    }

    /// HAProxy-like behavior: uses last CL, may ignore TE
    pub fn haproxy() -> Self {
        Self {
            server_header: "HAProxy".to_string(),
            te_handling: TeHandling::IgnoreTE,
            cl_handling: ClHandling::UseLast,
            extra_response_headers: String::new(),
        }
    }

    /// Apache-like behavior
    pub fn apache() -> Self {
        Self {
            server_header: "Apache/2.4.52 (Ubuntu)".to_string(),
            te_handling: TeHandling::AcceptChunked,
            cl_handling: ClHandling::UseFirst,
            extra_response_headers: "X-Powered-By: PHP/8.1\r\n".to_string(),
        }
    }
}

/// A running mock proxy instance.
pub struct MockProxy {
    pub host: String,
    pub port: u16,
    pub handle: JoinHandle<()>,
}

impl MockProxy {
    /// Start a mock proxy server on a random available port.
    ///
    /// The server responds to incoming connections based on the provided config,
    /// returning appropriate headers to enable fingerprint detection testing.
    pub async fn start(config: MockProxyConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = addr.ip().to_string();
        let port = addr.port();

        let handle = tokio::spawn(async move {
            // Accept connections in a loop
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let config = config.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let n = match stream.read(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                _ => return,
                            };
                            let request = String::from_utf8_lossy(&buf[..n]);

                            // Check for duplicate CL and decide response
                            let has_duplicate_cl = request
                                .lines()
                                .filter(|l| l.to_lowercase().starts_with("content-length:"))
                                .count()
                                > 1;

                            let (status, body) = if has_duplicate_cl {
                                match config.cl_handling {
                                    ClHandling::RejectDuplicate => {
                                        ("400 Bad Request", "Duplicate Content-Length")
                                    }
                                    _ => ("200 OK", "OK"),
                                }
                            } else {
                                ("200 OK", "OK")
                            };

                            let response = format!(
                                "HTTP/1.1 {}\r\nServer: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                                status,
                                config.server_header,
                                config.extra_response_headers,
                                body.len(),
                                body
                            );

                            let _ = stream.write_all(response.as_bytes()).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Self { host, port, handle }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smugglex::fingerprint::{ProxyType, fingerprint_target};

    #[tokio::test]
    async fn test_mock_nginx_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::nginx()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::Nginx);
        proxy.handle.abort();
    }

    #[tokio::test]
    async fn test_mock_varnish_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::varnish()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::Varnish);
        proxy.handle.abort();
    }

    #[tokio::test]
    async fn test_mock_cloudfront_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::cloudfront()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::CloudFront);
        proxy.handle.abort();
    }

    #[tokio::test]
    async fn test_mock_cloudflare_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::cloudflare()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::Cloudflare);
        proxy.handle.abort();
    }

    #[tokio::test]
    async fn test_mock_haproxy_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::haproxy()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::HAProxy);
        proxy.handle.abort();
    }

    #[tokio::test]
    async fn test_mock_apache_fingerprint() {
        let proxy = MockProxy::start(MockProxyConfig::apache()).await;
        let result = fingerprint_target(&proxy.host, proxy.port, "/", 5, false, false)
            .await
            .unwrap();
        assert_eq!(result.detected_proxy, ProxyType::Apache);
        proxy.handle.abort();
    }
}
