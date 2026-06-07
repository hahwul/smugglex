use colored::*;
use rustls::pki_types::ServerName;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::{Result, SmugglexError};

// Lazy static TLS configuration to avoid recreating for each request
static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
});

static PROXY: OnceLock<String> = OnceLock::new();

/// Set global proxy URL
pub fn set_proxy(proxy_url: String) {
    let _ = PROXY.set(proxy_url);
}

/// Get configured proxy URL
fn get_proxy() -> Option<&'static str> {
    PROXY.get().map(|s| s.as_str())
}

/// A trait that combines AsyncRead and AsyncWrite.
trait ReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// Creates a TCP or TLS stream, optionally through a proxy.
async fn get_stream(
    host: &str,
    port: u16,
    use_tls: bool,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    if let Some(proxy_url) = get_proxy() {
        get_stream_via_proxy(host, port, use_tls, proxy_url).await
    } else {
        get_stream_direct(host, port, use_tls).await
    }
}

/// Creates a direct TCP or TLS stream.
async fn get_stream_direct(
    host: &str,
    port: u16,
    use_tls: bool,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    let addr = format!("{}:{}", host, port);
    if use_tls {
        let connector = TlsConnector::from(Arc::clone(&TLS_CONFIG));
        let stream = TcpStream::connect(&addr).await?;
        let domain = ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(domain, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        let stream = TcpStream::connect(&addr).await?;
        Ok(Box::new(stream))
    }
}

/// Creates a stream through an HTTP proxy using CONNECT tunnel.
async fn get_stream_via_proxy(
    host: &str,
    port: u16,
    use_tls: bool,
    proxy_url: &str,
) -> Result<Box<dyn ReadWrite + Unpin + Send>> {
    let proxy = Url::parse(proxy_url)
        .map_err(|e| SmugglexError::Io(format!("invalid proxy URL: {}", e)))?;
    let proxy_host = proxy
        .host_str()
        .ok_or_else(|| SmugglexError::Io("proxy URL has no host".to_string()))?;
    let proxy_port = proxy.port_or_known_default().unwrap_or(8080);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        SmugglexError::Io(format!("failed to connect to proxy {}: {}", proxy_addr, e))
    })?;

    // Send CONNECT request to establish tunnel
    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host, port, host, port
    );
    stream.write_all(connect_req.as_bytes()).await?;

    // Read proxy response
    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    if !status_line.contains("200") {
        return Err(SmugglexError::Io(format!(
            "proxy CONNECT failed: {}",
            status_line.trim()
        )));
    }

    // Consume remaining headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Now we have a tunnel; do TLS handshake if needed
    if use_tls {
        let connector = TlsConnector::from(Arc::clone(&TLS_CONFIG));
        let domain = ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(domain, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

/// How the body of an HTTP/1.x response is framed on the wire, used to decide
/// when one complete response has been received.
enum BodyFraming {
    /// Body length is known from `Content-Length`.
    ContentLength(usize),
    /// `Transfer-Encoding: chunked`; body ends at the zero-size chunk terminator.
    Chunked,
    /// No length signalled (or unparseable); read until the peer closes the socket.
    ReadToClose,
}

/// Inspect a response header block (the bytes before the CRLF-CRLF terminator)
/// and decide how the body is framed. Per RFC 7230, `Transfer-Encoding` takes
/// precedence over `Content-Length`.
fn detect_framing(header_block: &[u8]) -> BodyFraming {
    let head = String::from_utf8_lossy(header_block);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    // skip(1) drops the status line; the rest are header fields.
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("content-length") {
                if let Ok(n) = value.trim().parse::<usize>() {
                    content_length = Some(n);
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    if chunked {
        BodyFraming::Chunked
    } else if let Some(n) = content_length {
        BodyFraming::ContentLength(n)
    } else {
        BodyFraming::ReadToClose
    }
}

/// Find the first occurrence of `needle` within `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Returns true once `body` holds a complete HTTP/1.1 chunked message: a run of
/// size-prefixed chunks ending in a zero-size chunk whose (possibly empty)
/// trailer section is terminated by CRLF. Tolerates chunk extensions (`;ext`)
/// and trailer headers, so it does not stop short of — or past — the real end.
fn chunked_body_complete(body: &[u8]) -> bool {
    let mut i = 0usize;
    loop {
        // Locate the CRLF that ends the chunk-size line.
        let rel = match find_subsequence(&body[i..], b"\r\n") {
            Some(p) => p,
            None => return false, // size line not fully received yet
        };
        let line_end = i + rel; // index of the '\r' ending the size line
        // Chunk size is hex, optionally followed by ';'-delimited extensions.
        let size_tok = body[i..line_end]
            .split(|&b| b == b';')
            .next()
            .unwrap_or(&[])
            .trim_ascii();
        let size = match std::str::from_utf8(size_tok)
            .ok()
            .and_then(|s| usize::from_str_radix(s, 16).ok())
        {
            Some(n) => n,
            None => return false, // malformed — let the outer timeout/EOF decide
        };
        if size == 0 {
            // Last chunk: complete once the terminating CRLF-CRLF of the trailer
            // section has arrived (zero or more trailer headers in between).
            return find_subsequence(&body[line_end..], b"\r\n\r\n").is_some();
        }
        // Skip the CRLF after the size line, the chunk data, and its trailing
        // CRLF. Use fully-checked arithmetic so a hostile server advertising a
        // near-usize::MAX chunk size cannot overflow (which would panic in debug
        // builds); such a chunk simply reads as "not yet complete".
        match size
            .checked_add(4)
            .and_then(|advance| line_end.checked_add(advance))
        {
            Some(next) if next <= body.len() => i = next,
            _ => return false, // chunk data not fully received (or overflow)
        }
    }
}

/// Sends a raw HTTP request and returns the response and duration.
pub async fn send_request(
    host: &str,
    port: u16,
    request: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Result<(String, Duration)> {
    if verbose {
        println!("\n{}", "--- REQUEST ---".bold().blue());
        println!("{}", request.cyan());
    }

    let start = Instant::now();
    let timeout_dur = Duration::from_secs(timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut stream = get_stream(host, port, use_tls).await?;
        stream.write_all(request.as_bytes()).await?;

        // Read exactly one complete HTTP/1.x response. We stop as soon as the
        // message is complete per its framing (Content-Length / chunked) rather
        // than waiting for EOF: attack payloads use `Connection: keep-alive`, so
        // the server holds the socket open after replying and a plain
        // `read_to_end` would block until the timeout on *every* request —
        // drowning the timing signal in keep-alive idle time. A genuinely
        // desynced backend that never completes a response still trips the
        // outer timeout, preserving the smuggling signal.
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut tmp = [0u8; 8192];
        let mut header_end: Option<usize> = None;
        let mut framing = BodyFraming::ReadToClose;
        loop {
            if let Some(he) = header_end {
                match framing {
                    BodyFraming::ContentLength(len) => {
                        if buf.len() >= he + len {
                            break;
                        }
                    }
                    BodyFraming::Chunked => {
                        if chunked_body_complete(&buf[he..]) {
                            break;
                        }
                    }
                    BodyFraming::ReadToClose => {}
                }
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break; // peer closed the connection
            }
            buf.extend_from_slice(&tmp[..n]);
            if header_end.is_none()
                && let Some(pos) = find_subsequence(&buf, b"\r\n\r\n")
            {
                header_end = Some(pos + 4);
                framing = detect_framing(&buf[..pos]);
            }
        }
        Ok::<Vec<u8>, crate::error::SmugglexError>(buf)
    })
    .await??;

    let response_str = match String::from_utf8(result) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };

    let duration = start.elapsed();

    if verbose {
        println!("\n{}", "--- RESPONSE ---".bold().blue());
        println!("{}", response_str.white());
    }

    Ok((response_str, duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subsequence_locates_header_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody";
        assert_eq!(find_subsequence(buf, b"\r\n\r\n"), Some(21));
        assert_eq!(find_subsequence(b"abc", b"\r\n\r\n"), None);
        assert_eq!(find_subsequence(b"", b"x"), None);
        assert_eq!(find_subsequence(b"abc", b""), None);
    }

    #[test]
    fn detect_framing_reads_content_length() {
        let head = b"HTTP/1.1 200 OK\r\nServer: x\r\nContent-Length: 42";
        assert!(matches!(
            detect_framing(head),
            BodyFraming::ContentLength(42)
        ));
    }

    #[test]
    fn detect_framing_content_length_is_case_insensitive() {
        let head = b"HTTP/1.1 200 OK\r\ncontent-length: 7";
        assert!(matches!(
            detect_framing(head),
            BodyFraming::ContentLength(7)
        ));
    }

    #[test]
    fn detect_framing_prefers_chunked_over_content_length() {
        // RFC 7230: Transfer-Encoding takes precedence over Content-Length.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked";
        assert!(matches!(detect_framing(head), BodyFraming::Chunked));
    }

    #[test]
    fn detect_framing_defaults_to_read_to_close() {
        let head = b"HTTP/1.1 200 OK\r\nServer: x";
        assert!(matches!(detect_framing(head), BodyFraming::ReadToClose));
        // A non-numeric Content-Length is unparseable and must not be trusted.
        let bad = b"HTTP/1.1 200 OK\r\nContent-Length: abc";
        assert!(matches!(detect_framing(bad), BodyFraming::ReadToClose));
    }

    #[test]
    fn chunked_complete_simple_cases() {
        assert!(chunked_body_complete(b"0\r\n\r\n"));
        assert!(chunked_body_complete(b"5\r\nhello\r\n0\r\n\r\n"));
        // Hex chunk size ('a' = 10 bytes of data).
        assert!(chunked_body_complete(b"a\r\n0123456789\r\n0\r\n\r\n"));
        // Chunk extensions on the size line are tolerated.
        assert!(chunked_body_complete(b"5;ext=1\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn chunked_complete_handles_trailer_headers() {
        // RFC 7230 trailers after the zero-size chunk must still be recognized
        // as a complete message (the regression that `ends_with("0\r\n\r\n")` missed).
        assert!(chunked_body_complete(
            b"5\r\nhello\r\n0\r\nServer: nginx\r\nX-T: 1\r\n\r\n"
        ));
    }

    #[test]
    fn chunked_incomplete_cases() {
        assert!(!chunked_body_complete(b"5\r\nhello\r\n0\r\n")); // final CRLF missing
        assert!(!chunked_body_complete(b"5\r\nhello\r\n")); // last chunk not seen
        assert!(!chunked_body_complete(b"5\r\nhel")); // chunk data incomplete
        assert!(!chunked_body_complete(
            b"5\r\nhello\r\n0\r\nServer: nginx\r\n"
        )); // trailers unterminated
        assert!(!chunked_body_complete(b"")); // nothing yet
    }

    #[test]
    fn chunked_huge_size_does_not_panic() {
        // A hostile server advertising a near-usize::MAX chunk size must not
        // overflow/panic; it just reads as incomplete.
        let huge = format!("{:x}\r\nAB", usize::MAX);
        assert!(!chunked_body_complete(huge.as_bytes()));
    }
}
