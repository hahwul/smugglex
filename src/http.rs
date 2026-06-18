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

/// Returns the byte length of a complete HTTP/1.1 chunked message in `body` (the
/// index just past the terminating CRLF-CRLF), or `None` if it is not yet
/// complete. A run of size-prefixed chunks ends in a zero-size chunk whose
/// (possibly empty) trailer section is terminated by CRLF. Tolerates chunk
/// extensions (`;ext`) and trailer headers.
fn chunked_body_end(body: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    loop {
        // Locate the CRLF that ends the chunk-size line.
        let rel = find_subsequence(&body[i..], b"\r\n")?; // size line not fully received
        let line_end = i + rel; // index of the '\r' ending the size line
        // Chunk size is hex, optionally followed by ';'-delimited extensions.
        let size_tok = body[i..line_end]
            .split(|&b| b == b';')
            .next()
            .unwrap_or(&[])
            .trim_ascii();
        let size = std::str::from_utf8(size_tok)
            .ok()
            .and_then(|s| usize::from_str_radix(s, 16).ok())?; // malformed — defer
        if size == 0 {
            // Last chunk: complete once the terminating CRLF-CRLF of the trailer
            // section has arrived (zero or more trailer headers in between).
            return find_subsequence(&body[line_end..], b"\r\n\r\n").map(|p| line_end + p + 4);
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
            _ => return None, // chunk data not fully received (or overflow)
        }
    }
}

/// True once `body` holds a complete chunked message.
fn chunked_body_complete(body: &[u8]) -> bool {
    chunked_body_end(body).is_some()
}

/// If `buf` starts with a complete HTTP/1.x response, return its total byte
/// length; otherwise `None`. `None` for `Connection: close`-style responses with
/// no length signal — those are only complete at EOF.
fn response_complete_len(buf: &[u8]) -> Option<usize> {
    let pos = find_subsequence(buf, b"\r\n\r\n")?;
    let header_end = pos + 4;
    match detect_framing(&buf[..pos]) {
        BodyFraming::ContentLength(n) => {
            let total = header_end.checked_add(n)?;
            (buf.len() >= total).then_some(total)
        }
        BodyFraming::Chunked => chunked_body_end(&buf[header_end..]).map(|l| header_end + l),
        BodyFraming::ReadToClose => None,
    }
}

/// Read one complete HTTP/1.x response, carrying any bytes that belong to the
/// *next* response in `carry` so the connection can be read again. This is what
/// makes response-queue capture work: when a smuggled request's response arrives
/// glued to the previous one, the surplus is preserved for the next read instead
/// of being discarded. Returns `None` at EOF with nothing buffered.
async fn read_one_framed<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    carry: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(end) = response_complete_len(carry) {
            let resp = carry.drain(..end).collect();
            return Ok(Some(resp));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            // EOF: a length-less (Connection: close) response ends here.
            if carry.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(carry)));
        }
        carry.extend_from_slice(&tmp[..n]);
    }
}

/// Read exactly one complete HTTP/1.x response from `stream`, stopping as soon
/// as the message is complete per its framing (Content-Length / chunked) rather
/// than waiting for EOF. This lets the connection be reused for the next request
/// (pipelining) and avoids blocking on keep-alive idle time. `?Sized` so trait
/// objects (the boxed TLS/TCP stream) can be passed by `&mut`.
async fn read_one_http_response<S: AsyncRead + Unpin + ?Sized>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut framing = BodyFraming::ReadToClose;
    loop {
        if let Some(he) = header_end {
            match framing {
                BodyFraming::ContentLength(len) => {
                    // Checked addition so a hostile/garbled response advertising a
                    // near-`usize::MAX` Content-Length cannot overflow `he + len`
                    // (a debug-build panic, or a release-build wrap that would make
                    // the comparison true and return a truncated response). An
                    // unsatisfiable total simply means "keep reading until EOF",
                    // which is the safe behavior. Mirrors `response_complete_len`.
                    if he.checked_add(len).is_some_and(|total| buf.len() >= total) {
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
    Ok(buf)
}

/// Send several requests over a *single* persistent connection, reading one
/// complete response after each. Used to exploit response-queue desync: a
/// smuggled request's response is delivered to a *later* request on the same
/// connection, so capturing that offset response reveals the smuggled
/// request's result (e.g. an admin panel reached past a front-end control).
///
/// The whole exchange is bounded by `timeout`; on timeout the responses
/// collected so far are returned.
pub async fn pipeline_requests(
    host: &str,
    port: u16,
    requests: &[String],
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Result<Vec<String>> {
    let timeout_dur = Duration::from_secs(timeout);
    // `responses` is owned *outside* the timeout scope so that an elapsed
    // timeout preserves whatever was collected so far — the documented
    // contract, and what response-queue capture relies on: a smuggled
    // request's response is delivered to a *later* request, and the exchange
    // routinely stalls on a hanging follow-up precisely when an interesting
    // response is already buffered. Dropping it would be a false negative.
    let mut responses: Vec<Vec<u8>> = Vec::with_capacity(requests.len());
    let outcome = tokio::time::timeout(timeout_dur, async {
        let mut stream = get_stream(host, port, use_tls).await?;
        // Bytes already read that belong to a later response (the response-queue
        // offset that capture relies on) are carried between reads.
        let mut carry: Vec<u8> = Vec::new();
        for request in requests {
            if verbose {
                println!("\n{}", "--- PIPELINED REQUEST ---".bold().blue());
                println!("{}", request.cyan());
            }
            stream.write_all(request.as_bytes()).await?;
            match read_one_framed(&mut *stream, &mut carry).await? {
                Some(resp) => responses.push(resp),
                None => break, // peer closed with nothing left to read
            }
        }
        Ok::<(), crate::error::SmugglexError>(())
    })
    .await;

    match outcome {
        // Completed within the timeout, or timed out: either way return what we
        // collected. A mid-exchange connection error only surfaces when nothing
        // was captured — once we hold at least one response it is more useful
        // (and matches the timeout contract) to return it than to discard it.
        Ok(Ok(())) | Err(_) => {}
        Ok(Err(e)) => {
            if responses.is_empty() {
                return Err(e);
            }
        }
    }

    Ok(responses
        .into_iter()
        .map(|b| match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        })
        .collect())
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
        // Read exactly one complete HTTP/1.x response (see read_one_http_response).
        read_one_http_response(&mut *stream).await
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

    #[test]
    fn response_complete_len_content_length() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAB";
        assert_eq!(response_complete_len(buf), Some(buf.len()));
        // One byte short of the declared body -> not yet complete.
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nA";
        assert_eq!(response_complete_len(short), None);
    }

    #[test]
    fn response_complete_len_chunked_with_trailers() {
        let buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(response_complete_len(buf), Some(buf.len()));
    }

    #[test]
    fn response_complete_len_oversized_content_length_does_not_panic() {
        // A hostile/garbled `Content-Length: <usize::MAX>` must not overflow the
        // `header_end + n` computation; the response simply reads as incomplete.
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nAB",
            usize::MAX
        );
        assert_eq!(response_complete_len(raw.as_bytes()), None);
    }

    #[tokio::test]
    async fn read_one_http_response_oversized_content_length_does_not_panic() {
        // Regression for the unchecked `he + len` overflow: under debug
        // overflow-checks this previously panicked; it must instead read to EOF
        // and return what arrived.
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nAB",
            usize::MAX
        );
        let data = raw.into_bytes();
        let mut slice: &[u8] = &data;
        let out = read_one_http_response(&mut slice).await.unwrap();
        assert!(out.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn read_one_framed_splits_two_glued_responses_and_carries_surplus() {
        // Two complete Content-Length responses arrive glued in one buffer. The
        // first call must return response A and carry B for the next read; the
        // second call returns B from the carry; the third hits EOF.
        let a = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAB";
        let b = b"HTTP/1.1 404 NF\r\nContent-Length: 2\r\n\r\nCD";
        let mut data = Vec::new();
        data.extend_from_slice(a);
        data.extend_from_slice(b);
        let mut slice: &[u8] = &data;
        let mut carry: Vec<u8> = Vec::new();

        let first = read_one_framed(&mut slice, &mut carry).await.unwrap();
        assert_eq!(first.as_deref(), Some(&a[..]));
        assert_eq!(carry, b.to_vec(), "surplus bytes for B must be carried");

        let second = read_one_framed(&mut slice, &mut carry).await.unwrap();
        assert_eq!(second.as_deref(), Some(&b[..]));

        let third = read_one_framed(&mut slice, &mut carry).await.unwrap();
        assert_eq!(third, None, "EOF with empty carry yields None");
    }
}
