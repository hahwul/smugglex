use colored::*;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::{Result, SmugglexError};

// Cached TLS client configs, built once by `init_tls_config`. HTTP/1.1 and
// HTTP/2 need separate configs because they advertise different ALPN protocols,
// but they share the same trust policy. Caching the h2 config here (rather than
// rebuilding it per probe) keeps `--cacert` from re-reading and re-parsing the
// CA file from disk on every h2 connection.
static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
static H2_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// A certificate verifier that accepts any certificate (for --insecure mode).
#[derive(Debug)]
struct PermitAnyCert;

impl rustls::client::danger::ServerCertVerifier for PermitAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Delegate to the active crypto provider instead of hardcoding a list.
        // rustls uses this both to build the `signature_algorithms` extension
        // and to filter the server's `CertificateVerify` *before*
        // `verify_tls1x_signature` runs. Any scheme missing here (e.g. ECDSA
        // P-521 or Ed448) makes the handshake abort before this accept-anything
        // verifier is ever consulted — leaving `--insecure` *less* compatible
        // than normal mode. The provider is guaranteed to be installed by the
        // time a handshake runs (building a `ClientConfig` installs the crate's
        // default provider), so the empty fallback is unreachable in practice.
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// A fresh root store seeded with the bundled webpki trust anchors.
fn webpki_root_store() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store
}

/// Load CA certificates from a PEM file into a root store seeded with the
/// webpki roots. PEM parsing goes through `rustls-pki-types`' own `pem`
/// support, so no separate (archived) PEM crate is needed.
fn load_ca_roots(ca_path: &Path) -> Result<rustls::RootCertStore> {
    let mut root_store = webpki_root_store();

    let pem_data = std::fs::read(ca_path).map_err(|e| {
        SmugglexError::Io(format!(
            "failed to read CA cert file '{}': {}",
            ca_path.display(),
            e
        ))
    })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem_data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| SmugglexError::Tls(format!("failed to parse CA cert: {}", e)))?;

    if certs.is_empty() {
        return Err(SmugglexError::Tls(format!(
            "no certificates found in CA file '{}'",
            ca_path.display()
        )));
    }

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| SmugglexError::Tls(format!("failed to add CA cert: {}", e)))?;
    }

    Ok(root_store)
}

/// Build a single TLS client config for the given trust policy. `alpn_h2`
/// advertises HTTP/2 (`h2`) via ALPN; the trust policy is otherwise identical
/// between the HTTP/1.1 and HTTP/2 configs. This is the one builder that the six
/// former per-protocol/per-mode builders collapse into.
fn build_config(
    insecure: bool,
    ca_cert: Option<&Path>,
    alpn_h2: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermitAnyCert))
            .with_no_client_auth()
    } else {
        let root_store = match ca_cert {
            Some(ca_path) => load_ca_roots(ca_path)?,
            None => webpki_root_store(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    if alpn_h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Ok(Arc::new(config))
}

/// Initialize the global TLS configuration. Must be called once before any
/// network requests. `insecure` disables certificate verification; `ca_cert`
/// adds a custom CA certificate file (PEM) alongside webpki roots. Both the
/// HTTP/1.1 and HTTP/2 configs are built and cached here, so h2 probes never
/// re-read the CA file from disk.
pub fn init_tls_config(insecure: bool, ca_cert: Option<&Path>) -> Result<()> {
    if insecure && ca_cert.is_some() {
        eprintln!(
            "{} --insecure overrides --cacert; TLS certificate verification is disabled",
            "[!]".yellow().bold()
        );
    }

    let http1 = build_config(insecure, ca_cert, false)?;
    let http2 = build_config(insecure, ca_cert, true)?;

    TLS_CONFIG
        .set(http1)
        .map_err(|_| SmugglexError::Tls("TLS config already initialized".to_string()))?;
    // If TLS_CONFIG was fresh (the `?` above did not bail), this one is too.
    let _ = H2_TLS_CONFIG.set(http2);

    Ok(())
}

/// Return the cached HTTP/1.1 TLS config. If `init_tls_config` was never called
/// (library consumers, tests), fall back to a default webpki-roots config
/// instead of panicking; the binary always inits first.
pub fn get_tls_config() -> &'static Arc<rustls::ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| build_config(false, None, false).expect("default TLS config is infallible"))
}

/// Return the cached HTTP/2 TLS config (ALPN `h2`), mirroring `get_tls_config`.
/// Built once at init time, so h2 probes reuse it rather than rebuilding (and,
/// with `--cacert`, re-reading the CA file) on every connection.
pub fn get_h2_tls_config() -> &'static Arc<rustls::ClientConfig> {
    H2_TLS_CONFIG.get_or_init(|| {
        build_config(false, None, true).expect("default h2 TLS config is infallible")
    })
}

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
        let connector = TlsConnector::from(Arc::clone(get_tls_config()));
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
        let connector = TlsConnector::from(Arc::clone(get_tls_config()));
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

    // A throwaway self-signed ECDSA P-256 certificate used only to exercise CA
    // PEM parsing. It is not trusted for anything beyond these tests.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBizCCATGgAwIBAgIUI+T8ON5AaiTHXj9NCrnmcjbX5w0wCgYIKoZIzj0EAwIw\n\
GzEZMBcGA1UEAwwQc211Z2dsZXgtdGVzdC1jYTAeFw0yNjA3MDIwMjE3MTRaFw0z\n\
NjA2MjkwMjE3MTRaMBsxGTAXBgNVBAMMEHNtdWdnbGV4LXRlc3QtY2EwWTATBgcq\n\
hkjOPQIBBggqhkjOPQMBBwNCAAS3odwa9jb2EDMyxaSJK0x3K8ClDOaqVOhl/WSD\n\
49cSDOAY/6YtsAfemTspMIlIF72/WKXC0OOaBA91F40D5lGko1MwUTAdBgNVHQ4E\n\
FgQUkHsScQHXJRom6fCCYxOHzDg6nnEwHwYDVR0jBBgwFoAUkHsScQHXJRom6fCC\n\
YxOHzDg6nnEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBxLwD7\n\
b7gsdI1uCJNQ7DVc6fBAO6R+RC2GY54m3FBDTgIhAN4e51Gx9T9E3Z6zytX8bLCr\n\
kJ8CRz+khnaPy0Io4PLR\n\
-----END CERTIFICATE-----\n";

    // Issue #114: the --insecure verifier must advertise the *provider's* full
    // scheme set. rustls filters the server's CertificateVerify against this
    // list before our accept-anything verifier is consulted, so any missing
    // scheme (e.g. ECDSA P-521) makes such a server unreachable even with -k.
    #[test]
    fn permit_any_cert_advertises_provider_schemes_including_p521() {
        use rustls::SignatureScheme;
        use rustls::client::danger::ServerCertVerifier;
        // Building any config installs the crate's default crypto provider, which
        // `supported_verify_schemes` delegates to.
        let _ = build_config(true, None, false).unwrap();
        let schemes = PermitAnyCert.supported_verify_schemes();
        assert!(
            !schemes.is_empty(),
            "verifier must advertise the provider's schemes, not an empty list"
        );
        // P-521 was missing from the old hardcoded list — the core of the bug.
        assert!(
            schemes.contains(&SignatureScheme::ECDSA_NISTP521_SHA512),
            "P-521 must be advertised so --insecure can reach P-521 servers"
        );
        // Regression guard: previously-advertised schemes must remain.
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }

    // Issue #115: one builder for both protocols; only the h2 variant advertises
    // ALPN `h2`, and the insecure variant needs no trust roots to build.
    #[test]
    fn build_config_sets_alpn_only_for_h2() {
        let http1 = build_config(false, None, false).unwrap();
        assert!(
            http1.alpn_protocols.is_empty(),
            "HTTP/1.1 config must not advertise h2"
        );
        let http2 = build_config(false, None, true).unwrap();
        assert_eq!(
            http2.alpn_protocols,
            vec![b"h2".to_vec()],
            "h2 config must advertise ALPN h2"
        );
        let insecure_h2 = build_config(true, None, true).unwrap();
        assert_eq!(insecure_h2.alpn_protocols, vec![b"h2".to_vec()]);
    }

    // Issue #116: CA PEM parsing now goes through rustls-pki-types instead of the
    // archived rustls-pemfile crate. Cover the success path plus the two error
    // paths (missing file -> Io, no certs -> Tls).
    #[test]
    fn load_ca_roots_parses_pem_and_reports_errors() {
        use std::io::Write;

        let dir = std::env::temp_dir();
        let pid = std::process::id();

        // A valid cert is added on top of the webpki baseline.
        let baseline = webpki_root_store().len();
        let good = dir.join(format!("smugglex_ca_good_{pid}.pem"));
        std::fs::File::create(&good)
            .unwrap()
            .write_all(TEST_CA_PEM.as_bytes())
            .unwrap();
        let roots = load_ca_roots(&good).expect("valid PEM cert should parse");
        assert_eq!(
            roots.len(),
            baseline + 1,
            "the custom CA must be added on top of the webpki roots"
        );
        let _ = std::fs::remove_file(&good);

        // An empty PEM file yields a clear Tls "no certificates" error.
        let empty = dir.join(format!("smugglex_ca_empty_{pid}.pem"));
        std::fs::File::create(&empty).unwrap();
        assert!(matches!(load_ca_roots(&empty), Err(SmugglexError::Tls(_))));
        let _ = std::fs::remove_file(&empty);

        // A missing file surfaces an Io error, distinct from a parse failure.
        let missing = dir.join(format!("smugglex_ca_missing_{pid}.pem"));
        let _ = std::fs::remove_file(&missing);
        assert!(matches!(load_ca_roots(&missing), Err(SmugglexError::Io(_))));
    }

    // Issue #115 (item 3): the getters must not panic when init was skipped;
    // they lazily fall back to a default config.
    #[test]
    fn tls_config_getters_fall_back_without_init() {
        assert!(
            get_tls_config().alpn_protocols.is_empty(),
            "default HTTP/1.1 config advertises no ALPN"
        );
        assert_eq!(
            get_h2_tls_config().alpn_protocols,
            vec![b"h2".to_vec()],
            "default h2 config advertises ALPN h2"
        );
    }

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
