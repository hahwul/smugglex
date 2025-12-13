use colored::*;
use once_cell::sync::Lazy;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::Result;

// Lazy static TLS configuration to avoid recreating for each request
static TLS_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
});

/// A trait that combines AsyncRead and AsyncWrite.
trait ReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// Creates a TCP or TLS stream.
async fn get_stream(
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

    let mut stream = get_stream(host, port, use_tls).await?;
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(timeout), stream.read_to_end(&mut buf)).await??;
    let response_str = String::from_utf8_lossy(&buf).to_string();

    let duration = start.elapsed();

    if verbose {
        println!("\n{}", "--- RESPONSE ---".bold().blue());
        println!("{}", response_str.white());
    }

    Ok((response_str, duration))
}

