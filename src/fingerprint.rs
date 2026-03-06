use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::http::send_request;

/// Known proxy/server types that can be identified via response headers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProxyType {
    Nginx,
    Apache,
    Varnish,
    CloudFront,
    Cloudflare,
    HAProxy,
    Envoy,
    ATS,
    Squid,
    Caddy,
    IIS,
    Traefik,
    Akamai,
    Fastly,
    Unknown(String),
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyType::Nginx => write!(f, "Nginx"),
            ProxyType::Apache => write!(f, "Apache"),
            ProxyType::Varnish => write!(f, "Varnish"),
            ProxyType::CloudFront => write!(f, "CloudFront"),
            ProxyType::Cloudflare => write!(f, "Cloudflare"),
            ProxyType::HAProxy => write!(f, "HAProxy"),
            ProxyType::Envoy => write!(f, "Envoy"),
            ProxyType::ATS => write!(f, "ATS"),
            ProxyType::Squid => write!(f, "Squid"),
            ProxyType::Caddy => write!(f, "Caddy"),
            ProxyType::IIS => write!(f, "IIS"),
            ProxyType::Traefik => write!(f, "Traefik"),
            ProxyType::Akamai => write!(f, "Akamai"),
            ProxyType::Fastly => write!(f, "Fastly"),
            ProxyType::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}

/// Result of fingerprinting a target's proxy/server stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub detected_proxy: ProxyType,
    pub server_header: Option<String>,
    pub via_header: Option<String>,
    pub powered_by: Option<String>,
    pub raw_headers: HashMap<String, String>,
}

impl fmt::Display for FingerprintResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Detected Proxy: {}", self.detected_proxy)?;
        if let Some(ref s) = self.server_header {
            writeln!(f, "Server: {}", s)?;
        }
        if let Some(ref v) = self.via_header {
            writeln!(f, "Via: {}", v)?;
        }
        if let Some(ref p) = self.powered_by {
            writeln!(f, "X-Powered-By: {}", p)?;
        }
        Ok(())
    }
}

/// Parse HTTP response headers into a map (lowercase keys).
fn parse_response_headers(response: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in response.lines() {
        if line.is_empty() || line.starts_with("HTTP/") {
            continue;
        }
        // End of headers
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(
                key.trim().to_ascii_lowercase(),
                value.trim().to_string(),
            );
        }
    }
    headers
}

/// Identify the proxy type from parsed response headers.
fn identify_proxy(headers: &HashMap<String, String>) -> ProxyType {
    // Check specific indicator headers first (most reliable)
    if headers.get("cf-ray").is_some() || headers.get("cf-cache-status").is_some() {
        return ProxyType::Cloudflare;
    }
    if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-cf-pop").is_some() {
        return ProxyType::CloudFront;
    }
    if headers.get("x-varnish").is_some() {
        return ProxyType::Varnish;
    }
    if headers.contains_key("x-served-by") {
        if let Some(val) = headers.get("x-served-by") {
            if val.contains("cache-") {
                return ProxyType::Fastly;
            }
        }
    }
    if let Some(via) = headers.get("via") {
        let via_lower = via.to_lowercase();
        if via_lower.contains("varnish") {
            return ProxyType::Varnish;
        }
        if via_lower.contains("cloudfront") {
            return ProxyType::CloudFront;
        }
        if via_lower.contains("akamai") || via_lower.contains("akamaighost") {
            return ProxyType::Akamai;
        }
        if via_lower.contains("squid") {
            return ProxyType::Squid;
        }
    }
    if let Some(server) = headers.get("server") {
        let server_lower = server.to_lowercase();
        if server_lower.contains("nginx") {
            return ProxyType::Nginx;
        }
        if server_lower.contains("apache") || server_lower.contains("httpd") {
            return ProxyType::Apache;
        }
        if server_lower.contains("cloudfront") {
            return ProxyType::CloudFront;
        }
        if server_lower.contains("cloudflare") {
            return ProxyType::Cloudflare;
        }
        if server_lower.contains("varnish") {
            return ProxyType::Varnish;
        }
        if server_lower.contains("haproxy") {
            return ProxyType::HAProxy;
        }
        if server_lower.contains("envoy") {
            return ProxyType::Envoy;
        }
        if server_lower.contains("ats") || server_lower.contains("trafficserver") {
            return ProxyType::ATS;
        }
        if server_lower.contains("squid") {
            return ProxyType::Squid;
        }
        if server_lower.contains("caddy") {
            return ProxyType::Caddy;
        }
        if server_lower.contains("microsoft-iis") || server_lower.contains("iis") {
            return ProxyType::IIS;
        }
        if server_lower.contains("traefik") {
            return ProxyType::Traefik;
        }
        if server_lower.contains("akamai") || server_lower.contains("akamaighost") {
            return ProxyType::Akamai;
        }
        if server_lower.contains("fastly") {
            return ProxyType::Fastly;
        }
        return ProxyType::Unknown(server.clone());
    }

    ProxyType::Unknown("unidentified".to_string())
}

/// Send a GET probe to the target and fingerprint the proxy/server from response headers.
pub async fn fingerprint_target(
    host: &str,
    port: u16,
    path: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Result<FingerprintResult> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path, host
    );

    let (response, _duration) = send_request(host, port, &request, timeout, verbose, use_tls).await?;
    let headers = parse_response_headers(&response);
    let detected_proxy = identify_proxy(&headers);

    Ok(FingerprintResult {
        detected_proxy,
        server_header: headers.get("server").cloned(),
        via_header: headers.get("via").cloned(),
        powered_by: headers.get("x-powered-by").cloned(),
        raw_headers: headers,
    })
}

/// Suggest an ordered list of check types based on the detected proxy.
///
/// Returns check names in priority order based on known proxy behaviors:
/// - Nginx: tends to use CL, making CL.TE most likely
/// - Varnish: known issues with both CL.TE and TE.CL
/// - CloudFront: CL.TE has been historically effective
/// - HAProxy: TE.CL issues have been documented
pub fn suggest_checks(fingerprint: &FingerprintResult) -> Vec<&'static str> {
    match &fingerprint.detected_proxy {
        ProxyType::Nginx => vec!["cl-te", "te-te", "te-cl", "h2c", "h2", "cl-edge"],
        ProxyType::Apache => vec!["te-cl", "cl-te", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::Varnish => vec!["cl-te", "te-cl", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::CloudFront => vec!["cl-te", "te-te", "te-cl", "h2", "h2c", "cl-edge"],
        ProxyType::Cloudflare => vec!["te-te", "cl-te", "te-cl", "h2", "h2c", "cl-edge"],
        ProxyType::HAProxy => vec!["te-cl", "cl-te", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::Envoy => vec!["cl-te", "te-cl", "te-te", "h2", "h2c", "cl-edge"],
        ProxyType::ATS => vec!["cl-te", "te-cl", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::Squid => vec!["te-cl", "cl-te", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::Caddy => vec!["cl-te", "te-cl", "te-te", "h2", "h2c", "cl-edge"],
        ProxyType::IIS => vec!["te-cl", "cl-te", "te-te", "h2c", "h2", "cl-edge"],
        ProxyType::Traefik => vec!["cl-te", "te-cl", "te-te", "h2", "h2c", "cl-edge"],
        ProxyType::Akamai => vec!["cl-te", "te-te", "te-cl", "h2", "h2c", "cl-edge"],
        ProxyType::Fastly => vec!["cl-te", "te-te", "te-cl", "h2", "h2c", "cl-edge"],
        ProxyType::Unknown(_) => vec!["cl-te", "te-cl", "te-te", "h2c", "h2", "cl-edge"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_headers() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\nbody";
        let headers = parse_response_headers(response);
        assert_eq!(headers.get("server").unwrap(), "nginx/1.24.0");
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn test_identify_nginx() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.24.0".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Nginx);
    }

    #[test]
    fn test_identify_cloudflare_by_cf_ray() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "abc123".to_string());
        headers.insert("server".to_string(), "cloudflare".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Cloudflare);
    }

    #[test]
    fn test_identify_cloudfront_by_amz_header() {
        let mut headers = HashMap::new();
        headers.insert("x-amz-cf-id".to_string(), "abc123".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::CloudFront);
    }

    #[test]
    fn test_identify_varnish() {
        let mut headers = HashMap::new();
        headers.insert("x-varnish".to_string(), "12345".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Varnish);
    }

    #[test]
    fn test_identify_unknown() {
        let headers = HashMap::new();
        assert_eq!(
            identify_proxy(&headers),
            ProxyType::Unknown("unidentified".to_string())
        );
    }

    #[test]
    fn test_identify_unknown_server() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "MyCustomServer/2.0".to_string());
        assert_eq!(
            identify_proxy(&headers),
            ProxyType::Unknown("MyCustomServer/2.0".to_string())
        );
    }

    #[test]
    fn test_suggest_checks_nginx() {
        let fp = FingerprintResult {
            detected_proxy: ProxyType::Nginx,
            server_header: Some("nginx".to_string()),
            via_header: None,
            powered_by: None,
            raw_headers: HashMap::new(),
        };
        let checks = suggest_checks(&fp);
        assert_eq!(checks[0], "cl-te");
    }

    #[test]
    fn test_suggest_checks_haproxy() {
        let fp = FingerprintResult {
            detected_proxy: ProxyType::HAProxy,
            server_header: Some("haproxy".to_string()),
            via_header: None,
            powered_by: None,
            raw_headers: HashMap::new(),
        };
        let checks = suggest_checks(&fp);
        assert_eq!(checks[0], "te-cl");
    }

    #[test]
    fn test_suggest_checks_unknown() {
        let fp = FingerprintResult {
            detected_proxy: ProxyType::Unknown("custom".to_string()),
            server_header: None,
            via_header: None,
            powered_by: None,
            raw_headers: HashMap::new(),
        };
        let checks = suggest_checks(&fp);
        assert_eq!(checks.len(), 6);
    }

    #[test]
    fn test_fingerprint_result_display() {
        let fp = FingerprintResult {
            detected_proxy: ProxyType::Nginx,
            server_header: Some("nginx/1.24.0".to_string()),
            via_header: Some("1.1 varnish".to_string()),
            powered_by: Some("Express".to_string()),
            raw_headers: HashMap::new(),
        };
        let display = format!("{}", fp);
        assert!(display.contains("Nginx"));
        assert!(display.contains("nginx/1.24.0"));
        assert!(display.contains("1.1 varnish"));
        assert!(display.contains("Express"));
    }

    #[test]
    fn test_proxy_type_display() {
        assert_eq!(format!("{}", ProxyType::Nginx), "Nginx");
        assert_eq!(format!("{}", ProxyType::CloudFront), "CloudFront");
        assert_eq!(
            format!("{}", ProxyType::Unknown("test".to_string())),
            "Unknown(test)"
        );
    }

    #[test]
    fn test_identify_via_header_varnish() {
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), "1.1 varnish (Varnish/6.0)".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Varnish);
    }

    #[test]
    fn test_identify_via_header_akamai() {
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), "1.1 akamai.net".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Akamai);
    }

    #[test]
    fn test_identify_fastly_by_served_by() {
        let mut headers = HashMap::new();
        headers.insert("x-served-by".to_string(), "cache-lax12345".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Fastly);
    }

    #[test]
    fn test_identify_apache() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.52".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Apache);
    }

    #[test]
    fn test_identify_iis() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Microsoft-IIS/10.0".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::IIS);
    }

    #[test]
    fn test_identify_envoy() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "envoy".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Envoy);
    }

    #[test]
    fn test_identify_traefik() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Traefik".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Traefik);
    }

    #[test]
    fn test_identify_caddy() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Caddy".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Caddy);
    }

    #[test]
    fn test_identify_squid() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "squid/5.7".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::Squid);
    }

    #[test]
    fn test_identify_ats() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "ATS/9.2.0".to_string());
        assert_eq!(identify_proxy(&headers), ProxyType::ATS);
    }
}
