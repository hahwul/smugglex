use serde::{Deserialize, Serialize};

/// Confidence level for a vulnerability detection
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Strong evidence of vulnerability
    High,
    /// Moderate evidence of vulnerability
    Medium,
    /// Weak or uncertain evidence of vulnerability
    Low,
}

/// Result of a vulnerability check
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckResult {
    /// Type of smuggling check performed (e.g., "CL.TE", "TE.CL")
    pub check_type: String,
    /// Whether the target was found vulnerable
    pub vulnerable: bool,
    /// Index of the payload that triggered detection
    pub payload_index: Option<usize>,
    /// HTTP status line from the baseline (normal) request
    pub normal_status: String,
    /// HTTP status line from the attack request, if available
    pub attack_status: Option<String>,
    /// Baseline request duration in milliseconds
    pub normal_duration_ms: u64,
    /// Attack request duration in milliseconds, if available
    pub attack_duration_ms: Option<u64>,
    /// ISO 8601 timestamp of when the check was performed
    pub timestamp: String,
    /// Raw HTTP payload that triggered detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Confidence level of the detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Fingerprint information for JSON output
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FingerprintInfo {
    /// Name of the detected reverse proxy or CDN
    pub detected_proxy: String,
    /// Value of the Server response header
    pub server_header: Option<String>,
    /// Value of the Via response header
    pub via_header: Option<String>,
    /// Value of the X-Powered-By response header
    pub powered_by: Option<String>,
}

/// Overall scan results
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    /// Target URL that was scanned
    pub target: String,
    /// HTTP method used for attack requests
    pub method: String,
    /// ISO 8601 timestamp of the scan
    pub timestamp: String,
    /// Proxy/CDN fingerprint info, if fingerprinting was enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FingerprintInfo>,
    /// Results of each individual smuggling check
    pub checks: Vec<CheckResult>,
}
