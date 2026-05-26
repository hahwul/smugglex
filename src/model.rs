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
    /// Concrete signals that contributed to the detection (e.g.,
    /// "status_504", "timing_anomaly:3.5x", "body_divergence_vs_control",
    /// "header_divergence_vs_control:2", "extreme_timing"). Empty when not
    /// vulnerable. Lets users audit *why* a finding was reported and
    /// corroborate manually.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_signals: Vec<String>,
    /// Diagnostic notes about the scan run itself, distinct from
    /// vulnerability evidence. Currently used to record early-termination
    /// reasons such as "early_termination:consecutive_fp_rejections=3",
    /// emitted when the check was abandoned because the backend repeatedly
    /// hit the control-based FP rule for this payload shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
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
    /// Error message if the target scan failed (e.g. connection or parsing error).
    /// When present, `checks` will usually be empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Summary statistics for a batch of scan results.
/// Useful for AI agents and scripts to get a quick overview without iterating.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BatchSummary {
    /// Total number of targets that were processed (including errors)
    pub total_targets: usize,
    /// Number of targets on which at least one vulnerability was confirmed
    pub vulnerable_targets: usize,
    /// Total number of individual check runs across all targets
    pub total_checks: usize,
    /// Total number of checks that reported vulnerable=true
    pub vulnerable_checks: usize,
}

/// Envelope for machine-readable (JSON) output when scanning multiple targets,
/// or when using --json. Provides both detailed per-target results and a summary.
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchScanResults {
    /// smugglex version that produced this output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smugglex_version: Option<String>,
    /// ISO 8601 timestamp when the batch run completed
    pub timestamp: String,
    /// Per-target results (one entry per attempted target)
    pub results: Vec<ScanResults>,
    /// Aggregate statistics
    pub summary: BatchSummary,
}
