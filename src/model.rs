use serde::{Deserialize, Serialize};

/// Result of a vulnerability check
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckResult {
    pub check_type: String,
    pub vulnerable: bool,
    pub payload_index: Option<usize>,
    pub normal_status: String,
    pub attack_status: Option<String>,
    pub normal_duration_ms: u64,
    pub attack_duration_ms: Option<u64>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Overall scan results
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub method: String,
    pub timestamp: String,
    pub checks: Vec<CheckResult>,
}

