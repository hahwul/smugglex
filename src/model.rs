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
}

/// Overall scan results
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub method: String,
    pub timestamp: String,
    pub checks: Vec<CheckResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_creation_vulnerable() {
        let result = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(3),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 200,
            attack_duration_ms: Some(5000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        assert_eq!(result.check_type, "CL.TE");
        assert!(result.vulnerable);
        assert_eq!(result.payload_index, Some(3));
        assert_eq!(result.normal_status, "HTTP/1.1 200 OK");
        assert_eq!(
            result.attack_status,
            Some("HTTP/1.1 504 Gateway Timeout".to_string())
        );
        assert_eq!(result.normal_duration_ms, 200);
        assert_eq!(result.attack_duration_ms, Some(5000));
    }

    #[test]
    fn test_check_result_creation_not_vulnerable() {
        let result = CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 150,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        assert_eq!(result.check_type, "TE.CL");
        assert!(!result.vulnerable);
        assert_eq!(result.payload_index, None);
        assert_eq!(result.attack_status, None);
        assert_eq!(result.attack_duration_ms, None);
    }

    #[test]
    fn test_check_result_serialization_vulnerable() {
        let result = CheckResult {
            check_type: "TE.TE".to_string(),
            vulnerable: true,
            payload_index: Some(1),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 408 Request Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(10000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&result).expect("Failed to serialize");

        // Verify JSON contains expected fields
        assert!(json.contains("\"check_type\":\"TE.TE\""));
        assert!(json.contains("\"vulnerable\":true"));
        assert!(json.contains("\"payload_index\":1"));
        assert!(json.contains("\"attack_duration_ms\":10000"));
    }

    #[test]
    fn test_check_result_deserialization() {
        let json = r#"{
            "check_type": "CL.TE",
            "vulnerable": true,
            "payload_index": 2,
            "normal_status": "HTTP/1.1 200 OK",
            "attack_status": "HTTP/1.1 504 Gateway Timeout",
            "normal_duration_ms": 150,
            "attack_duration_ms": 4500,
            "timestamp": "2024-01-01T12:00:00Z"
        }"#;

        let result: CheckResult = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(result.check_type, "CL.TE");
        assert!(result.vulnerable);
        assert_eq!(result.payload_index, Some(2));
        assert_eq!(result.normal_duration_ms, 150);
        assert_eq!(result.attack_duration_ms, Some(4500));
    }

    #[test]
    fn test_check_result_clone() {
        let result = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 200,
            attack_duration_ms: Some(3000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let cloned = result.clone();

        assert_eq!(result.check_type, cloned.check_type);
        assert_eq!(result.vulnerable, cloned.vulnerable);
        assert_eq!(result.payload_index, cloned.payload_index);
    }

    #[test]
    fn test_scan_results_creation() {
        let check1 = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(1),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 200,
            attack_duration_ms: Some(5000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let check2 = CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 150,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:01Z".to_string(),
        };

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks: vec![check1, check2],
        };

        assert_eq!(scan_results.target, "https://example.com");
        assert_eq!(scan_results.method, "POST");
        assert_eq!(scan_results.checks.len(), 2);
        assert!(scan_results.checks[0].vulnerable);
        assert!(!scan_results.checks[1].vulnerable);
    }

    #[test]
    fn test_scan_results_serialization() {
        let check = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 200,
            attack_duration_ms: Some(4000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let scan_results = ScanResults {
            target: "https://api.example.com/test".to_string(),
            method: "GET".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks: vec![check],
        };

        let json = serde_json::to_string_pretty(&scan_results).expect("Failed to serialize");

        assert!(json.contains("\"target\":"));
        assert!(json.contains("\"method\":"));
        assert!(json.contains("\"timestamp\":"));
        assert!(json.contains("\"checks\":"));
        assert!(json.contains("https://api.example.com/test"));
    }

    #[test]
    fn test_scan_results_deserialization() {
        let json = r#"{
            "target": "http://test.com",
            "method": "POST",
            "timestamp": "2024-01-01T12:00:00Z",
            "checks": [
                {
                    "check_type": "CL.TE",
                    "vulnerable": false,
                    "payload_index": null,
                    "normal_status": "HTTP/1.1 200 OK",
                    "attack_status": null,
                    "normal_duration_ms": 100,
                    "attack_duration_ms": null,
                    "timestamp": "2024-01-01T12:00:00Z"
                }
            ]
        }"#;

        let scan_results: ScanResults = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(scan_results.target, "http://test.com");
        assert_eq!(scan_results.method, "POST");
        assert_eq!(scan_results.checks.len(), 1);
        assert!(!scan_results.checks[0].vulnerable);
    }

    #[test]
    fn test_scan_results_empty_checks() {
        let scan_results = ScanResults {
            target: "http://test.com".to_string(),
            method: "GET".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks: vec![],
        };

        assert_eq!(scan_results.checks.len(), 0);

        let json = serde_json::to_string(&scan_results).expect("Failed to serialize");
        let deserialized: ScanResults = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.checks.len(), 0);
    }

    #[test]
    fn test_scan_results_multiple_checks() {
        let checks = vec![
            CheckResult {
                check_type: "CL.TE".to_string(),
                vulnerable: true,
                payload_index: Some(0),
                normal_status: "HTTP/1.1 200 OK".to_string(),
                attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
                normal_duration_ms: 150,
                attack_duration_ms: Some(3000),
                timestamp: "2024-01-01T12:00:00Z".to_string(),
            },
            CheckResult {
                check_type: "TE.CL".to_string(),
                vulnerable: false,
                payload_index: None,
                normal_status: "HTTP/1.1 200 OK".to_string(),
                attack_status: None,
                normal_duration_ms: 160,
                attack_duration_ms: None,
                timestamp: "2024-01-01T12:00:01Z".to_string(),
            },
            CheckResult {
                check_type: "TE.TE".to_string(),
                vulnerable: true,
                payload_index: Some(2),
                normal_status: "HTTP/1.1 200 OK".to_string(),
                attack_status: Some("Connection Timeout".to_string()),
                normal_duration_ms: 140,
                attack_duration_ms: Some(10000),
                timestamp: "2024-01-01T12:00:02Z".to_string(),
            },
        ];

        let scan_results = ScanResults {
            target: "https://vulnerable.example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks: checks.clone(),
        };

        assert_eq!(scan_results.checks.len(), 3);

        let vulnerable_count = scan_results.checks.iter().filter(|c| c.vulnerable).count();
        assert_eq!(vulnerable_count, 2);
    }

    #[test]
    fn test_check_result_different_check_types() {
        let check_types = vec!["CL.TE", "TE.CL", "TE.TE"];

        for check_type in check_types {
            let result = CheckResult {
                check_type: check_type.to_string(),
                vulnerable: false,
                payload_index: None,
                normal_status: "HTTP/1.1 200 OK".to_string(),
                attack_status: None,
                normal_duration_ms: 100,
                attack_duration_ms: None,
                timestamp: "2024-01-01T12:00:00Z".to_string(),
            };

            assert_eq!(result.check_type, check_type);
        }
    }

    #[test]
    fn test_check_result_timeout_scenarios() {
        // Scenario 1: Timeout via status code
        let result1 = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(15000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        assert!(result1.attack_status.as_ref().unwrap().contains("504"));

        // Scenario 2: Connection timeout
        let result2 = CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: true,
            payload_index: Some(1),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("Connection Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(10000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        assert_eq!(
            result2.attack_status,
            Some("Connection Timeout".to_string())
        );
    }
}
