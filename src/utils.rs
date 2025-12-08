use crate::error::Result;
use crate::http::send_request;
use chrono::Local;
use colored::{ColoredString, Colorize};
use std::fs;

/// Fetch cookies from the target server
pub async fn fetch_cookies(
    host: &str,
    port: u16,
    path: &str,
    use_tls: bool,
    timeout: u64,
    verbose: bool,
) -> Result<Vec<String>> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    let (response, _) = send_request(host, port, &request, timeout, verbose, use_tls).await?;

    let mut cookies = Vec::new();
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("set-cookie:")
            && let Some(cookie_value) = line.split(':').nth(1)
        {
            // Extract just the cookie name=value, stop at semicolon
            let cookie_part = cookie_value
                .trim()
                .split(';')
                .next()
                .unwrap_or("")
                .to_string();
            if !cookie_part.is_empty() {
                cookies.push(cookie_part);
            }
        }
    }

    Ok(cookies)
}

/// Sanitize hostname for use in filenames
pub fn sanitize_hostname(host: &str) -> String {
    host.replace([':', '/', '.'], "_")
}

/// Export payload to a file
pub fn export_payload(
    export_dir: &str,
    host: &str,
    check_type: &str,
    payload_index: usize,
    payload: &str,
    use_tls: bool,
) -> Result<String> {
    // Create export directory if it doesn't exist
    fs::create_dir_all(export_dir)?;

    // Sanitize hostname for filename
    let sanitized_host = sanitize_hostname(host);
    let protocol = if use_tls { "https" } else { "http" };

    let filename = format!(
        "{}/{}_{}_{}_{}.txt",
        export_dir, protocol, sanitized_host, check_type, payload_index
    );

    fs::write(&filename, payload)?;

    Ok(filename)
}

/// Log levels for consistent output formatting
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl LogLevel {
    fn prefix(&self) -> ColoredString {
        match self {
            LogLevel::Info => "INF".cyan(),
            LogLevel::Warning => "WRN".yellow(),
            LogLevel::Error => "ERR".red(),
        }
    }
}

/// Print a log message with timestamp and level prefix
pub fn log(level: LogLevel, message: &str) {
    let time = Local::now().format("%I:%M%p").to_string().to_uppercase();
    println!("{} {} {}", time.dimmed(), level.prefix(), message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    /// Helper function to create a temporary test directory
    fn create_test_dir(name: &str) -> String {
        let temp_dir = env::temp_dir().join(format!("smugglex_test_{}", name));
        let temp_dir_str = temp_dir.to_str().unwrap().to_string();
        let _ = fs::remove_dir_all(&temp_dir_str); // Clean up if exists
        temp_dir_str
    }

    /// Helper function to cleanup test directory
    fn cleanup_test_dir(dir: &str) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_export_payload_creates_file() {
        let temp_dir = create_test_dir("export");

        let payload = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = export_payload(&temp_dir, "example.com", "CLTE", 0, payload, true);

        assert!(result.is_ok(), "export_payload should succeed");
        let filename = result.unwrap();
        assert!(
            Path::new(&filename).exists(),
            "Exported file should exist at {}",
            filename
        );

        let content = fs::read_to_string(&filename).unwrap();
        assert_eq!(
            content, payload,
            "File content should match the payload exactly"
        );

        cleanup_test_dir(&temp_dir);
    }

    #[test]
    fn test_export_payload_sanitizes_hostname() {
        let temp_dir = create_test_dir("sanitize");

        let result = export_payload(&temp_dir, "sub.example.com:8080", "TECL", 1, "test", false);

        assert!(result.is_ok(), "export_payload should succeed");
        let filename = result.unwrap();

        // Verify filename contains sanitized components
        assert!(
            filename.contains("sub_example_com_8080"),
            "Filename should sanitize dots and colons to underscores"
        );
        assert!(
            filename.contains("http_"),
            "Filename should indicate HTTP protocol"
        );
        assert!(filename.contains("TECL"), "Filename should include check type");
        assert!(
            filename.contains("_1.txt"),
            "Filename should include payload index"
        );

        cleanup_test_dir(&temp_dir);
    }

    #[test]
    fn test_sanitize_hostname_dots() {
        let result = sanitize_hostname("example.com");
        assert_eq!(result, "example_com", "Dots should be replaced with underscores");
    }

    #[test]
    fn test_sanitize_hostname_colons() {
        let result = sanitize_hostname("example.com:8080");
        assert_eq!(
            result, "example_com_8080",
            "Colons should be replaced with underscores"
        );
    }

    #[test]
    fn test_sanitize_hostname_slashes() {
        let result = sanitize_hostname("example.com/path");
        assert_eq!(
            result, "example_com_path",
            "Slashes should be replaced with underscores"
        );
    }

    #[test]
    fn test_sanitize_hostname_multiple_special_chars() {
        let result = sanitize_hostname("sub.example.com:8080/path");
        assert_eq!(
            result, "sub_example_com_8080_path",
            "All special characters should be replaced with underscores"
        );
    }

    #[test]
    fn test_sanitize_hostname_no_special_chars() {
        let result = sanitize_hostname("localhost");
        assert_eq!(result, "localhost", "Should remain unchanged if no special chars");
    }

    #[test]
    fn test_export_payload_with_https() {
        let temp_dir = create_test_dir("https");

        let result = export_payload(&temp_dir, "secure.example.com", "CL.TE", 0, "payload", true);

        assert!(result.is_ok(), "export_payload should succeed");
        let filename = result.unwrap();
        assert!(
            filename.contains("https_"),
            "Filename should indicate HTTPS protocol"
        );

        cleanup_test_dir(&temp_dir);
    }

    #[test]
    fn test_export_payload_multiple_files() {
        let temp_dir = create_test_dir("multiple");

        // Export multiple payloads
        let result1 = export_payload(&temp_dir, "example.com", "CL.TE", 0, "payload1", true);
        let result2 = export_payload(&temp_dir, "example.com", "CL.TE", 1, "payload2", true);
        let result3 = export_payload(&temp_dir, "example.com", "TE.CL", 0, "payload3", true);

        assert!(result1.is_ok(), "First export should succeed");
        assert!(result2.is_ok(), "Second export should succeed");
        assert!(result3.is_ok(), "Third export should succeed");

        let file1 = result1.unwrap();
        let file2 = result2.unwrap();
        let file3 = result3.unwrap();

        // Verify all files exist and are different
        assert!(Path::new(&file1).exists(), "First file should exist");
        assert!(Path::new(&file2).exists(), "Second file should exist");
        assert!(Path::new(&file3).exists(), "Third file should exist");
        assert_ne!(file1, file2, "Files should have different names");
        assert_ne!(file1, file3, "Files should have different names");
        assert_ne!(file2, file3, "Files should have different names");

        cleanup_test_dir(&temp_dir);
    }

    #[test]
    fn test_export_payload_creates_directory_if_not_exists() {
        let temp_dir = env::temp_dir().join("smugglex_test_new_dir");
        let temp_dir_str = temp_dir.to_str().unwrap();
        
        // Ensure directory doesn't exist
        let _ = fs::remove_dir_all(temp_dir_str);

        let result = export_payload(temp_dir_str, "example.com", "CL.TE", 0, "test", true);

        assert!(result.is_ok(), "export_payload should create directory");
        assert!(
            Path::new(temp_dir_str).exists(),
            "Directory should be created"
        );

        cleanup_test_dir(temp_dir_str);
    }
}
