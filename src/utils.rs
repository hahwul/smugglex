use crate::error::Result;
use crate::http::send_request;
use chrono::Local;
use colored::*;
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
    let sanitized_host = host.replace([':', '/', '.'], "_");
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

    #[test]
    fn test_export_payload_creates_file() {
        use std::env;
        use std::path::Path;

        let temp_dir = env::temp_dir().join("smugglex_test_export");
        let temp_dir_str = temp_dir.to_str().unwrap();
        let _ = fs::remove_dir_all(temp_dir_str); // Clean up if exists

        let payload = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = export_payload(temp_dir_str, "example.com", "CLTE", 0, payload, true);

        assert!(result.is_ok());
        let filename = result.unwrap();
        assert!(Path::new(&filename).exists());

        let content = fs::read_to_string(&filename).unwrap();
        assert_eq!(content, payload);

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir_str);
    }

    #[test]
    fn test_export_payload_sanitizes_hostname() {
        use std::env;

        let temp_dir = env::temp_dir().join("smugglex_test_sanitize");
        let temp_dir_str = temp_dir.to_str().unwrap();
        let _ = fs::remove_dir_all(temp_dir_str);

        let result = export_payload(
            temp_dir_str,
            "sub.example.com:8080",
            "TECL",
            1,
            "test",
            false,
        );

        assert!(result.is_ok());
        let filename = result.unwrap();

        // Filename should have sanitized host
        assert!(filename.contains("sub_example_com_8080"));
        assert!(filename.contains("http_")); // Not https
        assert!(filename.contains("TECL"));
        assert!(filename.contains("_1.txt"));

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir_str);
    }
}
