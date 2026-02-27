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

/// Parse HTTP status code from a status line
pub fn parse_status_code(status_line: &str) -> Option<u16> {
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() >= 2 && (parts[0].starts_with("HTTP/1.") || parts[0].starts_with("HTTP/2")) {
        parts[1].parse::<u16>().ok()
    } else {
        None
    }
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

