use crate::error::Result;
use crate::http::send_request;
use chrono::Local;
use colored::{ColoredString, Colorize};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};

static QUIET: AtomicBool = AtomicBool::new(false);
static MACHINE: AtomicBool = AtomicBool::new(false);

/// Enable or disable quiet mode globally
pub fn set_quiet(enabled: bool) {
    QUIET.store(enabled, Ordering::Relaxed);
}

/// Check if quiet mode is enabled
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Enable or disable machine mode (JSON / structured output).
/// In machine mode, human-readable logs are suppressed or redirected to stderr.
pub fn set_machine(enabled: bool) {
    MACHINE.store(enabled, Ordering::Relaxed);
}

/// Check if machine mode (structured/JSON output) is active.
pub fn is_machine() -> bool {
    MACHINE.load(Ordering::Relaxed)
}

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

    Ok(parse_set_cookies(&response))
}

/// Extract the `name=value` part of every `Set-Cookie` header in an HTTP
/// response. Parsing stops at the first blank line (the header/body boundary),
/// so a body line that merely *looks* like `set-cookie: ...` is never harvested
/// as a cookie — mirroring the boundary handling in
/// [`crate::fingerprint`]'s header parser.
fn parse_set_cookies(response: &str) -> Vec<String> {
    let mut cookies = Vec::new();
    for line in response.lines() {
        // The first blank line terminates the header section; everything after
        // it is the response body and must not be scanned for headers.
        if line.trim().is_empty() {
            break;
        }
        if line.len() >= 11
            && line.as_bytes()[..11].eq_ignore_ascii_case(b"set-cookie:")
            && let Some((_, cookie_value)) = line.split_once(':')
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
    cookies
}

/// Sanitize a hostname for use in an export filename. Any byte that is not an
/// ASCII alphanumeric, `-` or `_` is replaced with `_`, so an IPv6 literal's
/// brackets (`[::1]`), colons, dots, and every Windows-illegal filename
/// character (`<>:"/\|?*`) are neutralized rather than reaching the filesystem.
/// (The previous version only replaced `:`, `/`, `.`, leaving brackets and other
/// hostile characters intact.)
pub fn sanitize_hostname(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Export payload to a file. `payload` is written verbatim as bytes so a
/// TE-obfuscation request carrying raw bytes > 0x7F (NEL, NBSP, …) is saved
/// exactly as it goes on the wire — usable directly for exploitation — rather
/// than a lossy UTF-8 rendering.
pub fn export_payload(
    export_dir: &str,
    host: &str,
    check_type: &str,
    payload_index: usize,
    payload: &[u8],
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

    if fs::metadata(&filename).is_ok() {
        log(
            LogLevel::Warning,
            &format!("overwriting existing payload file: {}", filename),
        );
    }
    fs::write(&filename, payload)?;

    Ok(filename)
}

/// Parse HTTP status code from a status line (allocation-free)
pub fn parse_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let protocol = parts.next()?;
    if protocol.starts_with("HTTP/1.") || protocol.starts_with("HTTP/2") {
        parts.next()?.parse::<u16>().ok()
    } else {
        None
    }
}

/// Log levels for consistent output formatting
pub enum LogLevel {
    /// Informational messages (suppressed in quiet mode)
    Info,
    /// Warning messages indicating potential issues
    Warning,
    /// Error messages indicating failures
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

    /// Plain (non-colored) prefix, used in machine mode where we write to stderr.
    fn prefix_plain(&self) -> &'static str {
        match self {
            LogLevel::Info => "INF",
            LogLevel::Warning => "WRN",
            LogLevel::Error => "ERR",
        }
    }
}

/// Print a log message with timestamp and level prefix.
/// In machine mode (JSON output), Info is suppressed and non-Info goes to stderr
/// so that stdout remains clean for structured data.
pub fn log(level: LogLevel, message: &str) {
    if is_machine() && matches!(level, LogLevel::Info) {
        return;
    }
    if is_quiet() && matches!(level, LogLevel::Info) {
        return;
    }

    let time = Local::now().format("%I:%M%p").to_string().to_uppercase();

    if is_machine() {
        // Machine mode: send warnings/errors to stderr without ANSI colors
        // to avoid polluting JSON consumers.
        match level {
            LogLevel::Info => {
                // Should not reach here (early return above), but be defensive.
                eprintln!("{} {}", time, message);
            }
            _ => {
                eprintln!("{} {} {}", time, level.prefix_plain(), message);
            }
        }
    } else {
        println!("{} {} {}", time.dimmed(), level.prefix(), message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_cookies_extracts_name_value_pairs() {
        let response = "HTTP/1.1 200 OK\r\n\
                        Set-Cookie: session=abc; Path=/; HttpOnly\r\n\
                        Set-Cookie: theme=dark; Max-Age=3600\r\n\
                        Content-Type: text/html\r\n\
                        \r\n\
                        body";
        assert_eq!(
            parse_set_cookies(response),
            vec!["session=abc".to_string(), "theme=dark".to_string()]
        );
    }

    #[test]
    fn parse_set_cookies_is_case_insensitive() {
        let response = "HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nSET-COOKIE: b=2\r\n\r\n";
        assert_eq!(
            parse_set_cookies(response),
            vec!["a=1".to_string(), "b=2".to_string()]
        );
    }

    #[test]
    fn parse_set_cookies_stops_at_body_boundary() {
        // A body line that merely looks like a Set-Cookie header must NOT be
        // harvested — parsing stops at the first blank line.
        let response = "HTTP/1.1 200 OK\r\n\
                        Set-Cookie: real=1\r\n\
                        \r\n\
                        Set-Cookie: injected=evil\r\n\
                        more body";
        assert_eq!(parse_set_cookies(response), vec!["real=1".to_string()]);
    }

    #[test]
    fn sanitize_hostname_neutralizes_ipv6_and_hostile_chars() {
        // IPv6 brackets and colons must not survive into a filename.
        assert_eq!(sanitize_hostname("[::1]"), "___1_");
        assert_eq!(sanitize_hostname("[fe80::1]:8080"), "_fe80__1__8080");
        // Windows-illegal characters are all mapped to '_'.
        assert_eq!(sanitize_hostname("a<b>c\"d|e?f*g"), "a_b_c_d_e_f_g");
        // Allowed characters (alphanumerics, '-', '_') pass through unchanged.
        assert_eq!(sanitize_hostname("my-host_1"), "my-host_1");
    }

    #[test]
    fn parse_set_cookies_ignores_empty_values() {
        // `Set-Cookie:` with no value contributes nothing.
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie:\r\nSet-Cookie:   \r\n\r\n";
        assert!(parse_set_cookies(response).is_empty());
    }
}
