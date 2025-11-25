use std::error::Error;
use std::fmt;

/// Custom error type for the smugglex application
#[derive(Debug)]
pub enum SmugglexError {
    /// HTTP request related errors
    HttpRequest(String),
    /// TLS connection errors
    Tls(String),
    /// URL parsing errors
    UrlParse(String),
    /// I/O errors (file operations)
    Io(String),
    /// JSON serialization/deserialization errors
    Json(String),
    /// Timeout errors
    Timeout(String),
    /// Invalid input parameters
    InvalidInput(String),
}

impl fmt::Display for SmugglexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmugglexError::HttpRequest(msg) => write!(f, "HTTP request error: {}", msg),
            SmugglexError::Tls(msg) => write!(f, "TLS error: {}", msg),
            SmugglexError::UrlParse(msg) => write!(f, "URL parsing error: {}", msg),
            SmugglexError::Io(msg) => write!(f, "I/O error: {}", msg),
            SmugglexError::Json(msg) => write!(f, "JSON error: {}", msg),
            SmugglexError::Timeout(msg) => write!(f, "Timeout error: {}", msg),
            SmugglexError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl Error for SmugglexError {}

impl From<std::io::Error> for SmugglexError {
    fn from(err: std::io::Error) -> Self {
        SmugglexError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for SmugglexError {
    fn from(err: serde_json::Error) -> Self {
        SmugglexError::Json(err.to_string())
    }
}

impl From<url::ParseError> for SmugglexError {
    fn from(err: url::ParseError) -> Self {
        SmugglexError::UrlParse(err.to_string())
    }
}

impl From<rustls::Error> for SmugglexError {
    fn from(err: rustls::Error) -> Self {
        SmugglexError::Tls(err.to_string())
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for SmugglexError {
    fn from(err: rustls::pki_types::InvalidDnsNameError) -> Self {
        SmugglexError::Tls(format!("Invalid DNS name: {}", err))
    }
}

impl From<tokio::time::error::Elapsed> for SmugglexError {
    fn from(_err: tokio::time::error::Elapsed) -> Self {
        SmugglexError::Timeout("Request timed out".to_string())
    }
}

impl From<&str> for SmugglexError {
    fn from(err: &str) -> Self {
        SmugglexError::InvalidInput(err.to_string())
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, SmugglexError>;
