mod cl_te;
mod h2;
mod h2c;
mod te_cl;
mod te_te;
mod te_variations;

mod cl_edge;

pub use cl_edge::get_cl_edge_case_payloads;
pub use cl_te::get_cl_te_payloads;
pub use h2::get_h2_payloads;
pub use h2c::get_h2c_payloads;
pub use te_cl::get_te_cl_payloads;
pub use te_te::get_te_te_payloads;
pub use te_variations::get_te_header_variations;

/// Helper function to format custom headers into a string
pub fn format_custom_headers(custom_headers: &[String]) -> String {
    if custom_headers.is_empty() {
        String::new()
    } else {
        let total_len: usize = custom_headers.iter().map(|h| h.len() + 2).sum::<usize>() + 2;
        let mut result = String::with_capacity(total_len);
        for (i, header) in custom_headers.iter().enumerate() {
            if i > 0 {
                result.push_str("\r\n");
            }
            result.push_str(header);
        }
        result.push_str("\r\n");
        result
    }
}

/// Helper function to format cookies into a Cookie header
pub fn format_cookies(cookies: &[String]) -> String {
    if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    }
}

/// Helper function to check if a payload contains a Transfer-Encoding related header
/// This handles various obfuscation techniques including control characters in header names
/// Note: This is only used in tests to verify payload generation, not in production code
pub fn contains_te_header_pattern(payload: &str) -> bool {
    let payload_lower = payload.to_lowercase();

    // Standard patterns (most reliable)
    if payload_lower.contains("transfer-encoding")
        || payload_lower.contains("transfer_encoding") // underjoin pattern
        || payload_lower.contains("transfer encoding") // spacejoin pattern
        || payload_lower.contains("transfer\\encoding") // backslash pattern
        || payload_lower.contains("content-encoding")
    {
        // Content-Encoding confusion
        return true;
    }

    // URL-encoded patterns
    if payload_lower.contains("transfer%") || payload_lower.contains("=?") {
        return true;
    }

    // Partial patterns for control character obfuscation
    // These catch cases where control chars (CR, null, etc.) are inserted into header names
    if payload_lower.contains("nsfer-encoding") // Handles CR in "Tra\rnsfer-Encoding"
        || payload_lower.contains("encoding: chunked")
        || payload_lower.contains("encoding:chunked")
        || payload_lower.contains("encoding:\tchunked")
    {
        return true;
    }

    // Check for "chunked" value which should appear in all TE headers
    if payload_lower.contains("chunked") {
        // Also verify there's some encoding-related text nearby
        if payload_lower.contains("encoding")
            || payload_lower.contains("encod")
            || payload_lower.contains("transf")
        {
            return true;
        }
    }

    false
}
