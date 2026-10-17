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
        format!("{}\r\n", custom_headers.join("\r\n"))
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
