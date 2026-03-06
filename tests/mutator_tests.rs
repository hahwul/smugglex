//! Tests for the mutation-based fuzzing engine
//!
//! This module contains tests for:
//! - Deterministic output with same seed
//! - Deduplication correctness
//! - Mutant validity (still contains HTTP/1.1)
//! - Different seeds produce different results
//! - Edge cases (empty input, single payload)

use smugglex::mutator::{Mutator, MutatorConfig};
use std::collections::HashSet;

fn sample_payload() -> String {
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string()
}

fn te_cl_payload() -> String {
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n".to_string()
}

#[test]
fn test_deterministic_same_seed() {
    let seeds = vec![sample_payload()];

    let mut m1 = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 10 });
    let mut m2 = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 10 });

    let r1 = m1.mutate_payloads(&seeds);
    let r2 = m2.mutate_payloads(&seeds);
    assert_eq!(r1, r2, "Same seed should produce identical output");
}

#[test]
fn test_different_seeds_differ() {
    let seeds = vec![sample_payload()];

    let mut m1 = Mutator::new(MutatorConfig { seed: 1, mutations_per_payload: 10 });
    let mut m2 = Mutator::new(MutatorConfig { seed: 9999, mutations_per_payload: 10 });

    let r1 = m1.mutate_payloads(&seeds);
    let r2 = m2.mutate_payloads(&seeds);
    assert_ne!(r1, r2, "Different seeds should produce different output");
}

#[test]
fn test_deduplication() {
    let seeds = vec![sample_payload(), sample_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
    let result = m.mutate_payloads(&seeds);

    let unique: HashSet<_> = result.iter().collect();
    assert_eq!(result.len(), unique.len(), "No duplicates should be present");
}

#[test]
fn test_originals_preserved_first() {
    let seeds = vec![sample_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
    let result = m.mutate_payloads(&seeds);

    assert_eq!(&result[0], &seeds[0], "First element should be the original seed");
}

#[test]
fn test_mutants_contain_http_version() {
    let seeds = vec![sample_payload(), te_cl_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 10 });
    let result = m.mutate_payloads(&seeds);

    for (i, payload) in result.iter().enumerate() {
        assert!(
            payload.contains("HTTP/"),
            "Mutant {} should contain HTTP version string",
            i
        );
    }
}

#[test]
fn test_generates_more_than_originals() {
    let seeds = vec![sample_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
    let result = m.mutate_payloads(&seeds);

    assert!(
        result.len() > 1,
        "Should generate mutants beyond the original (got {} total)",
        result.len()
    );
}

#[test]
fn test_empty_input() {
    let seeds: Vec<String> = vec![];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 5 });
    let result = m.mutate_payloads(&seeds);

    assert!(result.is_empty());
}

#[test]
fn test_multiple_seeds() {
    let seeds = vec![sample_payload(), te_cl_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 3 });
    let result = m.mutate_payloads(&seeds);

    // Should have at least 2 originals + some mutants
    assert!(result.len() >= 2, "Should have at least the originals");
    assert!(result.contains(&seeds[0]));
    assert!(result.contains(&seeds[1]));
}

#[test]
fn test_high_mutation_count() {
    let seeds = vec![sample_payload()];

    let mut m = Mutator::new(MutatorConfig { seed: 42, mutations_per_payload: 50 });
    let result = m.mutate_payloads(&seeds);

    // With 50 mutations attempted, we should get a good number of unique results
    assert!(result.len() > 10, "Should generate many mutants (got {})", result.len());
}
