# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## 0.4.0

### Added
- Opt-in parser-discrepancy, CL.0, and 0.CL checks: same-connection response-queue and framing-control audits that require reproducible desync signals and expose diagnostics suitable for JSON output (#141).
- Second-request desync detection for CL.TE/TE.CL/TE.TE: plants a TE payload and probes fresh follow-up requests for structural divergence from the baseline (reproduced across two plant+probe sequences), catching smuggling where the attack response is a clean `200` and only the *next* request on the shared connection is corrupted. Surfaced via the `second_request_desync` signal (#108).
- HTTP/2 → HTTP/1.1 downgrade smuggling detection (H2.CL / H2.TE).
- Exploit modes: `smuggle` (solve CL.TE/TE.CL targets), `capture` (recover queued responses via single-connection pipelining), and `reveal` (surface front-end-injected headers by reflecting a front-end-rewritten follow-up request), with escalation through TE obfuscations. Driven by `--exploit`, `--smuggle-request`, `--reveal-endpoint`, and `--reveal-param`; each fires directly without prior detection (#109).
- TLS: `-k`/`--insecure` to skip certificate verification and `--cacert <FILE>` to trust a custom CA (#112, #121).
- Crystal test lab (`lab/`) with real socket-level desync scenarios and a true/false-positive harness guarding against 5xx overload, attack-response status differences, and non-recurring transients (#108).

### Changed
- Refactored TLS plumbing into a single `build_config` plus a shared `load_ca_roots`; the HTTP/2 config is built and cached once so `--cacert` is no longer re-parsed per probe, `--insecure` warns when `--cacert` is also supplied (`-k` wins), and config getters fall back to a default instead of panicking (#121).
- Replaced the archived `rustls-pemfile` crate with `rustls-pki-types`' built-in PEM parsing for `--cacert` (#116).
- Extracted helpers and removed duplication in `scanner`/`main` for readability (#136).
- Redesigned the docs site (ink-serpent branding, flattened landing page) (#125, #140).
- Updated dependencies (tokio, rustls, indicatif, webpki-roots, rustls-pki-types, chrono) and CI/toolchain actions.

### Fixed
- Bound HTTP/1.x response and proxy CONNECT reads to prevent memory exhaustion on oversized/malicious responses (#139).
- `--insecure`/`-k` now advertises the crypto provider's full set of signature schemes (including ECDSA P-521, previously omitted), so such certificates are reachable in insecure mode instead of failing the handshake before verification (#114).
- Preserve virtual hosts and correct HTTP response framing (#143).
- Corrected detection false positives, the CLI/JSON contract, and TE-obfuscation wire bytes (#142).
- Round-based audit: scanner robustness fixes, proxy/reveal/IPv6-TLS handling, and unreachable-target/exploit/export edge cases (#132, #133, #134).

## 0.3.0

### Added
- `--raw-request <FILE>` to replay a captured raw HTTP request (e.g. a Burp Suite export) as the scan template, with `--raw-request-proto <http|https>` to choose the scheme.
- `--json` shorthand flag plus machine-friendly output: stdout emits only valid JSON, and batch / multi-target / stdin scans produce a single envelope with `results[]` and a rich `summary`.
- Meaningful exit codes for CI and agent workflows: `0` = no vulnerabilities, `1` = vulnerability found, `2` = usage/input error.
- `--delay` rate limiting is now applied to the exploit modules as well.
- Actionable hints in error messages and overwrite warnings when exporting files.

### Changed
- Reworked detection into a multi-signal false-positive reduction pipeline: robust baseline statistics, retry-based confirmation, differential control comparison, post-attack follow-up divergence, and variance-aware confidence (plus a lab harness).
- Internal refactor: split `payloads.rs` and `exploit.rs` into per-technique submodules, extracted output/reporting into its own module, and added public-API doc comments.
- CI: enabled clippy and rustfmt checks, added codecov coverage thresholds, and expanded test coverage.
- Updated dependencies (tokio, rustls, clap, serde_json, webpki-roots) and toolchain / CI actions.

### Fixed
- `--raw-request`: preserve the request-target verbatim (origin- and absolute-form), merge `-H` headers, warn on `--method` override, report the real request-target instead of the CONNECT root, and error on bad port / non-HTTP input.

## 0.2.0

### Added
- Proxy fingerprinting and mutation-based fuzzing.

### Changed
- Performance and general code improvements; dependency updates and Dependabot configuration.

## 0.1.0

- Initial release.

[0.4.0]: https://github.com/hahwul/smugglex/releases/tag/v0.4.0
[0.3.0]: https://github.com/hahwul/smugglex/releases/tag/v0.3.0
[0.2.0]: https://github.com/hahwul/smugglex/releases/tag/v0.2.0
[0.1.0]: https://github.com/hahwul/smugglex/releases/tag/0.1.0
