# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added
- `reveal` exploit (`--exploit reveal`): reveals front-end request rewriting by smuggling a `POST` to a reflecting endpoint whose `Content-Length` overshoots its body, so the back-end swallows the *next* request — as rewritten by the front-end — into the reflected parameter. smugglex tags the follow-up with a unique marker, recovers the reflection via the response queue, and diffs the captured headers to surface front-end-injected ones (`X-Forwarded-For`, rewritten `Host`, internal auth/routing headers). Configurable via `--reveal-endpoint <PATH>` and `--reveal-param <NAME>`; like `smuggle`/`capture` it fires directly and needs no prior detection.
- Second-request desync detection: when a CL.TE/TE.CL/TE.TE check finds no direct anomaly, smugglex now plants a TE payload and probes fresh follow-up requests for structural divergence (non-5xx status or body) from the baseline, reproduced across two independent plant+probe sequences. This catches "second-request" smuggling where the attack response itself is a clean `200` and only the *following* request on the shared upstream connection is corrupted — including the real socket-level lab in `lab/desync/`, which was previously missed by the `cl-te` check. Surfaced via the new `second_request_desync` detection signal.
- Lab harness scenarios (`lab/validate.cr`): three stateful `TP_second_request_*` true positives and three new false positives (`FP_followup_503_overload`, `FP_te_request_405`, `FP_transient_404`) guarding the new probe against 5xx overload, attack-response status differences, and non-recurring transients.

### Changed
- Refactored the TLS configuration plumbing: the six near-identical per-protocol/per-mode builders collapse into a single `build_config` plus a shared `load_ca_roots`, and the HTTP/2 config is now built and cached once at init time so `--cacert` no longer re-reads and re-parses the CA file on every h2 probe. `--insecure` warns when `--cacert` is also supplied (since `-k` takes precedence), and the config getters fall back to a default config instead of panicking when TLS init is skipped (#115).
- Replaced the archived `rustls-pemfile` crate with `rustls-pki-types`' built-in PEM parsing for `--cacert` (#116).

### Fixed
- `--insecure`/`-k` now advertises the active crypto provider's full set of signature schemes (including ECDSA P-521 and others previously omitted) instead of a hardcoded list, so servers presenting such certificates are reachable in insecure mode rather than failing the handshake before verification (#114).

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

[0.3.0]: https://github.com/hahwul/smugglex/releases/tag/v0.3.0
[0.2.0]: https://github.com/hahwul/smugglex/releases/tag/v0.2.0
[0.1.0]: https://github.com/hahwul/smugglex/releases/tag/0.1.0
