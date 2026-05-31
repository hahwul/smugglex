# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
