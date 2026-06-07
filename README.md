<div align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/static/images/smugglex-dark.png" width="500px;">
      <source media="(prefers-color-scheme: light)" srcset="docs/static/images/smugglex-light.png" width="500px;">
      <img alt="SmuggleX Logo" src="docs/static/images/smugglex-dark.png" width="500px;">
    </picture>
    <p>Rust-powered HTTP Request Smuggling Scanner.</p>
</div>

<p align="center">
<a href="https://github.com/hahwul/smugglex/blob/main/CONTRIBUTING.md">
<img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=black"></a>
<a href="https://github.com/hahwul/smugglex/releases">
<img src="https://img.shields.io/github/v/release/hahwul/smugglex?style=for-the-badge&color=black&labelColor=black&logo=web"></a>
<a href="https://rust-lang.org">
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"></a>
</p>

## Overview

Smugglex is a security testing tool that detects HTTP Request Smuggling vulnerabilities in web applications. It tests for CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling attacks, and — on HTTPS targets — speaks real HTTP/2 (ALPN `h2`) to detect HTTP/2&rarr;HTTP/1.1 downgrade smuggling (H2.CL / H2.TE) via the `h2-downgrade` check.

For detailed documentation, visit [smugglex.hahwul.com](https://smugglex.hahwul.com).

## Installation

### Homebrew (macOS and Linux)

```bash
brew install hahwul/smugglex/smugglex
```

### Build from Source

Requires Rust 1.70 or later:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
cargo install --path .
```

For other installation methods, see [Installation Guide](https://smugglex.hahwul.com/getting-started/installation/).

## Usage

Basic scan:

```bash
smugglex https://target.com
```

Read URLs from stdin:

```bash
cat urls.txt | smugglex
```

Replay a captured request (e.g. exported from Burp Suite) as the request template:

```bash
smugglex --raw-request request.txt              # target taken from the Host header
smugglex --raw-request request.txt --raw-request-proto http
smugglex --raw-request request.txt -H "X-Collab: abcd.oastify.com"  # -H is additive
```

The captured request-target is sent verbatim — dot-segments, matrix params and `#`
are preserved, not normalized — for both origin-form (`POST /path ...`) and
absolute-form (`GET http://...`) request lines, so path-based payloads survive.
Any `-H` headers are merged on top of the captured ones.

For detailed usage and options, see [Usage Guide](https://smugglex.hahwul.com/usage/).

## Examples

```bash
smugglex https://target.com -v -o results.json
cat urls.txt | smugglex --exit-first
```

## For AI Agents, Scripts & CI

smugglex is designed to be friendly to automated usage:

```bash
# Clean JSON output (only JSON on stdout) + proper exit code
smugglex --json https://target.com
echo $?   # 0 = clean, 1 = vulnerable found

# Batch + structured output (single valid JSON document)
cat urls.txt | smugglex -f json -o report.json

# Quiet + JSON for pipelines
smugglex -q --json https://target.com | jq '.summary.vulnerable_targets'
```

Exit codes:
- `0` — No vulnerabilities found
- `1` — At least one vulnerability found
- `2` — Usage / input error

See the [Pipeline Guide](https://smugglex.hahwul.com/advanced/pipeline/) and [Output Formats](https://smugglex.hahwul.com/usage/output/) for more.

## Troubleshooting

Common issues and solutions are available in the [Troubleshooting Guide](https://smugglex.hahwul.com/support/troubleshooting/).

## References

- [Documentation](https://smugglex.hahwul.com)
- [GitHub Repository](https://github.com/hahwul/smugglex)
- [HTTP Request Smuggling Research](https://portswigger.net/web-security/request-smuggling)

-----

![](docs/static/images/CONTRIBUTORS.svg)
