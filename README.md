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

Smugglex is a security testing tool that detects HTTP Request Smuggling vulnerabilities in web applications. It tests for CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling attacks.

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

For detailed usage and options, see [Usage Guide](https://smugglex.hahwul.com/usage/).

## Examples

```bash
smugglex https://target.com -v -o results.json
cat urls.txt | smugglex --exit-first
```

## Troubleshooting

Common issues and solutions are available in the [Troubleshooting Guide](https://smugglex.hahwul.com/support/troubleshooting/).

## References

- [Documentation](https://smugglex.hahwul.com)
- [GitHub Repository](https://github.com/hahwul/smugglex)
- [HTTP Request Smuggling Research](https://portswigger.net/web-security/request-smuggling)

-----

![](docs/static/images/CONTRIBUTORS.svg)
