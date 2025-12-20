+++
title = "Getting Started"
description = "This section provides everything you need to get started with smugglex, from installation to your first scan."
weight = 1
sort_by = "weight"

[extra]
+++

# Getting Started

This section guides you through using smugglex to test for HTTP Request Smuggling vulnerabilities.

## What You Will Learn

- [Overview](/get_started/overview) - Learn about HTTP Request Smuggling and smugglex
- [Installation](/get_started/installation) - Install smugglex on your system
- [Running SmuggleX](/get_started/running) - Learn how to run smugglex and configure scans

## Quick Start

### Install

```bash
cargo install smugglex
```

### Run First Scan

```bash
smugglex https://example.com/
```

### Review Results

Smugglex tests for all major HTTP Request Smuggling attack types and reports vulnerabilities.

For more detailed usage examples, see [Running SmuggleX](/get_started/running).

## Key Concepts

### HTTP Request Smuggling

HTTP Request Smuggling exploits differences in how servers parse requests. When servers disagree on request boundaries, attackers can smuggle malicious requests through security controls.

### Attack Types

Smugglex tests for these attack types:

- CL.TE - Content-Length vs Transfer-Encoding desync
- TE.CL - Transfer-Encoding vs Content-Length desync
- TE.TE - Transfer-Encoding obfuscation (40+ variations)
- H2C - HTTP/2 Cleartext smuggling (20+ payloads)
- H2 - HTTP/2 protocol-level smuggling (25+ payloads)

### Timing-Based Detection

Smugglex uses timing analysis to detect vulnerabilities. The tool compares response times between normal and attack requests to identify desynchronization.

## Prerequisites

To use smugglex, you need:

- Basic understanding of HTTP protocol
- Knowledge of web application security
- Authorization to test target systems
- Command-line tool experience

## Security Notice

This tool is for authorized security testing only. Use smugglex only on:

- Systems you own
- Systems with explicit written permission
- Authorized penetration testing engagements
- Educational purposes in controlled environments

Unauthorized testing may be illegal.

## References

- [GitHub Repository](https://github.com/hahwul/smugglex)
- [Issue Tracker](https://github.com/hahwul/smugglex/issues)
- Command-line help: `smugglex --help`
