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

## Learning Path

Follow these steps:

1. Read the [Overview](/get_started/overview) to understand HTTP Request Smuggling
2. Follow the [Installation](/get_started/installation) guide to install smugglex
3. Run simple scans on systems you have permission to test
4. Experiment with different command-line options
5. Learn to interpret scan results

## Examples

### Basic Scan

```bash
smugglex https://target.com/
```

### Verbose Output and Save Results

```bash
smugglex https://target.com/ -v -o results.json
```

### Custom Headers and Timeout

```bash
smugglex https://target.com/ -H "Authorization: Bearer token" -t 15
```

### Multiple URLs

```bash
cat urls.txt | smugglex -v
```

### Specific Checks

```bash
smugglex https://target.com/ -c cl-te,te-cl
```

### Export Payloads

```bash
smugglex https://target.com/ --export-payloads ./payloads
```

## Key Concepts

### HTTP Request Smuggling

HTTP Request Smuggling exploits differences in how servers parse requests. When servers disagree on request boundaries, attackers can smuggle malicious requests through security controls.

### Attack Types

Smugglex tests for these attack types:

- CL.TE - Content-Length vs Transfer-Encoding desync
- TE.CL - Transfer-Encoding vs Content-Length desync
- TE.TE - Transfer-Encoding obfuscation (60+ variations)
- H2C - HTTP/2 Cleartext smuggling
- H2 - HTTP/2 protocol-level smuggling

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
