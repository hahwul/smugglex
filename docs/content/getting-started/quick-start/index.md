+++
title = "Quick Start"
description = "Run your first scan with smugglex"
weight = 3
sort_by = "weight"

[extra]
+++

This guide helps you run your first scan with smugglex.

## Install

```bash
cargo install smugglex
```

For other installation methods, see the [Installation](/getting-started/installation) guide.

## Run First Scan

```bash
smugglex https://example.com/
```

Replace `https://example.com/` with a URL you have permission to test.

## Review Results

Smugglex tests for all major HTTP Request Smuggling attack types and reports vulnerabilities.

Example output:

```
=== TE.CL Vulnerability Details ===
Status: VULNERABLE
Payload Index: 0
Attack Response: Connection Timeout
Timing: Normal: 1279ms, Attack: 10000ms
```

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

This tool is for authorized security testing only. Use smugglex only on systems you own, systems with explicit written permission, authorized penetration testing engagements, or educational purposes in controlled environments.

Unauthorized testing may be illegal.

## Next Steps

- Explore [Usage](/usage) for detailed configuration options
- Learn about [Exploiting](/advanced/exploiting) vulnerabilities
- Understand [Performance Tips](/advanced/performance-tips) for efficient scanning
