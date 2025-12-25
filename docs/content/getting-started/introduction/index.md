+++
title = "Introduction"
description = "Learn about smugglex and HTTP Request Smuggling vulnerabilities"
weight = 1
sort_by = "weight"

[extra]
+++

Smugglex is a security testing tool that detects HTTP Request Smuggling vulnerabilities in web applications. Written in Rust for high performance and reliability.

## What is HTTP Request Smuggling?

HTTP Request Smuggling exploits differences in how servers parse HTTP requests. When front-end and back-end servers disagree on request boundaries, attackers can smuggle malicious requests through security controls.

### How It Works

The vulnerability occurs when servers interpret these headers differently:

- **Content-Length** - Message body length in bytes
- **Transfer-Encoding** - Encoding method (e.g., chunked)

When both headers are present or obfuscated, servers may disagree on request boundaries.

## Attack Types

Smugglex detects five attack types:

- **CL.TE** - Front-end uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL** - Front-end uses Transfer-Encoding, back-end uses Content-Length
- **TE.TE** - Both use Transfer-Encoding with obfuscation (40+ variations)
- **H2C** - HTTP/2 Cleartext smuggling (20+ payloads)
- **H2** - HTTP/2 protocol smuggling (25+ payloads)

## Key Features

- **Timing-based detection** - Analyzes response times to identify desynchronization
- **Multiple attack vectors** - Comprehensive payload coverage
- **High performance** - Built with Rust and async operations
- **Pipeline support** - Integrate with other security tools
- **Payload export** - Save vulnerable payloads for analysis

## Security Impact

Successful exploitation can lead to:

- Bypassing WAF and security controls
- Web cache poisoning
- Session hijacking
- Unauthorized access to resources

## Next Steps

- [Installation](/getting-started/installation) - Install smugglex
- [Quick Start](/getting-started/quick-start) - Run your first scan
