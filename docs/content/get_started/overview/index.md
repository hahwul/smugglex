+++
title = "Overview"
description = "Learn about smugglex and HTTP Request Smuggling vulnerabilities"
weight = 1
sort_by = "weight"

[extra]
+++

Smugglex is a security testing tool that detects HTTP Request Smuggling vulnerabilities in web applications. The tool is written in Rust and designed for penetration testing and security research.

## What is HTTP Request Smuggling?

HTTP Request Smuggling is a web security vulnerability that exploits differences in how servers parse HTTP requests. When a front-end server and back-end server disagree on request boundaries, attackers can smuggle malicious requests through security controls.

### How It Works

Request smuggling happens when servers disagree about request boundaries. This involves two HTTP headers:

- Content-Length - Specifies message body length in bytes
- Transfer-Encoding - Specifies encoding method for message body

When these headers conflict or use obfuscation, servers interpret them differently. This causes request boundary confusion.

### Security Impact

Request smuggling vulnerabilities enable:

- Bypass security controls like WAF (Web Application Firewall) and IDS (Intrusion Detection System)
- Poison web caches to serve malicious content
- Hijack user sessions and steal cookies
- Access unauthorized resources
- Intercept and modify user requests
- Capture sensitive data from other requests

## Why Use Smugglex?

### Multiple Attack Types

Smugglex tests for five attack types:

- CL.TE - Front-end uses Content-Length, back-end uses Transfer-Encoding
- TE.CL - Front-end uses Transfer-Encoding, back-end uses Content-Length
- TE.TE - Both use Transfer-Encoding with obfuscation (40+ variations)
- H2C - HTTP/1.1 to HTTP/2 upgrade exploitation (20+ payloads)
- H2 - HTTP/2 protocol-level smuggling (25+ payloads)

### Detection Methods

- Timing-based detection analyzes response times to find desynchronization
- Extended mutation testing with 40+ Transfer-Encoding variations
- HTTP/2 protocol support for H2C and H2 desync detection
- Connection timeout detection identifies vulnerabilities through behavior

### Testing Options

- Add custom headers for specific test scenarios
- Automatically fetch and include cookies
- Test different virtual hosts on the same IP address
- Use different HTTP methods like GET or POST
- Adjust timeouts for different network conditions
- Select specific attack types to test

### Integration Features

- Read URLs from stdin for tool integration
- Export results in JSON format
- Save vulnerable payloads for manual verification
- Exit after first vulnerability for quick checks
- View real-time progress bars and status

### Performance

- Built with Rust for high performance
- Uses async operations for concurrent testing
- Optimized for fast vulnerability detection
- Low memory footprint and CPU usage

## Key Features

### Comprehensive Attack Coverage

Smugglex supports all major HTTP request smuggling attack types with extensive payload variations. The tool includes research-based obfuscation techniques from security researchers and bug bounty hunters.

### High Performance

The tool is written in Rust and uses async operations for fast scanning. It tests hundreds of payload variations quickly without compromising accuracy.

### Accurate Detection

Smugglex uses timing-based detection algorithms to minimize false positives. The tool analyzes response timing patterns to identify desynchronization vulnerabilities.

### Flexible Configuration

Customize testing with HTTP methods, headers, cookies, timeouts, and virtual hosts. The tool adapts to your specific testing requirements.

### Detailed Reporting

View comprehensive scan results with vulnerability details, payload indices, timing information, and response analysis. Export results in JSON format for documentation.

### Tool Integration

Integrate with other security testing tools through stdin pipeline support. Smugglex works with subdomain enumeration tools, web crawlers, and security scanning pipelines.

## Use Cases

### Security Testing

- Identify vulnerabilities during authorized penetration tests
- Discover high-impact vulnerabilities in bug bounty programs
- Assess web application security for request smuggling risks

### Research and Education

- Explore HTTP request smuggling attack techniques
- Learn how request smuggling vulnerabilities work
- Practice identification in lab environments

### DevSecOps

- Integrate into security testing pipelines
- Test applications before production deployment
- Verify fixes for request smuggling vulnerabilities

## Ethical Use

This tool is for authorized security testing only. Use smugglex only on:

- Systems you own
- Systems with explicit written permission
- Authorized penetration testing engagements
- Educational purposes in controlled environments

Unauthorized testing may be illegal in your jurisdiction. Always obtain proper authorization before testing.

## Next Steps

- Install smugglex by following the [Installation](/get_started/installation) guide
- Learn how to run scans with [Running SmuggleX](/get_started/running)
- Understand HTTP Request Smuggling in depth at [Resources](/resources/http-smuggling)
- Explore development options in [Development](/development)
