+++
title = "Quick Start"
description = "Run your first scan with smugglex"
weight = 3
sort_by = "weight"

[extra]
+++

Get started with smugglex in minutes.

## Run First Scan

```bash
smugglex https://example.com/
```

Replace `https://example.com/` with a URL you have permission to test.

## Understand Results

Example output when a vulnerability is found:

```
=== TE.CL Vulnerability Details ===
Status: VULNERABLE
Payload Index: 0
Attack Response: Connection Timeout
Timing: Normal: 1279ms, Attack: 10000ms
```

## Common Options

```bash
# Verbose output
smugglex https://example.com/ -v

# Quick scan (exit on first vulnerability)
smugglex https://example.com/ -1

# Save results to JSON
smugglex https://example.com/ -o results.json

# Test specific attack types
smugglex https://example.com/ -c cl-te,te-cl
```

## Security Notice

⚠️ Only test systems you own or have explicit written permission to test. Unauthorized testing may be illegal.

## Next Steps

- [Options & Flags](/usage/options-and-flags) - All command-line options
- [Examples](/usage/examples) - More usage examples
- [Exploiting](/advanced/exploiting) - Exploitation techniques
