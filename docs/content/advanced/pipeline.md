+++
title = "Pipeline"
description = "Integrating smugglex with other tools"
+++

smugglex reads URLs from stdin, making it easy to integrate into security testing pipelines.

## With subfinder + httpx

```bash
subfinder -d target.com | httpx | smugglex
```

## From a file

```bash
cat urls.txt | smugglex -f json -o results.json
```

## With custom recon

```bash
echo "https://target.com" | smugglex -c cl-te,te-cl --fingerprint
```

## JSON Processing

Pipe JSON output to jq for filtering:

```bash
smugglex -f json https://target.com | jq '.checks[] | select(.vulnerable)'
```

## Through a Proxy

Route all traffic through an intercepting proxy like Burp Suite:

```bash
cat urls.txt | smugglex -x http://127.0.0.1:8080
```

## CI/CD Integration

Use JSON + exit codes for reliable automation. The tool exits with:
- `0` — no vulnerabilities
- `1` — vulnerabilities found
- `2` — input/usage error

```bash
# Recommended for agents/CI
smugglex -q --json -o report.json https://staging.example.com
echo $?   # inspect exit code

# Or pipe directly
cat urls.txt | smugglex --json | jq '.summary.vulnerable_targets'
```

## Fast Scan for Large Target Lists

Limit payloads per check type and increase concurrency for faster scans:

```bash
cat urls.txt | smugglex -j 5 --max-payloads 20 -q
```
