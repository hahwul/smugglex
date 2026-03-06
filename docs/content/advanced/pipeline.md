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

## CI/CD Integration

Use exit codes and JSON output for automated security checks:

```bash
smugglex -f json -o report.json https://staging.example.com
# Process report.json in your pipeline
```
