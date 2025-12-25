+++
title = "Performance Tips"
description = "Optimize smugglex scanning performance"
weight = 2
sort_by = "weight"

[extra]
+++

This guide provides tips for optimizing smugglex scanning performance.

## Quick Performance Options

### Exit on First Vulnerability

Stop scanning after finding the first vulnerability using the `--exit-first` or `-1` flag:

```bash
smugglex https://target.com/ --exit-first
smugglex https://target.com/ -1
```

This is the fastest way to check if a target has any HTTP Request Smuggling vulnerabilities. Smugglex will stop as soon as it detects the first vulnerability, saving significant time when you only need to confirm a vulnerability exists.

### Use Cases

- Quick validation during penetration testing
- Rapid scanning of multiple targets
- Bug bounty hunting when confirmation is sufficient
- Initial vulnerability assessment
- CI/CD pipeline checks

### Example Workflows

**Quick Scan Single Target:**
```bash
smugglex https://target.com/ -1 -v
```

**Fast Mass Scanning:**
```bash
cat targets.txt | smugglex -1 -o results.json
```

**Quick Check with Exploitation:**
```bash
smugglex https://target.com/ -1 --exploit localhost-access
```

## Specific Attack Type Testing

Test only specific vulnerability types to reduce scan time:

```bash
# Test only CL.TE (fastest single check)
smugglex https://target.com/ -c cl-te

# Test CL.TE and TE.CL only
smugglex https://target.com/ -c cl-te,te-cl

# Skip HTTP/2 checks if not needed
smugglex https://target.com/ -c cl-te,te-cl,te-te
```

## Timeout Optimization

### Reduce Timeout for Fast Networks

For targets with fast response times:

```bash
smugglex https://target.com/ -t 5
```

Default timeout is 10 seconds. Reducing it speeds up scans on responsive targets.

### Increase Timeout for Slow Networks

For targets with slow response times:

```bash
smugglex https://target.com/ -t 20
```

This prevents false negatives on slow or distant targets.

## Pipeline Optimization

### Parallel Scanning

Use GNU parallel for concurrent target scanning:

```bash
cat targets.txt | parallel -j 10 smugglex -1
```

This runs 10 smugglex instances in parallel.

### Tool Integration

Integrate with other tools efficiently:

```bash
# Fast subdomain enumeration and testing
subfinder -d example.com | httpx | smugglex -1

# Quick port scan and smuggling test
nmap -p 80,443 -oG - target.net | awk '/open/{print $2}' | smugglex -1
```

## Scan Strategy

### Progressive Approach

1. **Quick Initial Scan:**
   ```bash
   smugglex https://target.com/ -1 -c cl-te,te-cl
   ```

2. **If Vulnerable, Comprehensive Scan:**
   ```bash
   smugglex https://target.com/ -v -o results.json --export-payloads ./payloads
   ```

3. **Targeted Exploitation:**
   ```bash
   smugglex https://target.com/ -c cl-te --exploit localhost-access
   ```

### Focus on High-Value Targets

Test endpoints most likely to be vulnerable:

- API endpoints
- Admin panels
- Load balancer endpoints
- Reverse proxy paths
- CDN endpoints

## Output Optimization

### Minimal Output

Skip verbose output for faster processing:

```bash
smugglex https://target.com/ -1
```

### JSON Output for Automation

Use JSON output for automated processing:

```bash
cat targets.txt | smugglex -1 -o results.json
```

Parse results programmatically without human-readable formatting overhead.

## Network Considerations

### Local Network Testing

Testing on local networks is faster:

```bash
# Fast local testing
smugglex http://192.168.1.100/ -t 5 -1

# Skip TLS overhead for HTTP
smugglex http://target.com/ -1
```

### Batch Processing

Process URLs in batches for better resource utilization:

```bash
# Process 100 URLs at a time
split -l 100 targets.txt batch_
for batch in batch_*; do
  cat $batch | smugglex -1 >> results.txt
done
```

## Resource Management

### Memory Efficiency

Smugglex has low memory footprint. For very large scans:

```bash
# Stream processing without buffering
cat large_target_list.txt | smugglex -1 | tee results.txt
```

### CPU Optimization

Smugglex uses async operations efficiently. For CPU-limited systems:

```bash
# Limit concurrent operations by processing fewer targets
cat targets.txt | head -n 50 | smugglex -1
```

## Benchmarks

Typical scan times per target:

| Configuration | Approximate Time |
|--------------|------------------|
| `-1 -c cl-te` | 1-5 seconds |
| `-1 -c cl-te,te-cl` | 2-10 seconds |
| `-1` (all checks) | 10-60 seconds |
| Full scan (no `-1`) | 60-300 seconds |
| With exploitation | +10-30 seconds |

Times vary based on network conditions and target response times.

## Best Practices

### When to Use Exit-First

Use `--exit-first` / `-1` when:
- Scanning large numbers of targets
- Performing initial vulnerability assessment
- Time is limited
- Confirmation is sufficient
- Testing in CI/CD pipelines

### When to Use Full Scan

Use full scan (without `-1`) when:
- Detailed vulnerability analysis is needed
- Testing specific vulnerability types
- Generating comprehensive reports
- Verifying all attack vectors
- Research or thorough penetration testing

### Balanced Approach

```bash
# Quick check first
smugglex https://target.com/ -1

# If vulnerable, run comprehensive scan
if [ $? -eq 0 ]; then
  smugglex https://target.com/ -v -o detailed_results.json --export-payloads ./payloads
fi
```

## Performance Monitoring

### Track Scan Progress

Use verbose mode to monitor performance:

```bash
smugglex https://target.com/ -1 -v
```

### Measure Scan Time

Time your scans:

```bash
time smugglex https://target.com/ -1
```

## Troubleshooting Slow Scans

### Identify Bottlenecks

1. **Network latency**: Use `-t` to adjust timeout
2. **Target responsiveness**: Try different endpoints
3. **Check selection**: Use `-c` to limit checks
4. **DNS resolution**: Use IP addresses directly

### Solutions

**Slow network:**
```bash
smugglex https://target.com/ -t 5 -1 -c cl-te
```

**Unresponsive target:**
```bash
smugglex https://target.com/ -t 30 -c cl-te,te-cl
```

**Too many checks:**
```bash
smugglex https://target.com/ -1 -c cl-te
```

## References

- [Options and Flags](/usage/options-and-flags) - All command-line options
- [Examples](/usage/examples) - Usage examples
- [Exploiting](/advanced/exploiting) - Exploitation features
