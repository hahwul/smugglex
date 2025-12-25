+++
title = "Examples"
description = "Practical usage examples for smugglex"
weight = 3
sort_by = "weight"

[extra]
+++

This guide provides practical examples of using smugglex in different scenarios.

## Basic Scans

### Simple Scan

Run a basic scan on a target URL:

```bash
smugglex https://target.com/
```

This runs all available checks and reports any vulnerabilities found.

### Verbose Output

Enable detailed logging:

```bash
smugglex https://target.com/ -v
```

### Save Results

Export results to JSON format:

```bash
smugglex https://target.com/ -o results.json
```

## Configuration Examples

### Custom HTTP Method

Specify the HTTP method:

```bash
smugglex https://target.com/ -m POST
smugglex https://target.com/ -m GET
```

### Custom Headers

Add custom headers to requests:

```bash
smugglex https://target.com/ -H "Authorization: Bearer token123"
smugglex https://target.com/ -H "X-Custom: value" -H "User-Agent: custom"
```

### Timeout Configuration

Set request timeout in seconds:

```bash
smugglex https://target.com/ -t 15
smugglex https://target.com/ -t 30
```

### Virtual Host Testing

Test different virtual hosts on the same IP:

```bash
smugglex https://192.168.1.100/ --vhost example.com
```

### Cookie Support

Fetch and include cookies in requests:

```bash
smugglex https://target.com/ --cookies
```

## Scan Configuration

### Specific Attack Types

Run specific checks only:

```bash
# Test only CL.TE
smugglex https://target.com/ -c cl-te

# Test CL.TE and TE.CL
smugglex https://target.com/ -c cl-te,te-cl

# Test all HTTP/2 related
smugglex https://target.com/ -c h2c,h2
```

### Exit on First Vulnerability

Stop scanning after finding the first vulnerability:

```bash
smugglex https://target.com/ --exit-first
smugglex https://target.com/ -1
```

### Export Payloads

Save vulnerable payloads for manual verification:

```bash
smugglex https://target.com/ --export-payloads ./payloads
```

## Multiple Targets

### Pipeline Input

Read URLs from stdin:

```bash
# From a file
cat urls.txt | smugglex

# From echo
echo "https://target.com/" | smugglex

# From other tools
subfinder -d example.com | httpx | smugglex
```

### File Input

Create a file with one URL per line:

```bash
# urls.txt
https://target1.com/
https://target2.com/api
https://target3.com/admin
```

Then pipe it to smugglex:

```bash
cat urls.txt | smugglex -v -o results.json
```

## Workflow Examples

### Quick Vulnerability Check

```bash
smugglex https://target.com/ --exit-first -v
```

### Comprehensive Scan

```bash
smugglex https://target.com/ -v -o results.json --export-payloads ./payloads
```

### Authenticated Testing

```bash
smugglex https://target.com/ -H "Authorization: Bearer token" --cookies -v
```

### Targeted Testing

```bash
smugglex https://target.com/ -c cl-te,te-cl -t 20 -v
```

### Mass Scanning

```bash
cat targets.txt | smugglex -o results.json --exit-first
```

### Virtual Host Testing

```bash
smugglex https://10.0.0.1/ --vhost internal.example.com -H "X-Forwarded-For: 127.0.0.1"
```

## Exploitation Examples

### Localhost Access Exploit

After detecting a smuggling vulnerability, test for SSRF-like attacks:

```bash
smugglex https://target.com/ --exploit localhost-access
```

### Custom Ports

Test specific ports:

```bash
smugglex https://target.com/ --exploit localhost-access --exploit-ports 22,80,443
```

Test database services:

```bash
smugglex https://target.com/ --exploit localhost-access --exploit-ports 3306,5432,6379,27017
```

### Exploit with Detection

Combine with specific checks and exploitation:

```bash
# Only test CL.TE, then exploit if found
smugglex https://target.com/ -c cl-te --exploit localhost-access --exploit-ports 80,443

# Quick scan with exploitation
smugglex https://target.com/ -1 --exploit localhost-access -v
```

## Best Practices

### Testing Strategy

1. Start with a quick scan using `--exit-first`
2. If vulnerable, run a comprehensive scan
3. Export payloads for manual verification
4. Document findings with JSON output

### Performance Tips

- Use appropriate timeouts for network conditions
- Run specific checks when targeting known vulnerabilities
- Use `--exit-first` for quick validation
- Pipeline multiple targets for efficient scanning

### Safety Considerations

- Only test systems you have permission to test
- Use appropriate timeouts to avoid DoS
- Be aware that scans generate significant traffic
- Consider rate limiting for production systems

## References

- [Options and Flags](/usage/options-and-flags) - All command-line options
- [Exploiting](/advanced/exploiting) - Exploitation features
- [Performance Tips](/advanced/performance-tips) - Optimize scanning
