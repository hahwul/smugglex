+++
title = "Running SmuggleX"
description = "Learn how to run smugglex and configure scans"
weight = 3
sort_by = "weight"

[extra]
+++

This guide shows you how to run smugglex and configure scans for different testing scenarios.

## Basic Usage

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

Verbose mode shows:
- Request/response details
- Timing information
- Progress updates
- Detailed error messages

### Save Results

Export results to JSON format:

```bash
smugglex https://target.com/ -o results.json
```

The JSON file contains:
- Vulnerability details
- Payload information
- Timing data
- Response analysis

## Advanced Options

### Custom HTTP Method

Specify the HTTP method:

```bash
smugglex https://target.com/ -m POST
smugglex https://target.com/ -m GET
```

Default method is POST.

### Custom Headers

Add custom headers to requests:

```bash
smugglex https://target.com/ -H "Authorization: Bearer token123"
smugglex https://target.com/ -H "X-Custom: value" -H "User-Agent: custom"
```

Multiple headers can be specified with multiple `-H` flags.

### Timeout Configuration

Set request timeout in seconds:

```bash
smugglex https://target.com/ -t 15
smugglex https://target.com/ -t 30
```

Default timeout is 10 seconds. Increase for slow networks or servers.

### Virtual Host Testing

Test different virtual hosts on the same IP:

```bash
smugglex https://192.168.1.100/ --vhost example.com
```

This sets the Host header to the specified virtual host.

### Cookie Support

Fetch and include cookies in requests:

```bash
smugglex https://target.com/ --cookies
```

Smugglex fetches cookies from the target and includes them in subsequent requests.

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

Available checks:
- `cl-te` - Content-Length vs Transfer-Encoding
- `te-cl` - Transfer-Encoding vs Content-Length
- `te-te` - Transfer-Encoding obfuscation (40+ variations)
- `h2c` - HTTP/2 Cleartext smuggling (20+ payloads)
- `h2` - HTTP/2 protocol smuggling (25+ payloads)

### Exit on First Vulnerability

Stop scanning after finding the first vulnerability:

```bash
smugglex https://target.com/ --exit-first
smugglex https://target.com/ -1
```

Useful for quick checks or when you only need to confirm a vulnerability exists.

### Export Payloads

Save vulnerable payloads for manual verification:

```bash
smugglex https://target.com/ --export-payloads ./payloads
```

This creates files containing the raw HTTP requests that triggered vulnerabilities.

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

## Example Workflows

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

## Exploitation Features

### Localhost Access Exploit

After detecting a smuggling vulnerability, you can automatically test for SSRF-like attacks targeting localhost services:

```bash
smugglex https://target.com/ --exploit localhost-access
```

This leverages the detected vulnerability to attempt accessing localhost (127.0.0.1) on common ports: 22, 80, 443, 8080, 3306.

#### Custom Ports

Test specific ports:

```bash
smugglex https://target.com/ --exploit localhost-access --exploit-ports 22,80,443
```

Test database services:

```bash
smugglex https://target.com/ --exploit localhost-access --exploit-ports 3306,5432,6379,27017
```

#### Exploit with Detection

Combine with specific checks and exploitation:

```bash
# Only test CL.TE, then exploit if found
smugglex https://target.com/ -c cl-te --exploit localhost-access --exploit-ports 80,443

# Quick scan with exploitation
smugglex https://target.com/ -1 --exploit localhost-access -v
```

#### Understanding Exploit Results

When localhost access is successful, you'll see:

```
=== Localhost Access Exploit Results ===
Target: https://target.com/
Success Rate: 2/3

[+] Localhost Access Successful on port 22
  Reason: Found signature 'SSH-2.0' in response; Status code changed from 200 to 502
  Response Status: HTTP/1.1 502 Bad Gateway

[+] Localhost Access Successful on port 80
  Reason: Found error keyword 'Connection refused' in response body
  Response Status: HTTP/1.1 502 Bad Gateway
```

The exploit detects success based on:
- Status code changes (200 → 502/503/504/403/421)
- Service-specific signatures (SSH-2.0, Apache, nginx, etc.)
- Error messages with localhost-related keywords
- Significant timing differences

⚠️ **Important**: Exploitation features are for authorized security testing only.

## Command-Line Reference

### All Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--method` | `-m` | HTTP method | POST |
| `--timeout` | `-t` | Timeout in seconds | 10 |
| `--verbose` | `-v` | Enable verbose output | false |
| `--output` | `-o` | JSON output file | - |
| `--header` | `-H` | Add custom headers | - |
| `--checks` | `-c` | Specify checks to run | all |
| `--vhost` | | Virtual host for Host header | - |
| `--cookies` | | Fetch and include cookies | false |
| `--export-payloads` | | Export vulnerable payloads | - |
| `--exit-first` | `-1` | Exit after first vulnerability | false |
| `--exploit` | `-e` | Exploit types (e.g., localhost-access) | - |
| `--exploit-ports` | | Ports for localhost-access exploit | 22,80,443,8080,3306 |
| `--format` | `-f` | Output format (plain or json) | plain |
| `--help` | `-h` | Display help message | - |
| `--version` | `-V` | Display version | - |

### Getting Help

View all available options:

```bash
smugglex --help
```

Check version:

```bash
smugglex --version
```

## Understanding Results

### Vulnerability Output

When a vulnerability is found, smugglex displays:

```
=== TE.CL Vulnerability Details ===
Status: VULNERABLE
Payload Index: 0
Attack Response: Connection Timeout
Timing: Normal: 1279ms, Attack: 10000ms
```

This shows:
- **Status**: Vulnerability confirmation
- **Payload Index**: Which payload variant triggered it
- **Attack Response**: How the server responded
- **Timing**: Response time comparison

### JSON Output Format

The JSON output contains structured data:

```json
{
  "url": "https://target.com/",
  "vulnerabilities": [
    {
      "type": "TE.CL",
      "payload_index": 0,
      "timing": {
        "normal": 1279,
        "attack": 10000
      },
      "response": "Connection Timeout"
    }
  ],
  "scan_time": 141.099
}
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

## Troubleshooting

### No Output

If smugglex produces no output:
- Verify the target URL is accessible
- Check network connectivity
- Increase timeout with `-t 30`
- Use verbose mode `-v` to see details

### Connection Timeouts

If you see many timeouts:
- Increase timeout value
- Check if a firewall is blocking connections
- Verify target is responding to HTTP requests
- Try different HTTP methods

### False Positives

To verify suspected false positives:
- Re-run with `--export-payloads`
- Manually test the exported payloads
- Check response timing patterns
- Test with different timeout values

## References

- [Overview](/get_started/overview) - Understanding HTTP Request Smuggling
- [Installation](/get_started/installation) - Installing smugglex
- [Development](/development) - Building and developing smugglex
- [Resources](/resources) - HTTP Smuggling resources and references
