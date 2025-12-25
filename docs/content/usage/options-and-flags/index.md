+++
title = "Options and Flags"
description = "Command-line options and flags reference"
weight = 1
sort_by = "weight"

[extra]
+++

This guide shows you how to configure smugglex using command-line options and flags.

## Basic Options

### Verbose Output

Enable detailed logging:

```bash
smugglex https://target.com/ -v
```

Verbose mode shows:
- Request and response details
- Timing information
- Progress updates
- Detailed error messages

### Save Results

Export results to JSON format:

```bash
smugglex https://target.com/ -o results.json
```

The JSON file contains vulnerability details, payload information, timing data, and response analysis.

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

## Advanced Options

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

### Exploitation Options

Use detected vulnerabilities for exploitation:

```bash
smugglex https://target.com/ --exploit localhost-access
```

Custom ports for exploitation:

```bash
smugglex https://target.com/ --exploit localhost-access --exploit-ports 22,80,443
```

### Output Format

Specify output format:

```bash
smugglex https://target.com/ -f json
smugglex https://target.com/ -f plain
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

## References

- [Configuration](/usage/configuration) - Configuration settings
- [Examples](/usage/examples) - Practical usage examples
- [Exploiting](/advanced/exploiting) - Exploitation features
