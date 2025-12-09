# smugglex

A powerful HTTP Request Smuggling testing tool written in Rust.

```
smugglex https://********************.web-security-academy.net/
11:27PM INF start scan to https://********************.web-security-academy.net/
11:29PM WRN smuggling found 2 vulnerability(ies)

=== TE.CL Vulnerability Details ===
Status: VULNERABLE
Payload Index: 0
Attack Response: Connection Timeout
Timing: Normal: 1279ms, Attack: 10000ms

=== TE.TE Vulnerability Details ===
Status: VULNERABLE
Payload Index: 11
Attack Response: Connection Timeout
Timing: Normal: 1263ms, Attack: 10000ms

11:29PM INF scan completed in 141.099 seconds
```

## Recent Improvements

- **Extended Mutation Patterns**: Expanded from 6 to 30+ Transfer-Encoding header variations inspired by [smuggler](https://github.com/defparam/smuggler), including whitespace injection, control characters, case variations, and obfuscation techniques
- **Cookie Support**: Automatically fetch and append cookies from the target server for authenticated testing
- **Virtual Host Support**: Override the Host header to test different virtual hosts while connecting to the same IP
- **Payload Export**: Save vulnerable payloads to files for further analysis and exploitation
- **Code Refactoring**: Eliminated code duplication in payload generation functions, introduced custom error types for better error handling, and improved code readability with helper functions and better formatting
- **Error Handling**: Replaced generic `Box<dyn Error>` with custom `SmugglexError` enum for more specific error types
- **CI/CD**: Added GitHub Actions workflow for automated testing, linting, and building across multiple platforms and Rust versions
- **Code Quality**: Enhanced test coverage, applied rustfmt for consistent formatting, and resolved clippy warnings

## Features

- **Multiple Attack Types**: Tests for CL.TE, TE.CL, and TE.TE smuggling vulnerabilities
- **Extended Mutation Testing**: 30+ variations of Transfer-Encoding header obfuscations
- **HTTPS Support**: Automatically detects and uses TLS for HTTPS URLs
- **Custom Headers**: Add custom headers to requests for advanced testing
- **Cookie Fetching**: Automatically fetch and use cookies for authenticated testing
- **Virtual Host**: Test different virtual hosts on the same server
- **Payload Export**: Export successful attack payloads for further analysis
- **JSON Output**: Save scan results in JSON format for further analysis
- **Verbose Mode**: Detailed output showing requests and responses
- **Progress Indicators**: Real-time progress display during scans
- **Enhanced Payloads**: Multiple payload variations for better detection

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
```

## Usage

Basic usage:
```bash
smugglex http://target.com
```

With HTTPS:
```bash
smugglex https://target.com
```

With custom options:
```bash
smugglex https://target.com -m POST -t 15 -v -o results.json
```

With custom headers:
```bash
smugglex https://target.com -H "X-Custom: value" -H "Authorization: Bearer token"
```

Run only specific checks:
```bash
# Run only CL.TE check
smugglex https://target.com -c cl-te

# Run CL.TE and TE.CL checks
smugglex https://target.com -c cl-te,te-cl
```

With cookies (automatically fetch and use cookies):
```bash
smugglex https://target.com --cookies
```

With virtual host override:
```bash
smugglex https://192.168.1.100 --vhost internal.example.com
```

With payload export:
```bash
smugglex https://target.com --export-payloads ./payloads
```

Advanced usage combining multiple features:
```bash
smugglex https://api.example.com \
  -m POST \
  -t 15 \
  -v \
  --cookies \
  --vhost api-internal.example.com \
  --export-payloads ./found-payloads \
  -H "X-API-Key: secret" \
  -o results.json
```

### Options

- `-m, --method <METHOD>`: Custom HTTP method for attack requests (default: POST)
- `-t, --timeout <TIMEOUT>`: Socket timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose mode to see detailed requests and responses
- `-o, --output <OUTPUT>`: Save results to a JSON file
- `-H, --header <HEADERS>`: Add custom headers (can be specified multiple times)
- `-c, --checks <CHECKS>`: Specify which checks to run (comma-separated: cl-te,te-cl,te-te). Default: all checks
- `--vhost <VHOST>`: Virtual host to use in Host header (overrides URL hostname)
- `--cookies`: Fetch and append cookies from initial request
- `--export-payloads <DIR>`: Export payloads to directory when vulnerabilities are found

## Attack Types

### CL.TE (Content-Length vs Transfer-Encoding)
Tests scenarios where the front-end server uses Content-Length and the back-end uses Transfer-Encoding.

**How it works:** The front-end server processes the Content-Length header and forwards the request body based on that value. The back-end server processes the Transfer-Encoding header and might interpret the body differently, causing a desynchronization.

**Example payload variations:**
- Standard `Transfer-Encoding: chunked`
- Leading space: ` Transfer-Encoding: chunked`
- Space before colon: `Transfer-Encoding : chunked`
- Tab character: `Transfer-Encoding:\tchunked`
- Multiple spaces: `Transfer-Encoding:  chunked`
- Trailing whitespace: `Transfer-Encoding: chunked `
- Vertical tab: `Transfer-Encoding:\x0Bchunked`
- Newline injection: `Transfer-Encoding:\nchunked`
- Quoted values: `Transfer-Encoding: "chunked"`
- Multiple encodings: `Transfer-Encoding: chunked, identity`
- And 20+ more variations to bypass different parsers

### TE.CL (Transfer-Encoding vs Content-Length)
Tests scenarios where the front-end server uses Transfer-Encoding and the back-end uses Content-Length.

**How it works:** The front-end processes Transfer-Encoding (chunked) and forwards the complete chunked message. The back-end only reads up to Content-Length bytes, leaving the remainder in the buffer for the next request.

### TE.TE (Transfer-Encoding Obfuscation)
Tests scenarios where both servers support Transfer-Encoding but one can be tricked into ignoring it through obfuscation.

**How it works:** One server processes a properly formatted Transfer-Encoding header while the other server is confused by an obfuscated or malformed variant, leading to different interpretations of the request body.

**Example variations:**
- Duplicate headers with different values
- Using `identity` encoding
- Combining multiple encodings
- Using non-standard encoding names

## Security Considerations

⚠️ **Warning**: This tool is designed for security testing and should only be used:
- On systems you own or have explicit permission to test
- In authorized penetration testing engagements
- For educational and research purposes in controlled environments

Unauthorized testing of web applications may be illegal in your jurisdiction.

## Examples

### Basic Scan
```bash
smugglex http://testsite.local
```

### Scan with Verbose Output
```bash
smugglex https://api.example.com -v
```

### Save Results to File
```bash
smugglex https://target.com -o scan_results.json
```

### Custom Method and Timeout
```bash
smugglex https://target.com -m GET -t 20
```

### Test with Custom Headers
```bash
smugglex https://api.example.com \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: CustomBot/1.0"
```

### Run Specific Checks Only
```bash
# Only test CL.TE vulnerability
smugglex https://target.com -c cl-te

# Test both CL.TE and TE.CL
smugglex https://target.com -c "cl-te,te-cl"
```

## Output Format

When using the `-o` option, results are saved in JSON format:

```json
{
  "target": "https://example.com",
  "method": "POST",
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": [
    {
      "check_type": "CL.TE",
      "vulnerable": false,
      "payload_index": null,
      "normal_status": "HTTP/1.1 200 OK",
      "attack_status": null,
      "normal_duration_ms": 150,
      "attack_duration_ms": null,
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ]
}
```

## License

MIT
