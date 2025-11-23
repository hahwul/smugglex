# smugglex

A powerful HTTP Request Smuggling testing tool written in Rust.

## Features

- **Multiple Attack Types**: Tests for CL.TE, TE.CL, and TE.TE smuggling vulnerabilities
- **HTTPS Support**: Automatically detects and uses TLS for HTTPS URLs
- **Custom Headers**: Add custom headers to requests for advanced testing
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

### Options

- `-m, --method <METHOD>`: Custom HTTP method for attack requests (default: POST)
- `-t, --timeout <TIMEOUT>`: Socket timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose mode to see detailed requests and responses
- `-o, --output <OUTPUT>`: Save results to a JSON file
- `-H, --header <HEADERS>`: Add custom headers (can be specified multiple times)

## Attack Types

### CL.TE (Content-Length vs Transfer-Encoding)
Tests scenarios where the front-end server uses Content-Length and the back-end uses Transfer-Encoding.

### TE.CL (Transfer-Encoding vs Content-Length)
Tests scenarios where the front-end server uses Transfer-Encoding and the back-end uses Content-Length.

### TE.TE (Transfer-Encoding Obfuscation)
Tests scenarios where both servers support Transfer-Encoding but one can be tricked into ignoring it through obfuscation.

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
