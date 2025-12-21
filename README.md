<div align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/static/images/smugglex-dark.png" width="500px;">
      <source media="(prefers-color-scheme: light)" srcset="docs/static/images/smugglex-light.png" width="500px;">
      <img alt="SmuggleX Logo" src="docs/static/images/smugglex-dark.png" width="500px;">
    </picture>
    <p>A powerful HTTP Request Smuggling testing tool written in Rust.</p>
</div>

<p align="center">
<a href="https://github.com/hahwul/smugglex/blob/main/CONTRIBUTING.md">
<img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=black"></a>
<a href="https://github.com/hahwul/smugglex/releases">
<img src="https://img.shields.io/github/v/release/hahwul/smugglex?style=for-the-badge&color=black&labelColor=black&logo=web"></a>
<a href="https://rust-lang.org">
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"></a>
</p>

## Overview

Smugglex is a security testing tool that detects HTTP Request Smuggling vulnerabilities in web applications. The tool tests for multiple attack types including CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling.

HTTP Request Smuggling exploits differences in how front-end and back-end servers parse HTTP requests. When servers disagree on request boundaries, attackers can smuggle malicious requests through security controls. This leads to security vulnerabilities such as bypassing firewalls, poisoning caches, and accessing unauthorized resources.

### Key Features

- Detect multiple attack types: CL.TE, TE.CL, TE.TE, H2C, and H2
- Test 40+ variations of Transfer-Encoding header obfuscations
- Support HTTP/2 protocol-level desync detection
- Export vulnerable payloads for manual verification
- Save scan results in JSON format
- Read URLs from stdin for pipeline integration
- Configure custom headers, cookies, and virtual hosts

### Example Output

```bash
smugglex https://target.com/
11:27PM INF start scan to https://target.com/
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

## Installation

### Homebrew (macOS and Linux)

```bash
brew install hahwul/smugglex/smugglex
```

### Snapcraft (Linux)

```bash
snap install smugglex
```

### Nix (Linux and macOS)

Using Nix flakes (recommended):

```bash
nix run github:hahwul/smugglex
```

Or install to your profile:

```bash
nix profile install github:hahwul/smugglex
```

To build locally:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
nix build
./result/bin/smugglex
```

### Direct Binary Download

Download the latest release for your platform from the [GitHub releases page](https://github.com/hahwul/smugglex/releases).

Extract and install:

```bash
tar -xzf smugglex-*.tar.gz
sudo mv smugglex /usr/local/bin/
```

### Build from Source

Requires Rust 1.70 or later. Clone the repository and install:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
cargo install --path .
```

## Usage

### Basic Scan

Run a basic scan on a target URL:

```bash
smugglex https://target.com
```

### Common Options

```bash
smugglex https://target.com -v              # Enable verbose output
smugglex https://target.com -t 15           # Set timeout to 15 seconds
smugglex https://target.com -o results.json # Save results to JSON file
smugglex https://target.com --exit-first    # Stop after first vulnerability
```

### Scan Multiple URLs

Read URLs from a file:

```bash
cat urls.txt | smugglex
```

### Custom Configuration

Specify HTTP method:

```bash
smugglex https://target.com -m POST
```

Add custom headers:

```bash
smugglex https://target.com -H "Authorization: Bearer token"
```

Run specific checks:

```bash
smugglex https://target.com -c cl-te,te-cl
```

## Configuration

### Command-Line Options

- `-m, --method <METHOD>` - HTTP method to use (default: POST)
- `-t, --timeout <TIMEOUT>` - Socket timeout in seconds (default: 10)
- `-v, --verbose` - Enable verbose output
- `-o, --output <OUTPUT>` - Save results to JSON file
- `-H, --header <HEADERS>` - Add custom headers
- `-c, --checks <CHECKS>` - Specify checks to run (cl-te, te-cl, te-te, h2c, h2)
- `--vhost <VHOST>` - Set virtual host in Host header
- `--cookies` - Fetch and include cookies
- `--export-payloads <DIR>` - Export vulnerable payloads to directory
- `-1, --exit-first` - Exit after finding first vulnerability

### Attack Types

The tool tests for these attack types:

- CL.TE - Content-Length vs Transfer-Encoding desync
- TE.CL - Transfer-Encoding vs Content-Length desync
- TE.TE - Transfer-Encoding obfuscation with 40+ variations
- H2C - HTTP/2 Cleartext smuggling with 20+ payloads
- H2 - HTTP/2 protocol-level smuggling with 25+ payloads

## Examples

### Scan with Verbose Output

```bash
smugglex https://target.com -v
```

### Export Vulnerable Payloads

```bash
smugglex https://target.com --export-payloads ./payloads
```

### Test Specific Attack Types

```bash
smugglex https://target.com -c cl-te,te-cl
```

### Scan with Custom Headers and Timeout

```bash
smugglex https://target.com -H "X-Custom: value" -t 20 -v
```

### Pipeline Integration

```bash
echo "https://target1.com" | smugglex -v
cat targets.txt | smugglex -o results.json
```

## Troubleshooting

### Command Not Found

If you get a command not found error, ensure `~/.cargo/bin` is in your PATH:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add this line to your shell configuration file (~/.bashrc or ~/.zshrc) to make it permanent.

### Build Errors

Update Rust to the latest version:

```bash
rustup update
```

On some systems, you may need OpenSSL development libraries:

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev pkg-config

# macOS
brew install openssl pkg-config
```

### Connection Issues

If you experience connection timeouts:

- Increase the timeout value with `-t 30`
- Check network connectivity to the target
- Verify the target URL is accessible
- Check if a firewall is blocking connections

## References

- Documentation Site: [https://smugglex.hahwul.com](https://smugglex.hahwul.com)
- GitHub Repository: [https://github.com/hahwul/smugglex](https://github.com/hahwul/smugglex)
- Issue Tracker: [https://github.com/hahwul/smugglex/issues](https://github.com/hahwul/smugglex/issues)
- HTTP Request Smuggling: [PortSwigger Research](https://portswigger.net/web-security/request-smuggling)

## Security Warning

This tool is for authorized security testing only. Use smugglex only on:

- Systems you own
- Systems with explicit written permission
- Authorized penetration testing engagements
- Educational purposes in controlled environments

Unauthorized testing may be illegal in your jurisdiction.

## License

MIT
