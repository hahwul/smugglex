+++
title = "Installation"
description = "Install smugglex on your system"
weight = 2
sort_by = "weight"

[extra]
+++

# Installation

This guide shows you how to install smugglex on your system.

## Prerequisites

Before installing, ensure you have:

- Operating System: Linux, macOS, or Windows with WSL
- Rust: Version 1.70 or later (for building from source)
- Network Access: HTTP and HTTPS connections enabled

## Installation Methods

### Install from crates.io

This is the recommended installation method. It requires Rust and Cargo.

#### Install Rust and Cargo

Install Rust using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

For Windows, download the installer from [rustup.rs](https://rustup.rs/).

Restart your terminal or run:

```bash
source $HOME/.cargo/env
```

#### Install Smugglex

Install smugglex with Cargo:

```bash
cargo install smugglex
```

This installs smugglex to `~/.cargo/bin/` in your PATH.

#### Verify Installation

Check the installation:

```bash
smugglex --version
```

You should see the version number.

### Build from Source

Build from source to access the latest development version.

For detailed build instructions and development setup, see the [Development Guide](/development/building).

#### Quick Build

Clone the repository:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
```

#### Build and Install

Install with Cargo:

```bash
cargo install --path .
```

Or build without installing:

```bash
cargo build --release
```

The binary is at `./target/release/smugglex`. Run it directly:

```bash
./target/release/smugglex --version
```

#### Add to PATH

Copy the binary to your PATH:

```bash
sudo cp target/release/smugglex /usr/local/bin/
```

Or add the target directory to PATH:

```bash
export PATH="$PATH:$(pwd)/target/release"
```

## Updating Smugglex

### Update from crates.io

Update to the latest version:

```bash
cargo install smugglex --force
```

The `--force` flag overwrites the existing installation.

### Update from Source

Navigate to the repository:

```bash
cd /path/to/smugglex
```

Pull the latest changes:

```bash
git pull origin main
```

Rebuild and reinstall:

```bash
cargo install --path . --force
```

## Verify Installation

Check that smugglex works correctly:

### Check Version

```bash
smugglex --version
```

### View Help

```bash
smugglex --help
```

This shows all available options.

### Test Basic Functionality

Run a test on a system you own:

```bash
smugglex https://your-test-system.com/ -v
```

## Usage

### Basic Scan

```bash
smugglex https://example.com/
```

### Verbose Output

```bash
smugglex https://example.com/ -v
```

### Custom Timeout

```bash
smugglex https://example.com/ -t 15
```

### Save Results

```bash
smugglex https://example.com/ -o results.json
```

### Multiple URLs

```bash
cat urls.txt | smugglex
```

### Exit After First Vulnerability

```bash
smugglex https://example.com/ --exit-first
```

## Configuration

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--method` | `-m` | HTTP method (default: POST) |
| `--timeout` | `-t` | Timeout in seconds (default: 10) |
| `--verbose` | `-v` | Enable verbose output |
| `--output` | `-o` | JSON output file |
| `--header` | `-H` | Add custom headers |
| `--checks` | `-c` | Specify checks (cl-te,te-cl,te-te,h2c,h2) |
| `--vhost` | | Virtual host for Host header |
| `--cookies` | | Fetch and include cookies |
| `--export-payloads` | | Export vulnerable payloads |
| `--exit-first` | `-1` | Exit after first vulnerability |
| `--help` | `-h` | Display help |
| `--version` | `-V` | Display version |

### Custom Headers

```bash
smugglex https://example.com/ -H "Authorization: Bearer token123"
```

### Virtual Host Testing

```bash
smugglex https://192.168.1.100/ --vhost example.com
```

### Specific Attack Types

```bash
smugglex https://example.com/ -c cl-te,te-cl
```

### With Cookies

```bash
smugglex https://example.com/ --cookies
```

### Export Payloads

```bash
smugglex https://example.com/ --export-payloads ./payloads
```

## Troubleshooting

### Command Not Found

Check if `~/.cargo/bin` is in your PATH:

```bash
echo $PATH | grep .cargo/bin
```

If not, add it to your shell configuration file:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add this line to `~/.bashrc` or `~/.zshrc` for permanent use. Then reload:

```bash
source ~/.bashrc
```

### Build Errors

Update Rust to the latest version:

```bash
rustup update
```

Some systems need OpenSSL and pkg-config:

Ubuntu or Debian:

```bash
sudo apt-get install libssl-dev pkg-config
```

macOS:

```bash
brew install openssl pkg-config
```

### Connection Issues

If you experience connection timeouts:

- Check network connectivity
- Increase timeout: `-t 30`
- Verify target URL is accessible
- Check firewall settings

## References

- [Running SmuggleX](/get_started/running) - Learn how to run smugglex
- [Overview](/get_started/overview) - HTTP Request Smuggling overview
- [Development](/development/building) - Building from source for development
- [GitHub Repository](https://github.com/hahwul/smugglex)
- [Issue Tracker](https://github.com/hahwul/smugglex/issues)
