+++
title = "Installation"
description = "Install smugglex on your system"
weight = 2
sort_by = "weight"

[extra]
+++

# Installation

Smugglex can be installed in several ways depending on your preference and system setup. Choose the method that works best for you.

## Prerequisites

Before installing smugglex, ensure you have the following:

- **Operating System**: Linux, macOS, or Windows (WSL recommended for Windows)
- **Rust** (if building from source): Version 1.70 or later
- **Network Access**: Ability to make HTTP/HTTPS connections to target systems

## Installation Methods

### Method 1: Install from crates.io (Recommended)

The easiest way to install smugglex is from Rust's package registry, crates.io. This method requires Rust and Cargo to be installed on your system.

#### Install Rust and Cargo

If you don't have Rust installed, install it using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

For Windows users, download and run the installer from [rustup.rs](https://rustup.rs/).

After installation, restart your terminal or run:

```bash
source $HOME/.cargo/env
```

#### Install Smugglex

Once Rust and Cargo are installed, install smugglex with:

```bash
cargo install smugglex
```

This will download, compile, and install smugglex to `~/.cargo/bin/` (which should be in your PATH).

#### Verify Installation

Verify the installation was successful:

```bash
smugglex --version
```

You should see the version number displayed.

### Method 2: Build from Source

Building from source gives you access to the latest development version and allows you to modify the code if needed.

#### Clone the Repository

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
```

#### Build and Install

Build and install in one step:

```bash
cargo install --path .
```

Or build without installing:

```bash
cargo build --release
```

The compiled binary will be located at `./target/release/smugglex`. You can run it directly:

```bash
./target/release/smugglex --version
```

#### Add to PATH (Optional)

If you built without installing, you can add the binary to your PATH by copying it to a directory in your PATH:

```bash
sudo cp target/release/smugglex /usr/local/bin/
```

Or add the target directory to your PATH:

```bash
export PATH="$PATH:$(pwd)/target/release"
```

### Method 3: Docker (Coming Soon)

Docker support is planned for future releases.

## Updating Smugglex

### Update from crates.io

If you installed from crates.io, update to the latest version with:

```bash
cargo install smugglex --force
```

The `--force` flag will overwrite the existing installation.

### Update from Source

If you installed from source:

1. Navigate to your cloned repository:
   ```bash
   cd /path/to/smugglex
   ```

2. Pull the latest changes:
   ```bash
   git pull origin main
   ```

3. Rebuild and reinstall:
   ```bash
   cargo install --path . --force
   ```

## Verifying Your Installation

After installation, verify that smugglex is working correctly:

### Check Version

```bash
smugglex --version
```

### View Help

```bash
smugglex --help
```

This will display all available options and usage information.

### Test Basic Functionality

Test that the tool is working correctly by running the help command:

```bash
smugglex --help
```

You should see the usage information and available options. When you're ready to test on a system you have permission to scan, you can run a basic test (replace with a URL you own or have authorization to test):

```bash
smugglex https://your-test-system.com/ -v
```

## Basic Usage

Now that you have smugglex installed, here's a quick start:

### Simple Scan

```bash
smugglex https://example.com/
```

### Scan with Verbose Output

```bash
smugglex https://example.com/ -v
```

### Scan with Custom Timeout

```bash
smugglex https://example.com/ -t 15
```

### Save Results to JSON

```bash
smugglex https://example.com/ -o results.json
```

### Scan Multiple URLs from File

```bash
cat urls.txt | smugglex
```

### Exit After First Vulnerability

```bash
smugglex https://example.com/ --exit-first
```

## Command-Line Options

Here's a quick reference of available options:

| Option | Short | Description |
|--------|-------|-------------|
| `--method` | `-m` | HTTP method to use (default: POST) |
| `--timeout` | `-t` | Socket timeout in seconds (default: 10) |
| `--verbose` | `-v` | Enable verbose output |
| `--output` | `-o` | Output file for JSON results |
| `--header` | `-H` | Add custom headers (can be used multiple times) |
| `--checks` | `-c` | Specify checks to run (cl-te,te-cl,te-te,h2c,h2) |
| `--vhost` | | Virtual host for Host header |
| `--cookies` | | Fetch and include cookies |
| `--export-payloads` | | Export vulnerable payloads to directory |
| `--exit-first` | `-1` | Exit after finding first vulnerability |
| `--help` | `-h` | Display help information |
| `--version` | `-V` | Display version information |

## Advanced Configuration

### Custom Headers

Add custom headers to your requests:

```bash
smugglex https://example.com/ -H "Authorization: Bearer token123" -H "X-Custom: value"
```

### Virtual Host Testing

Test a specific virtual host:

```bash
smugglex https://192.168.1.100/ --vhost example.com
```

### Specific Attack Types

Run only specific checks:

```bash
smugglex https://example.com/ -c cl-te,te-cl
```

### With Cookies

Automatically fetch and include cookies:

```bash
smugglex https://example.com/ --cookies
```

### Export Vulnerable Payloads

Export payloads when vulnerabilities are found:

```bash
smugglex https://example.com/ --export-payloads ./payloads
```

## Troubleshooting

### Command Not Found

If you get a "command not found" error after installation:

1. Ensure `~/.cargo/bin` is in your PATH:
   ```bash
   echo $PATH | grep .cargo/bin
   ```

2. If not, add it to your shell configuration file (`~/.bashrc`, `~/.zshrc`, etc.):
   ```bash
   export PATH="$HOME/.cargo/bin:$PATH"
   ```

3. Reload your shell configuration:
   ```bash
   source ~/.bashrc  # or ~/.zshrc
   ```

### Build Errors

If you encounter build errors:

1. Ensure you have the latest Rust version:
   ```bash
   rustup update
   ```

2. Check for system dependencies (usually not needed, but some systems may require):
   - OpenSSL development libraries
   - pkg-config

   On Ubuntu/Debian:
   ```bash
   sudo apt-get install libssl-dev pkg-config
   ```

   On macOS:
   ```bash
   brew install openssl pkg-config
   ```

### Connection Issues

If you experience connection issues during testing:

1. Check your network connectivity
2. Increase the timeout value: `-t 30`
3. Verify the target URL is accessible
4. Check if a firewall is blocking connections

## Next Steps

Now that you have smugglex installed, you're ready to start testing! Here are some resources to help you get started:

- **Overview**: Learn about [HTTP Request Smuggling](/get_started/overview) and how smugglex detects vulnerabilities
- **GitHub Repository**: Check out the [source code](https://github.com/hahwul/smugglex) and contribute
- **Report Issues**: Found a bug? [Report it](https://github.com/hahwul/smugglex/issues) on GitHub

## Getting Help

If you need help or have questions:

- Check the `--help` output: `smugglex --help`
- Review the [GitHub Issues](https://github.com/hahwul/smugglex/issues)
- Open a new issue if you encounter problems
- Contact the maintainer on Twitter: [@hahwul](https://twitter.com/hahwul)
