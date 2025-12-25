+++
title = "Installation"
description = "Install smugglex on your system"
weight = 2
sort_by = "weight"

[extra]
+++

This guide shows you how to install smugglex on your system.

## Installation Methods

### Homebrew (macOS and Linux)

Install smugglex using Homebrew:

```bash
brew install hahwul/smugglex/smugglex
```

### Snapcraft (Linux)

Install smugglex using Snap:

```bash
snap install smugglex
```

### Nix (Linux and macOS)

Install smugglex using Nix package manager:

```bash
nix profile install github:hahwul/smugglex
```

Or run directly without installation:

```bash
nix run github:hahwul/smugglex
```

### Debian Package (.deb)

Download and install the Debian package from the [GitHub releases page](https://github.com/hahwul/smugglex/releases):

```bash
# Download the latest .deb package (example for version 0.1.0)
wget https://github.com/hahwul/smugglex/releases/download/v0.1.0/smugglex_0_1_0_-1_amd64.deb

# Install the package
sudo dpkg -i smugglex_0_1_0_-1_amd64.deb

# If there are dependency issues, fix them with:
sudo apt-get install -f
```

### Direct Binary Download

Download the latest release for your platform from the [GitHub releases page](https://github.com/hahwul/smugglex/releases).

Extract and install the binary:

```bash
tar -xzf smugglex-*.tar.gz
sudo mv smugglex /usr/local/bin/
```

### Build from Source

Build from source to access the latest development version. This requires Rust 1.70 or later.

For detailed build instructions and development setup, see the [Contributing](/support/contributing) guide.

Clone the repository:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
```

Install with Cargo:

```bash
cargo install --path .
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

## Troubleshooting

### Command Not Found

Check if the binary is in your PATH:

```bash
which smugglex
```

If using Homebrew, ensure Homebrew is in your PATH:

```bash
export PATH="/usr/local/bin:$PATH"
```

If building from source, check if `~/.cargo/bin` is in your PATH:

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

When building from source, update Rust to the latest version:

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

- [Quick Start](/getting-started/quick-start) - Run your first scan
- [Usage](/usage) - Learn detailed usage options
- [GitHub Repository](https://github.com/hahwul/smugglex)
- [Issue Tracker](https://github.com/hahwul/smugglex/issues)
