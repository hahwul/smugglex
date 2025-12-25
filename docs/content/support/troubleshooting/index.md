+++
title = "Troubleshooting"
description = "Common issues and solutions"
weight = 1
sort_by = "weight"

[extra]
+++

Common issues and solutions for smugglex.

## Installation Issues

### Command Not Found

Check if the binary is in your PATH:

```bash
which smugglex
```

**Solution for Homebrew:**
```bash
export PATH="/usr/local/bin:$PATH"
```

**Solution for Cargo:**

Ensure `~/.cargo/bin` is in your PATH:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add to `~/.bashrc` or `~/.zshrc` for permanent use.

### Build Errors

Update Rust to the latest version:

```bash
rustup update
```

**Install dependencies:**

Ubuntu/Debian:
```bash
sudo apt-get install libssl-dev pkg-config
```

macOS:
```bash
brew install openssl pkg-config
```

## Runtime Issues

### Connection Timeouts

If you experience connection timeouts:

- Check network connectivity
- Increase timeout: `smugglex https://target.com/ -t 30`
- Verify target URL is accessible
- Check firewall settings

### No Output

Use verbose mode to see detailed information:

```bash
smugglex https://target.com/ -v
```

## Getting Help

- [GitHub Issues](https://github.com/hahwul/smugglex/issues)
- [FAQ](/support/faq)
