+++
title = "Installation"
description = "Install smugglex on your system"
weight = 2
sort_by = "weight"

[extra]
+++

## Installation Methods

### Homebrew (macOS and Linux)

```bash
brew install hahwul/smugglex/smugglex
```

### Snapcraft (Linux)

```bash
snap install smugglex
```

### Nix (Linux and macOS)

```bash
nix profile install github:hahwul/smugglex
```

### Cargo (from crates.io)

```bash
cargo install smugglex
```

### Binary Download

Download pre-built binaries from [GitHub releases](https://github.com/hahwul/smugglex/releases).

### Build from Source

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
cargo install --path .
```

## Verify Installation

```bash
smugglex --version
```

## Next Steps

- [Quick Start](/getting-started/quick-start) - Run your first scan
- [Troubleshooting](/support/troubleshooting) - Common installation issues
