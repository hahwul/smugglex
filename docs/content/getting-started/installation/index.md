+++
title = "Installation"
description = "Install smugglex on your system"
weight = 2
sort_by = "weight"

[extra]
toc_expand = true
+++

## Installation Methods

### Homebrew

```bash
brew install hahwul/smugglex/smugglex
```

### Snapcraft

```bash
snap install smugglex
```

### Nix

```bash
nix profile install github:hahwul/smugglex
```

### Cargo

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
