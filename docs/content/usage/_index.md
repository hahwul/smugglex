+++
title = "Installation"
description = "Install smugglex on your system"
+++

## Homebrew

```bash
brew install hahwul/smugglex/smugglex
```

## Cargo

```bash
cargo install smugglex
```

## Snap

```bash
snap install smugglex
```

## Nix

```bash
nix profile install github:hahwul/smugglex
```

## Binary Download

Pre-built binaries are available from [GitHub Releases](https://github.com/hahwul/smugglex/releases).

## Build from Source

Requires Rust 1.70+.

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
cargo install --path .
```

## Verify

```bash
smugglex --version
```
