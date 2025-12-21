+++
title = "Building from Source"
description = "Build smugglex from source code"
weight = 1
sort_by = "weight"

[extra]
+++

# Building from Source

This guide shows you how to build smugglex from source code for development or to access the latest features.

## Prerequisites

### Required Tools

Before building, ensure you have:

- **Rust**: Version 1.70 or later
- **Cargo**: Rust's package manager (installed with Rust)
- **Git**: For cloning the repository
- **Build tools**: C compiler and linker

### Install Rust

Install Rust using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

For Windows, download the installer from [rustup.rs](https://rustup.rs/).

After installation, restart your terminal or run:

```bash
source $HOME/.cargo/env
```

Verify installation:

```bash
rustc --version
cargo --version
```

### System Dependencies

Some systems require additional libraries:

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev pkg-config
```

**macOS:**

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install OpenSSL if needed
brew install openssl pkg-config
```

**Windows:**

- Install Visual Studio Build Tools or Visual Studio with C++ support
- Ensure Rust toolchain is properly configured

## Clone the Repository

Clone the smugglex repository:

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
```

Check available branches:

```bash
git branch -a
```

## Build the Project

### Development Build

Build in debug mode (faster compilation, slower execution):

```bash
cargo build
```

The binary is located at `./target/debug/smugglex`.

Run it directly:

```bash
./target/debug/smugglex --version
```

### Release Build

Build in release mode (optimized for performance):

```bash
cargo build --release
```

The binary is located at `./target/release/smugglex`.

Run it directly:

```bash
./target/release/smugglex --version
```

### Install Locally

Install the binary to `~/.cargo/bin/`:

```bash
cargo install --path .
```

This makes `smugglex` available in your PATH.

## Run the Tool

### Development Mode

Run without building first:

```bash
cargo run -- https://target.com/
```

With options:

```bash
cargo run -- https://target.com/ -v
cargo run -- https://target.com/ --help
```

### Direct Execution

Run the built binary:

```bash
# Debug build
./target/debug/smugglex https://target.com/

# Release build
./target/release/smugglex https://target.com/
```

## Development Tasks

### Format Code

Format code according to Rust style guidelines:

```bash
cargo fmt
```

Check formatting without making changes:

```bash
cargo fmt -- --check
```

### Lint Code

Run Clippy to catch common mistakes:

```bash
cargo clippy
```

Treat warnings as errors:

```bash
cargo clippy -- -D warnings
```

### Run Tests

Run all tests:

```bash
cargo test
```

Run specific test:

```bash
cargo test test_name
```

Run tests with output:

```bash
cargo test -- --nocapture
```

### Check Code

Check for compile errors without building:

```bash
cargo check
```

This is faster than a full build.

### Build Documentation

Generate and view documentation:

```bash
cargo doc --open
```

This opens the documentation in your browser.

### Clean Build Artifacts

Remove build artifacts:

```bash
cargo clean
```

This frees disk space and forces a fresh build next time.

## Update Dependencies

### Update Cargo.lock

Update dependencies to latest compatible versions:

```bash
cargo update
```

### Check for Outdated Dependencies

Install cargo-outdated:

```bash
cargo install cargo-outdated
```

Check for outdated dependencies:

```bash
cargo outdated
```

## Troubleshooting

### Build Fails

**Update Rust:**

```bash
rustup update
```

**Clear build cache:**

```bash
cargo clean
cargo build
```

### OpenSSL Errors

**Ubuntu/Debian:**

```bash
sudo apt-get install libssl-dev pkg-config
```

**macOS:**

```bash
brew install openssl@3
export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig"
```

**Windows:**

Install OpenSSL or use vendored OpenSSL:

```bash
cargo build --features vendored-openssl
```

### Linking Errors

**Ubuntu/Debian:**

```bash
sudo apt-get install build-essential
```

**macOS:**

```bash
xcode-select --install
```

### Permission Errors

If cargo install fails with permission errors:

```bash
# Don't use sudo with cargo
# Instead, ensure ~/.cargo/bin is in your PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

## Advanced Build Options

### Profile-Guided Optimization

Build with maximum optimization:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Cross-Compilation

Install cross:

```bash
cargo install cross
```

Build for different targets:

```bash
# Linux x86_64
cross build --target x86_64-unknown-linux-gnu --release

# macOS
cross build --target x86_64-apple-darwin --release

# Windows
cross build --target x86_64-pc-windows-gnu --release
```

### Static Binary

Build a static binary (Linux):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release
```

## Continuous Integration

The project uses GitHub Actions for CI/CD:

- Automated testing on multiple platforms
- Code formatting checks
- Clippy linting
- Security audits

View the workflow files in `.github/workflows/`.

## Contributing

When building for contribution:

1. Create a feature branch
2. Make your changes
3. Run `cargo fmt` and `cargo clippy`
4. Ensure tests pass with `cargo test`
5. Build in release mode to verify
6. Submit a pull request

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Rustup Documentation](https://rust-lang.github.io/rustup/)
- [Development Guide](/development)
- [GitHub Repository](https://github.com/hahwul/smugglex)
