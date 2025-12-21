+++
title = "Development"
description = "Development guide for smugglex contributors"
weight = 2
sort_by = "weight"

[extra]
+++

# Development

This section provides information for developers who want to contribute to smugglex or build it from source.

## Overview

Smugglex is written in Rust and uses modern async/await patterns with Tokio. The codebase is organized into modular components for maintainability and testability.

## Quick Links

- [Building](/development/building) - Build smugglex from source
- [GitHub Repository](https://github.com/hahwul/smugglex)
- [Issue Tracker](https://github.com/hahwul/smugglex/issues)
- [Contributing Guidelines](https://github.com/hahwul/smugglex/blob/main/CONTRIBUTING.md)

## Getting Started

### Prerequisites

To develop smugglex, you need:

- Rust 1.70 or later
- Cargo package manager
- Git
- A code editor (VS Code, IntelliJ IDEA with Rust plugin, etc.)

### Clone the Repository

```bash
git clone https://github.com/hahwul/smugglex
cd smugglex
```

### Build the Project

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Run the Tool

```bash
cargo run -- https://target.com/
```

## Development Workflow

### Making Changes

1. Create a new branch for your feature or fix
2. Make your changes
3. Format your code: `cargo fmt`
4. Check for issues: `cargo clippy`
5. Run tests: `cargo test`
6. Commit your changes
7. Submit a pull request

### Code Style

- Follow Rust conventions and idioms
- Run `cargo fmt` before committing
- Address `cargo clippy` warnings
- Write descriptive function and variable names
- Add comments for complex logic

### Testing

Write tests for new functionality:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let payloads = get_cl_te_payloads("/", "example.com", "POST", &[], &[]);
        assert!(!payloads.is_empty());
    }
}
```

## Project Structure

```
smugglex/
├── src/
│   ├── main.rs          # Entry point and orchestration
│   ├── cli.rs           # CLI argument parsing
│   ├── scanner.rs       # Vulnerability scanning logic
│   ├── payloads.rs      # Attack payload generation
│   ├── http.rs          # HTTP communication layer
│   ├── model.rs         # Data structures
│   ├── error.rs         # Error handling
│   └── utils.rs         # Utility functions
├── tests/               # Integration tests
├── docs/                # Documentation site
├── Cargo.toml           # Dependencies and metadata
└── README.md            # Project overview
```

## Key Components

### main.rs

Entry point that orchestrates the scanning workflow:
- Parses CLI arguments
- Processes URLs (command line and stdin)
- Coordinates scan execution
- Reports results

### scanner.rs

Core vulnerability detection logic:
- Timing-based detection algorithms
- Progress tracking
- Payload export functionality

### payloads.rs

Generates attack payloads for different vulnerability types:
- `get_cl_te_payloads()` - CL.TE attacks
- `get_te_cl_payloads()` - TE.CL attacks
- `get_te_te_payloads()` - TE.TE obfuscation
- `get_h2c_payloads()` - HTTP/2 Cleartext smuggling
- `get_h2_payloads()` - HTTP/2 protocol smuggling

### http.rs

Low-level HTTP communication:
- Raw socket communication (TCP and TLS)
- Request sending and response parsing
- Timeout handling

## Contributing

### Areas for Contribution

- Adding new payload variations
- Improving detection algorithms
- Enhancing documentation
- Writing tests
- Reporting bugs
- Suggesting features

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure tests pass
5. Submit a pull request with a clear description

### Reporting Issues

When reporting bugs, include:
- Smugglex version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Resources

- [Building from Source](/development/building)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Tokio Documentation](https://tokio.rs/)
- [HTTP Request Smuggling Resources](/resources)
