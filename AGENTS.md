# Agent Instructions for smugglex

## Project Overview

smugglex is Rust-powered HTTP Request Smuggling Scanner. It's designed for security testing and penetration testing to detect various types of HTTP request smuggling vulnerabilities.

### Purpose
- Identify HTTP request smuggling vulnerabilities in web applications and proxies
- Test for CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling attack vectors
- Support security researchers and penetration testers in authorized testing

## Project Architecture

### Core Components

1. **main.rs** - Entry point and orchestration
   - CLI argument parsing
   - URL processing (command line and stdin pipeline)
   - Scan workflow coordination
   - Progress reporting and result output

2. **cli.rs** - Command-line interface definition
   - Uses `clap` for argument parsing
   - Defines all CLI options and flags
   - Documentation for each parameter

3. **scanner.rs** - Vulnerability scanning logic
   - Contains core vulnerability detection algorithms
   - Timing-based detection (TIMING_MULTIPLIER, MIN_DELAY_MS)
   - Progress tracking during scans
   - Export functionality for vulnerable payloads

4. **payloads.rs** - Attack payload generation
   - `get_cl_te_payloads()` - CL.TE attack payloads
   - `get_te_cl_payloads()` - TE.CL attack payloads
   - `get_te_te_payloads()` - TE.TE obfuscation payloads
   - `get_h2c_payloads()` - HTTP/2 Cleartext smuggling payloads
   - `get_h2_payloads()` - HTTP/2 protocol smuggling payloads

5. **http.rs** - HTTP communication layer
   - Raw socket communication (TCP and TLS)
   - Request sending and response parsing
   - Timeout handling

6. **model.rs** - Data structures
   - `CheckResult` - Individual vulnerability check results
   - `ScanResults` - Overall scan results container

7. **error.rs** - Error handling
   - Custom `SmugglexError` enum
   - Replaces generic `Box<dyn Error>` for better error types

8. **utils.rs** - Utility functions
   - Logging functions with color support
   - Cookie fetching functionality
   - Payload export functionality

## Key Attack Types

### CL.TE (Content-Length vs Transfer-Encoding)
Front-end uses Content-Length, back-end uses Transfer-Encoding. The mismatch causes desynchronization.

### TE.CL (Transfer-Encoding vs Content-Length)
Front-end uses Transfer-Encoding, back-end uses Content-Length. Remaining data in buffer causes issues.

### TE.TE (Transfer-Encoding Obfuscation)
Both servers support Transfer-Encoding but one can be tricked with obfuscation (30+ variations).

### H2C (HTTP/2 Cleartext Smuggling)
Exploits HTTP/1.1 to HTTP/2 upgrade mechanisms with 20+ payload variations.

### H2 (HTTP/2 Protocol Smuggling)
Exploits HTTP/2 protocol-level features during protocol translation with 25+ attack vectors.

## Coding Standards

### Rust Best Practices
- Use explicit error types (SmugglexError) instead of generic errors
- Leverage `async/await` with `tokio` for concurrent operations
- Apply `rustfmt` for consistent formatting
- Address all `clippy` warnings
- Write descriptive function and variable names

### Code Organization
- Keep functions focused and single-purpose
- Extract common patterns into helper functions
- Avoid code duplication, especially in payload generation
- Use const for detection thresholds and configuration values

### Error Handling
- Use `Result<T>` with custom error types
- Propagate errors with `?` operator
- Provide meaningful error messages
- Handle network timeouts gracefully

### Testing
- Write tests in the `tests/` directory
- Test critical detection logic
- Mock network responses where appropriate
- Test edge cases in payload generation

## Dependencies

Key dependencies and their purposes:
- **clap** (4.5.53) - CLI argument parsing with derive macros
- **tokio** (1.48.0) - Async runtime with full features
- **colored** (3.0.0) - Terminal color output
- **indicatif** (0.18.3) - Progress bars and spinners
- **url** (2.5.7) - URL parsing and validation
- **serde/serde_json** (1.0) - Serialization for JSON output
- **tokio-rustls** (0.26) - TLS support for HTTPS
- **chrono** (0.4) - Timestamp handling
- **once_cell** (1.21) - Lazy static initialization

## Development Guidelines

### Adding New Attack Types
1. Create payload generation function in `payloads.rs`
2. Add check type to CLI options in `cli.rs`
3. Implement detection logic in `scanner.rs` if needed
4. Add check to main scanning loop in `main.rs`
5. Update README.md with attack description
6. Add tests for new payloads

### Adding New Features
1. Define CLI arguments in `cli.rs` if needed
2. Implement core logic in appropriate module
3. Integrate with main scanning workflow
4. Add error handling for new failure modes
5. Update help text and documentation
6. Write tests for new functionality

### Modifying Payloads
- Payload functions are in `payloads.rs`
- Each function returns `Vec<String>` of HTTP requests
- Use helper functions to avoid duplication
- Include comments explaining obfuscation techniques
- Reference research papers or blogs when applicable

### Performance Considerations
- Use async operations for network I/O
- Implement timeout handling for all network requests
- Consider progress reporting for long-running operations
- Avoid blocking operations in async contexts

## Security Considerations

### Responsible Use
- Tool is for authorized testing only
- Include warnings about legal and ethical use
- Never test systems without permission
- Log activities appropriately

### Input Validation
- Validate and sanitize all user inputs
- Check URL formats before processing
- Validate custom headers format
- Handle malformed responses gracefully

### Output Safety
- Sanitize sensitive data in logs (if any)
- Be careful with verbose output containing full requests
- JSON output should be properly escaped

## Common Patterns

### Adding a New CLI Option
```rust
/// Description of the option
#[arg(long = "option-name")]
pub option_name: Option<String>,
```

### Creating Attack Payloads
```rust
pub fn get_attack_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let mut payloads = Vec::new();
    // Generate payloads
    payloads
}
```

### Running a Check
```rust
let result = run_checks_for_type(CheckParams {
    pb: &pb,
    check_name: "CHECK_NAME",
    host,
    port,
    path,
    attack_requests: payloads,
    timeout,
    verbose,
    use_tls,
    export_dir: cli.export_dir.as_deref(),
    current_check,
    total_checks,
}).await?;
```

## Building and Testing

### Build Commands
```bash
# Development build
cargo build

# Release build
cargo build --release

# Install locally
cargo install --path .
```

### Testing Commands
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Quality
```bash
# Format code
cargo fmt

# Run clippy
cargo clippy

# Run clippy with all checks
cargo clippy -- -D warnings
```

## Important Notes

1. **Timing-Based Detection**: The tool uses timing differences to detect vulnerabilities. `TIMING_MULTIPLIER` and `MIN_DELAY_MS` constants control sensitivity.

2. **Pipeline Support**: The tool supports reading URLs from stdin, enabling pipeline usage with other tools.

3. **Exit First Mode**: The `--exit-first` flag stops scanning after finding the first vulnerability, useful for quick checks.

4. **Payload Export**: When vulnerabilities are found, raw HTTP payloads can be exported for further analysis and exploitation.

5. **Virtual Host Testing**: The `--vhost` flag allows testing different virtual hosts on the same IP address.

6. **Cookie Support**: The `--cookies` flag automatically fetches and includes cookies in subsequent requests.

## Contributing

When contributing to smugglex:
- Follow the existing code style and patterns
- Write clear commit messages
- Add tests for new functionality
- Update documentation (README, help text, etc.)
- Ensure all tests pass and clippy is satisfied
- Consider security implications of changes
