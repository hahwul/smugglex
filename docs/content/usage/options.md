+++
title = "Options"
description = "All CLI options for smugglex"
+++

## Target

| Option | Description |
|--------|-------------|
| `<URLs>` | Target URLs (positional, supports multiple) |
| stdin | Pipe URLs from other tools |

## Request

| Option | Default | Description |
|--------|---------|-------------|
| `-m, --method` | POST | HTTP method |
| `-t, --timeout` | 10 | Socket timeout in seconds |
| `-H, --header` | | Custom header (repeatable) |
| `--vhost` | | Virtual host for Host header |
| `--cookies` | | Fetch and include cookies |

## Detection

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --checks` | all | Checks to run (comma-separated) |
| `-1, --exit-first` | | Stop after first vulnerability |
| `--fingerprint` | | Enable proxy fingerprinting |
| `--fuzz` | | Enable mutation-based fuzzing |
| `--fuzz-seed` | 42 | Mutation seed for reproducibility |

Available checks: `cl-te`, `te-cl`, `te-te`, `h2c`, `h2`, `cl-edge`

## Output

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output` | | Save results to file |
| `-f, --format` | plain | Output format: `plain` or `json` |
| `-V, --verbose` | | Enable detailed logging |
| `--export-payloads` | | Export vulnerable payloads to directory |

## Exploitation

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --exploit` | | Exploit types (comma-separated) |
| `--exploit-ports` | 22,80,443,8080,3306 | Ports to test |
| `--exploit-wordlist` | | Wordlist for path-fuzz |

Available exploits: `localhost-access`, `path-fuzz`

## Examples

```bash
# Full scan with fingerprinting and fuzzing
smugglex --fingerprint --fuzz https://target.com

# Custom headers and timeout
smugglex -H "Authorization: Bearer token" -t 15 https://target.com

# Exploit with custom ports
smugglex -e localhost-access --exploit-ports 80,8080,9090 https://target.com
```
