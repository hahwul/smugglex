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
| `--raw-request` | | Read a raw HTTP request from a file and use it as the request template |
| `--raw-request-proto` | https | Scheme for `--raw-request` when the request line is origin-form (`http` or `https`) |
| `--cookies` | | Fetch and append cookies from the initial request |
| `-d, --delay` | 0 | Delay between requests in milliseconds |
| `-j, --concurrency` | 1 | Number of URLs to scan concurrently |
| `-x, --proxy` | | HTTP or HTTPS proxy URL for CONNECT tunneling, e.g. `http://127.0.0.1:8080` (SOCKS is not supported) |

## Detection

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --checks` | all | Checks to run (comma-separated) |
| `-1, --exit-first` | | Stop after first vulnerability |
| `--fingerprint` | | Enable proxy fingerprinting |
| `--fuzz` | | Enable mutation-based fuzzing |
| `--fuzz-seed` | 42 | Mutation seed for reproducibility |
| `--max-payloads` | | Maximum payloads to test per check type |
| `--baseline-count` | 3 | Number of baseline requests for timing measurement |

Available checks: `cl-te`, `te-cl`, `te-te`, `h2c`, `h2`, `cl-edge`, `cl-0`, `0-cl`, `parser-discrepancy`, `h2-downgrade`

`cl-0` is an opt-in same-connection response-queue probe. It requires a control sequence and repeated response shift before reporting a finding.

`0-cl` is an opt-in `Expect: 100-continue`/body-pause probe. It reports only when an early response and a reproducible post-body response-queue change are both observed; a deadlock alone is recorded as a diagnostic.

`h2-downgrade` speaks real HTTP/2 (ALPN `h2`) to detect H2.CL / H2.TE and only runs on `https` targets; it connects directly and does not route through `--proxy`.

`parser-discrepancy` is an opt-in differential audit. It compares a bounded corpus of CL/TE probes with framing-stripped controls and records status/body/timeout differences in JSON diagnostics; only repeatable timeout-backed differences are promoted to a vulnerability.

## Output

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output` | | Save results to file |
| `-f, --format` | plain | Output format: `plain` or `json` |
| `--json` | | Shorthand for `--format json` (takes precedence over `-f`) |
| `-V, --verbose` | | Enable detailed logging |
| `-q, --quiet` | | Quiet mode (only show vulnerabilities) |
| `--export-payloads` | | Export vulnerable payloads to directory |
| `--no-color` | | Disable colored output |

## Exploitation

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --exploit` | | Exploit types (comma-separated) |
| `--exploit-ports` | 22,80,443,8080,3306 | Ports to test (localhost-access) |
| `--exploit-wordlist` | | Wordlist for path-fuzz |
| `--smuggle-request` | | Inner request for smuggle/capture |
| `--reveal-endpoint` | scanned path | Reflecting endpoint for reveal |
| `--reveal-param` | q | Reflected form parameter for reveal |

Available exploits: `localhost-access`, `path-fuzz`, `smuggle`, `capture`, `reveal`

## TLS

| Option | Default | Description |
|--------|---------|-------------|
| `-k, --insecure` | | Skip TLS certificate verification (allow self-signed certificates) |
| `--cacert` | | Custom CA certificate file (PEM format) for self-signed/internal certificates |

## Examples

```bash
# Full scan with fingerprinting and fuzzing
smugglex --fingerprint --fuzz https://target.com

# Custom headers and timeout
smugglex -H "Authorization: Bearer token" -t 15 https://target.com

# Replay a captured request (e.g. exported from Burp Suite) as the template.
# Method, request-target, Host and headers (cookies, auth, ...) are reused;
# the target is taken from the Host header. The request-target is sent verbatim
# — dot-segments, matrix params and '#' are preserved, not normalized — for both
# origin-form (POST /path ...) and absolute-form (GET http://...) request lines,
# so path-based payloads survive. The body is replaced by the generated smuggling
# payloads, and Content-Length / Transfer-Encoding are managed by smugglex.
smugglex --raw-request request.txt

# Same, but the captured request targets a plain-HTTP service
smugglex --raw-request request.txt --raw-request-proto http

# -H is additive on top of the captured headers (e.g. add a collaborator marker)
smugglex --raw-request request.txt -H "X-Collab: abcd.oastify.com"

# Route through a proxy (e.g., Burp Suite)
smugglex -x http://127.0.0.1:8080 https://target.com

# Quick scan with limited payloads
smugglex --max-payloads 10 https://target.com

# Quiet mode — only show vulnerabilities
smugglex -q https://target.com

# Adjust baseline measurements for noisy networks
smugglex --baseline-count 5 https://target.com

# Exploit with custom ports
smugglex -e localhost-access --exploit-ports 80,8080,9090 https://target.com
```
