+++
title = "Checks"
description = "Smuggling techniques supported by smugglex"
+++

smugglex supports 10 types of HTTP Request Smuggling checks. Each exploits differences in how front-end and back-end servers parse HTTP requests.

| Check | Description |
|-------|-------------|
| [CL.TE](/checks/cl-te/) | Content-Length vs Transfer-Encoding |
| [TE.CL](/checks/te-cl/) | Transfer-Encoding vs Content-Length |
| [TE.TE](/checks/te-te/) | Transfer-Encoding obfuscation (40+ variants) |
| [H2C](/checks/h2c/) | HTTP/2 Cleartext smuggling |
| [H2](/checks/h2/) | HTTP/2 protocol smuggling |
| [CL-Edge](/checks/cl-edge/) | Content-Length edge cases |
| [CL.0](/checks/cl-0/) | Opt-in same-connection CL.0 response-queue probe |
| [0.CL](/checks/0-cl/) | Opt-in Expect/body-pause 0.CL response-queue probe |
| `parser-discrepancy` | Opt-in CL/TE control-vs-probe response differential audit |
| `h2-downgrade` | Real HTTP/2 (ALPN `h2`) H2.CL / H2.TE downgrade — HTTPS targets only |

## Run Specific Checks

```bash
smugglex -c cl-te,te-cl https://target.com
```

With no `-c/--checks`, smugglex runs the default set (`cl-te`, `te-cl`, `te-te`, `h2c`, `h2`, `cl-edge`, plus `h2-downgrade` on `https` targets). The opt-in `cl-0`, `0-cl`, and `parser-discrepancy` checks run only when named explicitly.

## Detection Method

smugglex uses **timing-based detection**. It measures baseline response times, then sends smuggling payloads and compares. A response is flagged only when it is *both* well past the baseline — at least 3× the median (or the slowest baseline + 500 ms, whichever is larger) — *and* over 1 second, which indicates desynchronization.

The opt-in `cl-0` check uses a different signal: it sends a setup request and a normal follow-up over the same connection, verifies the control sequence against a fresh baseline, and requires the response-queue shift to reproduce.

The opt-in `0-cl` check uses an `Expect: 100-continue` two-phase exchange and rejects deadlock-only results; it requires an early response plus a reproducible post-body queue change.
