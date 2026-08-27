+++
title = "Output"
description = "Understanding smugglex output formats"
+++

## Plain Text

Default output format. Timestamped log lines (`INF`/`WRN`/`ERR`) report progress, and each finding is printed as a detail block.

```bash
smugglex https://target.com
```

```
09:15AM WRN smuggling found 1 vulnerability(ies)

=== CL.TE Vulnerability Details ===
Status: VULNERABLE (Confidence: High)
Payload Index: 3
Attack Response: 200
Timing: Normal: 45ms, Attack: 5023ms
Signals: timing-anomaly
HTTP Raw Request:
────────────────────────────────────────────────────────────
POST / HTTP/1.1
...
────────────────────────────────────────────────────────────
```

When nothing is found, smugglex logs `smuggling found 0 vulnerabilities`.

## JSON (Machine Readable)

Use `-f json` or `--json` for clean, structured output suitable for AI agents, scripts, jq, and CI systems.

```bash
smugglex --json https://target.com
# or the equivalent:
smugglex -f json https://target.com
```

Key properties for automation:
- **Stdout is pure JSON** — no progress bars, no log lines.
- **Exit code** indicates findings: `0` = clean, `1` = vulnerable found, `2` = input/usage error.
- JSON mode always emits a batch envelope with `results[]` + `summary`, even for a single target.

```json
{
  "smugglex_version": "0.3.0",
  "timestamp": "...",
  "results": [
    { "target": "...", "checks": [...] },
    { "target": "...", "checks": [], "error": "URL parse error: ..." },
    ...
  ],
  "summary": {
    "total_targets": 12,
    "vulnerable_targets": 3,
    "total_checks": 84,
    "vulnerable_checks": 5
  }
}
```

Write to file while keeping stdout clean:

```bash
smugglex --json -o report.json https://target.com
```

## Export Payloads

Save vulnerable payloads as raw HTTP requests for manual verification.

```bash
smugglex --export-payloads ./payloads https://target.com
```

Creates files named `<proto>_<host>_<check>_<index>.txt` — for example `payloads/https_target_com_cl-te_3.txt` — each containing the raw HTTP request.
