+++
title = "Output"
description = "Understanding smugglex output formats"
+++

## Plain Text

Default output format. Shows vulnerability status per check.

```bash
smugglex https://target.com
```

```
[VULNERABLE] CL.TE - https://target.com (payload #3)
  Normal: 200 (45ms) | Attack: 200 (5023ms)
[OK] TE.CL - https://target.com
[OK] TE.TE - https://target.com
```

## JSON (Machine Readable)

Use `-f json` or `--json` for clean, structured output suitable for AI agents, scripts, jq, and CI systems.

```bash
smugglex --json https://target.com
# or the equivalent:
smugglex -f json https://target.com
```

Key properties for automation:
- **Stdout is pure JSON** — no progress bars, no log lines.
- **Exit code** indicates findings: `0` = clean, `1` = vulnerable found.
- Single target → `ScanResults` object (per-target schema).
- Multiple targets / stdin batch → envelope with `results[]` + `summary`:

```json
{
  "smugglex_version": "0.2.0",
  "timestamp": "...",
  "results": [
    { "target": "...", "checks": [...], "error": null },
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

Creates files like `payloads/cl-te-payload-3.txt` containing the raw HTTP request.
