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

## JSON

Structured output for integration with other tools.

```bash
smugglex -f json -o results.json https://target.com
```

```json
{
  "target": "https://target.com",
  "method": "POST",
  "timestamp": "2025-01-15T10:30:00Z",
  "fingerprint": {
    "detected_proxy": "nginx",
    "server": "nginx/1.24.0"
  },
  "checks": [
    {
      "check_type": "cl-te",
      "vulnerable": true,
      "payload_index": 3,
      "normal_status": 200,
      "attack_status": 200,
      "normal_duration_ms": 45,
      "attack_duration_ms": 5023,
      "confidence": "high"
    }
  ]
}
```

## Export Payloads

Save vulnerable payloads as raw HTTP requests for manual verification.

```bash
smugglex --export-payloads ./payloads https://target.com
```

Creates files like `payloads/cl-te-payload-3.txt` containing the raw HTTP request.
