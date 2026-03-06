+++
title = "Checks"
description = "Smuggling techniques supported by smugglex"
+++

smugglex supports 6 types of HTTP Request Smuggling checks. Each exploits differences in how front-end and back-end servers parse HTTP requests.

| Check | Description |
|-------|-------------|
| [CL.TE](/checks/cl-te/) | Content-Length vs Transfer-Encoding |
| [TE.CL](/checks/te-cl/) | Transfer-Encoding vs Content-Length |
| [TE.TE](/checks/te-te/) | Transfer-Encoding obfuscation (40+ variants) |
| [H2C](/checks/h2c/) | HTTP/2 Cleartext smuggling |
| [H2](/checks/h2/) | HTTP/2 protocol smuggling |
| [CL-Edge](/checks/cl-edge/) | Content-Length edge cases |

## Run Specific Checks

```bash
smugglex -c cl-te,te-cl https://target.com
```

## Detection Method

smugglex uses **timing-based detection**. It measures baseline response times, then sends smuggling payloads and compares. A significant delay (3x baseline or 1s+ minimum) indicates desynchronization.
