+++
title = "H2C"
description = "HTTP/2 Cleartext smuggling"
+++

Tests HTTP/2 Cleartext (h2c) upgrade smuggling. The front-end may forward an `Upgrade: h2c` request to a back-end that handles it differently, allowing request smuggling through the upgrade mechanism.

## Tested Payloads

smugglex sends 20+ h2c payload variations including different `Connection` and `Upgrade` header combinations.

## Run

```bash
smugglex -c h2c https://target.com
```
