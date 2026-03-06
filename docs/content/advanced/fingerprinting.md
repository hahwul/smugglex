+++
title = "Fingerprinting"
description = "Proxy and server fingerprinting"
+++

smugglex can identify the proxy/server stack before scanning, helping prioritize which checks are most likely to succeed.

## Usage

```bash
smugglex --fingerprint https://target.com
```

## Detected Servers

Nginx, Apache, Varnish, CloudFront, Cloudflare, HAProxy, Envoy, ATS (Apache Traffic Server), Squid, Caddy, IIS, Traefik, Akamai, Fastly, and more.

## How It Works

Analyzes response headers (`Server`, `Via`, `X-Powered-By`, etc.) and behavior patterns to identify the proxy/server combination.

## JSON Output

```json
{
  "fingerprint": {
    "detected_proxy": "cloudflare",
    "server": "cloudflare",
    "via": null,
    "x_powered_by": null
  }
}
```
