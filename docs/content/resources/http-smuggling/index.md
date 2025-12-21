+++
title = "What is HTTP Request Smuggling?"
description = "Understanding HTTP Request Smuggling vulnerabilities"
weight = 1
sort_by = "weight"

[extra]
+++

HTTP Request Smuggling is a critical web security vulnerability that exploits differences in how servers parse HTTP requests. This technique allows attackers to interfere with how web applications process request sequences.

## Overview

Request smuggling occurs when a chain of HTTP servers (typically a front-end and back-end) disagree on the boundaries between HTTP requests. This desynchronization allows attackers to "smuggle" malicious requests through security controls.

## How It Works

### The Request Chain

Modern web applications often use multiple servers:

```
Client → Front-End Server → Back-End Server
         (Proxy/Load Balancer)  (Application Server)
```

The front-end server:
- Receives client requests
- Performs security checks
- Forwards requests to back-end

The back-end server:
- Processes application logic
- Returns responses

### The Vulnerability

Request smuggling exploits disagreements about request boundaries using two HTTP headers:

1. **Content-Length**: Specifies the message body length in bytes
2. **Transfer-Encoding**: Specifies the encoding method (e.g., chunked)

When both headers are present or obfuscated, servers may interpret them differently.

## Attack Types

### CL.TE (Content-Length vs Transfer-Encoding)

The front-end uses Content-Length, while the back-end uses Transfer-Encoding.

**Example:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front-end reads 13 bytes and forwards
- Back-end sees chunked encoding (0 = end)
- "SMUGGLED" remains in the buffer for the next request

### TE.CL (Transfer-Encoding vs Content-Length)

The front-end uses Transfer-Encoding, while the back-end uses Content-Length.

**Example:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

- Front-end reads until "0" (end of chunks)
- Back-end reads only 3 bytes
- Remaining data poisons the next request

### TE.TE (Transfer-Encoding Obfuscation)

Both servers support Transfer-Encoding, but one can be tricked with obfuscation.

**Obfuscation Techniques:**

- `Transfer-Encoding: chunked`
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding: chunked, chunked`
- `Transfer-Encoding: chunked;x=y`
- `Transfer-Encoding : chunked` (space before colon)
- `Transfer-Encoding: chunked\r\n\r\n` (extra CRLF)
- And 40+ more variations

### H2C (HTTP/2 Cleartext Smuggling)

Exploits HTTP/1.1 to HTTP/2 upgrade mechanisms.

**Attack Vector:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Upgrade: h2c
HTTP2-Settings: <base64-settings>
Content-Length: X

<HTTP/2 smuggled request>
```

When the front-end doesn't properly handle HTTP/2 upgrade requests, smuggled data can be interpreted as a new request.

### H2 (HTTP/2 Protocol Smuggling)

Exploits HTTP/2 protocol features during translation to HTTP/1.1.

**Key Issues:**

- HTTP/2 uses binary framing
- Multiple requests in a single connection
- Header compression (HPACK)
- Server Push capability
- Stream multiplexing

These features can cause desynchronization when converted to HTTP/1.1.

## Security Impact

### What Attackers Can Do

**Bypass Security Controls:**
- Web Application Firewalls (WAF)
- Intrusion Detection Systems (IDS)
- Access control mechanisms
- Rate limiting

**Cache Poisoning:**
- Inject malicious content into cache
- Serve malicious responses to other users
- Deface web pages
- Distribute malware

**Session Hijacking:**
- Steal authentication cookies
- Capture session tokens
- Impersonate legitimate users
- Access sensitive data

**Request Hijacking:**
- Intercept other users' requests
- Capture credentials
- Steal sensitive data
- Modify request parameters

**Privilege Escalation:**
- Access admin functionality
- Execute unauthorized actions
- Bypass authentication
- Access restricted resources

### Real-World Impact

Request smuggling vulnerabilities have been found in:

- Major cloud providers
- Content delivery networks (CDNs)
- API gateways
- Load balancers
- Web application firewalls
- Enterprise applications

## Why It Happens

### HTTP/1.1 Ambiguity

The HTTP/1.1 specification (RFC 7230) states:

> If a message is received with both a Transfer-Encoding header field and a Content-Length header field, the Transfer-Encoding overrides the Content-Length.

However:
- Some implementations ignore Transfer-Encoding
- Others prioritize Content-Length
- Obfuscation can break parsing
- Protocol translation introduces complexity

### Protocol Complexity

- HTTP/1.1 allows header ambiguity
- HTTP/2 introduces new complexity
- Protocol translation is error-prone
- Multiple implementations vary

### Implementation Differences

Different servers have different behaviors:
- Apache, Nginx, IIS handle headers differently
- Front-end and back-end may use different software
- Version differences within the same software
- Configuration options affect parsing

## Detection Methods

### Timing-Based Detection

Smugglex uses timing analysis:

1. Send a normal request - measure time
2. Send an attack request - measure time
3. Compare response times

If the attack request causes a significant delay or timeout, it indicates desynchronization.

**Key Indicators:**
- Connection timeout on attack request
- Significantly longer response time
- Error responses that differ from normal
- Connection closure patterns

### Response-Based Detection

Look for:
- Unexpected responses
- Error messages
- Different status codes
- Connection behavior changes

### Behavioral Analysis

Observe:
- Request queue behavior
- Connection persistence
- Response correlation
- Server state changes

## Prevention

### Server Configuration

**Disable HTTP/1.1 Pipeline:**
- Prevents request queuing issues
- Reduces attack surface

**Reject Ambiguous Requests:**
- Drop requests with both CL and TE
- Validate Transfer-Encoding values
- Strict header parsing

**Use HTTP/2 Only:**
- Eliminates HTTP/1.1 ambiguities
- Better protocol design
- Built-in protections

### Architecture Changes

**Eliminate Intermediate Proxies:**
- Direct client-to-application connections
- Reduces parsing layers

**Use Consistent Servers:**
- Same software for front-end and back-end
- Aligned configurations
- Unified parsing logic

**Normalize Requests:**
- Front-end normalizes all requests
- Removes ambiguous headers
- Enforces strict parsing

### Application Hardening

**Input Validation:**
- Validate request structure
- Reject malformed requests
- Sanitize headers

**Security Headers:**
- Use strict security policies
- Implement request validation
- Log suspicious patterns

## Testing for Vulnerabilities

### Using Smugglex

Basic scan:

```bash
smugglex https://target.com/
```

Comprehensive scan:

```bash
smugglex https://target.com/ -v -o results.json --export-payloads ./payloads
```

### Manual Testing

1. Test with both CL and TE headers
2. Try obfuscation techniques
3. Observe timing differences
4. Check for timeouts
5. Analyze response patterns

### Responsible Testing

- Only test systems you own or have permission to test
- Use appropriate timeouts to avoid DoS
- Document findings properly
- Report vulnerabilities responsibly

## Learning Resources

### Research Papers

- "HTTP Desync Attacks: Request Smuggling Reborn" by James Kettle (2019)
- "HTTP/2: The Sequel is Always Worse" by James Kettle (2021)
- Various CVE reports and security advisories

### Online Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/request-smuggling)
- [OWASP HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- Security conference presentations
- Bug bounty write-ups

### Practice

- PortSwigger Labs
- Vulnerable test applications
- CTF challenges
- Bug bounty programs (with permission)

## References

- [References and Research](/resources/references)
- [Running SmuggleX](/get_started/running)
- [Overview](/get_started/overview)
- [GitHub Repository](https://github.com/hahwul/smugglex)

## Conclusion

HTTP Request Smuggling is a complex vulnerability with serious security implications. Understanding how it works is essential for both attackers (in authorized testing) and defenders. Use smugglex to identify these vulnerabilities in systems you're authorized to test, and implement proper defenses in your applications.
