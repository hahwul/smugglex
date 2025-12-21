+++
title = "References and Research"
description = "HTTP Request Smuggling research, papers, and tools"
weight = 2
sort_by = "weight"

[extra]
+++

# References and Research

This page provides links to research papers, security advisories, tools, and educational resources related to HTTP Request Smuggling.

## Research Papers and Presentations

### Foundational Research

**HTTP Desync Attacks: Request Smuggling Reborn (2019)**
- Author: James Kettle (PortSwigger)
- [Read the paper](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- Revitalized interest in request smuggling
- Introduced timing-based detection
- Documented modern exploitation techniques
- Presented at Black Hat USA 2019

**HTTP/2: The Sequel is Always Worse (2021)**
- Author: James Kettle (PortSwigger)
- [Read the paper](https://portswigger.net/research/http2)
- HTTP/2-specific desync attacks
- H2C smuggling techniques
- HTTP/2 request smuggling via CRLF injection
- Protocol translation vulnerabilities

### Academic Research

**Browser-Powered Desync Attacks**
- [PortSwigger Research](https://portswigger.net/research/browser-powered-desync-attacks)
- Client-side request smuggling
- Browser behavior exploitation
- New attack vectors

**HTTP Request Smuggling in 2020**
- [PortSwigger Research](https://portswigger.net/research/http-request-smuggling-in-2020)
- Evolution of smuggling techniques
- New obfuscation methods
- Practical exploitation

## Security Advisories

### Notable CVEs

**CVE-2020-11724** - HAProxy Request Smuggling
- HTTP/1.1 request smuggling vulnerability
- Affected versions of HAProxy
- CL.TE variant

**CVE-2021-21295** - Netty HTTP/2 Request Smuggling
- HTTP/2 protocol-level smuggling
- Affects applications using Netty
- H2 variant

**CVE-2020-5902** - F5 BIG-IP Request Smuggling
- Critical smuggling vulnerability
- Allowed remote code execution
- Wide-scale impact

**CVE-2019-9516** - HTTP/2 Internal Data Buffering
- Denial of service via smuggling
- Affected multiple implementations
- Resource exhaustion

### Vendor Security Bulletins

- [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/)
- [Cloudflare Security Advisories](https://www.cloudflare.com/trust-hub/security-advisories/)
- [Nginx Security Advisories](https://nginx.org/en/security_advisories.html)
- [Apache Security Reports](https://httpd.apache.org/security_report.html)

## Tools and Projects

### Testing Tools

**Smugglex**
- [GitHub Repository](https://github.com/hahwul/smugglex)
- Written in Rust
- Multiple attack types
- Timing-based detection

**HTTP Request Smuggler (Burp Extension)**
- [GitHub Repository](https://github.com/defparam/smuggler)
- Burp Suite extension
- Interactive testing
- Manual verification

**h2csmuggler**
- [GitHub Repository](https://github.com/BishopFox/h2csmuggler)
- HTTP/2 Cleartext smuggling
- Specialized for H2C attacks
- Python-based

**smuggler.py**
- [GitHub Repository](https://github.com/gwen001/smuggler)
- Python implementation
- Multiple techniques
- CLI tool

**tiscripts**
- [GitHub Repository](https://github.com/neex/http2smugl)
- HTTP/2 smuggling PoCs
- Research demonstrations
- Python scripts

### Scanning and Detection

**Nuclei Templates**
- [HTTP Request Smuggling Templates](https://github.com/projectdiscovery/nuclei-templates)
- Automated detection
- Integration with Nuclei scanner
- Community-contributed

**OWASP ZAP Scripts**
- HTTP Request Smuggling detection scripts
- Active scan rules
- Passive detection

## Blog Posts and Write-ups

### Technical Deep Dives

**PortSwigger Blog**
- [Request Smuggling Articles](https://portswigger.net/blog/tag/request-smuggling)
- Detailed attack explanations
- Case studies
- New techniques

**Assetnote Blog**
- [HTTP Request Smuggling at Assetnote](https://blog.assetnote.io/)
- Bug bounty findings
- Real-world examples
- Exploitation techniques

**Bishop Fox Blog**
- [HTTP/2 Cleartext (H2C) Smuggling](https://bishopfox.com/blog/h2c-smuggling-request)
- H2C attack details
- Tool development
- Research findings

### Bug Bounty Reports

**HackerOne Disclosed Reports**
- [Search: HTTP Request Smuggling](https://hackerone.com/hacktivity?querystring=request%20smuggling)
- Real vulnerability reports
- Bounty amounts
- Impact descriptions

**Bugcrowd Disclosures**
- Various request smuggling reports
- Different attack variants
- Mitigation approaches

### Practitioner Guides

**Web Security Academy (PortSwigger)**
- [HTTP Request Smuggling Tutorial](https://portswigger.net/web-security/request-smuggling)
- Interactive labs
- Step-by-step exploitation
- Practice environments

**Practical HTTP Request Smuggling**
- Various blog posts and tutorials
- Hands-on demonstrations
- Testing methodologies

## Educational Resources

### Online Courses

**PortSwigger Web Security Academy**
- Free online training
- HTTP Request Smuggling module
- Interactive labs
- Certification available

**PentesterLab**
- Request smuggling exercises
- Guided exploitation
- Skill development

### Video Content

**Conference Talks**
- Black Hat USA presentations
- DEF CON talks
- OWASP AppSec presentations
- YouTube recordings

**Tutorial Videos**
- YouTube security channels
- Demonstration videos
- Exploitation guides

### Books

**The Web Application Hacker's Handbook**
- By Dafydd Stuttard and Marcus Pinto
- Classic reference
- Comprehensive coverage
- Exploitation techniques

**Real-World Bug Hunting**
- By Peter Yaworski
- Bug bounty focus
- Case studies
- Practical approach

## Community Resources

### Forums and Communities

**Reddit**
- /r/netsec - Network security discussions
- /r/bugbounty - Bug bounty community
- /r/websecurity - Web security topics

**Discord Servers**
- Bug bounty communities
- Security research groups
- Tool-specific channels

**Twitter/X**
- Follow @albinowax (James Kettle)
- Follow @defparam
- Follow @hahwul
- Security researcher community

### Bug Bounty Platforms

**HackerOne**
- [Platform](https://www.hackerone.com/)
- Request smuggling bounties
- Vulnerability disclosures

**Bugcrowd**
- [Platform](https://www.bugcrowd.com/)
- Researcher community
- Vulnerability reports

**Intigriti**
- [Platform](https://www.intigriti.com/)
- European focus
- Research opportunities

## Standards and Specifications

### HTTP Protocol Specifications

**RFC 7230 - HTTP/1.1 Message Syntax and Routing**
- [Read the RFC](https://www.rfc-editor.org/rfc/rfc7230)
- Defines Content-Length and Transfer-Encoding
- Conflict resolution rules
- Official specification

**RFC 7231 - HTTP/1.1 Semantics and Content**
- [Read the RFC](https://www.rfc-editor.org/rfc/rfc7231)
- HTTP methods and headers
- Status codes
- Request/response semantics

**RFC 7540 - HTTP/2**
- [Read the RFC](https://www.rfc-editor.org/rfc/rfc7540)
- HTTP/2 specification
- Binary framing
- Multiplexing

**RFC 9113 - HTTP/2 (Updated)**
- [Read the RFC](https://www.rfc-editor.org/rfc/rfc9113)
- Updated HTTP/2 specification
- Security improvements
- Clarifications

### Security Guidelines

**OWASP**
- [HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- Attack description
- Prevention techniques
- Testing guidance

**CWE-444: Inconsistent Interpretation of HTTP Requests**
- [CWE Entry](https://cwe.mitre.org/data/definitions/444.html)
- Weakness description
- Common consequences
- Mitigation strategies

## Practice Environments

### Vulnerable Applications

**PortSwigger Labs**
- [Web Security Academy Labs](https://portswigger.net/web-security/request-smuggling)
- Free practice labs
- Various smuggling scenarios
- Guided solutions

**DVWA (Damn Vulnerable Web Application)**
- Intentionally vulnerable
- Practice environment
- Multiple vulnerabilities

**WebGoat**
- OWASP project
- Interactive lessons
- Security training

### CTF Challenges

- HackTheBox
- TryHackMe
- PentesterLab
- OverTheWire

## Related Attack Techniques

### Cache Poisoning

- Web cache poisoning via smuggling
- Cache key manipulation
- Persistent XSS via cache

### Session Hijacking

- Cookie theft via smuggling
- Session fixation
- Authentication bypass

### Access Control Bypass

- WAF bypass techniques
- Authentication evasion
- Authorization circumvention

## Contributing

Found a useful resource not listed here?

- [Open an issue](https://github.com/hahwul/smugglex/issues)
- Submit a pull request
- Share with the community

## Staying Updated

### RSS Feeds

- PortSwigger Research RSS
- OWASP News Feed
- Security blog aggregators

### Newsletters

- OWASP Newsletter
- PortSwigger Daily Swig
- tl;dr sec

### Social Media

- Follow security researchers
- Join security communities
- Subscribe to YouTube channels

## Disclaimer

These resources are provided for educational and research purposes. Always obtain proper authorization before testing any systems. Unauthorized testing may be illegal in your jurisdiction.

## See Also

- [What is HTTP Request Smuggling?](/resources/http-smuggling)
- [Running SmuggleX](/get_started/running)
- [Development Guide](/development)
- [GitHub Repository](https://github.com/hahwul/smugglex)
