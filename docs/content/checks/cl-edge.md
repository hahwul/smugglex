+++
title = "CL-Edge"
description = "Content-Length edge case attacks"
+++

Tests edge cases in `Content-Length` header parsing. Different servers may interpret malformed or ambiguous Content-Length values differently.

## Edge Cases

- Duplicate Content-Length headers with different values
- Content-Length with leading zeros, spaces, or signs
- Negative or extremely large values

## Run

```bash
smugglex -c cl-edge https://target.com
```
