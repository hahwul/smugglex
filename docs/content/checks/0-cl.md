+++
title = "0.CL"
description = "Expect/body-pause response-queue detection for 0.CL request smuggling"
+++

## Overview

0.CL describes a parser path where the front-end treats a request as if its
`Content-Length` were zero while the back-end honors the length. The back-end
can wait for a body that the front-end has already interpreted as a later
request, producing a deadlock or a response-queue shift.

## Detection

The `0-cl` check is opt-in and uses a two-phase HTTP/1.1 exchange:

1. A direct follow-up request establishes the expected baseline.
2. A control request sends `Expect: 100-continue`, waits briefly, then sends a
   normal body and follow-up.
3. Candidate requests vary Content-Length parsing and Expect handling. Headers
   are sent first, an early non-100 response is recorded, and only then are the
   body and follow-up written.
4. The control follow-up must match the direct baseline, while a post-body
   attack response must differ.
5. The sequence must reproduce twice after the initial candidate.

A timeout/deadlock without a response-queue change is intentionally not
reported as a vulnerability because it is not enough to distinguish 0.CL from
an ordinary upstream timeout.

```bash
smugglex --checks 0-cl https://target.example
smugglex --checks 0-cl --max-payloads 2 https://target.example
```

Use this check only against systems you are authorized to test. It sends a
body after observing an early response and can affect stateful connection pools.
