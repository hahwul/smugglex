+++
title = "CL.0"
description = "Same-connection response-queue detection for CL.0 request smuggling"
+++

## Overview

CL.0 describes a front-end that honors a request's `Content-Length` while the
back-end treats the request as bodyless. The body can then be parsed as a new
request by the back-end, leaving the front-end and back-end response queues out
of sync.

## Detection

The `cl-0` check is opt-in because it deliberately reuses one connection:

1. A direct follow-up request establishes the expected baseline response.
2. A control setup request and follow-up are sent over one persistent connection.
3. A setup request whose body contains a harmless inner `GET` and the same
   follow-up are sent over a fresh persistent connection.
4. The control's follow-up response must match the direct baseline, while the
   attack's follow-up response must differ.
5. The response-queue shift must reproduce twice after the initial candidate.

Status and meaningful body-size shifts are recorded as evidence. A timeout or a
single connection anomaly is not enough to report a vulnerability.

```bash
smugglex --checks cl-0 https://target.example
smugglex --checks cl-0 --max-payloads 1 https://target.example
```

Use this check only against systems you are authorized to test. Because it uses
stateful connections, run it separately when a target has sensitive persistent
sessions or shared back-end connection pools.
