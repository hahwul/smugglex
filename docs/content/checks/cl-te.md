+++
title = "CL.TE"
description = "Content-Length vs Transfer-Encoding desynchronization"
+++

The front-end uses `Content-Length`, the back-end uses `Transfer-Encoding: chunked`. The front-end forwards the full body based on Content-Length, but the back-end only reads up to the chunk terminator, leaving the rest in the buffer.

## How It Works

```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end sends all 13 bytes. The back-end reads `0\r\n\r\n` (chunk end) and treats `SMUGGLED` as the start of the next request.

## Run

```bash
smugglex -c cl-te https://target.com
```
