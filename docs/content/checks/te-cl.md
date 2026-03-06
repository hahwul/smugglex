+++
title = "TE.CL"
description = "Transfer-Encoding vs Content-Length desynchronization"
+++

The front-end uses `Transfer-Encoding: chunked`, the back-end uses `Content-Length`. The front-end sends the chunked body, but the back-end reads a fixed number of bytes.

## How It Works

```
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

The front-end processes chunks. The back-end reads only 3 bytes based on Content-Length, leaving the rest as a new request.

## Run

```bash
smugglex -c te-cl https://target.com
```
