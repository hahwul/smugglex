# Crystal desync lab

A real socket-level HTTP request-smuggling test server written in
[Crystal](https://crystal-lang.org), as a self-contained companion to the Python
lab in [`../`](../README.md). One process runs two cooperating servers in fibers:

```
client → frontend (CL-first proxy, :9000) → backend (TE-priority, :9001)
```

The frontend frames request bodies strictly by the first **Content-Length** and
forwards every request over **one shared, persistent backend connection**. The
backend honours **`Transfer-Encoding: chunked`**. They disagree on where a
request ends, and because the backend connection is reused, the surplus the CL
frontend forwards past the chunked body becomes the prefix of the next request —
a genuine CL.TE desync.

Like the basic PortSwigger lab, the frontend rejects non-`GET`/`POST` methods
(403) while the backend answers 405 for them. So a smuggled `GPOST` is blocked at
the front door but reaches the backend through the desync, where it shows up as a
405 among 200s — the signal smugglex keys on.

## Run

```sh
# needs Crystal (https://crystal-lang.org/install)
crystal run lab/desync/crystal/desync_lab.cr
# or build once:
crystal build --release lab/desync/crystal/desync_lab.cr -o /tmp/desync_lab && /tmp/desync_lab
```

Docker:

```sh
cd lab/desync/crystal
docker build -t smugglex-desync-cr .
docker run --rm -p 9000:9000 smugglex-desync-cr            # vulnerable (FRAMING=te)
docker run --rm -p 9000:9000 -e FRAMING=cl smugglex-desync-cr   # patched
```

## Scan with smugglex

```sh
cargo build --release

# detect (vulnerable chain → te-cl fires: status_504 + ~6s timing + body divergence)
./target/release/smugglex http://127.0.0.1:9000/

# solve (smuggle GPOST → back-end 405 among 200s → "Smuggle delivered")
./target/release/smugglex --exploit smuggle http://127.0.0.1:9000/
```

Expected (vulnerable): the smuggle exploit prints `CL.TE [TE:plain]:
[200, 405, 405, …]` and `Smuggle delivered`. With `FRAMING=cl` (patched) the chain
is clean — no detection, no smuggle delivered.

## Config (env)

| var | default | meaning |
|-----|---------|---------|
| `FRAMING` | `te` | `te` = TE backend (vulnerable) / `cl` = CL backend (patched) |
| `FRONTEND_PORT` | `9000` | proxy listen port (scan target) |
| `BACKEND_PORT` | `9001` | internal backend port |
| `BIND_HOST` | `127.0.0.1` | frontend bind host (`0.0.0.0` for Docker) |
| `UPSTREAM_TIMEOUT` | `6` | seconds the proxy waits on the backend → 504 on a hang |
| `CLIENT_BODY_TIMEOUT` | `0.7` | seconds before a client that under-sends its body gets a 400 |

## Caveat

Deliberately naive processes that reproduce a real desync for testing
*detection and exploitation* — not a model of any specific production
proxy/server parser.
