# Desync lab — real socket-level request smuggling (Crystal)

Unlike [`../validate.cr`](../README.md), which *emulates* the externally
observable behavior of a desync, this lab performs an **actual** HTTP request
smuggling desync between two real servers and lets you point `smugglex` at it.

It is a single self-contained [Crystal](https://crystal-lang.org) process that
runs two cooperating servers in fibers:

```
client → frontend (CL-first proxy) → backend (TE-priority)
```

## The chains

A request-smuggling desync exists when a front-end and a back-end **disagree on
where one request ends**. This lab makes that disagreement the single variable:

| Chain | Frontend | Backend (`FRAMING`) | Result |
|-------|----------|---------------------|--------|
| **vulnerable** (`:8080`) | frames by **Content-Length** (first value), ignores `Transfer-Encoding` | `te` — honours **`Transfer-Encoding: chunked`** | they disagree → **desync** |
| **patched** (`:8081`) | same CL-first frontend | `cl` — frames by the **first Content-Length** too | they agree → no desync |

The frontend reuses **one persistent backend connection** across all client
requests (as real reverse proxies pool upstreams). So when the CL frontend
forwards bytes past the point the TE backend stops at, the surplus becomes the
**prefix of the next request** on that shared connection — a genuine desync, not
a simulated status code.

Like the basic PortSwigger lab, the frontend rejects non-`GET`/`POST` methods
(403) while the backend answers 405 for them. So a smuggled `GPOST` is blocked at
the front door but reaches the backend through the desync, where it surfaces as a
405 among 200s — exactly what smugglex keys on.

## Run it

### No docker (pure Crystal)

```sh
# needs Crystal (https://crystal-lang.org/install)
lab/desync/run-local.sh           # brings up vulnerable :8080 + patched :8081
```

Or run a single chain directly:

```sh
crystal run lab/desync/desync_lab.cr                 # vulnerable on :9000
FRAMING=cl crystal run lab/desync/desync_lab.cr      # patched on :9000
```

### Docker

```sh
cd lab/desync
docker compose up --build -d      # vulnerable :8080 + patched :8081
```

## Scan with smugglex

```sh
cargo build --release

# detect — vulnerable chain → findings, exit code 1
./target/release/smugglex http://127.0.0.1:8080/

# solve — smuggle GPOST → back-end 405 among 200s → "Smuggle delivered"
./target/release/smugglex --exploit smuggle http://127.0.0.1:8080/

# patched chain → clean, exit code 0
./target/release/smugglex http://127.0.0.1:8081/
```

Expected (vulnerable `:8080`): the scan reports the chain as vulnerable (exit
code `1`) via two complementary pathways:

- The **`cl-te`** check fires through the **second-request probe**
  (`second_request_desync`, `followup_divergence`, medium confidence). The
  CL.TE attack body (`0\r\n\r\nG`) carries a *complete* chunk, so the attack
  request itself gets a clean, fast `200` — no timing or status anomaly. The
  surplus `G` poisons the shared backend connection, so the *next* request is
  reframed (`GGET …` → backend `405`), which the probe observes as follow-up
  divergence from the baseline.
- The **`te-cl`** check fires through `status_504` and a multi-second
  `timing_anomaly`: its incomplete-chunk payloads leave the TE backend blocked
  reading a truncated chunk until the frontend's `UPSTREAM_TIMEOUT` fires (504).

The smuggle exploit prints `CL.TE [TE:plain]: [200, 405, 405, …]` and
`Smuggle delivered`.

Expected (patched `:8081`): **no** checks vulnerable, no smuggle delivered.

### Other exploits against this lab

`--exploit capture` and `--exploit reveal` also drive the same desync, but this
minimal backend only echoes the *first line* of the request it received
(`BACKEND ok: <line>`); it does not reflect request bodies or headers. So
`capture` can surface a diverging queued response, while `reveal` — which needs
an endpoint that reflects a submitted form parameter back in its response — has
nothing to echo here and will report that its marker was not reflected. Point
`reveal` at a real reflecting endpoint (a search box) to see front-end-injected
headers recovered.

## Config (env)

| var | default | meaning |
|-----|---------|---------|
| `FRAMING` | `te` | `te` = TE backend (vulnerable) / `cl` = CL backend (patched) |
| `FRONTEND_PORT` | `9000` | proxy listen port (scan target) |
| `BACKEND_PORT` | `9001` | internal backend port |
| `BIND_HOST` | `127.0.0.1` | frontend bind host (`0.0.0.0` for Docker) |
| `UPSTREAM_TIMEOUT` | `6` | seconds the proxy waits on the backend → 504 on a hang |
| `CLIENT_BODY_TIMEOUT` | `0.7` | seconds before a client that under-sends its body gets a 400 |

## Caveats

- This reproduces real desync against **deliberately naive** processes. It is a
  faithful end-to-end test of smuggling *detection and exploitation*, not a
  model of any specific production proxy/server's parser.
- For a broader real-world corpus, PortSwigger's Web Security Academy
  request-smuggling labs are the standard — scan only lab instances **you** have
  launched, and never a target you are not authorized to test.
