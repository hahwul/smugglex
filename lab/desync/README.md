# Desync lab — real socket-level request smuggling

Unlike [`../validate.py`](../README.md), which *emulates* the externally
observable behavior of a desync, this lab performs an **actual** HTTP request
smuggling desync between two real processes and lets you point `smugglex` at it.

## The chains

A request-smuggling desync exists when a front-end and a back-end **disagree on
where one request ends**. This lab makes that disagreement the single variable:

| Chain | Frontend (`frontend.py`) | Backend (`backend.py`) | Result |
|-------|--------------------------|------------------------|--------|
| **vulnerable** (`:8080`) | frames by **Content-Length** (first value), ignores `Transfer-Encoding` | honours **`Transfer-Encoding: chunked`** | they disagree → **desync** |
| **patched** (`:8081`) | same CL-first frontend | frames by the **first Content-Length** too | they agree → no desync |

The frontend reuses **one persistent backend connection** across all client
requests (as real reverse proxies pool upstreams). So when the CL frontend
forwards bytes past the point the TE backend stops at, the surplus becomes the
**prefix of the next request** on that shared connection — a genuine desync, not
a simulated status code.

See it directly — the victim's `GET /benign` is served the *smuggled* route:

```
attack  (conn A): POST / … CL:n / TE:chunked … 0\r\n\r\nGET /ADMIN-SECRET …
victim  (conn B): GET /benign …
backend serves B: "BACKEND served: [GET /ADMIN-SECRET HTTP/1.1]"   ← poisoned
```

## Run it

### Docker (as requested)

```sh
cd lab/desync
docker compose up --build -d
```

### No docker (pure stdlib Python)

```sh
lab/desync/run-local.sh
```

## Scan with smugglex

```sh
cargo build --release

# vulnerable chain → findings, exit code 1
./target/release/smugglex http://127.0.0.1:8080/

# patched chain → clean, exit code 0
./target/release/smugglex http://127.0.0.1:8081/
```

Expected (vulnerable `:8080`): 5 of 6 checks fire at **high** confidence with
signals such as `status_504`, `timing_anomaly:~6000x`, `extreme_timing`,
`body_divergence_vs_control`, `header_divergence_vs_control`. The ~6 s timing is
the back-end genuinely hanging on a truncated chunk until the frontend's
`UPSTREAM_TIMEOUT` fires (504) — exactly the signature smugglex keys on.

Expected (patched `:8081`): **no** checks vulnerable.

## Knobs

Frontend: `UPSTREAM_TIMEOUT` (default 6 s — backend-hang → 504 latency),
`CLIENT_BODY_TIMEOUT` (default 0.7 s — a client that under-sends its declared
Content-Length gets a fast 400 instead of stalling the proxy).
Backend: `FRAMING` = `te` (vulnerable) | `cl` (patched).

## Caveats

- This reproduces real desync against **deliberately naive** processes. It is a
  faithful end-to-end test of smuggling *detection*, not a model of any specific
  production proxy/server's parser.
- For a broader real-world corpus, PortSwigger's Web Security Academy
  request-smuggling labs are the standard — scan only lab instances **you** have
  launched, and never a target you are not authorized to test.
