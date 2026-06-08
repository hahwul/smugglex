# Lab — end-to-end validation harness

A [Crystal](https://crystal-lang.org) harness that runs the **actual**
`smugglex` binary against a set of local mock backends and asserts that each
scenario produces the expected verdict and detection signals. Complements
`cargo test`, which exercises the library in isolation, by verifying the full
CLI → output pipeline against a sweep of true-positive and false-positive
scenarios.

## Usage

```sh
just lab               # builds release binary + runs validate.cr
# or directly:
cargo build --release
crystal run lab/validate.cr
```

Exits 0 if every scenario matches its expected outcome, non-zero otherwise.

## What it validates

Each scenario is a small socket-level "backend" that produces a deterministic
response pattern. The harness runs `smugglex --quiet --format json --checks
cl-te --timeout 6 http://127.0.0.1:<port>/` against each and compares:

1. **Verdict** — was `vulnerable` reported as expected?
2. **Required signals** — for true-positive scenarios, the harness asserts
   that the *specific* detection pathway under test fired (e.g.,
   `followup_divergence` for the second-request scenario), not just that
   *some* detection happened.

## Scenarios

### False positives (must NOT flag)

| Name | Backend behavior | What it exercises |
|------|-----------------|---|
| `FP_clean` | Always 200, fast, normal body | Baseline sanity — no anomalies → no detection |
| `FP_slow_post_uniform` | All POSTs ~1.4 s, GETs fast | Method-matched POST baseline lifting the threshold |
| `FP_uniform_504` | Everything returns 504 | Baseline-majority-timeout suppression of status signal |
| `FP_noisy_baseline` | One slow (1.5 s) baseline GET, borderline 1.2 s POSTs | Noise-aware threshold (`max + buffer`) |
| `FP_heavy_post` | POSTs with body slow, CL:0 POSTs and GETs fast | Differential control comparison + consecutive-FP early termination |
| `FP_waf_blocks_te` | WAF returns 403 on TE shapes, 200 otherwise | Verifies the scanner does not over-interpret WAF-shaped status/body differences as smuggling |
| `FP_natural_body_jitter` | Every response body varies ±4% (480–520 B) within similarity threshold | Body/follow-up divergence heuristics do not over-trigger on natural backend variability |
| `FP_intermittent_504` | ~5% of post-baseline requests return 504 (realistic flake rate) | Strict-majority confirmation + all-retries-for-status-only suppress sparse intermittent failures. Pathologically high flake rates (≥20%) remain a known limitation. |

### True positives (must flag)

| Name | Backend behavior | Signal exercised |
|------|-----------------|---|
| `TP_clte_status` | TE-carrying requests get 504 | `status_504` |
| `TP_clte_timing` | TE-carrying requests are slow, all other shapes fast | `timing_anomaly` |
| `TP_followup_desync` | Attack + control both slow with identical small body, but post-attack GETs return a divergent body | `followup_divergence` *(only path keeping the finding alive)* |
| `TP_body_divergence` | TE attack body diverges from control body despite similar timing | `body_divergence_vs_control` |

The follow-up and body-divergence scenarios are constructed so that *only*
the named signal can rescue the finding from the standard FP rejection rules
— this verifies the intended detection pathway in isolation.

## Adding a scenario

Add a handler method to `validate.cr`:

```crystal
def my_scenario(sock : TCPSocket, req : Bytes, n : Int32)
  # `sock` is the accepted client socket
  # `req`  is the raw HTTP request bytes (headers up to \r\n\r\n)
  # `n`    is the per-listener request count (1-indexed)
  sock.write(http_response(NORMAL_BODY))
end
```

Then register it in the `SCENARIOS` list with the expected verdict and (for
positives) the required signal substring(s):

```crystal
Scenario.new(
  "TP_my_scenario",
  ->my_scenario(TCPSocket, Bytes, Int32),
  expected_vulnerable: true,
  required_signal_substrings: ["timing_anomaly"],
)
```

## Limitations

- The mock backends emulate the externally observable behavior of vulnerable
  proxy/backend chains rather than performing actual HTTP desync. Good
  enough to validate detection-pipeline behavior; not a substitute for
  testing against real proxy software — for that, see the real socket-level
  desync lab in [`desync/`](desync/README.md).
- FP scenarios self-bound their runtime via the scanner's consecutive-FP early
  termination (no `--max-payloads` cap), so a scenario where every TE variation
  triggers detection + control rejection aborts instead of iterating through
  the full payload set.
