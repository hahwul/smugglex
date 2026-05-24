#!/usr/bin/env python3
"""
Local smuggling-lab validation harness for smugglex.

Spins up a series of socket-level fake backends, each simulating a distinct
scenario (real smuggling, benign-noisy backend, slow POST handler, etc.),
invokes the smugglex binary against each, parses the JSON output, and reports
whether the verdict matches expectations.

Run from the repository root:
    python3 lab/validate.py

Exits non-zero if any scenario disagrees with its expected outcome.
"""

from __future__ import annotations

import dataclasses
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMUGGLEX = REPO_ROOT / "target" / "release" / "smugglex"

# Each scenario is given (conn_socket, request_bytes, request_count_int).
ScenarioHandler = Callable[[socket.socket, bytes, int], None]


# ----------------------------- response helpers -----------------------------


def http_response(body: bytes | str, status: str = "200 OK", server: str = "test") -> bytes:
    if isinstance(body, str):
        body = body.encode()
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: {server}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return head + body


# Body sizes chosen to give the body-divergence heuristic clear signal:
# NORMAL_BODY is large (500 B), SMALL_ERROR_BODY is below MIN_BYTES (3 B),
# DESYNC_BODY is well over MIN_BYTES but far below NORMAL_BODY (80 B vs 500 B
# = 16% — clearly diverges per CONTROL_BODY_DIVERGENCE_PCT=75 rule).
NORMAL_BODY = b"X" * 500
SMALL_ERROR_BODY = b"ERR"
DESYNC_BODY = b"D" * 80


# --------------------------- scenario implementations -----------------------


def clean(sock, req, n):
    """Always returns a normal fast response — nothing suspicious anywhere."""
    sock.sendall(http_response(NORMAL_BODY))


def slow_post_uniform(sock, req, n):
    """Every POST is slow (~1.4s). The method-matched POST baseline should
    lift the threshold so a POST attack at ~1.4s does NOT flag."""
    if not req.startswith(b"GET"):
        time.sleep(1.4)
    sock.sendall(http_response(NORMAL_BODY))


def uniform_504(sock, req, n):
    """Backend always returns 504. Baseline majority is 504 → status signal
    must be suppressed."""
    sock.sendall(http_response(b"Gateway timeout", status="504 Gateway Timeout"))


def noisy_baseline(sock, req, n):
    """One slow baseline GET (1500ms) creates a high-variance baseline. A
    borderline 1200ms attack must NOT flag (noise-aware threshold + variance
    demotion)."""
    if n == 1:
        time.sleep(1.5)
    elif n > 3 and req.startswith(b"POST"):
        time.sleep(1.2)
    sock.sendall(http_response(NORMAL_BODY))


def heavy_post_uniform(sock, req, n):
    """POSTs with body are slow (mimicking expensive serverside processing for
    any non-empty body); CL:0 POSTs and GETs are fast. Attack with TE body and
    control with padded body both look slow — control comparison must reject."""
    body_present = (
        b"transfer-encoding" in req.lower()
        or _has_nonzero_content_length(req)
    )
    if body_present:
        time.sleep(2.0)
    sock.sendall(http_response(NORMAL_BODY))


# ---- True-positive scenarios ----


def tp_clte_status(sock, req, n):
    """TE-carrying requests get 504; other shapes 200. Classic CL.TE
    status-code signal."""
    if b"transfer-encoding" in req.lower():
        sock.sendall(http_response(b"Gateway timeout", status="504 Gateway Timeout"))
    else:
        sock.sendall(http_response(NORMAL_BODY))


def tp_clte_timing(sock, req, n):
    """TE-carrying requests are slow (2s); other shapes fast. Timing-only TE
    smuggling indicator that survives the method-matched POST baseline
    (because POST with CL:0 baseline is fast — only TE-carrying POSTs slow)."""
    if b"transfer-encoding" in req.lower():
        time.sleep(2.0)
    sock.sendall(http_response(NORMAL_BODY))


def tp_followup_desync(sock, req, n):
    """TE attack AND control both return the same small error body slowly —
    body/header divergence escapes do NOT fire. Only the post-attack follow-up
    GETs return a divergent body relative to baseline, exercising the
    second-request smuggling signal in isolation.

    Request order with R8 method-matched POST baseline:
      1..=3   GET baseline                 (NORMAL_BODY)
      4..=6   POST CL:0 baseline           (NORMAL_BODY, fast)
      7       attack (TE)                  (slow, SMALL_ERROR_BODY)
      8..=10  3 confirmation retries (TE)  (slow, SMALL_ERROR_BODY)
      11..=12 2 control samples (POST padded body, no TE)
                                           (slow, SMALL_ERROR_BODY ← matches attack)
      13..=15 3 follow-up GETs             (fast, DESYNC_BODY ← diverges from
                                            baseline)
    """
    has_te = b"transfer-encoding" in req.lower()
    has_body = has_te or _has_nonzero_content_length(req)
    is_followup = 13 <= n <= 15

    if has_body:
        # Attack AND control both slow + identical small body so divergence
        # escapes via body/header are inert; only follow-up can save the
        # finding.
        time.sleep(2.0)
        sock.sendall(http_response(SMALL_ERROR_BODY))
        return
    if is_followup:
        sock.sendall(http_response(DESYNC_BODY))
        return
    sock.sendall(http_response(NORMAL_BODY))


def tp_body_divergence(sock, req, n):
    """TE attack: slow + small error body. Control (TE stripped, padded body):
    slow + normal body. Bodies diverge → escape clause keeps the finding even
    though timing similarity would otherwise reject."""
    has_te = b"transfer-encoding" in req.lower()
    has_body = has_te or _has_nonzero_content_length(req)
    if has_body:
        time.sleep(2.0)
    if has_te:
        sock.sendall(http_response(SMALL_ERROR_BODY))
    else:
        sock.sendall(http_response(NORMAL_BODY))


# ----------------------------- helpers -------------------------------------


def _has_nonzero_content_length(req: bytes) -> bool:
    for line in req.split(b"\r\n"):
        ls = line.lower().lstrip()
        if ls.startswith(b"content-length:"):
            value = ls.split(b":", 1)[1].strip()
            if value and value != b"0":
                return True
    return False


# ---------------------------- harness --------------------------------------


@dataclasses.dataclass
class Scenario:
    name: str
    handler: ScenarioHandler
    expected_vulnerable: bool
    # Substrings that MUST appear in detection_signals (each entry only needs
    # to be a prefix/substring of some signal). Empty for non-vulnerable
    # scenarios. Lets the harness validate not just the verdict but also that
    # the *intended* signal pathway is what produced it.
    required_signal_substrings: tuple[str, ...] = ()
    notes: str = ""


SCENARIOS: list[Scenario] = [
    # Negatives (must NOT flag)
    Scenario(
        "FP_clean",
        clean,
        expected_vulnerable=False,
        notes="benign backend, no anomalies",
    ),
    Scenario(
        "FP_slow_post_uniform",
        slow_post_uniform,
        expected_vulnerable=False,
        notes="all POSTs ~1.4s; method-matched baseline must suppress",
    ),
    Scenario(
        "FP_uniform_504",
        uniform_504,
        expected_vulnerable=False,
        notes="baseline majority 504; status signal must be suppressed",
    ),
    Scenario(
        "FP_noisy_baseline",
        noisy_baseline,
        expected_vulnerable=False,
        notes="one slow baseline GET; borderline POST must not flag",
    ),
    Scenario(
        "FP_heavy_post",
        heavy_post_uniform,
        expected_vulnerable=False,
        notes="all POSTs-with-body slow; control comparison must reject",
    ),
    # Positives (must flag)
    Scenario(
        "TP_clte_status",
        tp_clte_status,
        expected_vulnerable=True,
        required_signal_substrings=("status_504",),
        notes="TE-carrying requests return 504 — classic status signal",
    ),
    Scenario(
        "TP_clte_timing",
        tp_clte_timing,
        expected_vulnerable=True,
        required_signal_substrings=("timing_anomaly",),
        notes="TE-carrying requests are slow but other shapes fast",
    ),
    Scenario(
        "TP_followup_desync",
        tp_followup_desync,
        expected_vulnerable=True,
        required_signal_substrings=("followup_divergence",),
        notes="post-attack GETs diverge from baseline — second-request smuggling",
    ),
    Scenario(
        "TP_body_divergence",
        tp_body_divergence,
        expected_vulnerable=True,
        required_signal_substrings=("body_divergence_vs_control",),
        notes="TE response body diverges from control body despite timing match",
    ),
]


def bind_free_port() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(64)
    listener.settimeout(0.5)
    return listener, port


def serve_forever(listener: socket.socket, handler: ScenarioHandler, stop_event: threading.Event):
    counter = 0
    counter_lock = threading.Lock()

    def serve_one(conn: socket.socket, n: int):
        with closing(conn):
            try:
                conn.settimeout(5.0)
                buf = b""
                # Drain whatever the client sent (up to 16KB).
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) >= 16384:
                            break
                        if b"\r\n\r\n" in buf:
                            # Headers received; for our scenarios we don't
                            # need to honor any further body bytes.
                            break
                except (socket.timeout, ConnectionError):
                    pass
                handler(conn, buf, n)
            except Exception:
                # Swallow — scenarios should be best-effort, scanner must
                # tolerate broken backends.
                pass

    while not stop_event.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with counter_lock:
            counter += 1
            n = counter
        threading.Thread(target=serve_one, args=(conn, n), daemon=True).start()


def run_smugglex_against(port: int) -> dict:
    """Invoke smugglex with JSON output, return parsed dict."""
    cmd = [
        str(SMUGGLEX),
        "--quiet",
        "--format",
        "json",
        "--checks",
        "cl-te",
        "--timeout",
        "6",
        # Cap payload count: FP scenarios that get repeatedly FP-rejected via
        # control comparison would otherwise iterate through every TE variation
        # and blow the harness budget. 5 is enough to verify the rejection
        # behavior triggers on the canonical CL.TE shape.
        "--max-payloads",
        "5",
        f"http://127.0.0.1:{port}/",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        raise RuntimeError(f"no JSON in smugglex output:\nstdout={out!r}\nstderr={proc.stderr!r}")
    return json.loads(out[start:])


def evaluate_scenario(sc: Scenario) -> tuple[str, bool, list[str], str]:
    """Returns (verdict, actual_vulnerable, signals, summary_str)."""
    listener, port = bind_free_port()
    stop = threading.Event()
    t = threading.Thread(target=serve_forever, args=(listener, sc.handler, stop), daemon=True)
    t.start()
    try:
        result = run_smugglex_against(port)
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass

    checks = result.get("checks", [])
    any_vuln = any(c.get("vulnerable", False) for c in checks)
    signals: list[str] = []
    confidence = None
    for c in checks:
        if c.get("vulnerable"):
            signals.extend(c.get("detection_signals", []) or [])
            confidence = c.get("confidence")

    verdict = "PASS"
    missing_signals: list[str] = []
    if any_vuln != sc.expected_vulnerable:
        verdict = "FAIL"
    if any_vuln and sc.required_signal_substrings:
        for needle in sc.required_signal_substrings:
            if not any(needle in s for s in signals):
                missing_signals.append(needle)
        if missing_signals:
            verdict = "FAIL"

    summary_parts: list[str] = []
    if any_vuln:
        summary_parts.append(f"confidence={confidence}")
        summary_parts.append(f"signals={signals}")
    if missing_signals:
        summary_parts.append(f"missing_signals={missing_signals}")
    summary = " ".join(summary_parts)
    return verdict, any_vuln, signals, summary


def main() -> int:
    if not SMUGGLEX.exists():
        print(f"smugglex binary not found at {SMUGGLEX}", file=sys.stderr)
        print("Run: cargo build --release", file=sys.stderr)
        return 2

    print(f"{'Scenario':<26} {'Expected':<10} {'Actual':<10} {'Verdict':<7}  Detail")
    print("-" * 100)
    failures: list[str] = []
    for sc in SCENARIOS:
        try:
            verdict, actual, signals, summary = evaluate_scenario(sc)
        except Exception as e:
            verdict = "ERROR"
            actual = False
            signals = []
            summary = f"exception: {e}"
        marker = " " if verdict == "PASS" else "!"
        print(
            f"{marker} {sc.name:<24} {str(sc.expected_vulnerable):<10} {str(actual):<10} {verdict:<7}  {summary}"
        )
        if verdict != "PASS":
            failures.append(sc.name)

    print()
    if failures:
        print(f"{len(failures)} / {len(SCENARIOS)} scenario(s) failed: {', '.join(failures)}")
        return 1
    print(f"All {len(SCENARIOS)} scenarios passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
