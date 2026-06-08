# Local smuggling-lab validation harness for smugglex.
#
# Spins up a series of socket-level fake backends, each simulating a distinct
# scenario (real smuggling, benign-noisy backend, slow POST handler, etc.),
# invokes the smugglex binary against each, parses the JSON output, and reports
# whether the verdict matches expectations.
#
# Run from the repository root:
#     crystal run lab/validate.cr
#
# Exits non-zero if any scenario disagrees with its expected outcome.

require "socket"
require "json"
require "process"

REPO_ROOT = File.expand_path("..", __DIR__)
SMUGGLEX  = File.join(REPO_ROOT, "target", "release", "smugglex")

# Each scenario is given (conn_socket, request_bytes, request_count_int).
alias ScenarioHandler = Proc(TCPSocket, Bytes, Int32, Nil)

# ----------------------------- response helpers -----------------------------

def http_response(body : String, status : String = "200 OK", server : String = "test") : Bytes
  head = "HTTP/1.1 #{status}\r\n" \
         "Content-Length: #{body.bytesize}\r\n" \
         "Server: #{server}\r\n" \
         "Connection: close\r\n" \
         "\r\n"
  (head + body).to_slice
end

# Body sizes chosen to give the body-divergence heuristic clear signal:
# NORMAL_BODY is large (500 B), SMALL_ERROR_BODY is below MIN_BYTES (3 B),
# DESYNC_BODY is well over MIN_BYTES but far below NORMAL_BODY (80 B vs 500 B
# = 16% — clearly diverges per CONTROL_BODY_DIVERGENCE_PCT=75 rule).
NORMAL_BODY      = "X" * 500
SMALL_ERROR_BODY = "ERR"
DESYNC_BODY      = "D" * 80

# ----------------------------- request inspection ---------------------------

def request_starts_with?(req : Bytes, method : String) : Bool
  String.new(req).starts_with?(method)
end

def has_transfer_encoding?(req : Bytes) : Bool
  String.new(req).downcase.includes?("transfer-encoding")
end

def has_nonzero_content_length?(req : Bytes) : Bool
  String.new(req).each_line do |line|
    ls = line.lstrip.downcase
    if ls.starts_with?("content-length:")
      value = ls.split(':', 2)[1].strip
      return true if !value.empty? && value != "0"
    end
  end
  false
end

# --------------------------- scenario implementations -----------------------

# Always returns a normal fast response — nothing suspicious anywhere.
def clean(sock : TCPSocket, req : Bytes, n : Int32)
  sock.write(http_response(NORMAL_BODY))
end

# Every POST is slow (~1.4s). The method-matched POST baseline should
# lift the threshold so a POST attack at ~1.4s does NOT flag.
def slow_post_uniform(sock : TCPSocket, req : Bytes, n : Int32)
  sleep 1.4.seconds unless request_starts_with?(req, "GET")
  sock.write(http_response(NORMAL_BODY))
end

# Backend always returns 504. Baseline majority is 504 → status signal
# must be suppressed.
def uniform_504(sock : TCPSocket, req : Bytes, n : Int32)
  sock.write(http_response("Gateway timeout", status: "504 Gateway Timeout"))
end

# One slow baseline GET (1500ms) creates a high-variance baseline. A
# borderline 1200ms attack must NOT flag (noise-aware threshold + variance
# demotion).
def noisy_baseline(sock : TCPSocket, req : Bytes, n : Int32)
  if n == 1
    sleep 1.5.seconds
  elsif n > 3 && request_starts_with?(req, "POST")
    sleep 1.2.seconds
  end
  sock.write(http_response(NORMAL_BODY))
end

# POSTs with body are slow (mimicking expensive serverside processing for
# any non-empty body); CL:0 POSTs and GETs are fast. Attack with TE body and
# control with padded body both look slow — control comparison must reject.
def heavy_post_uniform(sock : TCPSocket, req : Bytes, n : Int32)
  body_present = has_transfer_encoding?(req) || has_nonzero_content_length?(req)
  sleep 2.0.seconds if body_present
  sock.write(http_response(NORMAL_BODY))
end

# ---- True-positive scenarios ----

# TE-carrying requests get 504; other shapes 200. Classic CL.TE
# status-code signal.
def tp_clte_status(sock : TCPSocket, req : Bytes, n : Int32)
  if has_transfer_encoding?(req)
    sock.write(http_response("Gateway timeout", status: "504 Gateway Timeout"))
  else
    sock.write(http_response(NORMAL_BODY))
  end
end

# TE-carrying requests are slow (2s); other shapes fast. Timing-only TE
# smuggling indicator that survives the method-matched POST baseline
# (because POST with CL:0 baseline is fast — only TE-carrying POSTs slow).
def tp_clte_timing(sock : TCPSocket, req : Bytes, n : Int32)
  sleep 2.0.seconds if has_transfer_encoding?(req)
  sock.write(http_response(NORMAL_BODY))
end

# TE attack AND control both return the same small error body slowly —
# body/header divergence escapes do NOT fire. Only the post-attack follow-up
# GETs return a divergent body relative to baseline, exercising the
# second-request smuggling signal in isolation.
#
# Request order with R8 method-matched POST baseline:
#   1..=3   GET baseline                 (NORMAL_BODY)
#   4..=6   POST CL:0 baseline           (NORMAL_BODY, fast)
#   7       attack (TE)                  (slow, SMALL_ERROR_BODY)
#   8..=10  3 confirmation retries (TE)  (slow, SMALL_ERROR_BODY)
#   11..=12 2 control samples (POST padded body, no TE)
#                                        (slow, SMALL_ERROR_BODY ← matches attack)
#   13..=15 3 follow-up GETs             (fast, DESYNC_BODY ← diverges from baseline)
def tp_followup_desync(sock : TCPSocket, req : Bytes, n : Int32)
  has_te = has_transfer_encoding?(req)
  has_body = has_te || has_nonzero_content_length?(req)
  is_followup = 13 <= n <= 15

  if has_body
    # Attack AND control both slow + identical small body so divergence
    # escapes via body/header are inert; only follow-up can save the finding.
    sleep 2.0.seconds
    sock.write(http_response(SMALL_ERROR_BODY))
    return
  end
  if is_followup
    sock.write(http_response(DESYNC_BODY))
    return
  end
  sock.write(http_response(NORMAL_BODY))
end

# TE attack: slow + small error body. Control (TE stripped, padded body):
# slow + normal body. Bodies diverge → escape clause keeps the finding even
# though timing similarity would otherwise reject.
def tp_body_divergence(sock : TCPSocket, req : Bytes, n : Int32)
  has_te = has_transfer_encoding?(req)
  has_body = has_te || has_nonzero_content_length?(req)
  sleep 2.0.seconds if has_body
  if has_te
    sock.write(http_response(SMALL_ERROR_BODY))
  else
    sock.write(http_response(NORMAL_BODY))
  end
end

# ---- Additional realistic FP scenarios ----

# A WAF in front of a healthy backend rejects any request carrying
# Transfer-Encoding with a small 403 body. Non-TE shapes pass through to
# the backend and return the normal substantial body. Status differs (200
# vs 403), body sizes differ — looks suspicious to a naive detector, but
# is not desync.
def fp_waf_blocks_te(sock : TCPSocket, req : Bytes, n : Int32)
  if has_transfer_encoding?(req)
    sock.write(http_response("Forbidden by WAF", status: "403 Forbidden"))
  else
    sock.write(http_response(NORMAL_BODY))
  end
end

# Backend with natural body-size jitter on every response (A/B testing,
# server-side rendering variation, multiple cache variants). No timing
# or status anomalies — only body size varies within ±4% of the
# canonical NORMAL_BODY length. Validates that the body-divergence and
# follow-up-divergence heuristics do not over-trigger on natural
# per-request body variability inside the similarity threshold.
def fp_natural_body_jitter(sock : TCPSocket, req : Bytes, n : Int32)
  # Deterministic jitter 480..520 B = within ~92% of 500 B (per
  # CONTROL_BODY_DIVERGENCE_PCT=75 rule, anything ≥ 75% similar is NOT
  # divergent). No timing/status anomalies — pure body variation.
  jitter = (n * 7919) % 41 # 0..40
  body = "X" * (480 + jitter)
  sock.write(http_response(body))
end

# Backend occasionally returns 504 (~5% of post-baseline requests) due
# to realistic upstream flakiness (e.g., periodic backend GC pauses,
# sparse upstream load spikes). The strict-majority confirmation rule +
# all-retries-required for status-only signals must suppress detection.
#
# NOTE: Pathologically high flake rates (≥20%) are a known limitation —
# they can still false-confirm with low probability when retry seeds
# align unfavorably. Distinguishing high-rate intermittent failures from
# real status-only smuggling would require statistical sampling across
# multiple payload variants, which conflicts with the exit-first design.
def fp_intermittent_504(sock : TCPSocket, req : Bytes, n : Int32)
  # Deterministic pseudo-random based on request number so the test is
  # reproducible. ~5% post-baseline failure rate — realistic for a
  # marginally-healthy backend, well below the false-confirmation
  # threshold (0.05^3 = 0.0125%).
  rng = Random.new((n.to_u64 &* 1000003_u64))
  is_failure = n > 3 && rng.rand < 0.05
  if is_failure
    sock.write(http_response("Gateway timeout", status: "504 Gateway Timeout"))
  else
    sock.write(http_response(NORMAL_BODY))
  end
end

# ---------------------------- harness --------------------------------------

# Substrings that MUST appear in detection_signals (each entry only needs to be
# a prefix/substring of some signal). Empty for non-vulnerable scenarios. Lets
# the harness validate not just the verdict but also that the *intended* signal
# pathway is what produced it.
record Scenario,
  name : String,
  handler : ScenarioHandler,
  expected_vulnerable : Bool,
  required_signal_substrings : Array(String) = [] of String,
  notes : String = ""

SCENARIOS = [
  # Negatives (must NOT flag)
  Scenario.new(
    "FP_clean",
    ->clean(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "benign backend, no anomalies",
  ),
  Scenario.new(
    "FP_slow_post_uniform",
    ->slow_post_uniform(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "all POSTs ~1.4s; method-matched baseline must suppress",
  ),
  Scenario.new(
    "FP_uniform_504",
    ->uniform_504(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "baseline majority 504; status signal must be suppressed",
  ),
  Scenario.new(
    "FP_noisy_baseline",
    ->noisy_baseline(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "one slow baseline GET; borderline POST must not flag",
  ),
  Scenario.new(
    "FP_heavy_post",
    ->heavy_post_uniform(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "all POSTs-with-body slow; control comparison + R10 early termination",
  ),
  Scenario.new(
    "FP_waf_blocks_te",
    ->fp_waf_blocks_te(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "WAF returns 403 on TE shapes; not smuggling — should not flag",
  ),
  Scenario.new(
    "FP_natural_body_jitter",
    ->fp_natural_body_jitter(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "natural body-size variation within similarity threshold; no anomalies",
  ),
  Scenario.new(
    "FP_intermittent_504",
    ->fp_intermittent_504(TCPSocket, Bytes, Int32),
    expected_vulnerable: false,
    notes: "~5% transient 504s; strict-majority confirmation must suppress",
  ),
  # Positives (must flag)
  Scenario.new(
    "TP_clte_status",
    ->tp_clte_status(TCPSocket, Bytes, Int32),
    expected_vulnerable: true,
    required_signal_substrings: ["status_504"],
    notes: "TE-carrying requests return 504 — classic status signal",
  ),
  Scenario.new(
    "TP_clte_timing",
    ->tp_clte_timing(TCPSocket, Bytes, Int32),
    expected_vulnerable: true,
    required_signal_substrings: ["timing_anomaly"],
    notes: "TE-carrying requests are slow but other shapes fast",
  ),
  Scenario.new(
    "TP_followup_desync",
    ->tp_followup_desync(TCPSocket, Bytes, Int32),
    expected_vulnerable: true,
    required_signal_substrings: ["followup_divergence"],
    notes: "post-attack GETs diverge from baseline — second-request smuggling",
  ),
  Scenario.new(
    "TP_body_divergence",
    ->tp_body_divergence(TCPSocket, Bytes, Int32),
    expected_vulnerable: true,
    required_signal_substrings: ["body_divergence_vs_control"],
    notes: "TE response body diverges from control body despite timing match",
  ),
]

def serve_one(conn : TCPSocket, n : Int32, handler : ScenarioHandler)
  conn.read_timeout = 5.seconds
  buf = IO::Memory.new
  tmp = Bytes.new(4096)
  # Drain whatever the client sent (up to 16KB), stopping once the request
  # headers are complete — our scenarios never need the body bytes.
  loop do
    read = begin
      conn.read(tmp)
    rescue
      break
    end
    break if read == 0
    buf.write(tmp[0, read])
    break if buf.bytesize >= 16384
    break if buf.to_s.includes?("\r\n\r\n")
  end
  handler.call(conn, buf.to_slice, n)
rescue
  # Swallow — scenarios should be best-effort, scanner must tolerate broken
  # backends.
ensure
  conn.close rescue nil
end

def serve_forever(server : TCPServer, handler : ScenarioHandler)
  counter = 0
  loop do
    conn = begin
      server.accept?
    rescue
      break
    end
    break if conn.nil?
    counter += 1
    n = counter
    spawn serve_one(conn, n, handler)
  end
end

# Invoke smugglex with JSON output and return the flattened list of checks.
def run_smugglex_against(port : Int32) : Array(JSON::Any)
  args = [
    "--quiet",
    "--format", "json",
    "--checks", "cl-te",
    "--timeout", "6",
    "http://127.0.0.1:#{port}/",
  ]
  # No --max-payloads cap: with R10 consecutive-FP early termination, FP
  # scenarios that previously needed the cap should now self-abort.
  stdout = IO::Memory.new
  stderr = IO::Memory.new
  process = Process.new(SMUGGLEX, args, output: stdout, error: stderr)

  done = Channel(Nil).new(1)
  spawn do
    process.wait
    done.send(nil)
  end
  timed_out = Channel(Nil).new(1)
  spawn do
    sleep 180.seconds
    timed_out.send(nil)
  end

  select
  when done.receive
    # finished within the time limit
  when timed_out.receive
    process.terminate(graceful: false) rescue nil
    done.receive # reap the wait fiber
  end

  stdout_str = stdout.to_s
  start = stdout_str.index('{')
  raise "no JSON in smugglex output:\nstdout=#{stdout_str.inspect}\nstderr=#{stderr.to_s.inspect}" unless start

  raw = JSON.parse(stdout_str[start..])
  checks = [] of JSON::Any
  # smugglex emits a batch envelope: {results: [{checks: [...]}], summary}.
  # Flatten every target's checks. Fall back to a bare ScanResults if the
  # format changes.
  if results = raw["results"]?
    results.as_a.each do |r|
      if cks = r["checks"]?
        cks.as_a.each { |c| checks << c }
      end
    end
  elsif cks = raw["checks"]?
    cks.as_a.each { |c| checks << c }
  end
  checks
end

record Evaluation,
  verdict : String,
  actual_vulnerable : Bool,
  signals : Array(String),
  summary : String

def evaluate_scenario(sc : Scenario) : Evaluation
  server = TCPServer.new("127.0.0.1", 0)
  port = server.local_address.port
  spawn serve_forever(server, sc.handler)
  begin
    checks = run_smugglex_against(port)
  ensure
    server.close rescue nil
  end

  any_vuln = checks.any? { |c| c["vulnerable"]?.try(&.as_bool?) == true }
  signals = [] of String
  confidence : String? = nil
  checks.each do |c|
    next unless c["vulnerable"]?.try(&.as_bool?) == true
    if sigs = c["detection_signals"]?
      sigs.as_a.each { |s| signals << s.as_s }
    end
    if conf = c["confidence"]?
      confidence = conf.as_s? || conf.to_s
    end
  end

  verdict = "PASS"
  missing_signals = [] of String
  verdict = "FAIL" if any_vuln != sc.expected_vulnerable
  if any_vuln && !sc.required_signal_substrings.empty?
    sc.required_signal_substrings.each do |needle|
      missing_signals << needle unless signals.any?(&.includes?(needle))
    end
    verdict = "FAIL" unless missing_signals.empty?
  end

  summary_parts = [] of String
  if any_vuln
    summary_parts << "confidence=#{confidence}"
    summary_parts << "signals=#{signals}"
  end
  summary_parts << "missing_signals=#{missing_signals}" unless missing_signals.empty?
  Evaluation.new(verdict, any_vuln, signals, summary_parts.join(" "))
end

def main : Int32
  unless File.exists?(SMUGGLEX)
    STDERR.puts "smugglex binary not found at #{SMUGGLEX}"
    STDERR.puts "Run: cargo build --release"
    return 2
  end

  puts "#{"Scenario".ljust(26)} #{"Expected".ljust(10)} #{"Actual".ljust(10)} #{"Verdict".ljust(7)}  Detail"
  puts "-" * 100
  failures = [] of String
  SCENARIOS.each do |sc|
    eval = begin
      evaluate_scenario(sc)
    rescue ex
      Evaluation.new("ERROR", false, [] of String, "exception: #{ex.message}")
    end
    marker = eval.verdict == "PASS" ? " " : "!"
    puts "#{marker} #{sc.name.ljust(24)} #{sc.expected_vulnerable.to_s.ljust(10)} " \
         "#{eval.actual_vulnerable.to_s.ljust(10)} #{eval.verdict.ljust(7)}  #{eval.summary}"
    failures << sc.name if eval.verdict != "PASS"
  end

  puts
  if failures.empty?
    puts "All #{SCENARIOS.size} scenarios passed."
    0
  else
    puts "#{failures.size} / #{SCENARIOS.size} scenario(s) failed: #{failures.join(", ")}"
    1
  end
end

exit(main)
