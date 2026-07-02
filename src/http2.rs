//! Minimal offensive HTTP/2 client for detecting HTTP/2 -> HTTP/1.1 downgrade
//! request smuggling (H2.CL / H2.TE).
//!
//! The HTTP/1.1 scanner in [`crate::http`] cannot reach these vulnerabilities:
//! they live in how an HTTP/2 front-end rewrites a request for an HTTP/1.1
//! back-end. Detecting them requires *speaking real HTTP/2* — ALPN `h2`, the
//! connection preface, SETTINGS, and an HPACK-encoded HEADERS frame — while
//! being free to send a deliberately malformed message (a `content-length` /
//! `transfer-encoding` that disagrees with the actual DATA) that a compliant
//! HTTP/2 library would refuse to emit.
//!
//! Detection is differential and timing-based, mirroring the HTTP/1.1 scanner:
//! a well-formed baseline request answers promptly; the malformed attack makes
//! the downgraded back-end wait for body bytes that never arrive, so the stream
//! stalls until the timeout. A well-formed control request rules out a backend
//! that is simply slow for this shape.

use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::Result;
use crate::model::{CheckResult, Confidence};

/// HTTP/2 client connection preface (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame type codes.
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_GOAWAY: u8 = 0x7;

// Frame flags.
const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Number of attack confirmation retries that must also stall.
const H2_CONFIRMATION_RETRIES: usize = 2;

// ----------------------------- HPACK encoding ------------------------------

/// Encode an HPACK integer (RFC 7541 §5.1) into `out`. `prefix` carries the
/// pattern bits above the `n`-bit prefix; the low `n` bits hold the value.
fn hpack_int(out: &mut Vec<u8>, prefix: u8, n: u32, value: usize) {
    let max = (1usize << n) - 1;
    if value < max {
        out.push(prefix | value as u8);
    } else {
        out.push(prefix | max as u8);
        let mut rest = value - max;
        while rest >= 128 {
            out.push(((rest & 0x7f) | 0x80) as u8);
            rest >>= 7;
        }
        out.push(rest as u8);
    }
}

/// Encode an HPACK string literal (no Huffman) into `out`.
fn hpack_string(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, 0x00, 7, s.len()); // H=0
    out.extend_from_slice(s);
}

/// A single header to encode, expressed in whichever HPACK form fits.
enum HField<'a> {
    /// Fully indexed static-table entry (e.g. `:method GET`).
    Indexed(usize),
    /// Literal value with a static-table *name* index (e.g. `content-length`).
    NamedValue(usize, &'a [u8]),
    /// Literal with a brand-new name (arbitrary header).
    NewName(&'a [u8], &'a [u8]),
}

fn encode_field(out: &mut Vec<u8>, field: &HField) {
    match field {
        HField::Indexed(i) => hpack_int(out, 0x80, 7, *i),
        HField::NamedValue(i, v) => {
            // Literal Header Field with Incremental Indexing — Indexed Name.
            hpack_int(out, 0x40, 6, *i);
            hpack_string(out, v);
        }
        HField::NewName(name, v) => {
            out.push(0x40); // incremental indexing, new name (index 0)
            hpack_string(out, name);
            hpack_string(out, v);
        }
    }
}

/// Describes the request smugglex sends over HTTP/2, including malformed shapes.
struct H2Request<'a> {
    /// `:method` value.
    method: &'a str,
    /// `:authority` value (the Host).
    authority: &'a str,
    /// `:path` value.
    path: &'a str,
    /// Extra regular headers (name, value). Values may contain bytes a
    /// compliant H2 stack would reject — that is the point.
    extra: Vec<(&'a str, &'a str)>,
    /// Optional `content-length` header value, sent verbatim even when it lies
    /// about the body.
    content_length: Option<&'a str>,
    /// Body bytes sent in a DATA frame (empty = no DATA frame).
    body: &'a [u8],
}

impl H2Request<'_> {
    fn header_block(&self) -> Vec<u8> {
        let mut b = Vec::new();
        // Pseudo-headers first.
        match self.method {
            "GET" => encode_field(&mut b, &HField::Indexed(2)),
            "POST" => encode_field(&mut b, &HField::Indexed(3)),
            m => encode_field(&mut b, &HField::NamedValue(2, m.as_bytes())),
        }
        encode_field(&mut b, &HField::Indexed(7)); // :scheme https
        if self.path == "/" {
            encode_field(&mut b, &HField::Indexed(4));
        } else {
            encode_field(&mut b, &HField::NamedValue(4, self.path.as_bytes()));
        }
        encode_field(&mut b, &HField::NamedValue(1, self.authority.as_bytes())); // :authority
        if let Some(cl) = self.content_length {
            encode_field(&mut b, &HField::NamedValue(28, cl.as_bytes())); // content-length
        }
        for (name, value) in &self.extra {
            encode_field(&mut b, &HField::NewName(name.as_bytes(), value.as_bytes()));
        }
        b
    }
}

// ----------------------------- frame I/O -----------------------------------

fn put_frame(out: &mut Vec<u8>, ftype: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len();
    // The frame length field is 24 bits. All payloads smugglex emits are tiny
    // (a small HPACK header block or a few-byte DATA body), so exceeding this
    // would be a bug — guard it rather than silently truncating into a corrupt
    // frame that desyncs the whole outbound stream.
    debug_assert!(
        len <= 0xFF_FFFF,
        "HTTP/2 frame payload ({len} bytes) exceeds the 24-bit length field"
    );
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Outcome of one HTTP/2 probe.
struct H2Outcome {
    /// A response HEADERS frame arrived for our stream.
    responded: bool,
    /// Decoded `:status`, if it was a simple static-table reference.
    status: Option<u16>,
    /// The peer reset our stream or closed the connection (a fast rejection,
    /// distinct from a stall).
    reset: bool,
    duration: Duration,
}

/// Map a fully-indexed `:status` HPACK byte to its code (static table 8..14).
fn status_from_indexed(byte: u8) -> Option<u16> {
    match byte {
        0x88 => Some(200),
        0x89 => Some(204),
        0x8a => Some(206),
        0x8b => Some(304),
        0x8c => Some(400),
        0x8d => Some(404),
        0x8e => Some(500),
        _ => None,
    }
}

async fn h2_connect(host: &str, port: u16) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = TlsConnector::from(std::sync::Arc::clone(crate::http::get_h2_tls_config()));
    let tcp = TcpStream::connect((host, port)).await?;
    let dnsname = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tls = connector.connect(dnsname, tcp).await?;
    Ok(tls)
}

/// Send one HTTP/2 request on a fresh connection and observe the response (or
/// stall). `end_stream_on_headers` controls whether END_STREAM rides the
/// HEADERS frame (the H2.CL/H2.TE attack: a declared body that is never sent)
/// or a DATA frame closes the stream (a well-formed request).
async fn h2_probe(
    host: &str,
    port: u16,
    req: &H2Request<'_>,
    end_stream_on_headers: bool,
    timeout: Duration,
) -> H2Outcome {
    let start = Instant::now();
    let result = tokio::time::timeout(timeout, async {
        let mut stream = h2_connect(host, port).await?;

        let mut out = Vec::new();
        out.extend_from_slice(PREFACE);
        put_frame(&mut out, FRAME_SETTINGS, 0, 0, &[]);
        let hb = req.header_block();
        let mut hflags = FLAG_END_HEADERS;
        if end_stream_on_headers {
            hflags |= FLAG_END_STREAM;
        }
        put_frame(&mut out, FRAME_HEADERS, hflags, 1, &hb);
        if !end_stream_on_headers {
            put_frame(&mut out, FRAME_DATA, FLAG_END_STREAM, 1, req.body);
        }
        stream.write_all(&out).await?;

        read_response(&mut stream).await
    })
    .await;

    match result {
        Ok(Ok(outcome)) => H2Outcome {
            duration: start.elapsed(),
            ..outcome
        },
        // Connection/IO error: treat as a fast reset, not a stall.
        Ok(Err(_)) => H2Outcome {
            responded: false,
            status: None,
            reset: true,
            duration: start.elapsed(),
        },
        // Timed out: the stream stalled — the smuggling signal.
        Err(_) => H2Outcome {
            responded: false,
            status: None,
            reset: false,
            duration: start.elapsed(),
        },
    }
}

/// A single declared frame larger than this is treated as a hostile/garbled
/// peer and rejected, instead of letting the accumulation buffer grow toward
/// the 16 MiB the 24-bit length field allows. A real response HEADERS frame is
/// tiny; 1 MiB is a generous ceiling.
const MAX_FRAME_BYTES: usize = 1 << 20;

/// Outcome of scanning the accumulation buffer for a decisive frame.
enum FrameScan {
    /// A terminal frame (response HEADERS / RST / GOAWAY, or an oversized frame)
    /// decided the outcome. `send_settings_ack` is true if a non-ACK server
    /// SETTINGS frame was seen first and still needs acknowledging.
    Outcome {
        outcome: H2Outcome,
        send_settings_ack: bool,
    },
    /// No terminal frame yet; `consumed` leading bytes were fully parsed and can
    /// be drained. `send_settings_ack` flags an owed SETTINGS ACK.
    NeedMore {
        consumed: usize,
        send_settings_ack: bool,
    },
}

/// Pure frame-boundary scan over the accumulation buffer. Reads the 24-bit
/// length, type, flags and stream id of each fully-buffered frame and decides
/// the probe outcome. Bounds are fully checked (`acc.len() >= i + 9` before
/// reading a header, `acc.len() >= i + 9 + flen` before slicing the payload),
/// so a hostile length field can never index out of bounds; an oversized
/// declared length is rejected via [`MAX_FRAME_BYTES`].
fn scan_frames(acc: &[u8]) -> FrameScan {
    let terminal = |responded: bool, status: Option<u16>, reset: bool| H2Outcome {
        responded,
        status,
        reset,
        duration: Duration::ZERO,
    };
    let mut i = 0;
    let mut send_settings_ack = false;
    while acc.len() >= i + 9 {
        let flen = ((acc[i] as usize) << 16) | ((acc[i + 1] as usize) << 8) | acc[i + 2] as usize;
        let ftype = acc[i + 3];
        let flags = acc[i + 4];
        let stream_id = u32::from_be_bytes([acc[i + 5] & 0x7f, acc[i + 6], acc[i + 7], acc[i + 8]]);
        if flen > MAX_FRAME_BYTES {
            return FrameScan::Outcome {
                outcome: terminal(false, None, true),
                send_settings_ack,
            };
        }
        if acc.len() < i + 9 + flen {
            break; // frame body not fully received yet
        }
        let payload = &acc[i + 9..i + 9 + flen];

        if ftype == FRAME_SETTINGS && flags & FLAG_ACK == 0 {
            send_settings_ack = true;
        } else if ftype == FRAME_HEADERS && stream_id == 1 {
            let status = payload.first().copied().and_then(status_from_indexed);
            return FrameScan::Outcome {
                outcome: terminal(true, status, false),
                send_settings_ack,
            };
        } else if (ftype == FRAME_RST_STREAM && stream_id == 1) || ftype == FRAME_GOAWAY {
            return FrameScan::Outcome {
                outcome: terminal(false, None, true),
                send_settings_ack,
            };
        }
        i += 9 + flen;
    }
    FrameScan::NeedMore {
        consumed: i,
        send_settings_ack,
    }
}

/// Read frames until a response HEADERS for our stream arrives, or the peer
/// resets/closes. ACKs the server SETTINGS so the connection stays live.
async fn read_response<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<H2Outcome> {
    let mut buf = vec![0u8; 16384];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(H2Outcome {
                responded: false,
                status: None,
                reset: true,
                duration: Duration::ZERO,
            });
        }
        acc.extend_from_slice(&buf[..n]);

        match scan_frames(&acc) {
            FrameScan::Outcome {
                outcome,
                send_settings_ack,
            } => {
                if send_settings_ack {
                    let mut ack = Vec::new();
                    put_frame(&mut ack, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                    stream.write_all(&ack).await?;
                }
                return Ok(outcome);
            }
            FrameScan::NeedMore {
                consumed,
                send_settings_ack,
            } => {
                if send_settings_ack {
                    let mut ack = Vec::new();
                    put_frame(&mut ack, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                    stream.write_all(&ack).await?;
                }
                acc.drain(0..consumed);
            }
        }
    }
}

// ----------------------------- detection -----------------------------------

/// True when a probe stalled (no response and not a fast reset) for at least
/// 80% of the timeout — i.e. the stream hung rather than being rejected.
fn stalled(o: &H2Outcome, timeout: Duration) -> bool {
    !o.responded && !o.reset && o.duration.as_millis() * 100 >= timeout.as_millis() * 80
}

/// Run the real-HTTP/2 downgrade smuggling check (H2.CL / H2.TE) and return a
/// [`CheckResult`]. Requires TLS (ALPN `h2`).
pub async fn run_h2_downgrade_check(
    host: &str,
    port: u16,
    authority: &str,
    path: &str,
    timeout: u64,
    verbose: bool,
) -> CheckResult {
    let check_name = "h2-downgrade";
    let dur = Duration::from_secs(timeout);
    let not_vulnerable =
        |normal_status: String, normal_ms: u64, diagnostics: Vec<String>| CheckResult {
            check_type: check_name.to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status,
            attack_status: None,
            normal_duration_ms: normal_ms,
            attack_duration_ms: None,
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
            confidence: None,
            detection_signals: Vec::new(),
            diagnostics,
        };

    // Baseline: a well-formed GET must answer promptly, establishing both that
    // we can speak HTTP/2 here and a reference latency.
    let baseline = H2Request {
        method: "GET",
        authority,
        path,
        extra: Vec::new(),
        content_length: None,
        body: b"",
    };
    let base = h2_probe(host, port, &baseline, true, dur).await;
    if !base.responded {
        return not_vulnerable(
            "no h2 response".to_string(),
            base.duration.as_millis() as u64,
            vec!["h2_baseline_no_response".to_string()],
        );
    }
    let base_ms = base.duration.as_millis();
    let normal_status = base
        .status
        .map(|s| format!("HTTP/2 {}", s))
        .unwrap_or_else(|| "HTTP/2 (ok)".to_string());

    // A well-formed POST whose content-length matches its DATA. If even this
    // stalls, the backend is just slow for POSTs and any finding is rejected.
    let control = H2Request {
        method: "POST",
        authority,
        path,
        extra: Vec::new(),
        content_length: Some("5"),
        body: b"hello",
    };

    // Malformed attack shapes: each declares a body it never sends, so a
    // vulnerable downgrade leaves the HTTP/1.1 backend waiting forever.
    let shapes: [(&str, &str, H2Request); 2] = [
        (
            "h2.cl",
            "content-length: 50",
            H2Request {
                method: "POST",
                authority,
                path,
                extra: Vec::new(),
                content_length: Some("50"),
                body: b"",
            },
        ),
        (
            "h2.te",
            "transfer-encoding: chunked",
            H2Request {
                method: "POST",
                authority,
                path,
                extra: vec![("transfer-encoding", "chunked")],
                content_length: None,
                body: b"",
            },
        ),
    ];

    for (name, desc, attack_req) in &shapes {
        let attack = h2_probe(host, port, attack_req, true, dur).await;
        if !stalled(&attack, dur) {
            continue; // responded or fast-rejected -> not this vector
        }

        let control_out = h2_probe(host, port, &control, false, dur).await;
        if stalled(&control_out, dur) {
            if verbose {
                println!(
                    "  [*] {} {} control also stalled — backend slow for POST shape, rejecting",
                    check_name, name
                );
            }
            continue;
        }

        // Require ALL confirmation retries to reproduce the stall (strict;
        // transient hangs should not confirm a finding).
        let mut all_stalled = true;
        for _ in 0..H2_CONFIRMATION_RETRIES {
            if !stalled(&h2_probe(host, port, attack_req, true, dur).await, dur) {
                all_stalled = false;
                break;
            }
        }
        if !all_stalled {
            continue;
        }

        let signals = vec![
            format!("{}_stall", name.replace('.', "_")),
            "h2_downgrade_desync".to_string(),
            "control_responds_fast".to_string(),
            format!(
                "timing_anomaly:{:.1}x",
                attack.duration.as_millis() as f64 / base_ms.max(1) as f64
            ),
        ];
        let payload = format!(
            "HTTP/2 {} smuggling: :method POST :authority {} :path {} {} (declared body never sent, END_STREAM on HEADERS)",
            name, authority, path, desc,
        );
        return CheckResult {
            check_type: check_name.to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status,
            attack_status: Some("stream stalled (no response)".to_string()),
            normal_duration_ms: base_ms as u64,
            attack_duration_ms: Some(attack.duration.as_millis() as u64),
            timestamp: Utc::now().to_rfc3339(),
            payload: Some(payload),
            confidence: Some(Confidence::High),
            detection_signals: signals,
            diagnostics: Vec::new(),
        };
    }

    not_vulnerable(normal_status, base_ms as u64, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &'static str, cl: Option<&'static str>) -> H2Request<'static> {
        H2Request {
            method,
            authority: "h.test",
            path: "/",
            extra: Vec::new(),
            content_length: cl,
            body: b"",
        }
    }

    #[test]
    fn hpack_int_small_fits_prefix() {
        let mut out = Vec::new();
        hpack_int(&mut out, 0x80, 7, 2); // :method GET static index
        assert_eq!(out, vec![0x82]);
    }

    #[test]
    fn hpack_int_boundary_uses_continuation() {
        // value == max for a 6-bit prefix (63) must spill into continuation.
        let mut out = Vec::new();
        hpack_int(&mut out, 0x40, 6, 63);
        assert_eq!(out, vec![0x7f, 0x00]);
    }

    #[test]
    fn hpack_int_large_value() {
        // RFC 7541 example: encoding 1337 with a 5-bit prefix -> 31, 154, 10.
        let mut out = Vec::new();
        hpack_int(&mut out, 0x00, 5, 1337);
        assert_eq!(out, vec![31, 154, 10]);
    }

    #[test]
    fn hpack_string_no_huffman() {
        let mut out = Vec::new();
        hpack_string(&mut out, b"ab");
        assert_eq!(out, vec![0x02, b'a', b'b']);
    }

    #[test]
    fn header_block_get_root() {
        let b = req("GET", None).header_block();
        // :method GET, :scheme https, :path /, :authority literal(name idx 1)
        assert_eq!(b[0], 0x82);
        assert_eq!(b[1], 0x87);
        assert_eq!(b[2], 0x84);
        assert_eq!(b[3], 0x41);
        assert_eq!(b[4], 6); // len("h.test")
        assert_eq!(&b[5..11], b"h.test");
    }

    #[test]
    fn header_block_content_length_named_value() {
        let b = req("POST", Some("50")).header_block();
        // contains content-length literal (name idx 28 -> 0x5c) then "50"
        let pos = b.iter().position(|&x| x == 0x5c).unwrap();
        assert_eq!(b[pos + 1], 2); // len("50")
        assert_eq!(&b[pos + 2..pos + 4], b"50");
    }

    #[test]
    fn header_block_new_name_for_transfer_encoding() {
        let r = H2Request {
            method: "POST",
            authority: "h.test",
            path: "/",
            extra: vec![("transfer-encoding", "chunked")],
            content_length: None,
            body: b"",
        };
        let b = r.header_block();
        // 0x40 (new name) somewhere, followed by len + "transfer-encoding".
        let pos = b.iter().position(|&x| x == 0x40).unwrap();
        assert_eq!(b[pos + 1], 17); // len("transfer-encoding")
        assert_eq!(&b[pos + 2..pos + 19], b"transfer-encoding");
    }

    #[test]
    fn status_decode_static() {
        assert_eq!(status_from_indexed(0x88), Some(200));
        assert_eq!(status_from_indexed(0x8d), Some(404));
        assert_eq!(status_from_indexed(0x12), None);
    }

    #[test]
    fn frame_header_layout() {
        let mut out = Vec::new();
        put_frame(
            &mut out,
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            b"xy",
        );
        assert_eq!(&out[0..3], &[0, 0, 2]); // length
        assert_eq!(out[3], FRAME_HEADERS);
        assert_eq!(out[4], 0x5);
        assert_eq!(&out[5..9], &[0, 0, 0, 1]); // stream 1
        assert_eq!(&out[9..11], b"xy");
    }

    #[test]
    fn stalled_requires_near_timeout() {
        let to = Duration::from_secs(10);
        let hang = H2Outcome {
            responded: false,
            status: None,
            reset: false,
            duration: Duration::from_secs(9),
        };
        assert!(stalled(&hang, to));
        let fast_reset = H2Outcome {
            responded: false,
            status: None,
            reset: true,
            duration: Duration::from_millis(50),
        };
        assert!(!stalled(&fast_reset, to));
        let ok = H2Outcome {
            responded: true,
            status: Some(200),
            reset: false,
            duration: Duration::from_millis(200),
        };
        assert!(!stalled(&ok, to));
    }

    #[test]
    fn scan_frames_decodes_headers_status() {
        let mut acc = Vec::new();
        put_frame(&mut acc, FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]); // :status 200
        match scan_frames(&acc) {
            FrameScan::Outcome { outcome, .. } => {
                assert!(outcome.responded);
                assert_eq!(outcome.status, Some(200));
            }
            _ => panic!("expected a terminal HEADERS outcome"),
        }
    }

    #[test]
    fn scan_frames_acks_settings_before_headers() {
        let mut acc = Vec::new();
        put_frame(&mut acc, FRAME_SETTINGS, 0, 0, &[]); // server SETTINGS (needs ACK)
        put_frame(&mut acc, FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]);
        match scan_frames(&acc) {
            FrameScan::Outcome {
                outcome,
                send_settings_ack,
            } => {
                assert!(outcome.responded);
                assert!(send_settings_ack, "non-ACK SETTINGS must be acknowledged");
            }
            _ => panic!("expected a terminal outcome"),
        }
    }

    #[test]
    fn scan_frames_maps_rst_and_goaway_to_reset() {
        let mut rst = Vec::new();
        put_frame(&mut rst, FRAME_RST_STREAM, 0, 1, &[0, 0, 0, 0]);
        match scan_frames(&rst) {
            FrameScan::Outcome { outcome, .. } => assert!(outcome.reset && !outcome.responded),
            _ => panic!("RST_STREAM(1) should be terminal"),
        }
        let mut goaway = Vec::new();
        put_frame(&mut goaway, FRAME_GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        match scan_frames(&goaway) {
            FrameScan::Outcome { outcome, .. } => assert!(outcome.reset),
            _ => panic!("GOAWAY should be terminal"),
        }
    }

    #[test]
    fn scan_frames_needs_more_on_partial_frame() {
        // A 9-byte header declaring a 10-byte payload with no body yet.
        let acc = vec![0, 0, 10, FRAME_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1];
        match scan_frames(&acc) {
            FrameScan::NeedMore { consumed, .. } => assert_eq!(consumed, 0),
            _ => panic!("a partial frame should request more bytes"),
        }
    }

    #[test]
    fn scan_frames_rejects_oversized_frame_without_buffering() {
        // 0xFFFFFF (16 MiB) exceeds MAX_FRAME_BYTES: reject fast, never slice.
        let acc = vec![0xFF, 0xFF, 0xFF, FRAME_HEADERS, 0, 0, 0, 0, 1];
        match scan_frames(&acc) {
            FrameScan::Outcome { outcome, .. } => assert!(outcome.reset),
            _ => panic!("an oversized declared frame must be rejected"),
        }
    }

    #[test]
    fn scan_frames_drains_settings_then_awaits_partial_headers() {
        let mut acc = Vec::new();
        put_frame(&mut acc, FRAME_SETTINGS, 0, 0, &[]); // 9 bytes, fully present
        acc.extend_from_slice(&[0, 0, 10, FRAME_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1]); // partial
        match scan_frames(&acc) {
            FrameScan::NeedMore {
                consumed,
                send_settings_ack,
            } => {
                assert_eq!(consumed, 9, "the complete SETTINGS frame should be drained");
                assert!(send_settings_ack);
            }
            _ => panic!("expected NeedMore after the complete SETTINGS frame"),
        }
    }

    #[tokio::test]
    async fn read_response_decodes_headers_over_duplex() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let mut frames = Vec::new();
        put_frame(&mut frames, FRAME_SETTINGS, 0, 0, &[]);
        put_frame(&mut frames, FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]);
        server.write_all(&frames).await.unwrap();
        let outcome = read_response(&mut client).await.unwrap();
        assert!(outcome.responded);
        assert_eq!(outcome.status, Some(200));
    }

    #[tokio::test]
    async fn read_response_reset_on_eof() {
        let (server, mut client) = tokio::io::duplex(64);
        drop(server); // closing the peer makes the next read return 0 (EOF)
        let outcome = read_response(&mut client).await.unwrap();
        assert!(!outcome.responded);
        assert!(outcome.reset);
    }
}
