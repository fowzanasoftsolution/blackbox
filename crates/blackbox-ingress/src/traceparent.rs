//! W3C Trace Context (`traceparent`) handling — Engine 1's correlation
//! backbone.
//!
//! Every request entering the proxy either arrives with a valid
//! `traceparent` (passed through unchanged) or gets one generated:
//!
//! ```text
//! traceparent: 00-<32 hex trace-id>-<16 hex parent-span-id>-01
//! ```
//!
//! The 128-bit trace id doubles as blackbox's global [`TraceId`] — the same
//! value indexes `TraceRecord`s on disk, OTLP logs/spans and Sentry crash
//! envelopes, so one id stitches an entire incident together. The response
//! always carries `x-blackbox-trace-id` so callers can quote it in bug
//! reports.

use blackbox_core::schema::{parse_trace_hex, trace_id_to_hex, TraceId};

/// Response header echoing the trace id back to the caller.
pub const TRACE_ID_RESPONSE_HEADER: &str = "x-blackbox-trace-id";
/// Request header per the W3C Trace Context spec.
pub const TRACEPARENT_HEADER: &str = "traceparent";
/// Sentry's proprietary trace header — the official sentry-sdk (all
/// languages) continues a trace from this header when it arrives on an
/// inbound request, so injecting it upstream is what makes a REAL SDK's
/// crash envelope land on blackbox's trace instead of a random one.
pub const SENTRY_TRACE_HEADER: &str = "sentry-trace";
/// W3C Baggage header — the shared propagation bus the Sentry dynamic
/// sampling context rides on. @sentry/node v8+ joins and propagates traces
/// through it (alongside `sentry-trace`), and sentry-sdk (Python) carries
/// the same `sentry-*` entries, so injecting ours upstream is what makes
/// the EXACT same trace id survive async boundaries in the Node world too.
pub const BAGGAGE_HEADER: &str = "baggage";

/// A validated W3C traceparent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traceparent {
    pub version: [u8; 2],
    pub trace_id: TraceId,
    pub parent_span_id: [u8; 8],
    pub flags: [u8; 2],
}

impl Traceparent {
    /// Generate a fresh `00-<tid>-<span>-01` with random ids.
    pub fn generate() -> Self {
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        fastrand::fill(&mut trace_id);
        fastrand::fill(&mut span_id);
        // Spec: ids of all zeroes are invalid.
        if trace_id == [0u8; 16] {
            trace_id[0] = 1;
        }
        if span_id == [0u8; 8] {
            span_id[0] = 1;
        }
        Traceparent {
            version: *b"00",
            trace_id,
            parent_span_id: span_id,
            flags: *b"01",
        }
    }

    /// Parse a `traceparent` header value per the W3C ABNF (version `00`
    /// and `0x` future versions accepted; `ff` is forbidden).
    pub fn parse(value: &str) -> Option<Self> {
        let v = value.trim();
        let parts: Vec<&str> = v.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let (ver, tid, sid, flags) = (parts[0], parts[1], parts[2], parts[3]);
        if ver.len() != 2 || sid.len() != 16 || flags.len() != 2 {
            return None;
        }
        let ver_bytes = hex2(ver.as_bytes())?;
        // Version 0xFF is forbidden by the spec.
        if ver_bytes[0] == 0xF && ver_bytes[1] == 0xF {
            return None;
        }
        let trace_id = parse_trace_hex(tid)?;
        if trace_id == [0u8; 16] {
            return None; // all-zero trace id is invalid
        }
        let mut parent_span_id = [0u8; 8];
        let mut sb = [0u8; 16];
        sb.copy_from_slice(sid.as_bytes());
        for i in 0..8 {
            let hi = hex_val(sb[i * 2])?;
            let lo = hex_val(sb[i * 2 + 1])?;
            parent_span_id[i] = (hi << 4) | lo;
        }
        if parent_span_id == [0u8; 8] {
            return None;
        }
        hex2(flags.as_bytes())?; // validate flags are hex
        // Store version/flags as their raw ASCII bytes (as they appear in
        // the header) so `to_header_value` round-trips losslessly.
        Some(Traceparent {
            version: [ver.as_bytes()[0], ver.as_bytes()[1]],
            trace_id,
            parent_span_id,
            flags: [flags.as_bytes()[0], flags.as_bytes()[1]],
        })
    }

    /// Serialize back to the canonical header form (lowercase hex).
    pub fn to_header_value(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            std::str::from_utf8(&self.version).unwrap_or("00"),
            trace_id_to_hex(&self.trace_id),
            hex8(&self.parent_span_id),
            std::str::from_utf8(&self.flags).unwrap_or("01"),
        )
    }

    /// The hex form of the trace id (what we index and echo back).
    pub fn trace_id_hex(&self) -> String {
        trace_id_to_hex(&self.trace_id)
    }

    /// Sentry wire format: `<32-hex trace id>-<16-hex span id>-<sampled>`
    /// — note there is NO version prefix (unlike W3C traceparent) and the
    /// sampled flag is a bare `0`/`1`. The trace id space is identical
    /// (128-bit), so the same id works in both headers.
    pub fn to_sentry_trace(&self) -> String {
        format!(
            "{}-{}-1",
            trace_id_to_hex(&self.trace_id),
            hex8(&self.parent_span_id)
        )
    }

    /// The Sentry dynamic-sampling-context entries carrying THIS trace id
    /// (see [`baggage_entries`]) — byte-identical id to `traceparent` and
    /// `sentry-trace`.
    pub fn to_baggage_entries(&self) -> String {
        baggage_entries(&trace_id_to_hex(&self.trace_id))
    }
}

/// Sentry dynamic-sampling-context entries for the W3C `baggage` header —
/// the exact key/value grammar @sentry/node v8+ and sentry-sdk emit and
/// parse: `sentry-trace_id=<32-hex>,sentry-sampled=true`.
pub fn baggage_entries(trace_id_hex: &str) -> String {
    format!("sentry-trace_id={trace_id_hex},sentry-sampled=true")
}

/// Merge blackbox's sentry-* entries into the caller's `baggage` header.
///
/// * no existing baggage → inject ours fresh.
/// * baggage without `sentry-trace_id` → append ours — W3C baggage is a
///   SHARED propagation bus, so caller entries (OTel, feature flags, user
///   ids) must survive untouched.
/// * baggage already carrying `sentry-trace_id` (case-insensitive per the
///   W3C baggage key rule) → `None`: never duplicate the key.
pub fn merge_baggage(existing: Option<&str>, trace_id_hex: &str) -> Option<String> {
    let ours = baggage_entries(trace_id_hex);
    match existing {
        None => Some(ours),
        Some(v) if v.trim().is_empty() => Some(ours),
        Some(v) => {
            if baggage_has_sentry_trace_id(v) {
                None
            } else {
                Some(format!("{v},{ours}"))
            }
        }
    }
}

fn baggage_has_sentry_trace_id(value: &str) -> bool {
    value.split(',').any(|member| {
        member
            .trim()
            .split_once('=')
            .map(|(k, _)| k.trim().eq_ignore_ascii_case("sentry-trace_id"))
            .unwrap_or(false)
    })
}

/// Format an 8-byte span id as 16 lowercase hex chars.
pub fn hex8(id: &[u8; 8]) -> String {
    let mut s = String::with_capacity(16);
    for b in id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex2(b: &[u8]) -> Option<[u8; 2]> {
    if b.len() != 2 {
        return None;
    }
    Some([hex_val(b[0])?, hex_val(b[1])?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_header_roundtrips() {
        let tp = Traceparent::generate();
        let hdr = tp.to_header_value();
        assert_eq!(hdr.len(), 55, "00-32-16-01 plus 3 dashes = 55");
        let parsed = Traceparent::parse(&hdr).unwrap();
        assert_eq!(parsed, tp);
    }

    #[test]
    fn parse_accepts_canonical_sample() {
        let tp = Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("spec sample must parse");
        assert_eq!(
            tp.trace_id,
            parse_trace_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        assert_eq!(hex8(&tp.parent_span_id), "00f067aa0ba902b7");
    }

    #[test]
    fn parse_rejects_invalid() {
        for bad in [
            "",
            "00",
            "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // bad version
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",    // missing flags
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero span
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // forbidden version
            "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01", // non-hex
        ] {
            assert!(Traceparent::parse(bad).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn baggage_entries_match_sentry_dsc_grammar() {
        let entries = baggage_entries("4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            entries,
            "sentry-trace_id=4bf92f3577b34da6a3ce929d0e0e4736,sentry-sampled=true"
        );
        // via the Traceparent method: same bytes as sentry-trace's id segment
        let tp = Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .unwrap();
        assert_eq!(
            tp.to_baggage_entries(),
            "sentry-trace_id=4bf92f3577b34da6a3ce929d0e0e4736,sentry-sampled=true"
        );
    }

    #[test]
    fn baggage_injected_when_absent_appended_when_present() {
        let tid = "4bf92f3577b34da6a3ce929d0e0e4736";
        // absent → inject fresh
        assert_eq!(
            merge_baggage(None, tid).as_deref(),
            Some("sentry-trace_id=4bf92f3577b34da6a3ce929d0e0e4736,sentry-sampled=true")
        );
        // present without sentry keys → append, caller entries preserved
        assert_eq!(
            merge_baggage(Some("userId=42,session=abc"), tid).as_deref(),
            Some(
                "userId=42,session=abc,sentry-trace_id=4bf92f3577b34da6a3ce929d0e0e4736,sentry-sampled=true"
            )
        );
        // empty / whitespace-only baggage behaves like absent
        assert_eq!(merge_baggage(Some(""), tid), merge_baggage(None, tid));
        assert_eq!(merge_baggage(Some("   "), tid), merge_baggage(None, tid));
    }

    #[test]
    fn baggage_never_duplicates_sentry_trace_id() {
        let tid = "4bf92f3577b34da6a3ce929d0e0e4736";
        // exact key already present → untouched (None)
        assert_eq!(
            merge_baggage(
                Some("sentry-trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,foo=bar"),
                tid
            ),
            None
        );
        // case-insensitive per the W3C baggage key rule
        assert_eq!(
            merge_baggage(Some("SENTRY-TRACE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), tid),
            None
        );
        // whitespace after commas tolerated
        assert_eq!(
            merge_baggage(
                Some("foo=bar, sentry-trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                tid
            ),
            None
        );
        // near-miss keys do NOT count
        assert!(merge_baggage(Some("sentry-traceid=x,foo=bar"), tid).is_some());
        assert!(merge_baggage(Some("trace_id=x"), tid).is_some());
    }

    #[test]
    fn generated_ids_are_unique_enough() {
        let a = Traceparent::generate();
        let b = Traceparent::generate();
        assert_ne!(a.trace_id, b.trace_id);
    }

    #[test]
    fn sentry_trace_format_matches_official_sdk_grammar() {
        // sentry-trace: <32-hex trace id>-<16-hex span id>-<0|1> — 51 chars,
        // NO version prefix. sentry-sdk parses exactly this shape.
        let tp = Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .unwrap();
        let st = tp.to_sentry_trace();
        assert_eq!(st.len(), 51, "32+1+16+1+1 = 51 chars: {st}");
        assert_eq!(st, "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1");
        // The trace id segment is byte-identical to the W3C form — the same
        // incident indexes under one id in both ecosystems.
        let mut parts = st.split('-');
        assert_eq!(
            parts.next().unwrap(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(parts.next().unwrap(), "00f067aa0ba902b7");
        assert_eq!(parts.next().unwrap(), "1");
    }
}
