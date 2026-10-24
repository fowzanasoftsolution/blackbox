//! Wire-compatible Sentry envelope parsing (`POST /api/{project_id}/envelope/`).
//!
//! Envelope layout (Sentry Relay spec):
//!
//! ```text
//! {"event_id":"…","sent_at":"…","trace":{"trace_id":"…"}}\n
//! {"type":"event","length":123}\n
//! {…123 bytes of JSON…}\n
//! {"type":"attachment","length":9}\n
//! <9 raw bytes>\n
//! ```
//!
//! - Item payloads with a `length` field are exactly that many bytes.
//! - JSON items without `length` are one newline-terminated line.
//!
//! Blackbox stores the envelope **verbatim** (drop-in DSN replacement) and
//! correlates it to the W3C trace id from `trace.trace_id` (envelope header)
//! or `contexts.trace.trace_id` (event payload).

use crate::decompress;
use blackbox_core::schema::TraceId;

/// A parsed (but still verbatim-stored) envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `event_id` from the envelope header (empty string if absent).
    pub event_id: String,
    /// Trace id from the envelope header `trace.trace_id` or the first
    /// event/transaction item's `contexts.trace.trace_id`.
    pub trace_id: Option<TraceId>,
    /// Where the trace id was found (observability).
    pub trace_id_source: TraceIdSource,
    /// Number of items walked (sanity bound).
    pub item_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceIdSource {
    EnvelopeHeader,
    EventPayload,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope is empty")]
    Empty,
    #[error("envelope header is not a JSON object")]
    BadHeader,
    #[error("envelope header line exceeds 64 KiB")]
    HeaderTooLarge,
    #[error("item header is not a JSON object at offset {0}")]
    BadItemHeader(usize),
    /// Item payload length exceeds the decompression cap → HTTP 413.
    #[error("envelope item payload exceeds the decompression cap")]
    ItemTooLarge,
    #[error("truncated envelope: item header at {0} declares {1} payload bytes, {2} remain")]
    Truncated(usize, usize, usize),
    #[error("envelope exceeds 128 KiB without terminating cleanly")]
    Oversized,
}

/// Envelope headers/items never legitimately exceed this.
const ENVELOPE_MAX: usize = decompress::MAX_DECOMPRESSED; // 2 MiB, shared cap

const HEADER_LINE_MAX: usize = 64 * 1024;

/// Parse a raw (already decompressed) envelope. Returns metadata; the raw
/// bytes are stored verbatim by the caller.
pub fn parse(raw: &[u8]) -> Result<Envelope, EnvelopeError> {
    if raw.is_empty() {
        return Err(EnvelopeError::Empty);
    }
    if raw.len() > ENVELOPE_MAX {
        return Err(EnvelopeError::Oversized);
    }

    // --- envelope header: first line ---
    let header_end = find_line_end(raw, 0, HEADER_LINE_MAX, true)?;
    let header_line = trim_cr(&raw[..header_end]);
    let header: serde_json::Value = serde_json::from_slice(header_line)
        .map_err(|_| EnvelopeError::BadHeader)?;
    if !header.is_object() {
        return Err(EnvelopeError::BadHeader);
    }
    let event_id = header
        .get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut out = Envelope {
        event_id,
        trace_id: None,
        trace_id_source: TraceIdSource::None,
        item_count: 0,
    };

    // Header `trace.trace_id` wins.
    if let Some(tid) = extract_trace_obj(&header) {
        out.trace_id = Some(tid);
        out.trace_id_source = TraceIdSource::EnvelopeHeader;
    }

    // --- items ---
    let mut pos = header_end + 1;
    while pos < raw.len() {
        // Item header line.
        let ih_end = find_line_end(raw, pos, HEADER_LINE_MAX, false)?;
        let ih_line = trim_cr(&raw[pos..ih_end]);
        if ih_line.is_empty() {
            pos = ih_end + 1;
            continue;
        }
        let ih: serde_json::Value = serde_json::from_slice(ih_line)
            .map_err(|_| EnvelopeError::BadItemHeader(pos))?;
        if !ih.is_object() {
            return Err(EnvelopeError::BadItemHeader(pos));
        }
        out.item_count += 1;
        if out.item_count > 256 {
            return Err(EnvelopeError::Oversized);
        }

        let kind = ih.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let declared = match ih.get("length") {
            Some(v) => Some(v.as_u64().unwrap_or(u64::MAX) as usize),
            None => None,
        };

        // Locate payload.
        let payload_start = ih_end + 1;
        let payload: &[u8] = match declared {
            Some(len) => {
                if len > ENVELOPE_MAX {
                    return Err(EnvelopeError::ItemTooLarge);
                }
                if payload_start + len > raw.len() {
                    return Err(EnvelopeError::Truncated(pos, len, raw.len() - payload_start));
                }
                &raw[payload_start..payload_start + len]
            }
            None => {
                // Unlengthed JSON item: one line (tolerate EOF tail).
                let end = find_line_end(raw, payload_start, ENVELOPE_MAX, true)?;
                &raw[payload_start..end]
            }
        };

        // Fallback trace extraction: first event/transaction item payload.
        if out.trace_id.is_none() && matches!(kind.as_str(), "event" | "transaction") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                if let Some(tid) = v
                    .pointer("/contexts/trace/trace_id")
                    .and_then(|t| t.as_str())
                    .and_then(blackbox_core::schema::parse_trace_hex)
                {
                    out.trace_id = Some(tid);
                    out.trace_id_source = TraceIdSource::EventPayload;
                }
            }
        }

        pos = payload_start + payload.len() + 1; // skip payload + terminator
    }

    Ok(out)
}

fn extract_trace_obj(header: &serde_json::Value) -> Option<TraceId> {
    header
        .pointer("/trace/trace_id")
        .and_then(|t| t.as_str())
        .and_then(blackbox_core::schema::parse_trace_hex)
}

/// Find the end index of the line starting at `pos` (exclusive of `\n`).
///
/// `tail_ok` accepts an EOF-terminated final line (envelope headers and
/// unlengthed payloads may lack the trailing newline); item headers must
/// always be newline-terminated.
fn find_line_end(raw: &[u8], pos: usize, max: usize, tail_ok: bool) -> Result<usize, EnvelopeError> {
    let end = match memchr(b'\n', &raw[pos..]) {
        Some(rel) => pos + rel,
        None => {
            if tail_ok {
                raw.len()
            } else {
                return Err(EnvelopeError::Truncated(pos, 0, raw.len() - pos));
            }
        }
    };
    if end - pos > max {
        return Err(if pos == 0 {
            EnvelopeError::HeaderTooLarge
        } else {
            EnvelopeError::Oversized
        });
    }
    Ok(end)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Tiny memchr (no dep): find first occurrence of `needle`.
fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackbox_core::schema::parse_trace_hex;

    const TID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

    fn envelope(header_extra: &str, items: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("{{\"event_id\":\"abc123\"{header_extra}}}\n").as_bytes());
        for (ih, payload) in items {
            out.extend_from_slice(ih.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(payload);
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn header_trace_id_is_extracted() {
        let raw = envelope(
            &format!(",\"trace\":{{\"trace_id\":\"{TID}\",\"public_key\":\"k\"}}"),
            &[(r#"{"type":"event"}"#, br#"{"message":"boom"}"#)],
        );
        let env = parse(&raw).unwrap();
        assert_eq!(env.event_id, "abc123");
        assert_eq!(env.trace_id, parse_trace_hex(TID));
        assert_eq!(env.trace_id_source, TraceIdSource::EnvelopeHeader);
        assert_eq!(env.item_count, 1);
    }

    #[test]
    fn contexts_trace_fallback_in_event_payload() {
        let payload = format!(r#"{{"contexts":{{"trace":{{"trace_id":"{TID}"}}}},"message":"x"}}"#);
        let raw = envelope("", &[("{\"type\":\"event\"}", payload.as_bytes())]);
        let env = parse(&raw).unwrap();
        assert_eq!(env.trace_id, parse_trace_hex(TID));
        assert_eq!(env.trace_id_source, TraceIdSource::EventPayload);
    }

    #[test]
    fn contexts_trace_fallback_with_declared_length() {
        let payload = format!(r#"{{"contexts":{{"trace":{{"trace_id":"{TID}"}}}}}}"#);
        let ih = format!(r#"{{"type":"event","length":{}}}"#, payload.len());
        let raw = envelope("", &[(ih.as_str(), payload.as_bytes())]);
        assert_eq!(parse(&raw).unwrap().trace_id, parse_trace_hex(TID));
    }

    #[test]
    fn length_delimited_binary_item() {
        let bin = [0xDEu8; 64];
        let raw = envelope(
            "",
            &[
                (r#"{"type":"event"}"#, br#"{"message":"m"}"#),
                (r#"{"type":"attachment","length":64,"filename":"a.bin"}"#, &bin),
            ],
        );
        let env = parse(&raw).unwrap();
        assert_eq!(env.item_count, 2);
    }

    #[test]
    fn truncated_length_item_is_rejected() {
        let raw = envelope(
            "",
            &[(r#"{"type":"attachment","length":100}"#, &[0u8; 10])],
        );
        assert!(matches!(parse(&raw), Err(EnvelopeError::Truncated(..))));
    }

    #[test]
    fn bad_header_rejected() {
        assert_eq!(parse(b""), Err(EnvelopeError::Empty));
        assert_eq!(parse(b"not json\n"), Err(EnvelopeError::BadHeader));
        assert_eq!(parse(b"[1,2]\n"), Err(EnvelopeError::BadHeader));
    }

    #[test]
    fn oversized_header_rejected() {
        let mut raw = b"\"".to_vec();
        raw.extend(std::iter::repeat(b'x').take(80 * 1024));
        raw.push(b'\n');
        assert_eq!(parse(&raw), Err(EnvelopeError::HeaderTooLarge));
    }

    #[test]
    fn envelope_without_trace_id_is_accepted() {
        let raw = envelope("", &[(r#"{"type":"event"}"#, br#"{"message":"m"}"#)]);
        let env = parse(&raw).unwrap();
        assert_eq!(env.trace_id, None);
        assert_eq!(env.trace_id_source, TraceIdSource::None);
    }
}
