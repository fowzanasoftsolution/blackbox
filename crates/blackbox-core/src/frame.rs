//! Self-describing frame codec with CRC32C integrity and 16-byte alignment.
//!
//! ## On-disk layout (blueprint §3, Engine 3)
//!
//! ```text
//! ┌────────────────────────── 32-byte header ──────────────────────────┐
//! │ 0..2   magic      u16 LE = 0xBB0C                                  │
//! │ 2..3   version    u8 = 1                                           │
//! │ 3..4   flags      u8 (reserved, 0)                                 │
//! │ 4..8   payload_len     u32 LE                                      │
//! │ 8..12  payload_crc32c u32 LE (CRC32C of payload bytes only)        │
//! │ 12..28 trace_id      [u8; 16] (mirrored from TraceRecord)          │
//! │ 28..32 header_crc32c u32 LE (CRC32C of header bytes 0..28)         │
//! ├────────────────────────────────────────────────────────────────────┤
//! │ payload: rkyv 0.8 serialization of `TraceRecord`                   │
//! │ padding: zeros to the next 16-byte boundary                        │
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The critical alignment rule (user decision #6)
//!
//! The header is exactly 32 bytes (a multiple of 16) and every frame is padded
//! to a 16-byte boundary. Since segment files start at offset 0 and every frame
//! length is a multiple of 16, frame starts AND payload starts are always
//! 16-byte-aligned on disk. Payloads are read into `rkyv::AlignedVec` (which
//! itself guarantees 16-byte alignment), so `rkyv::access` never sees a
//! misaligned buffer — avoiding the UB class from blueprint §2 landmine #2.
//!
//! ## Defense in depth
//!
//! - `header_crc32c` catches any header bit-flip (including `payload_len`,
//!   which would otherwise redirect reads into arbitrary offsets).
//! - `payload_crc32c` catches content corruption inside payloads.
//! - `bytecheck` (`rkyv::access`) catches structural corruption that survives
//!   CRC collisions or mis-sized reads before any zero-copy dereference.
//!
//! Content corruption inside plain data bytes is bytecheck-legal; that class
//! is the CRC's job. Structure corruption is bytecheck's job. Both are checked
//! before a frame is ever handed to the index.

use crate::error::StorageError;
use crate::schema::{TraceId, TraceRecord};

/// Frame magic: `0xBB0C` ("Blackbox Codec").
pub const MAGIC: u16 = 0xBB0C;
/// Frame format version.
pub const VERSION: u8 = 1;
/// Exact header size — a multiple of [`ALIGN`].
pub const HEADER_SIZE: usize = 32;
/// On-disk alignment of every frame start and payload start.
pub const ALIGN: usize = 16;
/// Hard payload cap (blueprint §2 landmine #4: never buffer runaway bodies).
pub const MAX_PAYLOAD: u32 = 64 * 1024 * 1024;

/// Detected problems while scanning a frame. `Partial` means "not enough
/// bytes yet" — a torn write at the tail of the active segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameProblem {
    /// Fewer than [`HEADER_SIZE`] bytes remain at this offset.
    PartialHeader,
    /// Header parsed but the frame extends past the end of the buffer
    /// (payload truncated mid-write).
    PartialFrame { declared_total: u64, available: u64 },
    /// Magic bytes do not match.
    BadMagic { got: u16 },
    /// Unsupported frame version.
    BadVersion { got: u8 },
    /// Header CRC mismatch — a header byte was corrupted.
    BadHeaderCrc,
    /// Payload CRC mismatch — payload bytes were corrupted.
    BadPayloadCrc,
    /// payload_len is zero or exceeds [`MAX_PAYLOAD`].
    BadLength { got: u64 },
    /// bytecheck rejected the payload structure.
    BadSchema { detail: String },
}

impl FrameProblem {
    /// Stable short reason tag for logs and recovery events.
    pub fn reason(&self) -> &'static str {
        match self {
            FrameProblem::PartialHeader => "partial_header",
            FrameProblem::PartialFrame { .. } => "partial_frame",
            FrameProblem::BadMagic { .. } => "bad_magic",
            FrameProblem::BadVersion { .. } => "bad_version",
            FrameProblem::BadHeaderCrc => "bad_header_crc",
            FrameProblem::BadPayloadCrc => "bad_payload_crc",
            FrameProblem::BadLength { .. } => "bad_length",
            FrameProblem::BadSchema { .. } => "bad_schema",
        }
    }
}

/// Parsed, CRC-verified frame header (payload not yet decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameView {
    pub trace_id: TraceId,
    pub payload_len: u32,
    /// Total on-disk frame length including header and padding.
    pub total_len: u32,
    /// Byte offset of the payload inside the segment.
    pub payload_offset: u64,
    pub flags: u8,
}

#[inline]
pub(crate) fn round_up_16(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// Total on-disk size of a frame carrying `payload_len` payload bytes.
#[inline]
pub fn frame_total_len(payload_len: usize) -> usize {
    round_up_16(HEADER_SIZE + payload_len)
}

/// Encode a record into a padded, ready-to-write frame buffer.
///
/// The returned buffer's length is a multiple of 16; the payload begins at
/// offset 32. Magic/version/CRCs are all filled in.
pub fn encode_frame(record: &TraceRecord) -> Result<Vec<u8>, StorageError> {
    // rkyv 0.8 high API — validated by construction, 16-byte-aligned AlignedVec.
    let payload = rkyv::to_bytes::<rkyv::rancor::Error>(record)?;
    if payload.len() > MAX_PAYLOAD as usize {
        return Err(StorageError::Codec(format!(
            "payload {} exceeds MAX_PAYLOAD {}",
            payload.len(),
            MAX_PAYLOAD
        )));
    }
    Ok(build_frame(record.trace_id, &payload))
}

/// Assemble header + payload + padding. Exposed `pub(crate)` for tests.
pub(crate) fn build_frame(trace_id: TraceId, payload: &[u8]) -> Vec<u8> {
    let total = frame_total_len(payload.len());
    let mut buf = vec![0u8; total]; // padding pre-zeroed
    let payload_crc = crc32c::crc32c(payload);

    buf[0..2].copy_from_slice(&MAGIC.to_le_bytes());
    buf[2] = VERSION;
    buf[3] = 0; // flags
    buf[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&payload_crc.to_le_bytes());
    buf[12..28].copy_from_slice(&trace_id);
    let header_crc = crc32c::crc32c(&buf[0..28]);
    buf[28..32].copy_from_slice(&header_crc.to_le_bytes());
    buf[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
    buf
}

/// Parse + CRC-verify the frame header at `start` inside `buf`.
///
/// Returns a [`FrameView`] (header only — payload bytes are NOT decoded here
/// so index scans stay cheap). CRC checks do read the payload bytes.
pub fn parse_frame(buf: &[u8], start: usize) -> Result<FrameView, FrameProblem> {
    let remaining = buf.len().saturating_sub(start);
    if remaining < HEADER_SIZE {
        return Err(FrameProblem::PartialHeader);
    }
    let h = &buf[start..start + HEADER_SIZE];

    let magic = u16::from_le_bytes([h[0], h[1]]);
    if magic != MAGIC {
        return Err(FrameProblem::BadMagic { got: magic });
    }
    let version = h[2];
    if version != VERSION {
        return Err(FrameProblem::BadVersion { got: version });
    }
    let flags = h[3];
    let payload_len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as u64;
    let payload_crc = u32::from_le_bytes([h[8], h[9], h[10], h[11]]);
    let mut trace_id = [0u8; 16];
    trace_id.copy_from_slice(&h[12..28]);
    let header_crc = u32::from_le_bytes([h[28], h[29], h[30], h[31]]);

    // Header CRC first: a flipped payload_len would otherwise redirect reads.
    if crc32c::crc32c(&h[0..28]) != header_crc {
        return Err(FrameProblem::BadHeaderCrc);
    }
    if payload_len == 0 || payload_len > MAX_PAYLOAD as u64 {
        return Err(FrameProblem::BadLength { got: payload_len });
    }

    let declared_total = frame_total_len(payload_len as usize) as u64;
    let available = (buf.len() - start) as u64;
    if declared_total > available {
        return Err(FrameProblem::PartialFrame {
            declared_total,
            available,
        });
    }

    let payload = &buf[start + HEADER_SIZE..start + HEADER_SIZE + payload_len as usize];
    if crc32c::crc32c(payload) != payload_crc {
        return Err(FrameProblem::BadPayloadCrc);
    }

    Ok(FrameView {
        trace_id,
        payload_len: payload_len as u32,
        total_len: declared_total as u32,
        payload_offset: start as u64 + HEADER_SIZE as u64,
        flags,
    })
}

/// Decode + bytecheck-validate the payload bytes into an owned record.
///
/// The slice is copied into a 16-byte-aligned [`rkyv::AlignedVec`] first —
/// see the module docs for why alignment is a hard invariant here.
pub fn decode_payload(payload: &[u8]) -> Result<TraceRecord, StorageError> {
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(payload.len());
    aligned.extend_from_slice(payload);
    let archived =
        rkyv::access::<rkyv::Archived<TraceRecord>, rkyv::rancor::Error>(&aligned[..])?;
    let owned: TraceRecord =
        rkyv::deserialize::<TraceRecord, rkyv::rancor::Error>(archived)?;
    Ok(owned)
}

/// Parse, CRC-verify AND fully decode the record at `start`.
pub fn decode_frame(buf: &[u8], start: usize) -> Result<(FrameView, TraceRecord), FrameProblem> {
    let view = parse_frame(buf, start)?;
    let payload = &buf[start + HEADER_SIZE..start + HEADER_SIZE + view.payload_len as usize];
    match decode_payload(payload) {
        Ok(rec) => Ok((view, rec)),
        Err(e) => Err(FrameProblem::BadSchema { detail: e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EgressHttpMock, RecordPayload};

    fn rec(seq: u64, body_len: usize) -> TraceRecord {
        TraceRecord::new(
            [0xA5u8; 16],
            seq,
            RecordPayload::EgressHttpMock(EgressHttpMock {
                seq_no: seq,
                request_fingerprint: [seq as u8; 32],
                method: "POST".into(),
                request_url: "https://unit.test/v1/charges".into(),
                response_status: 201,
                response_headers: vec![("server".into(), "blackbox-test".into())],
                response_body: vec![0x42u8; body_len],
                upstream_host: "unit.test".into(),
                recorded_at_ms: 1_724_000_000_000,
            }),
        )
    }

    #[test]
    fn encode_parse_decode_roundtrip() {
        for body_len in [0usize, 1, 15, 16, 17, 255, 4096, 65535] {
            let record = rec(body_len as u64, body_len);
            let frame = encode_frame(&record).unwrap();
            // Alignment invariant: frame length is a multiple of 16.
            assert_eq!(frame.len() % ALIGN, 0, "frame len {}", frame.len());

            let view = parse_frame(&frame, 0).unwrap();
            assert_eq!(view.payload_offset as usize % ALIGN, 0);
            assert_eq!(view.total_len as usize, frame.len());
            assert_eq!(view.trace_id, record.trace_id);
            // Padding (after the real payload, whose length is the rkyv
            // serialization size — larger than the embedded body) is zeroed.
            assert!(frame[HEADER_SIZE + view.payload_len as usize..]
                .iter()
                .all(|&b| b == 0));

            let (view2, decoded) = decode_frame(&frame, 0).unwrap();
            assert_eq!(view2, view);
            assert_eq!(decoded, record);
        }
    }

    #[test]
    fn payload_offset_alignment_across_many_frames() {
        // Chain frames back-to-back and verify every payload offset stays
        // 16-byte aligned — the invariant rkyv::access depends on.
        let mut buf = Vec::new();
        for seq in 0..50u64 {
            let record = rec(seq, 100 + seq as usize);
            buf.extend_from_slice(&encode_frame(&record).unwrap());
        }
        let mut off = 0usize;
        let mut count = 0;
        while off < buf.len() {
            let view = parse_frame(&buf, off).unwrap();
            assert_eq!(view.payload_offset as usize % ALIGN, 0);
            off += view.total_len as usize;
            count += 1;
        }
        assert_eq!(count, 50);
    }

    #[test]
    fn header_crc_catches_every_header_flip() {
        let record = rec(1, 128);
        let frame = encode_frame(&record).unwrap();
        // Flip every byte in the first 28 header bytes — each must be caught
        // by magic/version/length validation or the header CRC.
        for i in 0..28 {
            let mut f = frame.clone();
            f[i] ^= 0x01 << (i % 7);
            match parse_frame(&f, 0) {
                Err(_) => {}                              // detected — good
                Ok(v) => panic!("header flip at byte {i} undetected: {v:?}"),
            }
        }
    }

    #[test]
    fn payload_crc_catches_content_flips() {
        let record = rec(2, 1024);
        let frame = encode_frame(&record).unwrap();
        // Flip one bit inside the payload body.
        let mut f = frame.clone();
        let p = HEADER_SIZE + 512;
        f[p] ^= 0x80;
        match parse_frame(&f, 0) {
            Err(FrameProblem::BadPayloadCrc) => {}
            other => panic!("expected BadPayloadCrc, got {other:?}"),
        }
    }

    #[test]
    fn partial_frames_reported_as_partial() {
        let record = rec(3, 600);
        let frame = encode_frame(&record).unwrap();

        // Cut mid-payload.
        let cut = HEADER_SIZE + 300;
        let (view, _) = {
            match parse_frame(&frame[..cut], 0) {
                Err(FrameProblem::PartialFrame { .. }) => ((), ()),
                other => panic!("expected PartialFrame, got {other:?}"),
            }
        };
        let _ = view;

        // Cut mid-header.
        match parse_frame(&frame[..10], 0) {
            Err(FrameProblem::PartialHeader) => {}
            other => panic!("expected PartialHeader, got {other:?}"),
        }

        // Empty buffer.
        assert_eq!(parse_frame(&[], 0), Err(FrameProblem::PartialHeader));
    }

    #[test]
    fn max_payload_enforced() {
        let record = rec(4, 16);
        let mut payload = rkyv::to_bytes::<rkyv::rancor::Error>(&record).unwrap();
        payload.extend_from_slice(&vec![0u8; (MAX_PAYLOAD as usize) + 1]);
        assert!(encode_frame(&record).is_ok()); // normal path fine
        // Oversize via build path guard:
        let huge = build_frame(record.trace_id, &payload);
        match parse_frame(&huge, 0) {
            Err(FrameProblem::BadLength { .. }) => {}
            other => panic!("expected BadLength, got {other:?}"),
        }
    }
}
