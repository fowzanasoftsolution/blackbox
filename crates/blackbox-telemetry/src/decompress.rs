//! Content-decoding for telemetry ingestion with a strict decompression
//! ceiling (blueprint §2 landmine #4 class: never let a hostile payload
//! dictate memory use).
//!
//! `gzip` and `zstd` are decoded with a hard output cap — the classic
//! "zip bomb" (a few KB of compressed data expanding to gigabytes) is
//! rejected the moment output exceeds [`MAX_DECOMPRESSED`], before any
//! allocation past the cap happens.

use blackbox_core::error::StorageError;

/// Hard decompressed-size ceiling for telemetry bodies: 2 MiB.
pub const MAX_DECOMPRESSED: usize = 2 * 1024 * 1024;

/// Hard compressed-size ceiling enforced while reading the request body:
/// 4 MiB (a legitimately-compressible 2 MiB body never exceeds this).
pub const MAX_COMPRESSED: usize = 4 * 1024 * 1024;

/// Why a body was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// Output exceeded the decompression ceiling → HTTP 413.
    #[error("payload expands past the {MAX_DECOMPRESSED}-byte decompression cap (zip-bomb guard)")]
    TooLarge,
    /// Raw body exceeded the compressed ceiling → HTTP 413.
    #[error("payload exceeds the {MAX_COMPRESSED}-byte request cap")]
    TooLargeRaw,
    /// Content-Encoding unknown → HTTP 415.
    #[error("unsupported Content-Encoding {0:?}")]
    UnsupportedEncoding(String),
    /// Body was not decodable → HTTP 400.
    #[error("malformed body: {0}")]
    Malformed(String),
}

impl From<BodyError> for StorageError {
    fn from(e: BodyError) -> Self {
        StorageError::Codec(e.to_string())
    }
}

/// A body reader that accumulates at most [`MAX_COMPRESSED`] raw bytes.
///
/// Call [`Capped::push`] per HTTP chunk; `TooLargeRaw` stops the read early
/// so oversized uploads never reach memory in full.
#[derive(Default)]
pub struct Capped {
    pub buf: Vec<u8>,
}

impl Capped {
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if self.buf.len() + chunk.len() > MAX_COMPRESSED {
            return Err(BodyError::TooLargeRaw);
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Decode a telemetry body according to `Content-Encoding`.
///
/// - `identity` / `""` → passthrough (still capped).
/// - `gzip` / `x-gzip` → flate2 (pure-Rust miniz backend).
/// - `zstd` → zstd crate.
///
/// Any path that would produce more than [`MAX_DECOMPRESSED`] bytes is
/// rejected with [`BodyError::TooLarge`].
pub fn decode_body(content_encoding: &str, raw: &[u8]) -> Result<Vec<u8>, BodyError> {
    match content_encoding.trim().to_ascii_lowercase().as_str() {
        "" | "identity" => {
            if raw.len() > MAX_DECOMPRESSED {
                return Err(BodyError::TooLarge);
            }
            Ok(raw.to_vec())
        }
        "gzip" | "x-gzip" => decode_gzip(raw),
        "zstd" => decode_zstd(raw),
        other => Err(BodyError::UnsupportedEncoding(other.to_string())),
    }
}

/// gzip decode with a hard output ceiling.
pub fn decode_gzip(raw: &[u8]) -> Result<Vec<u8>, BodyError> {
    use std::io::Read;
    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut decoder = flate2::read::MultiGzDecoder::new(raw);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match decoder.read(&mut chunk) {
            // MultiGzDecoder returns Ok(0) only after the final member's
            // CRC/ISIZE trailer verified cleanly; bad trailers surface as Err.
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > MAX_DECOMPRESSED {
                    return Err(BodyError::TooLarge);
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(BodyError::Malformed(format!("gzip: {e}"))),
        }
    }
}

/// zstd decode with a hard output ceiling.
///
/// A streaming (size-less) frame would otherwise expand unbounded — the
/// read loop enforces the cap on every chunk.
pub fn decode_zstd(raw: &[u8]) -> Result<Vec<u8>, BodyError> {
    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut decoder =
        zstd::stream::read::Decoder::new(raw).map_err(|e| BodyError::Malformed(format!("zstd: {e}")))?;
    use std::io::Read;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match decoder.read(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > MAX_DECOMPRESSED {
                    return Err(BodyError::TooLarge);
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(BodyError::Malformed(format!("zstd: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_roundtrip_and_cap() {
        let plain = b"hello blackbox telemetry".repeat(100);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let gz = enc.finish().unwrap();

        let got = decode_gzip(&gz).unwrap();
        assert_eq!(got, plain);

        // Multi-member gzip also decodes (Sentry SDKs may concatenate).
        let double = [gz.clone(), gz].concat();
        let got2 = decode_gzip(&double).unwrap();
        assert_eq!(got2, [plain.clone(), plain].concat());
    }

    #[test]
    fn gzip_bomb_is_rejected_with_too_large() {
        // 3 MiB of 'A' compresses to a few KB but expands past the 2 MiB cap.
        let plain = vec![b'A'; 3 * 1024 * 1024];
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let bomb = enc.finish().unwrap();
        assert!(bomb.len() < 100 * 1024, "fixture sanity: bomb should compress tiny");
        assert_eq!(decode_gzip(&bomb).unwrap_err(), BodyError::TooLarge);
    }

    #[test]
    fn zstd_bomb_is_rejected_with_too_large() {
        let plain = vec![b'B'; 3 * 1024 * 1024];
        let bomb = zstd::stream::encode_all(&plain[..], 3).unwrap();
        assert!(bomb.len() < 20 * 1024);
        assert_eq!(decode_zstd(&bomb).unwrap_err(), BodyError::TooLarge);
    }

    #[test]
    fn zstd_roundtrip() {
        let plain = b"zstd payload".repeat(1000);
        let enc = zstd::stream::encode_all(&plain[..], 3).unwrap();
        assert_eq!(decode_zstd(&enc).unwrap(), plain);
    }

    #[test]
    fn identity_passthrough_capped() {
        assert_eq!(decode_body("identity", b"ok").unwrap(), b"ok");
        assert_eq!(decode_body("", b"ok").unwrap(), b"ok");
        let big = vec![0u8; MAX_DECOMPRESSED + 1];
        assert_eq!(decode_body("", &big).unwrap_err(), BodyError::TooLarge);
    }

    #[test]
    fn unknown_encoding_rejected() {
        assert!(matches!(
            decode_body("br", b"x"),
            Err(BodyError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn capped_reader_stops_early() {
        let mut c = Capped::default();
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..4 {
            c.push(&chunk).unwrap(); // 4 MiB total == cap, accepted
        }
        assert!(matches!(c.push(&chunk), Err(BodyError::TooLargeRaw)));
    }
}
