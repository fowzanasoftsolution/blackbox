//! Minimal, dependency-free protobuf wire-format walker for OTLP/HTTP
//! protobuf payloads (`application/x-protobuf`).
//!
//! Only what OTLP needs: varints, 64-bit, length-delimited, 32-bit fields.
//! Unknown fields are skipped by wire type — forward compatible with
//! newer OTLP schema revisions. Eagerly parses a (≤2 MiB) buffer into a
//! flat field list; nested messages are re-walked from their slices.

/// Wire types (protobuf encoding spec).
pub const WIRE_VARINT: u8 = 0;
pub const WIRE_I64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_I32: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PbField<'a> {
    pub no: u32,
    pub wire: u8,
    /// Decoded value for `WIRE_VARINT` fields (0 otherwise).
    pub varint: u64,
    /// Byte slice for `WIRE_LEN` fields (empty otherwise).
    pub bytes: &'a [u8],
}

impl<'a> PbField<'a> {
    pub fn as_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("protobuf decode error: {0}")]
pub struct PbError(pub String);

#[inline]
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, PbError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(PbError("varint truncated".into()));
        }
        let b = buf[*pos];
        *pos += 1;
        // 10th byte may only carry one significant bit; tolerate the raw bits.
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 70 {
            return Err(PbError("varint too long".into()));
        }
    }
}

/// Parse every top-level field of `buf` into a flat list.
pub fn fields(buf: &[u8]) -> Result<Vec<PbField<'_>>, PbError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let no = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        if no == 0 {
            return Err(PbError("field number 0 is reserved".into()));
        }
        match wire {
            WIRE_VARINT => {
                let v = read_varint(buf, &mut pos)?;
                out.push(PbField { no, wire, varint: v, bytes: &[] });
            }
            WIRE_I64 => {
                if pos + 8 > buf.len() {
                    return Err(PbError("i64 field truncated".into()));
                }
                pos += 8;
                out.push(PbField { no, wire, varint: 0, bytes: &[] });
            }
            WIRE_LEN => {
                let len = read_varint(buf, &mut pos)? as usize;
                if pos + len > buf.len() {
                    return Err(PbError("len-delim field truncated".into()));
                }
                let bytes = &buf[pos..pos + len];
                pos += len;
                out.push(PbField { no, wire, varint: 0, bytes });
            }
            WIRE_I32 => {
                if pos + 4 > buf.len() {
                    return Err(PbError("i32 field truncated".into()));
                }
                pos += 4;
                out.push(PbField { no, wire, varint: 0, bytes: &[] });
            }
            other => {
                return Err(PbError(format!("unsupported wire type {other} (groups deprecated)")));
            }
        }
    }
    Ok(out)
}

/// Extract all `no == field` sub-message slices (len-delim fields).
pub fn sub<'a, 'b>(fs: &'b [PbField<'a>], field: u32) -> Vec<&'b [u8]> {
    fs.iter()
        .filter(|f| f.no == field && f.wire == WIRE_LEN)
        .map(|f| f.bytes)
        .collect()
}

/// First varint value of `no == field`.
pub fn var(fs: &[PbField<'_>], field: u32) -> Option<u64> {
    fs.iter().find(|f| f.no == field && f.wire == WIRE_VARINT).map(|f| f.varint)
}

/// First bytes slice of `no == field`.
pub fn bytes<'a, 'b>(fs: &'b [PbField<'a>], field: u32) -> Option<&'b [u8]> {
    fs.iter().find(|f| f.no == field && f.wire == WIRE_LEN).map(|f| f.bytes)
}

/// First string of `no == field`.
pub fn string<'a, 'b>(fs: &'b [PbField<'a>], field: u32) -> Option<&'b str> {
    bytes(fs, field).and_then(|b| std::str::from_utf8(b).ok())
}

/// All string values of `no == field` (attribute key/value pairs use this).
pub fn strings<'a, 'b>(fs: &'b [PbField<'a>], field: u32) -> Vec<&'b str> {
    fs.iter()
        .filter(|f| f.no == field && f.wire == WIRE_LEN)
        .filter_map(|f| std::str::from_utf8(f.bytes).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encode: message { field1 (len) = "abc", field2 (varint) = 300 }
    #[test]
    fn roundtrip_basic_fields() {
        let mut buf = Vec::new();
        // field 1, wire 2, len 3
        buf.push((1 << 3) | WIRE_LEN);
        buf.push(3);
        buf.extend_from_slice(b"abc");
        // field 2, wire 0, varint 300 = 0b100101100 → AC 02
        buf.push((2 << 3) | WIRE_VARINT);
        buf.extend_from_slice(&[0xAC, 0x02]);
        // field 3, wire 5 (i32)
        buf.push((3 << 3) | WIRE_I32);
        buf.extend_from_slice(&[0; 4]);

        let fs = fields(&buf).unwrap();
        assert_eq!(fs.len(), 3);
        assert_eq!(string(&fs, 1), Some("abc"));
        assert_eq!(var(&fs, 2), Some(300));
        assert_eq!(fs[2].wire, WIRE_I32);
    }

    #[test]
    fn nested_submessage_walk() {
        // inner { f1 varint = 7 } ; outer { f2 len = inner }
        let inner = [(1 << 3) | WIRE_VARINT, 7];
        let mut outer = vec![(2 << 3) | WIRE_LEN, inner.len() as u8];
        outer.extend_from_slice(&inner);
        let fs = fields(&outer).unwrap();
        let sub_fs = fields(sub(&fs, 2)[0]).unwrap();
        assert_eq!(var(&sub_fs, 1), Some(7));
    }

    #[test]
    fn truncated_input_rejected() {
        assert!(fields(&[0x0A, 0xFF]).is_err());
        assert!(fields(&[(1 << 3) | WIRE_VARINT, 0x80]).is_err());
    }
}
