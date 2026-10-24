//! Tiny hex encode/decode — zero dependencies (the "zero-bloat" rule).

/// Lowercase hex encode.
pub fn enc(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Hex decode (accepts upper or lower case, ignores nothing — strict).
pub fn dec(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let hi = val(pair[0])?;
        let lo = val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject() {
        assert_eq!(enc(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(dec("000FFFA5").unwrap(), vec![0x00, 0x0f, 0xff, 0xa5]);
        assert_eq!(dec("abc"), None);
        assert_eq!(dec("zz"), None);
        assert_eq!(dec(""), Some(vec![]));
    }
}
