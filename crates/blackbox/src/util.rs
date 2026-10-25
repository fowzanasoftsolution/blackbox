//! Shared byte utilities.

/// Lowercase hex of arbitrary bytes.
pub fn hex_of(bytes: &[u8]) -> String {
    hex::enc(bytes)
}

/// Decode a lowercase hex string (odd length → `None`).
pub fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::dec(s)
}

mod hex {
    pub fn enc(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }

    pub fn dec(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        if b.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(b.len() / 2);
        for pair in b.chunks(2) {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
        }
        Some(out)
    }
}
