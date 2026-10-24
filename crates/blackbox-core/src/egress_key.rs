//! Shared egress request-key helpers (Phase 3/4).
//!
//! Two distinct key families live here:
//!
//! 1. [`fingerprint`] — the **replay** fingerprint stored in
//!    [`crate::schema::EgressHttpMock::request_fingerprint`]:
//!    `SHA256(TenantID + AuthScope + Method + URL + CanonicalBody)` with
//!    NUL separators (tenant/auth empty until tenants exist). The
//!    deterministic replay matcher compares fingerprints only against
//!    other fingerprints produced by this exact function, so the
//!    composition is internal and stable.
//! 2. [`canonical_url`] — URL canonicalization used by both replay
//!    matching and the FinOps cache key: lowercase scheme + host, default
//!    ports stripped, path + query verbatim.
//!
//! The Phase 4 *cache* key additionally uses BLAKE3 over
//! `tenant_id + blake3(auth_header) + method + canonical_url + body`
//! (see `blackbox_egress::key`) — a different concern with a different
//! formula; this module only owns the replay-shared pieces.

use sha2::{Digest, Sha256};

/// `SHA256(TenantID + AuthScope + Method + URL + CanonicalBody)` with the
/// tenant/auth scopes NUL-separated (empty in Phase 3 replay).
pub fn fingerprint(method: &str, url: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"\0\0"); // tenant + authscope
    h.update(method.as_bytes());
    h.update(b"\0");
    h.update(url.as_bytes());
    h.update(b"\0");
    h.update(body);
    h.finalize().into()
}

/// Canonical request URL for matching: lowercase scheme + host, default
/// ports (:80/:443) stripped, path + query preserved verbatim.
pub fn canonical_url(raw: &str) -> String {
    let raw = raw.trim();
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("http".to_string(), raw),
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut authority = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" {
        Some(":443")
    } else if scheme == "http" {
        Some(":80")
    } else {
        None
    };
    if let Some(p) = default_port {
        if authority.ends_with(p) {
            authority.truncate(authority.len() - p.len());
        }
    }
    if path.is_empty() {
        format!("{scheme}://{authority}/")
    } else {
        format!("{scheme}://{authority}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_normalizes() {
        assert_eq!(
            canonical_url("HTTP://Stripe.COM:80/v1/charges?a=1"),
            "http://stripe.com/v1/charges?a=1"
        );
        assert_eq!(canonical_url("https://api.twilio.com:443/"), "https://api.twilio.com/");
        assert_eq!(canonical_url("api.stripe.com"), "http://api.stripe.com/");
    }

    #[test]
    fn fingerprint_is_body_sensitive() {
        let a = fingerprint("POST", "http://x/y", b"one");
        let b = fingerprint("POST", "http://x/y", b"two");
        let c = fingerprint("GET", "http://x/y", b"one");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, fingerprint("POST", "http://x/y", b"one"));
    }
}
