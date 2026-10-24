//! Composite cache keys + cacheability policy (Landmine #6).
//!
//! ## The composite key
//!
//! `BLAKE3(tenant_id ‖ blake3(auth_header) ‖ method ‖ canonical_url ‖ body_bytes)`.
//!
//! The auth header is hashed *before* composition so the raw credential
//! never participates in the outer hash domain, and two tenants with
//! identical requests but different credentials always land on different
//! keys — **zero cross-tenant leakage by construction**.
//!
//! ## Cacheability policy
//!
//! | Request                                        | Cacheable?                          |
//! |------------------------------------------------|-------------------------------------|
//! | `GET` / `HEAD`                                 | yes (unless `x-blackbox-cache: disable`) |
//! | `POST /v1/chat/completions` … deterministic AI routes | yes, unless `stream: true` in body |
//! | any method with `x-blackbox-cache: enable`     | yes, unless `stream: true` in body  |
//! | everything else                                | bypass (streamed, recorded, never cached) |
//!
//! Deterministic AI routes are POST endpoints whose responses are a pure
//! function of the request (completions/embeddings) — safe to deduplicate.
//! Streaming requests (`"stream": true`) produce SSE bodies that can never
//! be buffered verbatim, so they are excluded explicitly.

use blake3::Hasher;

/// POST routes with deterministic (cache-safe) responses. Matched as exact
/// path or path prefix segments on the UPSTREAM canonical path.
pub const AI_DETERMINISTIC_ROUTES: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/messages",
    "/v1/moderations",
    "/v1/responses",
];

/// Provider alias table: request path prefix → upstream base URL. Apps set
/// `OPENAI_BASE_URL=http://blackbox:9700/v1` and everything just works with
/// zero custom root CA certificates (Blackbox terminates plain HTTP locally
/// and speaks TLS upstream via rustls with bundled webpki roots).
pub const PROVIDER_ALIASES: &[(&str, &str)] = &[
    ("/v1/chat/completions", "https://api.openai.com"),
    ("/v1/completions", "https://api.openai.com"),
    ("/v1/embeddings", "https://api.openai.com"),
    ("/v1/models", "https://api.openai.com"),
    ("/v1/moderations", "https://api.openai.com"),
    ("/v1/uploads", "https://api.openai.com"),
    ("/v1/messages", "https://api.anthropic.com"),
    ("/v1/complete", "https://api.anthropic.com"),
];

/// `BLAKE3(tenant ‖ blake3(auth) ‖ method ‖ canonical_url ‖ body)`.
pub fn composite_key(
    tenant_id: &str,
    auth_header: &str,
    method: &str,
    canonical: &str,
    body: &[u8],
) -> [u8; 32] {
    let auth_inner = blake3::hash(auth_header.as_bytes());
    let mut h = Hasher::new();
    h.update(tenant_id.as_bytes());
    h.update(auth_inner.as_bytes());
    h.update(method.as_bytes());
    h.update(canonical.as_bytes());
    h.update(body);
    *h.finalize().as_bytes()
}

/// Hex form for logs / admin UI.
pub fn key_hex(key: &[u8; 32]) -> String {
    blake3::hash(key).to_hex().get(..16).unwrap_or("").to_string()
}

/// Does the (JSON) request body ask for streaming? Non-JSON bodies never
/// stream via this flag.
pub fn body_streams(body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    matches!(
        v.get("stream"),
        Some(serde_json::Value::Bool(true))
    )
}

/// Is the upstream *path* a deterministic AI POST route?
pub fn is_ai_route(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    AI_DETERMINISTIC_ROUTES.iter().any(|r| path == *r)
}

/// Full cacheability decision (see module table).
pub fn cacheable(
    method: &str,
    upstream_path: &str,
    cache_header: Option<&str>,
    body: &[u8],
) -> bool {
    if body_streams(body) {
        return false; // SSE can never be buffered verbatim
    }
    match cache_header.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v == "disable" || v == "off" || v == "no" => false,
        Some(v) if v == "enable" || v == "on" || v == "yes" => true,
        _ => {
            let m = method.to_ascii_uppercase();
            if m == "GET" || m == "HEAD" {
                return true;
            }
            if m == "POST" && is_ai_route(upstream_path) {
                return true;
            }
            false
        }
    }
}

/// Best-effort provider label for the ledger.
pub fn provider_for(host: &str, path: &str) -> &'static str {
    let host = host.to_ascii_lowercase();
    if host.starts_with("api.openai.com") {
        return "openai";
    }
    if host.starts_with("api.anthropic.com") {
        return "anthropic";
    }
    if host.starts_with("generativelanguage.googleapis.com") {
        return "google";
    }
    // Path fallback for mock/local upstreams and base-URL routing.
    if path.starts_with("/v1/messages") || path.starts_with("/v1/complete") {
        return "anthropic";
    }
    if is_ai_route(path) {
        return "openai";
    }
    "custom"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_key_separates_tenants_and_auth() {
        let body = br#"{"model":"gpt-4o-mini"}"#;
        let a = composite_key("tenant-a", "sk-aaa", "POST", "https://api.openai.com/v1/chat/completions", body);
        let b = composite_key("tenant-b", "sk-aaa", "POST", "https://api.openai.com/v1/chat/completions", body);
        let c = composite_key("tenant-a", "sk-bbb", "POST", "https://api.openai.com/v1/chat/completions", body);
        let d = composite_key("tenant-a", "sk-aaa", "POST", "https://api.openai.com/v1/chat/completions", body);
        assert_ne!(a, b, "tenant must be in the key");
        assert_ne!(a, c, "auth credential must be in the key");
        assert_eq!(a, d, "identical inputs -> identical key");
    }

    #[test]
    fn cacheability_matrix() {
        let chat = "/v1/chat/completions";
        assert!(cacheable("GET", "/anything", None, b""));
        assert!(cacheable("POST", chat, None, br#"{"model":"m"}"#));
        assert!(!cacheable("POST", chat, None, br#"{"model":"m","stream":true}"#));
        assert!(cacheable("POST", chat, None, br#"{"model":"m","stream":false}"#));
        assert!(!cacheable("POST", "/payments", None, br#"{"amount":1}"#));
        assert!(cacheable("POST", "/payments", Some("enable"), br#"{"amount":1}"#));
        assert!(!cacheable("GET", "/x", Some("disable"), b""));
        assert!(cacheable("POST", "/v1/messages/", None, br#"{"model":"claude"}"#));
        assert!(cacheable("POST", "/v1/messages?beta=true", None, br#"{"model":"claude"}"#));
    }

    #[test]
    fn provider_detection() {
        assert_eq!(provider_for("api.openai.com", "/v1/x"), "openai");
        assert_eq!(provider_for("api.anthropic.com", "/v1/messages"), "anthropic");
        assert_eq!(provider_for("127.0.0.1:8080", "/v1/chat/completions"), "openai");
        assert_eq!(provider_for("127.0.0.1:8080", "/v1/messages"), "anthropic");
        assert_eq!(provider_for("127.0.0.1:8080", "/api/pay"), "custom");
    }
}
