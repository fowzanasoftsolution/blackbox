//! Response validator — the soft-error cache guard (Landmine #6).
//!
//! Provider rate-limits frequently answer **HTTP 200** with a JSON body
//! like `{"error": {"message": "rate_limit_exceeded"}}`. Caching that
//! would poison every subsequent identical request for the cache lifetime.
//! [`validate`] refuses to bless anything but a fully healthy response:
//!
//! 1. status must be exactly `200 OK`;
//! 2. `application/json` bodies must parse as COMPLETE JSON (truncated
//!    streams are rejected);
//! 3. a top-level JSON object must NOT contain an `"error"` key;
//! 4. a top-level `"status"` string must NOT be `"failed"`.

/// Outcome of the cache-insertion validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Cache-worthy: 200 + complete JSON + no soft-error markers
    /// (or a non-JSON body, which is cached as opaque bytes).
    Cacheable,
    /// Valid JSON but a soft-error payload — NEVER cache.
    SoftError,
    /// Wrong status / truncated JSON — NEVER cache.
    Unhealthy,
}

/// Validate an upstream response for cache insertion.
pub fn validate(status: u16, content_type: Option<&str>, body: &[u8]) -> Verdict {
    if status != 200 {
        return Verdict::Unhealthy;
    }
    let is_json = content_type
        .map(|ct| {
            let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            ct == "application/json" || ct.ends_with("+json")
        })
        .unwrap_or(false);
    if !is_json {
        return Verdict::Cacheable; // opaque bytes (images, binaries, text)
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(map)) => {
            if map.contains_key("error") {
                return Verdict::SoftError;
            }
            if matches!(
                map.get("status"),
                Some(serde_json::Value::String(s)) if s == "failed"
            ) {
                return Verdict::SoftError;
            }
            Verdict::Cacheable
        }
        Ok(_) => Verdict::Cacheable, // top-level array/scalar JSON
        Err(_) => Verdict::Unhealthy, // truncated or invalid JSON
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CT: Option<&str> = Some("application/json");

    #[test]
    fn healthy_json_is_cacheable() {
        let v = validate(200, CT, br#"{"id":"x","usage":{"total_tokens":3}}"#);
        assert_eq!(v, Verdict::Cacheable);
    }

    #[test]
    fn soft_error_200_is_rejected() {
        let v = validate(200, CT, br#"{"error":{"message":"rate_limit_exceeded"}}"#);
        assert_eq!(v, Verdict::SoftError);
    }

    #[test]
    fn failed_status_is_rejected() {
        assert_eq!(validate(200, CT, br#"{"status":"failed"}"#), Verdict::SoftError);
        assert_eq!(validate(200, CT, br#"{"status":"succeeded"}"#), Verdict::Cacheable);
    }

    #[test]
    fn truncated_json_is_rejected() {
        let v = validate(200, CT, br#"{"id":"x","choices":[{"message":{"conte"#);
        assert_eq!(v, Verdict::Unhealthy);
    }

    #[test]
    fn non_200_is_rejected() {
        assert_eq!(validate(201, CT, br#"{"ok":true}"#), Verdict::Unhealthy);
        assert_eq!(validate(429, CT, br#"{"error":"slow down"}"#), Verdict::Unhealthy);
    }

    #[test]
    fn non_json_bytes_are_cacheable_opaque() {
        assert_eq!(validate(200, Some("image/png"), &[0u8, 1, 2, 3]), Verdict::Cacheable);
        assert_eq!(validate(200, Some("text/plain"), b"plain ok"), Verdict::Cacheable);
    }

    #[test]
    fn error_key_nested_only_is_fine() {
        // Only TOP-LEVEL "error" poisons; nested keys are legitimate payloads.
        assert_eq!(
            validate(200, CT, br#"{"data":{"error":"ignored"}}"#),
            Verdict::Cacheable
        );
    }
}
