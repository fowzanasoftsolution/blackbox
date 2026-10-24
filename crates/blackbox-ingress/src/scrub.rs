//! Edge PII scrubber — the flight recorder must never persist secrets.
//!
//! Runs on every captured header snapshot and JSON body **before framing**:
//!
//! - **Headers**: `authorization`, `cookie`, `set-cookie`, `x-api-key` (plus
//!   any name where one of those tokens appears hyphen/underscore-bounded,
//!   e.g. `x-custom-authorization`) → value replaced with `[REDACTED]`.
//! - **JSON bodies**: values under keys matching `password`, `secret`,
//!   `token`, `credit_card`, `cvv` (case-insensitive, per the spec list)
//!   are replaced in place — strings with `"[REDACTED]"`, numbers with `0`,
//!   booleans/null with `null`, whole objects/arrays with `"[REDACTED]"`.
//!
//! Matching uses `aho-corasick` with `ascii_case_insensitive` — a single
//! SIMD multi-pattern pass over the buffer, O(n + matches).

use aho_corasick::AhoCorasick;

/// Value substituted for redacted header values / string JSON values.
pub const REDACTED: &str = "[REDACTED]";

/// Tokens that make a HEADER name sensitive.
const HEADER_TOKENS: &[&str] = &["authorization", "cookie", "set-cookie", "x-api-key"];

/// JSON KEYS whose VALUES are sensitive.
const JSON_KEYS: &[&str] = &["password", "secret", "token", "credit_card", "cvv"];

/// Whether a match position sits between non-alphanumeric boundaries inside
/// `name` (so `authorization` matches inside `x-custom-authorization` but
/// not inside `authorization2` or `unauthorized`).
fn bounded_match(hay: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !hay[start - 1].is_ascii_alphanumeric();
    let after_ok = end == hay.len() || !hay[end].is_ascii_alphanumeric();
    before_ok && after_ok
}

#[derive(Debug, Clone)]
pub struct Scrubber {
    header_auto: AhoCorasick,
    json_auto: AhoCorasick,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrubber {
    pub fn new() -> Self {
        let header_auto = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(HEADER_TOKENS)
            .expect("static patterns compile");
        let json_auto = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(JSON_KEYS)
            .expect("static patterns compile");
        Scrubber {
            header_auto,
            json_auto,
        }
    }

    /// Is this header name sensitive?
    pub fn is_sensitive_header(&self, name: &str) -> bool {
        let name = name.trim();
        for m in self.header_auto.find_iter(name) {
            if bounded_match(name.as_bytes(), m.start(), m.end()) {
                return true;
            }
        }
        false
    }

    /// Scrub a header list in place: sensitive names get `[REDACTED]`.
    /// (Names are preserved; values are what leaks.)
    pub fn scrub_headers(&self, headers: &mut Vec<(String, String)>) {
        for (name, value) in headers.iter_mut() {
            if self.is_sensitive_header(name) {
                *value = REDACTED.to_string();
            }
        }
    }

    /// Redact sensitive JSON values in place. Returns true if the buffer
    /// was modified. Non-JSON input passes through untouched (the matcher
    /// only fires at `key":"`-shaped positions).
    pub fn scrub_json(&self, body: &mut Vec<u8>) -> bool {
        let original_len = body.len();
        let matches: Vec<(usize, usize)> = self
            .json_auto
            .find_iter(body.as_slice())
            .map(|m| (m.start(), m.end()))
            .collect();
        if matches.is_empty() {
            return false;
        }

        let mut out: Vec<u8> = Vec::with_capacity(original_len);
        let mut copied: usize = 0;
        let src = body.as_slice();

        for (m_start, m_end) in matches {
            if m_start < copied {
                continue; // inside an already-redacted region
            }
            // The match must sit inside a quoted key: scan back over key-name
            // characters to the opening quote (so `access_token` matches, but
            // `note: "my token: x"` does not).
            let mut s = m_start;
            while s > 0
                && (src[s - 1].is_ascii_alphanumeric() || src[s - 1] == b'_' || src[s - 1] == b'-')
            {
                s -= 1;
            }
            if s == 0 || src[s - 1] != b'"' {
                continue; // not a key position ("token" appearing inside a value)
            }
            // From the key's closing quote, expect ws ':' ws then a value.
            // Forward-scan over remaining key-name chars first (so the key
            // `secrets` matches the pattern `secret` too).
            let mut p = m_end;
            while p < src.len()
                && (src[p].is_ascii_alphanumeric() || src[p] == b'_' || src[p] == b'-')
            {
                p += 1;
            }
            if p >= src.len() || src[p] != b'"' {
                continue; // key's closing quote expected right after the name
            }
            p += 1;
            while p < src.len() && src[p].is_ascii_whitespace() {
                p += 1;
            }
            if p >= src.len() || src[p] != b':' {
                continue; // not a key position ("token" appearing inside a value)
            }
            p += 1;
            while p < src.len() && src[p].is_ascii_whitespace() {
                p += 1;
            }
            if p >= src.len() {
                continue;
            }

            // Find the end of the value at `p` and its replacement.
            // NOTE: string/object/array regions INCLUDE their delimiters, so
            // the replacement keeps the value a valid JSON string.
            let (val_end, replacement): (usize, &[u8]) = match src[p] {
                b'"' => match string_end(src, p) {
                    Some(end) => (end, b"\"[REDACTED]\""),
                    None => continue, // unterminated string — leave alone
                },
                b'-' | b'0'..=b'9' => {
                    let mut e = p;
                    while e < src.len()
                        && (src[e].is_ascii_digit()
                            || src[e] == b'.'
                            || src[e] == b'-'
                            || src[e] == b'+'
                            || src[e] == b'e'
                            || src[e] == b'E')
                    {
                        e += 1;
                    }
                    (e, b"0")
                }
                b't' | b'f' | b'n' => {
                    // true / false / null literal
                    let mut e = p;
                    while e < src.len() && src[e].is_ascii_alphabetic() {
                        e += 1;
                    }
                    (e, b"null")
                }
                b'{' | b'[' => match balanced_end(src, p) {
                    Some(end) => (end, b"\"[REDACTED]\""),
                    None => continue, // unbalanced — malformed, leave alone
                },
                _ => continue,
            };

            out.extend_from_slice(&src[copied..p]);
            out.extend_from_slice(replacement);
            copied = val_end;
        }
        out.extend_from_slice(&src[copied..]);

        if out.len() != original_len || out != *body {
            *body = out;
            true
        } else {
            false
        }
    }
}

/// Given `src[at] == '"'` (an opening quote), return the index just past the
/// matching closing quote, honoring `\"` escapes.
fn string_end(src: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while i < src.len() {
        match src[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Given `src[at]` is `{` or `[`, return the index just past its balanced
/// closing bracket, ignoring brackets inside strings.
fn balanced_end(src: &[u8], at: usize) -> Option<usize> {
    let (open, close) = match src[at] {
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let mut depth = 0usize;
    let mut i = at;
    let mut in_string = false;
    while i < src.len() {
        let b = src[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_string = true,
                b if b == open => depth += 1,
                b if b == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrub_json(s: &str, sc: &Scrubber) -> String {
        let mut buf = s.as_bytes().to_vec();
        sc.scrub_json(&mut buf);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn sensitive_headers_detected_case_insensitively() {
        let sc = Scrubber::new();
        for name in [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "cookie",
            "Set-Cookie",
            "x-api-key",
            "X-API-KEY",
            "x-custom-authorization",
            "x_auth_token_bearer", // 'token'? no — header tokens don't include token; but 'authorization' not here. This must be FALSE.
        ] {
            match name {
                "x_auth_token_bearer" => assert!(!sc.is_sensitive_header(name)),
                _ => assert!(sc.is_sensitive_header(name), "expected sensitive: {name}"),
            }
        }
        assert!(!sc.is_sensitive_header("content-type"));
        assert!(!sc.is_sensitive_header("x-authorization2"));
        assert!(!sc.is_sensitive_header("unauthorized-check"));
    }

    #[test]
    fn headers_redacted_in_place() {
        let sc = Scrubber::new();
        let mut headers = vec![
            ("authorization".to_string(), "Bearer sk-live-123".to_string()),
            ("Cookie".to_string(), "session=xyz".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("x-api-key".to_string(), "k-123".to_string()),
        ];
        sc.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, REDACTED);
        assert_eq!(headers[1].1, REDACTED);
        assert_eq!(headers[2].1, "application/json");
        assert_eq!(headers[3].1, REDACTED);
    }

    #[test]
    fn json_string_values_redacted() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{"user":"ana","password":"hunter2","note":"ok"}"#,
            &sc,
        );
        assert_eq!(
            out,
            r#"{"user":"ana","password":"[REDACTED]","note":"ok"}"#
        );
    }

    #[test]
    fn json_case_insensitive_and_camelcase() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{"PassWord":"x","CREDIT_CARD":"4111","Cvv":123,"SECRET":{"nested":"y"}}"#,
            &sc,
        );
        assert!(out.contains(r#""PassWord":"[REDACTED]""#));
        assert!(out.contains(r#""CREDIT_CARD":"[REDACTED]""#));
        assert!(out.contains(r#""Cvv":0"#));
        assert!(out.contains(r#""SECRET":"[REDACTED]""#));
    }

    #[test]
    fn json_substring_values_untouched() {
        let sc = Scrubber::new();
        // "token" appears as a VALUE, not a key — must stay.
        let out = scrub_json(r#"{"note":"my password: hunter2","n":1}"#, &sc);
        assert_eq!(out, r#"{"note":"my password: hunter2","n":1}"#);
    }

    #[test]
    fn json_numbers_bools_redacted_validly() {
        let sc = Scrubber::new();
        let out = scrub_json(r#"{"token":42,"secret":true,"cvv":null}"#, &sc);
        assert_eq!(out, r#"{"token":0,"secret":null,"cvv":null}"#);
    }

    #[test]
    fn nested_objects_arrays_wholly_redacted() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{"a":1,"password":{"nested":"deep","x":[1,2,{"y":"z"}]},"b":2}"#,
            &sc,
        );
        assert_eq!(out, r#"{"a":1,"password":"[REDACTED]","b":2}"#);

        let out2 = scrub_json(r#"{"secrets":["a","b"],"keep":true}"#, &sc);
        assert_eq!(out2, r#"{"secrets":"[REDACTED]","keep":true}"#);
    }

    #[test]
    fn key_name_prefixes_match() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{"access_token":"abc","user_token":"def","stripe_secret":"ghi"}"#,
            &sc,
        );
        assert!(out.contains(r#""access_token":"[REDACTED]""#), "{out}");
        assert!(out.contains(r#""user_token":"[REDACTED]""#));
        assert!(out.contains(r#""stripe_secret":"[REDACTED]""#));
    }

    #[test]
    fn multiple_occurrences_and_whitespace() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{ "password" : "a" , "password":"b" }"#,
            &sc,
        );
        assert!(out.contains(r#""password":"[REDACTED]""#), "{out}");
        assert!(!out.contains("\"a\""));
        assert!(!out.contains("\"b\""));
    }

    #[test]
    fn non_json_binary_untouched() {
        let sc = Scrubber::new();
        let mut buf = b"\x00\x01password\x02\xff".to_vec();
        // No '"' before the match, no ':' after → no changes.
        let changed = sc.scrub_json(&mut buf);
        assert!(!changed);
    }

    #[test]
    fn escaped_strings_handled() {
        let sc = Scrubber::new();
        let out = scrub_json(
            r#"{"password":"has \"quotes\" and \\ backslash","ok":1}"#,
            &sc,
        );
        assert_eq!(
            out,
            r#"{"password":"[REDACTED]","ok":1}"#
        );
    }
}
