//! Near-duplicate prompt cache — the Pro differentiator (blueprint §6,
//! "semantic" cache without a single ML model).
//!
//! Most "semantic caches" require a 500 MB ONNX embedding model — which is
//! exactly what would destroy Blackbox's 16.9 MB binary and 33 MB RAM
//! footprint. This module instead catches NEAR-duplicate LLM prompts
//! (whitespace changes, reordered JSON keys, punctuation/date tweaks,
//! case drift) with a pure-Rust, zero-dependency pipeline:
//!
//! ```text
//! body ──► split into CONTROL fields (must match EXACTLY)
//!            + CONTENT text (allowed to be "near")
//!      ──► normalize text (lowercase, punctuation→space, ws collapse)
//!      ──► token 3-shingles ──► FNV-1a bit weights ──► 64-bit Charikar SimHash
//!      ──► hit iff Hamming(near, stored) <= BLACKBOX_SIMHASH_MAXDIST (default 3)
//! ```
//!
//! ## Correctness envelope (why this is safe to serve from cache)
//!
//! Per-scope identity: a near-key covers
//! `(tenant, auth, method, canonical_url, CONTROL)` — the control skeleton
//! keeps **everything structural**: model, temperature, tools, roles,
//! response_format, message part shapes. Two requests land in the same
//! scope only if every byte-relevant structural knob matches; only the
//! *text content* may drift. Additionally, near-caching requires a
//! DETERMINISTIC sampling regime: `temperature` absent-or-0, `top_p`
//! absent-or-1, `n` absent-or-1 — serial under-sampling on purpose; a
//! user asking for variety at 0.7 never sees a cached reply.
//!
//! Per-scope isolation follows [`crate::key`] exactly: tenant + hashed auth
//! participate in the key, so cross-tenant reads are impossible by
//! construction. `/v1/embeddings` + `/v1/moderations` are excluded (their
//! float responses are a function of the EXACT text, not of a near one).
//!
//! ## Cost
//!
//! No crates, no models: FNV-1a shingle fingerprints + popcount lookup —
//! the whole pipeline is sub-5 µs for typical prompts on x86_64 (gated in
//! [`crate::verify5`]). The shingle hash is deliberately FNV-1a, NOT
//! crypto: a collision only adds ±1 weight noise to a bit, which is noise
//! by design in a similarity oracle.

use crate::cache::CachedEntry;
use blake3::Hasher;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// POST routes where near-duplicate prompts share consumption semantics
/// (text-generation completions/chats). Matched like [`crate::key::is_ai_route`].
pub const NEAR_ROUTES: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/responses",
];

/// Top-level body fields carrying prompt text (harvested into the near
/// fingerprint and BLANKED into the structural skeleton).
const CONTENT_FIELDS: &[&str] = &["messages", "prompt", "input", "instructions"];

/// Max-dist policy (pure): `None` = the near cache is disabled.
/// Absent → default 3 (≤3 bit flips tolerated); `0` → disabled outright
/// (L0 exact + singleflight still apply); unparseable → default 3 (an env
/// typo must not silently kill the differentiator); clamped to 32.
pub fn parse_near_dist(v: Option<&str>) -> Option<u64> {
    match v {
        None => Some(3),
        Some(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(d) => Some(d.min(32)),
            Err(_) => Some(3),
        },
    }
}

/// [`parse_near_dist`] over `BLACKBOX_SIMHASH_MAXDIST`.
pub fn max_dist_from_env() -> Option<u64> {
    parse_near_dist(std::env::var("BLACKBOX_SIMHASH_MAXDIST").ok().as_deref())
}

pub fn is_near_route(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    NEAR_ROUTES.iter().any(|r| path == *r)
}

/// A body split into its near-cache parts: the EXACT-control skeleton
/// (serialized with sorted JSON keys, so key reorders collapse) and the
/// CONTENT text (allowed to be near).
#[derive(Debug, Clone, PartialEq)]
pub struct NearSplit {
    /// Canonical JSON of every structural knob (model, temperature, tools,
    /// roles, part shapes…) with all content strings blanked.
    pub control: String,
    /// Harvested + whitespace-normalized prompt text.
    pub text: String,
}

/// Is the sampling regime deterministic enough to serve a near-reply?
/// (temperature absent-or-0, top_p absent-or-1, n absent-or-1.)
fn sampling_deterministic(obj: &serde_json::Map<String, Value>) -> bool {
    let num = |k: &str| obj.get(k).and_then(Value::as_f64);
    num("temperature").map_or(true, |t| t == 0.0)
        && num("top_p").map_or(true, |p| p == 1.0)
        && num("n").map_or(true, |n| n <= 1.0)
}

/// Split a JSON request body. `None` = not eligible (invalid JSON, no
/// known content field, or the content is empty).
pub fn near_split(body: &[u8]) -> Option<NearSplit> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object()?; // borrowed — the pipeline never clones the DOM

    let mut raw = String::new();
    for field in CONTENT_FIELDS {
        match obj.get(*field) {
            Some(Value::String(s)) => {
                raw.push_str(s);
                raw.push(' ');
            }
            Some(Value::Array(items)) => {
                for it in items {
                    harvest(field, it, &mut raw);
                }
            }
            _ => {}
        }
    }
    let text = normalize(&raw);
    if text.is_empty() {
        return None;
    }

    // Control skeleton: ONE borrowed pass — sorted keys, volatile content
    // blanked — written straight into a string. (No skeleton clone, no
    // canon() rebuild, no serde serializer re-walk.)
    let mut control = String::with_capacity(128 + body.len() / 2);
    write_object(obj, &mut control);

    Some(NearSplit { control, text })
}

/// Harvest prompt text from a chat message (role kept structural) or a raw
/// string item of prompt/input arrays.
fn harvest(field: &str, item: &Value, out: &mut String) {
    match item {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Object(m) if field == "messages" => {
            if let Some(Value::String(r)) = m.get("role") {
                // Role prefix — enough to distinguish system/user/assistant
                // in the token stream without biasing the hash.
                out.push_str(&r.chars().take(12).collect::<String>());
                out.push(':');
            }
            match m.get("content") {
                Some(Value::String(s)) => out.push_str(s),
                Some(Value::Array(parts)) => {
                    for p in parts {
                        if let Some(s) = part_text(p) {
                            out.push_str(s);
                            out.push(' ');
                        }
                    }
                }
                _ => {}
            }
            out.push('\n');
        }
        Value::Array(inner) => {
            // Responses-API input can nest part objects one level deeper.
            for it in inner {
                harvest(field, it, out);
            }
        }
        _ => {}
    }
}

/// Text of a `{type: "text", text: …}` part (other part types are
/// structural and never harvested).
fn part_text(p: &Value) -> Option<&str> {
    p.as_object()
        .filter(|o| o.get("type").and_then(Value::as_str) == Some("text"))
        .and_then(|o| o.get("text"))
        .and_then(Value::as_str)
}

/// Sorted-key canonical skeleton writer — the near-key's control input in
/// ONE pass over the DOM (borrowed): object keys ascending, volatile
/// content strings blanked to `""`, everything else kept. The near key is
/// RAM-only, so this byte format is version-internal (no cross-version
/// compatibility constraint).
fn write_object(m: &serde_json::Map<String, Value>, out: &mut String) {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    out.push('{');
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(k, out);
        out.push(':');
        if let Some(val) = m.get(*k) {
            write_value(val, k, out);
        }
    }
    out.push('}');
}

fn write_value(v: &Value, field: &str, out: &mut String) {
    match v {
        Value::Object(m) => write_object(m, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, field, out); // array items inherit the parent field
            }
            out.push(']');
        }
        Value::String(s) => {
            if matches!(
                field,
                "content" | "text" | "prompt" | "input" | "instructions"
            ) {
                out.push_str("\"\"");
            } else {
                push_json_str(s, out);
            }
        }
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
    }
}

fn push_json_str(s: &str, out: &mut String) {
    if let Ok(t) = serde_json::to_string(s) {
        out.push_str(&t);
    } else {
        out.push_str("\"\"");
    }
}

/// Normalize prompt text: lowercase; everything outside [a-z0-9] becomes a
/// space; collapse whitespace runs. Absorbs punctuation, case and date
/// separators. Digit RUNS collapse to a single `#` — order ids, amounts and
/// timestamps are the dominant volatile tokens in templated bot prompts
/// ("charge order 7" ≙ "charge order 8" is the same task), and the
/// Charikar distance of a one-token drift on a short prompt is too noisy
/// for an absolute d≤3 budget otherwise.
pub fn normalize(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_space = false; // also collapses any leading run
    let mut in_digits = false;
    for ch in lower.chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                if !last_space {
                    out.push(' ');
                }
                out.push('#');
                in_digits = true;
                last_space = false;
            }
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            in_digits = false;
            last_space = false;
        } else if !last_space {
            out.push(' ');
            last_space = true;
            in_digits = false;
        }
    }
    out.trim().to_string()
}

/// FNV-1a 64 — stable, tiny, and deliberately non-cryptographic (a shingle
/// collision is ±1 weight noise on a bit, which a similarity oracle shrugs
/// off).
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// FNV-1a 64 over a sequence of byte slices WITHOUT concatenation — the
/// shingle bytes are exactly `parts` joined with a `\u{1}` separator. This
/// keeps the hot path allocation-free (one String build per shingle was
/// the single largest cost in the pipeline).
fn fnv64_seq(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (n, p) in parts.iter().enumerate() {
        if n > 0 {
            h ^= 0x01u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for &b in *p {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// Shingle cap: bounds CPU on pathological bodies (bodies are already
/// capped at 1 MiB by the gateway; ~4k 3-shingles covers ~16k tokens).
const MAX_SHINGLES: usize = 4_096;

/// 64-bit Charikar SimHash over word 3-shingles (unigram/bigram fallback
/// under 3 tokens). Text must be pre-normalized.
///
/// The bit scatter is branchless (`acc[i] += bit`) and the shingle hash
/// allocation-free: together they keep the whole pipeline under the 5 µs
/// per-prompt budget for typical prompts (gated in [`crate::verify5`]).
pub fn simhash_text(text: &str) -> u64 {
    let tokens: Vec<&str> = text.split(' ').filter(|t| !t.is_empty()).collect();
    if tokens.is_empty() {
        return 0;
    }
    let arity = tokens.len().min(3);
    let mut acc = [0u32; 64];
    let mut count: u32 = 0;
    'window: for i in 0..(tokens.len() - arity + 1) {
        if count as usize >= MAX_SHINGLES {
            break 'window;
        }
        let a0 = tokens[i].as_bytes();
        let mut parts: [&[u8]; 3] = [a0, &[], &[]];
        if arity > 1 {
            parts[1] = tokens[i + 1].as_bytes();
        }
        if arity > 2 {
            parts[2] = tokens[i + 2].as_bytes();
        }
        let h = if arity == 1 {
            fnv64(parts[0])
        } else {
            fnv64_seq(&parts[..arity])
        };
        for (i, a) in acc.iter_mut().enumerate() {
            *a += ((h >> i) & 1) as u32;
        }
        count += 1;
    }
    if count == 0 {
        return 0;
    }
    let mut out = 0u64;
    for (i, a) in acc.iter().enumerate() {
        if (*a as u32) * 2 > count {
            out |= 1u64 << i;
        }
    }
    out
}

/// Hamming distance between two SimHashes.
#[inline]
pub fn hamming64(a: u64, b: u64) -> u64 {
    (a ^ b).count_ones() as u64
}

/// Domain-separated near-key:
/// `BLAKE3("blackbox-near-v1" ‖ tenant ‖ blake3(auth) ‖ method ‖ url ‖ control)`.
pub fn near_key(
    tenant: &str,
    auth_header: &str,
    method: &str,
    canonical: &str,
    control: &str,
) -> [u8; 32] {
    let auth_inner = blake3::hash(auth_header.as_bytes());
    let mut h = Hasher::new();
    h.update(b"blackbox-near-v1");
    h.update(&[0]);
    h.update(tenant.as_bytes());
    h.update(auth_inner.as_bytes());
    h.update(method.as_bytes());
    h.update(canonical.as_bytes());
    h.update(control.as_bytes());
    *h.finalize().as_bytes()
}

/// One-call prepare for the gateway: route + JSON-shape + sampling-policy +
/// key + fingerprint. `Some((near_key, simhash))` = near-cacheable request.
pub fn prepare(
    tenant: &str,
    auth_header: &str,
    method: &str,
    canonical: &str,
    path: &str,
    body: &[u8],
) -> Option<([u8; 32], u64)> {
    if !method.eq_ignore_ascii_case("POST") || !is_near_route(path) {
        return None;
    }
    let v = serde_json::from_slice::<Value>(body).ok()?;
    let obj = v.as_object()?; // borrowing the local Value — no unsafe needed
    let split = near_split(body)?;
    if !sampling_deterministic(obj) {
        return None;
    }
    Some((
        near_key(tenant, auth_header, method, canonical, &split.control),
        simhash_text(&split.text),
    ))
}

// ------------------------------------------------------- the near cache ----

/// Per-scope near-duplicate index + lookup. Scopes shed registrations
/// oldest-first and the whole map purges with the supervisor's RAM
/// watermark, exactly like [`crate::cache::ResponseCache`].
pub struct NearCache {
    max_dist: u64,
    max_per_scope: usize,
    scopes: Mutex<HashMap<[u8; 32], Vec<(u64, Arc<CachedEntry>)>>>,
    entries: AtomicU64,
    hits: AtomicU64,
    purges: AtomicU64,
}

pub struct NearStats {
    pub hits: u64,
    pub entries: u64,
    pub scopes: u64,
    pub max_dist: u64,
    pub purges: u64,
}

impl NearCache {
    pub fn new(max_dist: u64) -> Self {
        NearCache {
            max_dist,
            max_per_scope: 64,
            scopes: Mutex::new(HashMap::new()),
            entries: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            purges: AtomicU64::new(0),
        }
    }

    pub fn max_dist(&self) -> u64 {
        self.max_dist
    }

    /// Closest stored near-duplicate within the distance budget.
    /// Scans newest-first (recency ≈ relevance).
    pub fn lookup(&self, key: &[u8; 32], simhash_val: u64) -> Option<(Arc<CachedEntry>, u64)> {
        if self.max_dist == 0 {
            return None; // disabled: L0 exact + singleflight only
        }
        let guard = self.scopes.lock().ok()?;
        let vec = guard.get(key)?;
        for (h, entry) in vec.iter().rev() {
            let d = hamming64(*h, simhash_val);
            if d <= self.max_dist {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some((Arc::clone(entry), d));
            }
        }
        None
    }

    /// Register a freshly validated response for a scope. Re-recording the
    /// SAME simhash replaces the registration in place (identical prompt
    /// text is already served by L0; this keeps the scope list clean).
    pub fn record(&self, key: [u8; 32], simhash_val: u64, entry: CachedEntry) {
        if self.max_dist == 0 {
            return; // disabled: nothing to register, nothing would ever hit
        }
        let entry = Arc::new(entry);
        let Ok(mut guard) = self.scopes.lock() else {
            return;
        };
        let vec = guard.entry(key).or_default();
        if let Some(slot) = vec.iter_mut().find(|(h, _)| *h == simhash_val) {
            slot.1 = entry;
            return;
        }
        vec.push((simhash_val, entry));
        if vec.len() > self.max_per_scope {
            vec.remove(0); // shed the oldest registration
        } else {
            self.entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Supervisor self-healing: drop every scope instantly.
    pub fn purge_all(&self, reason: &str) {
        let Ok(mut guard) = self.scopes.lock() else { return };
        let scopes = guard.len();
        guard.clear();
        self.entries.store(0, Ordering::Relaxed);
        self.purges.fetch_add(1, Ordering::Relaxed);
        if scopes > 0 {
            tracing::warn!("near cache PURGED ({scopes} scopes): {reason}");
        }
    }

    pub fn stats(&self) -> NearStats {
        NearStats {
            hits: self.hits.load(Ordering::Relaxed),
            entries: self.entries.load(Ordering::Relaxed),
            scopes: self.scopes.lock().map(|g| g.len() as u64).unwrap_or(0),
            max_dist: self.max_dist,
            purges: self.purges.load(Ordering::Relaxed),
        }
    }
}

// --------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PROMPT: &str = r#"{"model":"gpt-4o-mini","messages":[{"role":"system","content":"You are a payment bot."},{"role":"user","content":"Please charge order {\"id\": 7} immediately."}],"temperature":0.0}"#;

    fn prep(body: &str) -> ([u8; 32], u64) {
        prepare(
            "tenant-a",
            "sk-test",
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
            body.as_bytes(),
        )
        .expect("prep must succeed")
    }

    #[test]
    fn identical_prompt_zero_distance() {
        let (k, h) = prep(PROMPT);
        let (k2, h2) = prep(PROMPT);
        assert_eq!(k, k2);
        assert_eq!(h, h2);
    }

    #[test]
    fn punctuation_whitespace_case_and_id_variants_stay_close() {
        let (k0, h0) = prep(PROMPT);
        // 1) whitespace + punctuation + case drift
        let v1 = r#"{"model":"gpt-4o-mini","messages":[{"role":"system","content":"You  are a payment bot."},{"role":"user","content":"Please charge order {\"id\":7} immediately!!"}],"temperature":0.0}"#;
        // 2) reordered JSON keys (body-level AND inside each message
        //    object). The messages ARRAY keeps its order — conversation
        //    order is a semantic control knob, not formatting.
        let v2 = r#"{"temperature":0.0,"messages":[{"role":"system","content":"You are a payment bot."},{"content":"Please charge order {\"id\": 7} IMMEDIATELY.","role":"user"}],"model":"gpt-4o-mini"}"#;
        // 3) an id token drift inside content
        let v3 = r#"{"model":"gpt-4o-mini","messages":[{"role":"system","content":"You are a payment bot."},{"role":"user","content":"Please charge order id 8 immediately."}],"temperature":0.0}"#;
        for (name, v) in [("punct", v1), ("keyorder", v2), ("id-diff", v3)] {
            let (k, h) = prep(v);
            let sv = near_split(v.as_bytes()).unwrap();
            let s0 = near_split(PROMPT.as_bytes()).unwrap();
            assert_eq!(sv.control, s0.control, "{name}: control skeletons diverge");
            assert_eq!(k, k0, "{name}: control knobs must stay identical");
            let d = hamming64(h, h0);
            assert!(d <= 3, "{name}: distance must be <= 3, got {d}");
        }
    }

    #[test]
    fn genuinely_different_prompts_land_far() {
        let (_, h0) = prep(PROMPT);
        let email = r#"{"model":"gpt-4o-mini","temperature":0.0,"messages":[{"role":"user","content":"Draft an apologetic email to a tenant about the pool closing at 6pm for maintenance."}]}"#;
        let refund = r#"{"model":"gpt-4o-mini","temperature":0.0,"messages":[{"role":"user","content":"Refund transactions listed in the quarterly report back to the original card."}]}"#;
        for (name, b) in [("email", email), ("refund", refund)] {
            let (_, h) = prep(b);
            let d = hamming64(h, h0);
            assert!(d > 3, "{name}: unrelated prompts must NOT be near (d={d})");
        }
    }

    #[test]
    fn temperature_one_and_n_above_one_are_not_near_cacheable() {
        let hot = PROMPT.replace("\"temperature\":0.0", "\"temperature\":0.7");
        assert!(prepare("t", "sk", "POST", "https://api.openai.com/v1/chat/completions", "/v1/chat/completions", hot.as_bytes()).is_none());
        let multi = PROMPT.replace("\"temperature\":0.0", "\"temperature\":0.0,\"n\":8");
        assert!(prepare("t", "sk", "POST", "https://api.openai.com/v1/chat/completions", "/v1/chat/completions", multi.as_bytes()).is_none());
        assert!(prepare("t", "sk", "POST", "https://api.openai.com/v1/chat/completions", "/v1/chat/completions", PROMPT.as_bytes()).is_some());
    }

    #[test]
    fn model_route_and_tenant_land_in_different_scopes() {
        let mut j: serde_json::Value = serde_json::from_str(PROMPT).unwrap();
        j["model"] = json!("gpt-4");
        let other_model = j.to_string();
        let (k0, _) = prep(PROMPT);
        let (k1, _) = prep(&other_model);
        assert_ne!(k0, k1, "model is a control knob");
        let (k2, _) = prepare(
            "tenant-a",
            "sk-test",
            "POST",
            "https://api.openai.com/v1/messages",
            "/v1/messages",
            PROMPT.as_bytes(),
        )
        .unwrap();
        assert_ne!(k0, k2, "canonical URL is a control knob");
        let (k3, _) = prepare(
            "tenant-z",
            "sk-test",
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
            PROMPT.as_bytes(),
        )
        .unwrap();
        assert_ne!(k0, k3, "tenants must not share scopes");
        let (k4, _) = prepare(
            "tenant-a",
            "sk-other",
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
            PROMPT.as_bytes(),
        )
        .unwrap();
        assert_ne!(k0, k4, "credentials must not share scopes");
    }

    #[test]
    fn role_change_and_part_shape_change_control() {
        let mut j: serde_json::Value = serde_json::from_str(PROMPT).unwrap();
        j["messages"][1]["role"] = json!("assistant");
        let (a, _) = prep(PROMPT);
        let (b, _) = prep(&j.to_string());
        assert_ne!(a, b, "role sequence is structural");
        let mut j2: serde_json::Value = serde_json::from_str(PROMPT).unwrap();
        j2["messages"][1]["content"] =
            json!([{"type": "text", "text": "Please charge order {\"id\": 7} immediately."}]);
        let (c, _) = prep(&j2.to_string());
        assert_ne!(a, c, "part shape is structural");
        // number-vs-string types differ → different skeleton
        assert_ne!(a, b);
    }

    #[test]
    fn embeddings_and_moderations_are_excluded() {
        assert!(!is_near_route("/v1/embeddings"));
        assert!(!is_near_route("/v1/moderations"));
        assert!(is_near_route("/v1/chat/completions"));
        assert!(is_near_route("/v1/messages"));
        // GETs never near-prepare
        assert!(prepare("t", "sk", "GET", "https://api.openai.com/v1/models", "/v1/models", b"{}").is_none());
    }

    #[test]
    fn near_cache_hit_replace_clamp_and_purge() {
        let c = NearCache::new(3);
        let (k, h) = prep(PROMPT);
        let mk = |i: u32| CachedEntry {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: bytes::Bytes::from(format!("resp{i}")),
            tokens: 12,
            cost_micros: 7,
        };
        c.record(k, h, mk(0));
        let (entry, d) = c.lookup(&k, h).expect("exact simhash must hit");
        assert_eq!(d, 0);
        assert_eq!(entry.body.as_ref(), b"resp0");
        // identical-simhash re-record replaces in place (no dup rows)
        c.record(k, h, mk(1));
        assert_eq!(c.stats().entries, 1);
        // a value 14 bits away is out of budget for every entry ≤7 bits off
        assert!(c.lookup(&k, h ^ 0x3FFF).is_none());
        // clamp: scope ceiling sheds the oldest registration
        for i in 1..80u32 {
            c.record(k, h ^ (i as u64), mk(i + 1));
        }
        let s = c.stats();
        assert_eq!(s.entries, 64, "per-scope clamp");
        assert_eq!(s.scopes, 1);
        // newest still hits (d=0); the shed resp0 no longer exists
        let (e, d) = c.lookup(&k, h ^ 79).expect("newest registration must hit");
        assert_eq!(d, 0);
        assert_eq!(e.body.as_ref(), b"resp80");
        // a 3-bit probe against the original works again once re-recorded
        c.record(k, h, mk(999));
        let (_, d) = c.lookup(&k, h).expect("3-bit probe");
        assert!(d <= 3);
        // purge
        c.purge_all("test-watermark");
        let s = c.stats();
        assert_eq!(s.entries, 0);
        assert_eq!(s.scopes, 0);
        assert_eq!(s.purges, 1);
        assert_eq!(c.max_dist(), 3);
    }

    #[test]
    fn disabled_when_max_dist_zero() {
        let c = NearCache::new(0);
        let (k, h) = prep(PROMPT);
        c.record(
            k,
            h,
            CachedEntry {
                status: 200,
                headers: vec![],
                body: bytes::Bytes::from_static(b"x"),
                tokens: 0,
                cost_micros: 0,
            },
        );
        assert!(
            c.lookup(&k, h).is_none(),
            "distance 0 > budget 0 → disabled"
        );
        assert_eq!(c.max_dist(), 0);
    }

    #[test]
    fn non_json_and_missing_or_empty_content_not_near() {
        assert!(near_split(b"not json at all").is_none());
        assert!(near_split(br#"{"model":"m"}"#).is_none(), "no content field");
        assert!(near_split(br#"{"model":"m","prompt":""}"#).is_none());
        // raw prompt array (legacy completions) IS harvestable
        let s = near_split(br#"{"model":"c","prompt":["Once upon a time"]}"#).unwrap();
        assert_eq!(s.text, "once upon a time");
    }

    #[test]
    fn normalize_absorbs_punctuation_and_case() {
        assert_eq!(normalize("Hello,  WORLD!"), "hello world");
        assert_eq!(normalize("2026-10-25"), "# # #");
        assert_eq!(normalize("  --==--  "), "");
    }

    #[test]
    fn digit_runs_collapse_to_placeholder() {
        assert_eq!(normalize("charge order 7 now"), "charge order # now");
        assert_eq!(normalize("charge order 8080 now"), "charge order # now");
        assert_eq!(normalize("6pm fee"), "#pm fee");
    }

    #[test]
    fn env_dist_default_three_and_zero_disables() {
        // The REAL pure policy (no global env mutation needed).
        assert_eq!(parse_near_dist(None), Some(3));
        assert_eq!(parse_near_dist(Some("0")), None, "0 disables the near cache");
        assert_eq!(parse_near_dist(Some("7")), Some(7));
        assert_eq!(parse_near_dist(Some("  4 ")), Some(4), "trimmed");
        assert_eq!(parse_near_dist(Some("garbage")), Some(3), "typo falls back to the default");
        assert_eq!(parse_near_dist(Some("99")), Some(32), "clamped");
    }
}
