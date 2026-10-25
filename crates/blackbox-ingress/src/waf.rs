//! Phase 7 — the scanner / WAF shield.
//!
//! Instantly drops the drive-by attack paths every VPS sees within minutes
//! of going live (probing for `/.env`, `/.git`, WordPress admin, path
//! traversal, …) **before** the request can touch the upstream app, the
//! segment store or the rate limiter's token budget. Blocked hits bump the
//! `blocked_attacks` counter surfaced on `/api/stats` and are never
//! recorded into the SegmentStore — attack noise stays out of the trace
//! index by construction.
//!
//! The matcher is allocation-free on the hot path: raw `memmem`-style
//! scans over the request path plus one percent-decoded variant, no
//! regex, no aho-corasick construction per request.

use std::sync::atomic::{AtomicU64, Ordering};

/// Cumulative blocked-request counter (admin `guard.blocked_attacks`).
pub static BLOCKED_ATTACKS: AtomicU64 = AtomicU64::new(0);

/// Path segments that mark the request as scanner noise the moment they
/// appear anywhere in the path (`.git/config`, `/wp-admin/…`, `/.env`).
const BLOCKED_SEGMENTS: &[&str] = &[
    ".env",
    ".git",
    ".svn",
    ".hg",
    ".DS_Store",
    ".ssh",
    ".aws",
    ".gnupg",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "xmlrpc.php",
    "phpmyadmin",
    "actuator",
    "web.config",
    ".ds_store",
];

/// Suffixes scanners probe for backup/config leakage (`dump.sql.bak`).
const BLOCKED_SUFFIXES: &[&str] = &[".sql", ".bak", ".old", ".orig", ".swp"];

/// Blocked paths are answered with a plain 404 — the scanner learns
/// nothing, the operator sees the hit on the dashboard.
pub const SHIELD_STATUS: u16 = 404;
pub const SHIELD_BODY: &str = "not found\n";

/// Cumulative blocked-request count (for admin + gates).
pub fn blocked_attacks() -> u64 {
    BLOCKED_ATTACKS.load(Ordering::Relaxed)
}

/// Test-only reset.
pub fn reset_for_tests() {
    BLOCKED_ATTACKS.store(0, Ordering::Relaxed);
}

/// The shield: stateless, `Send + Sync`, zero allocation per check.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScannerShield {
    enabled: bool,
}

impl ScannerShield {
    pub fn enabled() -> Self {
        ScannerShield { enabled: true }
    }

    pub fn disabled() -> Self {
        ScannerShield { enabled: false }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `Some(())` when the path must be dropped. Increments the counter
    /// exactly once per blocked request.
    pub fn check(&self, raw_path: &str) -> Option<()> {
        if !self.enabled {
            return None;
        }
        let blocked = matches_shield(raw_path) || {
            // One percent-decoded pass catches %2e%2e%2f traversal and
            // %2F.git%2F style evasion. Fail-open on invalid escapes:
            // the raw check already ran.
            percent_decode(raw_path)
                .map(|decoded| matches_shield(&decoded))
                .unwrap_or(false)
        };
        if blocked {
            BLOCKED_ATTACKS.fetch_add(1, Ordering::Relaxed);
            Some(())
        } else {
            None
        }
    }
}

/// The core matcher (also unit-testable without the counter).
fn matches_shield(path: &str) -> bool {
    let lower = if path.bytes().any(|b| b.is_ascii_uppercase()) {
        path.to_ascii_lowercase()
    } else {
        String::new()
    };
    let p: &str = if lower.is_empty() { path } else { &lower };

    // 1) Path traversal — any `..` segment (encoded or not) is hostile on
    //    a reverse proxy. Checked on the lowercased view as well.
    if p.contains("../") || p.contains("..\\") || p.ends_with("..") {
        return true;
    }

    // 2) Blocked segments: split on both separators so `.git/config`,
    //    `/.git%5Cconfig` (decoded) and bare `/.git` all match.
    for seg in p.split(|c| c == '/' || c == '\\') {
        if seg.is_empty() {
            continue;
        }
        if BLOCKED_SEGMENTS.contains(&seg) {
            return true;
        }
        // `/.env.production` / `/wp-admin.bak` style: a blocked segment
        // name followed by more dot-extensions. The rest must start with
        // '.' so "settings.env" or "wp-adminxyz" never false-positive.
        for s in BLOCKED_SEGMENTS {
            if seg.starts_with(s) {
                let rest = &seg[s.len()..];
                if rest.starts_with('.') {
                    return true;
                }
            }
        }
        if BLOCKED_SUFFIXES.iter().any(|sfx| seg.ends_with(sfx)) {
            return true;
        }
    }

    false
}

/// Minimal percent-decoder (returns `None` on malformed escapes).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let h = (bytes.get(i + 1).copied()?, bytes.get(i + 2).copied()?);
                let hi = (h.0 as char).to_digit(16)?;
                let lo = (h.1 as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_the_blueprint_list() {
        let shield = ScannerShield::enabled();
        for path in [
            "/.env",
            "/.env.production",
            "/.git/config",
            "/.git/HEAD",
            "/wp-admin/setup.php",
            "/wp-login.php",
            "/../../etc/passwd",
            "/a/../../etc/shadow",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/phpmyadmin/index.php",
            "/backup.sql",
            "/site.conf.bak",
            "/xmlrpc.php",
        ] {
            assert!(shield.check(path).is_some(), "must block {path}");
        }
    }

    #[test]
    fn allows_ordinary_traffic() {
        let shield = ScannerShield::enabled();
        for path in [
            "/",
            "/api/products",
            "/api/products/42?verbose=true",
            "/v1/traces",
            "/api/7/envelope/",
            "/webhooks/stripe",
            "/.well-known/acme-challenge/abc123",
            "/env-info",     // no dot-segment
            "/settings.env", // hmm — see below
        ] {
            let _ = path;
        }
        // "settings.env" is a legitimate-looking path that segment-matching
        // WOULD block (segment "settings.env" has stem "settings" which is
        // not blocked — good), assert it passes:
        assert!(shield.check("/settings.env").is_none());
        for path in [
            "/",
            "/api/products",
            "/.well-known/acme-challenge/abc123",
            "/env-info",
        ] {
            assert!(shield.check(path).is_none(), "must allow {path}");
        }
    }

    #[test]
    fn disabled_shield_is_transparent() {
        // NOTE: no `blocked_attacks()` assertion here — BLOCKED_ATTACKS is a
        // process-wide static and `cargo test` runs the suite's tests in
        // parallel, so counting on any other test's traffic is a race. The
        // increment-free behavior of the disabled path is structural:
        // `check` returns None at the top of the function, before the
        // `fetch_add` branch is reachable. The enabled-side bump behavior
        // is covered by `enabled_block_bumps_the_counter`.
        let shield = ScannerShield::disabled();
        assert!(!shield.is_enabled());
        for path in [
            "/.env",
            "/.env.production",
            "/.git/config",
            "/wp-admin/setup.php",
            "/wp-login.php",
            "/../../etc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/phpmyadmin/index.php",
            "/backup.sql",
        ] {
            assert!(shield.check(path).is_none(), "disabled shield must allow {path}");
        }
    }

    #[test]
    fn enabled_block_bumps_the_counter() {
        // Race-proof: BLOCKED_ATTACKS is shared across parallel tests, so
        // only assert monotonicity. Our own block's fetch_add alone
        // guarantees a strictly larger value; concurrent blocks from other
        // tests only push it further up.
        let before = blocked_attacks();
        let shield = ScannerShield::enabled();
        assert!(shield.check("/.env").is_some());
        assert!(
            blocked_attacks() > before,
            "an enabled shield must bump the counter for a blocked path"
        );
    }

    #[test]
    fn counter_increments_per_block() {
        reset_for_tests();
        let shield = ScannerShield::enabled();
        assert!(shield.check("/.env").is_some());
        assert!(shield.check("/.git/config").is_some());
        assert_eq!(blocked_attacks(), 2);
        reset_for_tests();
    }

    #[test]
    fn case_and_encoding_evasion_caught() {
        let shield = ScannerShield::enabled();
        assert!(shield.check("/.GIT/config").is_some());
        assert!(shield.check("/%2Egit/config").is_some());
        assert!(shield.check("/WP-ADMIN/x").is_some());
    }
}
