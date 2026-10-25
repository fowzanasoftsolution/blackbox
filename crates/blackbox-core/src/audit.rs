//! Tamper-evident audit chain (blueprint §6 — SSO/Audit compliance layer).
//!
//! An append-only JSONL file (`<data>/audit.log`) where every line is a
//! state-touch record chained over SHA-256:
//!
//! ```text
//! {"seq":1,"ts":…,"src":"queue","ev":"enqueue","tid":"…","d":"…","prev":"<h0>","hash":"<h1>"}
//! {"seq":2,…,"prev":"<h1>","hash":"<h2>"}
//! ```
//!
//! `hash = SHA256(payload)` where the payload is the line's exact byte
//! prefix through `"prev":"…"` (everything except the trailing `"hash"`).
//! Interior edits, insertions and deletions all break the chain. Every
//! 1,024 records a **checkpoint** line commits the running anchor and
//! fsyncs — the `(seq, hash)` anchor is the exportable trust root
//! (`blackbox audit current-anchor` / [`current_anchor`]): once anchored
//! externally (CI job → KMS/cosign note), any truncation of history is
//! detectable, because [`verify`] refuses a chain that ends before the
//! exported anchor.
//!
//! Zero keys needed for local tamper-evidence; enterprises pin their own
//! anchor. Zero I/O on the hot path until [`init`] runs — [`record`]
//! no-ops entirely when auditing was never enabled. The node runs [`init`]
//! at boot by default (`BLACKBOX_AUDIT=0` escapes).

use crate::schema::now_ms;
use crate::StorageError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Commit a checkpoint line + fsync every N records.
const CHECKPOINT_EVERY: u64 = 1_024;

static ENABLED: AtomicBool = AtomicBool::new(false);
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

struct Active {
    file: File,
    seq: u64,
    prev: String,
    /// Non-checkpoint records committed since this chain started (survives
    /// restarts via [`resume_state`]; checkpoint lines consume their own
    /// chain seqs, so `seq` alone cannot tell you the record count).
    records: u64,
    path: PathBuf,
}

fn io_err(e: std::io::Error) -> StorageError {
    StorageError::Io(e)
}

/// Enable auditing under `dir` (creates `dir/audit.log`). Idempotent for
/// the same dir; a RESTART resumes the existing chain (the running hash is
/// recovered from the file's last line) — restarts never fork history.
pub fn init(dir: &Path) -> Result<(), StorageError> {
    std::fs::create_dir_all(dir).map_err(io_err)?;
    let path = dir.join("audit.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(io_err)?;
    let (seq, prev, records) = resume_state(&path)?;
    let mut guard = ACTIVE.lock().map_err(|e| {
        StorageError::Db(format!("audit lock poisoned: {e}"))
    })?;
    // Re-init for the same path only refreshes the handle (tests); another
    // data dir in one process replaces the chain (unusual but explicit).
    if let Some(a) = guard.as_mut() {
        if a.path == path && a.seq == seq && a.prev == prev && a.records == records {
            return Ok(());
        }
    }
    *guard = Some(Active { file, seq, prev, records, path });
    ENABLED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Restart recovery: `(seq, prev-hash, records)` of the last committed
/// chain, or `(0, zero-hash, 0)` for a fresh log.
fn resume_state(path: &Path) -> Result<(u64, String, u64), StorageError> {
    let Ok(f) = File::open(path) else {
        return Ok((0, ZERO_ANCHOR.into(), 0));
    };
    let mut last: Option<String> = None;
    let mut records = 0u64;
    for line in BufReader::new(f).lines() {
        let line = line.map_err(io_err)?;
        if !line.trim().is_empty() {
            if field_str(&line, "ev") != Some("checkpoint") {
                records += 1;
            }
            last = Some(line);
        }
    }
    let Some(line) = last else {
        return Ok((0, ZERO_ANCHOR.into(), 0));
    };
    let Some((seq, hash)) = parse_seq_and_hash(&line) else {
        return Err(StorageError::Db(format!(
            "audit resume: unparseable last line in {}",
            path.display()
        )));
    };
    Ok((seq, hash, records))
}

/// Emit one event. No-op unless [`init`] ran (the node runs it at boot;
/// `BLACKBOX_AUDIT=0` escapes).
pub fn record(src: &str, ev: &str, tid: &str, detail: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Ok(mut guard) = ACTIVE.lock() else { return };
    let Some(a) = guard.as_mut() else { return };
    if a.commit(src, ev, tid, detail).is_ok() {
        a.records += 1;
        if a.seq % CHECKPOINT_EVERY == 0 {
            // Checkpoint: another chained line that freezes the running
            // anchor and fsyncs it. It documents how many RECORDS (checkpoint
            // lines excluded) the frozen anchor covers — [`verify`] recomputes
            // the same count from `seq − 1 − prior checkpoints`.
            let anchor = a.prev.clone();
            let count = a.records;
            let _ = a.commit(
                "audit",
                "checkpoint",
                "",
                &format!("records_before={count} anchor={anchor}"),
            );
            let _ = a.file.sync_all();
        }
    }
}

impl Active {
    fn commit(&mut self, src: &str, ev: &str, tid: &str, detail: &str) -> std::io::Result<()> {
        self.seq += 1;
        let ts = now_ms();
        let payload = format!(
            "{{\"seq\":{},\"ts\":{},\"src\":\"{}\",\"ev\":\"{}\",\"tid\":\"{}\",\"d\":\"{}\",\"prev\":\"{}\"",
            self.seq,
            ts,
            esc(src),
            esc(ev),
            esc(tid),
            esc(detail),
            self.prev
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let hex = hex_lower(&hasher.finalize());
        let line = format!("{payload},\"hash\":\"{hex}\"}}\n");
        self.file.write_all(line.as_bytes())?;
        self.prev = hex;
        Ok(())
    }
}

/// `(seq, hash)` of the last committed record — the exportable anchor.
pub fn current_anchor() -> Option<(u64, String)> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let Ok(guard) = ACTIVE.lock() else { return None };
    let a = guard.as_ref()?;
    Some((a.seq, a.prev.clone()))
}

/// `(seq, hash)` of the last line of `<dir>/audit.log`, read straight from
/// the FILE TAIL without activating auditing — what `blackbox audit
/// current-anchor` reports for offline anchoring. Export it into external
/// storage (CI → KMS/cosign note) and later pass it back via
/// `audit verify --anchor seq:hash` ([`verify`] detects any truncation of
/// the anchored history). `None` when the log is absent or empty.
pub fn read_anchor(dir: &Path) -> Option<(u64, String)> {
    let (seq, hash, _) = resume_state(&dir.join("audit.log")).ok()?;
    if seq == 0 {
        None // fresh chain: nothing to anchor yet
    } else {
        Some((seq, hash))
    }
}

const ZERO_ANCHOR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ------------------------------------------------------------ verification --

/// What [`verify`] reports about a clean chain.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditSummary {
    pub records: u64,
    pub checkpoints: u64,
    pub per_src: BTreeMap<String, u64>,
    pub last_seq: u64,
    pub last_anchor: String,
}

/// Exactly where and why a chain broke.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditFault {
    /// 1-based file line number (0 = pre-pass problems, e.g. missing file or
    /// a violation of an externally exported anchor).
    pub line_no: usize,
    pub reason: String,
}

/// Full re-verification of `<dir>/audit.log`:
///
/// 1. every line's `hash` recomputed over its exact payload bytes,
/// 2. `prev` equals the hash of the previous line (chain continuity),
/// 3. `seq` is 1, 2, 3, … with no gaps (interior deletion detection),
/// 4. checkpoint lines carry `records_before=<seq−1−prior checkpoints>`
///    (checkpoint lines consume their own chain seqs),
/// 5. when `expected=(seq, hash)` is provided (an externally exported
///    anchor), the chain must CONTAIN that seq with the exact hash —
///    truncation BELOW the anchor is detectable (the file may legitimately
///    extend past it; only the anchored line itself must be verbatim).
pub fn verify(dir: &Path, expected: Option<(u64, String)>) -> Result<AuditSummary, AuditFault> {
    let path = dir.join("audit.log");
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            return Err(AuditFault {
                line_no: 0,
                reason: format!("no audit log at {}", path.display()),
            })
        }
    };

    let mut summary = AuditSummary {
        records: 0,
        checkpoints: 0,
        per_src: BTreeMap::new(),
        last_seq: 0,
        last_anchor: ZERO_ANCHOR.into(),
    };

    let mut anchor_ok = expected.is_none();
    let anchor_spec = expected.clone();

    for (idx, maybe) in BufReader::new(file).lines().enumerate() {
        let line = match maybe {
            Ok(l) => l,
            Err(e) => {
                return Err(AuditFault {
                    line_no: idx + 1,
                    reason: format!("unreadable line: {e}"),
                })
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with('{') || !line.ends_with('}') {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "malformed record (missing braces)".into(),
            });
        }

        // Parse the fixed-order fields (our own writer's schema).
        let seq = match field_digits(&line, "seq") {
            Ok(n) => n,
            Err(_) => {
                return Err(AuditFault {
                    line_no: idx + 1,
                    reason: "missing or malformed seq".into(),
                })
            }
        };
        if seq != summary.last_seq + 1 {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: format!("seq break: expected {}, got {seq}", summary.last_seq + 1),
            });
        }

        // hash: must exist as the LAST field — find its exact payload span.
        let Some(hash_start) = line.rfind(",\"hash\":\"") else {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "missing hash".into(),
            });
        };
        let after = &line[hash_start + 9..];
        let Some(close) = after.rfind("\"}") else {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "malformed hash".into(),
            });
        };
        let hash_hex = &after[..close];
        if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "malformed hash digest".into(),
            });
        }
        let payload = &line[..hash_start];
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let recomputed = hex_lower(&hasher.finalize());
        if recomputed != hash_hex {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: format!(
                    "hash break (record edited): expected {recomputed}"
                ),
            });
        }

        // Exported-anchor check (correct home: AFTER the hash spans above
        // exist). At the anchored seq the line's hash must be verbatim;
        // hash-tampering at that line already faulted as "hash break", so a
        // false anchor here only means an internally-consistent DIFFERENT
        // history (full rewrite) — reported post-loop as divergence. The
        // file may extend past the anchor; only this line must match.
        if let Some((want_seq, want_hash)) = &anchor_spec {
            if seq == *want_seq && hash_hex == want_hash.as_str() {
                anchor_ok = true;
            }
        }

        // prev: chain continuity. payload ends: …"prev":"<hex64>"
        let Some(prev_start) = payload.rfind(",\"prev\":\"") else {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "missing prev".into(),
            });
        };
        let prev_hex = &payload[prev_start + 9..payload.len() - 1];
        if prev_hex != summary.last_anchor.as_str() {
            return Err(AuditFault {
                line_no: idx + 1,
                reason: "prev break: chain hash mismatch".to_string(),
            });
        }

        // Checkpoint bookkeeping (src/ev are our own simple columns).
        let src = field_str(&line, "src").unwrap_or("").to_string();
        let ev = field_str(&line, "ev").unwrap_or("").to_string();
        if ev == "checkpoint" {
            if src != "audit" {
                return Err(AuditFault {
                    line_no: idx + 1,
                    reason: "checkpoint from non-audit source".into(),
                });
            }
            let d = unesc(field_str(&line, "d").unwrap_or(""));
            // Writer's invariant: records_before = lines before this
            // checkpoint (seq − 1) minus the checkpoints among them. The
            // writer packs ` anchor=…` into the same field (it is chain-
            // covered by the hash, so verify only owns the count token).
            let want = seq - 1 - summary.checkpoints;
            let got = d
                .strip_prefix("records_before=")
                .and_then(|rest| rest.split(' ').next())
                .and_then(|num| num.parse::<u64>().ok());
            if got != Some(want) {
                return Err(AuditFault {
                    line_no: idx + 1,
                    reason: format!(
                        "checkpoint count mismatch: want record counts before={want}, got {d:?}"
                    ),
                });
            }
            summary.checkpoints += 1;
        }

        if src != "audit" || ev != "checkpoint" {
            *summary.per_src.entry(src).or_insert(0) += 1;
            summary.records += 1;
        }
        summary.last_seq = seq;
        summary.last_anchor = hash_hex.to_string();
    }

    // Exported-anchor verdict, post-loop: an anchor that was never matched
    // at its seq means either truncation (chain ends before it) or
    // divergence (an internally-consistent but different history).
    if !anchor_ok {
        if let Some((want_seq, want_hash)) = &expected {
            if summary.last_seq < *want_seq {
                return Err(AuditFault {
                    line_no: 0,
                    reason: format!(
                        "history truncated or absent: chain ends at seq {} < anchored seq {want_seq}",
                        summary.last_seq
                    ),
                });
            }
            return Err(AuditFault {
                line_no: 0,
                reason: format!(
                    "anchor divergence: chain does not contain the exported anchor {want_seq}:{want_hash}"
                ),
            });
        }
    }

    Ok(summary)
}

fn field_str<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":\"");
    let pos = line.find(&needle)?;
    let rest = &line[pos + needle.len()..];
    // values contain no raw quotes (escaped only) — first `"` ends it.
    let end = rest.find('"')?;
    Some(&rest[..end])
}

// ------------------------------------------------------------- plumbing ----

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
    }
    s
}

/// Minimal JSON string escaper for our own lines (_control chars via \u).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`esc`] for the fields verification re-inspects.
fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            out.push(ch);
                        }
                    }
                }
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_seq_and_hash(line: &str) -> Option<(u64, String)> {
    let seq: u64 = field_digits(line, "seq").ok()?;
    let hash = field_str_raw(line, "hash")?;
    Some((seq, hash))
}

fn field_digits(line: &str, key: &str) -> std::result::Result<u64, ()> {
    let needle = format!("\"{key}\":");
    let pos = line.find(&needle).ok_or(())?;
    let rest = &line[pos + needle.len()..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).ok_or(())?;
    rest[..end].parse::<u64>().map_err(|_| ())
}

fn field_str_raw(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let pos = line.rfind(&needle)?; // hash is the last field → rfind
    let rest = &line[pos + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// Use the robust finder for strings everywhere (no dead helpers).

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn fresh_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "bb-audit-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn reset_audit() {
        // Test-local: swap in a brand-new chain.
        ENABLED.store(false, Ordering::Relaxed);
        if let Ok(mut g) = ACTIVE.lock() {
            *g = None;
        }
    }

    /// The audit module owns process-global state (`ENABLED`/`ACTIVE`), so
    /// its tests must never run concurrently — gate every test on a shared
    /// lock (poison-tolerant: a panicking peer must not cascade).
    static AUDIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn clean_chain_verifies_with_counts_and_anchors() {
        let _g = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_audit();
        let dir = fresh_dir("ok");
        init(&dir).unwrap();
        record("queue", "enqueue", "", "job-1");
        record("egress", "upstream", "aabb", "12 tokens");
        record("replay", "start", "ccdd", "target=app");
        let summary = verify(&dir, None).expect("clean chain");
        assert_eq!(summary.records, 3);
        assert_eq!(summary.per_src.get("queue"), Some(&1));
        assert_eq!(summary.last_seq, 3);
        assert_eq!(summary.checkpoints, 0);
        // anchor stable across a restart-resumed init
        let anchor = current_anchor().unwrap();
        assert_eq!(anchor.0, 3);
        record("cold", "heal", "eeee", "segment zst");
        let summary = verify(&dir, None).unwrap();
        assert_eq!(summary.records, 4);
        // tamper ONE interior byte → fault at that line
        let path = dir.join("audit.log");
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[1].contains("upstream"), true);
        let tampered = lines[1].replace("stream", "STR34M");
        lines[1] = tampered.as_str();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let err = verify(&dir, None).unwrap_err();
        assert_eq!(err.line_no, 2);
        assert!(err.reason.contains("hash break"), "got: {}", err.reason);
        reset_audit();
    }

    #[test]
    fn interior_deletion_breaks_seq() {
        let _g = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_audit();
        let dir = fresh_dir("seq");
        init(&dir).unwrap();
        for i in 0..5 {
            record("test", "ev", "", &format!("n{i}"));
        }
        let path = dir.join("audit.log");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // delete line 3 (seq 3)
        let mut keep = lines.clone();
        keep.remove(2);
        std::fs::write(&path, keep.join("\n") + "\n").unwrap();
        let err = verify(&dir, None).unwrap_err();
        assert_eq!(err.line_no, 3);
        assert!(err.reason.contains("seq break"), "got: {}", err.reason);
        reset_audit();
    }

    #[test]
    fn checkpoint_every_1024_and_anchor_export_detects_truncation() {
        let _g = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_audit();
        let dir = fresh_dir("ckpt");
        init(&dir).unwrap();
        for i in 0..2_050 {
            record("q", "run", "", &format!("{}", i));
        }
        // 2,050 records + 2 checkpoint lines = chain seq 2_052.
        let (seq, anchor) = current_anchor().unwrap();
        assert_eq!(seq, 2_052);
        let summary = verify(&dir, None).unwrap();
        assert_eq!(summary.checkpoints, 2); // at 1024 and 2048
        // exported anchor is satisfiable on the intact file
        verify(&dir, Some((seq, anchor.clone()))).unwrap();

        // TRUNCATE the tail by dropping the last 30 lines → anchor mismatch
        let path = dir.join("audit.log");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let cut = lines.len() - 30;
        std::fs::write(&path, lines[..cut].join("\n") + "\n").unwrap();
        let err = verify(&dir, Some((seq, anchor))).unwrap_err();
        assert_eq!(err.line_no, 0, "anchor violations are pre-pass");
        assert!(err.reason.contains("truncated"), "got: {}", err.reason);
        // WITHOUT an exported anchor the truncated tail is reported honestly:
        // the chain recomputes clean — that is the documented boundary.
        let summary = verify(&dir, None).unwrap();
        assert_eq!(summary.last_seq, seq - 30);
        reset_audit();
    }

    #[test]
    fn verify_on_missing_file_is_a_fault() {
        let dir = fresh_dir("missing");
        let err = verify(&dir, None).unwrap_err();
        assert_eq!(err.line_no, 0);
        assert!(err.reason.contains("no audit log"));
    }

    #[test]
    fn record_before_init_is_silent_noop() {
        let _g = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_audit();
        let a = current_anchor();
        assert!(a.is_none());
        record("x", "y", "", "z"); // must not panic
    }
}
