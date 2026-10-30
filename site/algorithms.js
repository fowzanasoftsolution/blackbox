/* Browser ports of Blackbox's pure Rust algorithms. No requests, no dependencies.
   Sources: crates/blackbox-egress/src/simhash.rs and
   crates/blackbox-ingress/src/{waf,tee}.rs. See test/rust-parity.py. */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

  function normalize(text) {
    let out = '', lastSpace = false, inDigits = false;
    for (const ch of text.toLowerCase()) {
      if (ch >= '0' && ch <= '9') {
        if (!inDigits) {
          if (!lastSpace) out += ' ';
          out += '#'; inDigits = true; lastSpace = false;
        }
      } else if (ch >= 'a' && ch <= 'z') {
        out += ch; inDigits = false; lastSpace = false;
      } else if (!lastSpace) {
        out += ' '; lastSpace = true; inDigits = false;
      }
    }
    return out.trim();
  }

  function fnv64(bytes) {
    let h = 0xcbf29ce484222325n;
    for (const byte of bytes) h = BigInt.asUintN(64, (h ^ BigInt(byte)) * 0x100000001b3n);
    return h;
  }

  function simhash(text) {
    const tokens = normalize(text).split(' ').filter(Boolean);
    if (!tokens.length) return 0n;
    const arity = Math.min(3, tokens.length);
    const count = Math.min(4096, tokens.length - arity + 1);
    const weights = new Uint32Array(64);
    for (let i = 0; i < count; i++) {
      const h = fnv64(encoder.encode(tokens.slice(i, i + arity).join('\x01')));
      for (let bit = 0; bit < 64; bit++) weights[bit] += Number((h >> BigInt(bit)) & 1n);
    }
    let out = 0n;
    for (let bit = 0; bit < 64; bit++) if (weights[bit] * 2 > count) out |= 1n << BigInt(bit);
    return out;
  }

  function hamming(a, b) {
    let xor = BigInt.asUintN(64, a ^ b), count = 0;
    while (xor) { xor &= xor - 1n; count++; }
    return count;
  }

  function asciiLower(text) {
    return text.replace(/[A-Z]/g, ch => ch.toLowerCase());
  }

  const segments = Object.freeze(['.env', '.git', '.svn', '.hg', '.DS_Store', '.ssh',
    '.aws', '.gnupg', 'wp-admin', 'wp-login.php', 'wp-content', 'xmlrpc.php',
    'phpmyadmin', 'actuator', 'web.config', '.ds_store']);
  const suffixes = Object.freeze(['.sql', '.bak', '.old', '.orig', '.swp']);

  function matchPath(path) {
    const p = asciiLower(path);
    if (p.includes('../') || p.includes('..\\') || p.endsWith('..')) return 'path traversal';
    for (const seg of p.split(/[\/\\]/)) {
      if (segments.includes(seg)) return 'blocked segment: ' + seg;
      for (const stem of segments) if (seg.startsWith(stem + '.')) return 'blocked extension: ' + stem;
      for (const suffix of suffixes) if (seg.endsWith(suffix)) return 'backup/config suffix: ' + suffix;
    }
    return null;
  }

  // Match Rust's byte-wise, one-pass decoder, including malformed UTF-8 fail-open.
  function percentDecode(text) {
    const bytes = encoder.encode(text), out = [];
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== 37) { out.push(bytes[i]); continue; }
      const pair = String.fromCharCode(bytes[i + 1], bytes[i + 2]);
      if (!/^[0-9a-f]{2}$/i.test(pair)) return null;
      out.push(parseInt(pair, 16)); i += 2;
    }
    try { return decoder.decode(new Uint8Array(out)); } catch { return null; }
  }

  function scanner(path) {
    const rawRule = matchPath(path);
    if (rawRule) return { blocked: true, rule: rawRule, pass: 'raw', decoded: null };
    const decoded = percentDecode(path);
    const rule = decoded === null ? null : matchPath(decoded);
    return { blocked: rule !== null, rule, pass: rule ? 'percent-decoded' : 'none', decoded };
  }

  function dedupFlood(total, distinct) {
    if (!Number.isInteger(total) || total < 1 || total > 5000 ||
        !Number.isInteger(distinct) || distinct < 1 || distinct > total) {
      throw new RangeError('Use 1–5,000 requests and no more distinct IDs than requests.');
    }
    const seen = new Set();
    let duplicates = 0;
    for (let i = 0; i < total; i++) {
      const id = 'evt_' + (i % distinct);
      if (seen.has(id)) duplicates++; else seen.add(id);
    }
    return { queued: seen.size, duplicates, total };
  }

  function ramLevel(percent) {
    return percent >= 95 ? 'Backpressure95' : percent >= 85 ? 'Shed85' :
      percent >= 75 ? 'Warn75' : 'Normal';
  }

  function keepRate(percent, status, durationMs) {
    return percent >= 85 && status >= 200 && status < 300 && durationMs < 1000 ? .01 : 1;
  }

  const api = Object.freeze({ normalize, fnv64, simhash, hamming, scanner, percentDecode,
    dedupFlood, ramLevel, keepRate });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else globalThis.BlackboxLab = api;
})();
