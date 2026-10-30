"""Compile the actual pure Rust source and compare it with the browser ports.

No Cargo dependencies, Linux node, or generated fixtures in the repository.
Requires rustc, Node, Python. Temporary build files are removed on completion.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EGRESS = ROOT / "crates/blackbox-egress/src/simhash.rs"
WAF = ROOT / "crates/blackbox-ingress/src/waf.rs"

texts = [
    "", "hello", "hello world", "hello world now", "Hello,  WORLD!",
    "2026-10-25", "charge order 7 now", "charge order 8080 now", "6pm fee",
    "foo123bar", "  --==--  ", "1 2 3", "123abc456def", "a 12 34 b",
    "Summarize the invoice for order 1042, then list the next steps.",
    "SUMMARIZE the invoice for order 8080! Then list the next steps.",
    "Transfer 100 rupees to account 42.", "Transfer 900 rupees to account 99.",
    "Write a poem about monsoon clouds over the mountains.",
    "café résumé invoice", "İstanbul invoice", "🇮🇳 नमस्ते", "a\t\nb",
    "one two three four five six", "one two THREE four FIVE six",
    " ".join(["hello"] * 4098) + " changed tail words",
    " ".join(f"word{n}" for n in range(4300)),
]
paths = [
    "/", "/.env", "/.env.production", "/.git/config", "/.GIT/HEAD", "/.DS_Store",
    "/wp-admin/setup.php", "/wp-login.php", "/wp-content/x", "/xmlrpc.php",
    "/../../etc/passwd", "/a/../../etc/shadow", "/a..", "/a..\\x",
    "/%2e%2e/%2e%2e/etc/passwd", "/%2Egit/config", "/.git%5Cconfig",
    "/%2F.git%2Fconfig", "/phpmyadmin/index.php", "/backup.sql", "/site.conf.bak",
    "/foo.old", "/foo.orig", "/foo.swp", "/web.config", "/actuator/health",
    "/settings.env", "/env-info", "/wp-adminxyz", "/api/products",
    "/.well-known/acme-challenge/abc123", "/%252Egit/config", "/%ZZ", "/%2",
    "/%FF", "/%FF%2Egit", "/.git/%FF", "/.env/%ZZ", "/caf%C3%A9",
    "/%EF%BB%BF.git", "/é/.env", "/a\\.ssh\\config", "/.gitignore",
]
# Deterministic extra vectors exercise digit runs, punctuation, and token windows.
texts += [f"invoice {n} total {n * 17}, account ref-{n + 1}! please review now" for n in range(80)]
paths += [f"/x/{stem}/child" for stem in [".ssh", ".aws", ".gnupg", ".svn", ".hg", ".ds_store"]]


def raw_string(text):
    assert '"#' not in text
    return 'r#"' + text + '"#'


source = EGRESS.read_text(encoding="utf-8")
pure = source[source.index("pub fn normalize("):source.index("/// Domain-separated near-key:")]
program = pure + '\n#[path = ' + raw_string(WAF.as_posix()) + '] mod waf;\nfn main() {\n'
program += "for text in [" + ",".join(map(raw_string, texts)) + "] {\n"
program += 'println!("S\\t{:016x}\\t{}", simhash_text(&normalize(text)), normalize(text));\n}\n'
program += "let shield = waf::ScannerShield::enabled();\nfor path in [" + ",".join(map(raw_string, paths)) + "] {\n"
program += 'println!("W\\t{}", shield.check(path).is_some());\n}\n}\n'

approved_temp = Path.home() / "AppData/Local/Temp/opencode" if os.name == "nt" else None
with tempfile.TemporaryDirectory(prefix="blackbox-parity-", dir=approved_temp) as tmp:
    rust_file = Path(tmp) / "parity.rs"
    binary = Path(tmp) / ("parity.exe" if os.name == "nt" else "parity")
    rust_file.write_text(program, encoding="utf-8")
    subprocess.run(["rustc", "--edition=2021", "-A", "dead_code", str(rust_file), "-o", str(binary)], check=True)
    output = subprocess.run([str(binary)], check=True, capture_output=True, encoding="utf-8").stdout.splitlines()

fingerprints, blocked = [], []
for line in output:
    if line.startswith("S\t"):
        _, fingerprint, normalized = line.split("\t", 2)
        fingerprints.append({"hash": fingerprint, "normalized": normalized})
    elif line.startswith("W\t"):
        blocked.append(line == "W\ttrue")
assert len(fingerprints) == len(texts) and len(blocked) == len(paths)

node_check = """
const assert = require('node:assert/strict');
const fs = require('node:fs');
const A = require('./site/algorithms.js');
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
data.texts.forEach((text, i) => {
  assert.equal(A.normalize(text), data.fingerprints[i].normalized, 'normalize #' + i);
  assert.equal(A.simhash(text).toString(16).padStart(16, '0'), data.fingerprints[i].hash, 'SimHash #' + i);
});
data.paths.forEach((path, i) => assert.equal(A.scanner(path).blocked, data.blocked[i], 'scanner ' + path));
console.log(`Rust/JS parity PASS: ${data.texts.length} text vectors, ${data.paths.length} paths`);
"""
subprocess.run(["node", "-e", node_check], input=json.dumps({"texts": texts, "paths": paths,
    "fingerprints": fingerprints, "blocked": blocked}), encoding="utf-8", cwd=ROOT, check=True)
