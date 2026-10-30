/* Run with node --test site/test/*.test.cjs. No dev dependencies. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const A = require('../algorithms.js');

test('FNV-1a uses exact wrapping 64-bit arithmetic', () => {
  assert.equal(A.fnv64(new TextEncoder().encode('hello')), 0xa430d84680aabd0bn);
  assert.equal(A.fnv64(new Uint8Array()), 0xcbf29ce484222325n);
});

for (const [text, expected] of [
  ['Hello,  WORLD!', 'hello world'], ['2026-10-25', '# # #'], ['  --==--  ', ''],
  ['charge order 7 now', 'charge order # now'], ['charge order 8080 now', 'charge order # now'],
  ['6pm fee', '#pm fee'], ['foo123bar', 'foo #bar'], ['🇮🇳 नमस्ते', '']
]) test('Rust normalization: ' + JSON.stringify(text), () => assert.equal(A.normalize(text), expected));

test('formatting and numeric-run drift produce the same fingerprint', () => {
  assert.equal(A.simhash('Summarize order 1042 now.'), A.simhash('SUMMARIZE order 8080 NOW!'));
});
test('numeric amounts collide; the playground must not imply semantic equivalence', () => {
  assert.equal(A.simhash('Transfer 100 rupees to account 42.'), A.simhash('Transfer 900 rupees to account 99.'));
});
test('empty normalized text is fingerprint zero', () => assert.equal(A.simhash(' --- '), 0n));
test('distance is symmetric and covers all 64 bits', () => {
  assert.equal(A.hamming(0n, 0xffffffffffffffffn), 64);
  assert.equal(A.hamming(0x1234n, 0x5678n), A.hamming(0x5678n, 0x1234n));
});
test('different tasks do not trivially collapse', () => {
  assert.ok(A.hamming(A.simhash('summarize this invoice'), A.simhash('write a monsoon poem')) > 3);
});
test('the 4,096-shingle cap ignores later windows', () => {
  const prefix = Array(4098).fill('hello').join(' ');
  assert.equal(A.simhash(prefix), A.simhash(prefix + ' changed tail words'));
});

for (const path of ['/.env', '/.env.production', '/.GIT/config', '/%2Egit/config',
  '/wp-admin/setup.php', '/wp-login.php', '/../../etc/passwd', '/a/../../etc/shadow',
  '/%2e%2e/%2e%2e/etc/passwd', '/phpmyadmin/index.php', '/backup.sql', '/site.conf.bak',
  '/xmlrpc.php', '/.git%5Cconfig', '/%2F.git%2Fconfig', '/actuator/health', '/.DS_Store']) {
  test('shield blocks ' + path, () => assert.equal(A.scanner(path).blocked, true));
}
for (const path of ['/', '/api/products', '/settings.env', '/env-info',
  '/.well-known/acme-challenge/abc123', '/wp-adminxyz', '/%252Egit/config', '/%FF', '/%ZZ', '/%2']) {
  test('shield passes (not a safety claim) ' + path, () => assert.equal(A.scanner(path).blocked, false));
}
test('invalid encoding cannot bypass a raw blocked path', () => assert.equal(A.scanner('/.env/%ZZ').blocked, true));
test('one decoding pass, not recursive decoding', () => {
  assert.equal(A.percentDecode('/%252Egit'), '/%2Egit');
  assert.equal(A.scanner('/%252Egit').blocked, false);
});
test('UTF-8 invalidity fails open only after the raw matcher', () => {
  assert.equal(A.percentDecode('/%FF%2Egit'), null);
  assert.equal(A.scanner('/%FF%2Egit').blocked, false);
  assert.equal(A.scanner('/.git/%FF').blocked, true);
});
test('BOM and non-ASCII bytes are preserved by the percent decoder', () => {
  assert.equal(A.percentDecode('%EF%BB%BFfoo'), '\ufefffoo');
  assert.equal(A.percentDecode('/caf%C3%A9'), '/café');
});
test('matching reports raw versus decoded provenance', () => {
  assert.equal(A.scanner('/.env').pass, 'raw');
  assert.equal(A.scanner('/%2Egit/config').pass, 'percent-decoded');
  assert.equal(A.scanner('/settings.env').pass, 'none');
});
for (const distinct of [1, 100, 5000]) test('local flood with ' + distinct + ' distinct IDs', () => {
  assert.deepEqual(A.dedupFlood(5000, distinct), { queued: distinct, duplicates: 5000 - distinct, total: 5000 });
});
test('local flood rejects invalid or unbounded work', () => {
  for (const [total, distinct] of [[0, 1], [5001, 1], [5, 6], [5, 0], [5.5, 1]]) {
    assert.throws(() => A.dedupFlood(total, distinct), RangeError);
  }
});
test('RAM thresholds and healthy-only sampling match the documented policy', () => {
  for (const [percent, level] of [[74, 'Normal'], [75, 'Warn75'], [84, 'Warn75'],
    [85, 'Shed85'], [94, 'Shed85'], [95, 'Backpressure95']]) assert.equal(A.ramLevel(percent), level);
  assert.equal(A.keepRate(84, 200, 100), 1);
  assert.equal(A.keepRate(85, 200, 999), .01);
  assert.equal(A.keepRate(95, 299, 999), .01);
  assert.equal(A.keepRate(95, 200, 1000), 1);
  assert.equal(A.keepRate(95, 500, 100), 1);
  assert.equal(A.keepRate(95, 404, 100), 1);
});
