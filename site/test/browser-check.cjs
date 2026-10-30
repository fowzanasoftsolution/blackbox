/* Dev-only Playwright smoke check. The published site has no dependencies.
   Usage: NODE_PATH=<isolated dev node_modules> node site/test/browser-check.cjs <dist>
   Or pass the live https://…/blackbox/ URL to verify a deployment. */
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const target = process.argv[2];
  assert.ok(target, 'Pass an assembled site directory or a live URL.');
  let server, browser;
  try {
    let base = target;
    if (!/^https?:\/\//.test(target)) {
      const root = path.resolve(target);
      const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript',
        '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff',
        '.png': 'image/png', '.ico': 'image/x-icon' };
      server = http.createServer((req, res) => {
        const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
        if (!pathname.startsWith('/blackbox/')) { res.writeHead(404); res.end(); return; }
        let file = path.resolve(root, pathname.slice('/blackbox/'.length));
        if (file !== root && !file.startsWith(root + path.sep)) { res.writeHead(403); res.end(); return; }
        if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
        if (!fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
        res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
        res.end(fs.readFileSync(file));
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      base = `http://127.0.0.1:${server.address().port}/blackbox/`;
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.BLACKBOX_BROWSER_CHANNEL ? { channel: process.env.BLACKBOX_BROWSER_CHANNEL } : {}) });
    const context = await browser.newContext({ reducedMotion: 'reduce', viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    const errors = [], badResponses = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push(request.url()));
    page.on('response', response => { if (response.status() >= 400) badResponses.push(response.status() + ' ' + response.url()); });
    const response = await page.goto(base, { waitUntil: 'networkidle' });
    assert.equal(response.status(), 200);
    await page.locator('#terminal-state').filter({ hasText: 'ready' }).waitFor();
    const initialRequests = requests.length;
    let checks = 0;
    function check(condition, label) { assert.ok(condition, label); checks++; }

    for (const width of [320, 375, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal overflow at ' + width);
    }
    for (let i = 0; i < 5; i++) await page.locator('[data-probe="kill"]').click();
    check((await page.locator('#kill-state').textContent()).includes('complete'), 'crash stepper completes');
    check(await page.locator('#kill-tape li').count() === 5, 'crash has five explanatory steps');
    await page.locator('[data-reset="kill"]').click();
    check(await page.locator('#kill-tape li').count() === 0, 'crash reset clears tape');
    for (let i = 0; i < 5; i++) await page.locator('[data-probe="corrupt"]').click();
    check((await page.locator('#corrupt-state').textContent()).includes('complete'), 'self-heal stepper completes');

    for (const [distinct, expected] of [['1', '4,999 duplicate'], ['100', '4,900 duplicate'], ['5000', '0 duplicate']]) {
      await page.locator('#flood-distinct').selectOption(distinct);
      await page.locator('[data-probe="flood"]').click();
      check((await page.locator('#flood-output').textContent()).includes(expected), 'dedup counts for ' + distinct);
    }
    await page.locator('#rss-level').focus();
    await page.keyboard.press('End');
    check((await page.locator('#shed-output').textContent()).includes('Backpressure95'), 'slider keyboard End selects 100%');
    check((await page.locator('#shed-output').textContent()).includes('1% keep probability'), 'healthy sampling at pressure');
    await page.keyboard.press('Home');
    check((await page.locator('#shed-output').textContent()).includes('Normal'), 'slider keyboard Home restores normal');

    await page.locator('[data-preset="format"]').click();
    check((await page.locator('#sim-distance').textContent()) === '0 / 64 bits', 'format / numeric drift distance zero');
    check(await page.locator('#bits-a .bit').count() === 64, '64-bit view renders');
    await page.locator('[data-preset="different"]').click();
    check((await page.locator('#sim-result').textContent()).includes('Outside'), 'different task misses');
    check(await page.locator('#bits-b .changed').count() > 3, 'distance is visible in differing bits');
    await page.locator('[data-preset="numbers"]').click();
    check((await page.locator('#sim-distance').textContent()) === '0 / 64 bits', 'numeric collision is exposed');
    await page.locator('#prompt-b').fill('');
    await page.locator('#sim-result').filter({ hasText: 'empty' }).waitFor();
    check((await page.locator('#sim-result').textContent()).includes('No near-cache candidate'), 'empty prompt excluded');
    await page.locator('#prompt-a').fill('<img src=x onerror="window.INJECTED=true">');
    await page.locator('#normalized-a').filter({ hasText: 'img src' }).waitFor({ state: 'attached' });
    check(await page.evaluate(() => !window.INJECTED), 'prompt input is not executable markup');

    await page.locator('[data-path="/%2Egit/config"]').click();
    check((await page.locator('#scanner-output').textContent()).includes('percent-decoded'), 'encoded scanner path matched');
    await page.locator('[data-path="/settings.env"]').click();
    check((await page.locator('#scanner-verdict').textContent()).startsWith('PASS'), 'legitimate suffix passes');
    await page.locator('[data-path="/%252Egit/config"]').click();
    check((await page.locator('#scanner-verdict').textContent()).startsWith('PASS'), 'double-decoding limit is honest');
    await page.locator('#scanner-path').fill('/backup.sql?download=1');
    await page.locator('#scanner-path').press('Enter');
    check((await page.locator('#scanner-verdict').textContent()).startsWith('BLOCK'), 'query stripped before rule evaluation');
    await page.locator('#scanner-path').fill('/<img src=x onerror="window.INJECTED=true">');
    await page.locator('#scanner-path').press('Enter');
    check(await page.locator('#scanner-output img').count() === 0 && await page.evaluate(() => !window.INJECTED), 'scanner input renders as text');
    await page.locator('#scanner-reset').click();
    check((await page.locator('#scanner-total').textContent()) === '0', 'range reset clears counters');

    async function command(text) {
      await page.locator('#cmdline').fill(text);
      await page.locator('#cmdline').press('Enter');
      await page.locator('#terminal-state').filter({ hasText: 'ready' }).waitFor();
    }
    await command('demo');
    check((await page.locator('#screen').textContent()).includes('✓ 4 engines exercised in 3.1s'), 'terminal demo replay completes');
    await command('kill -9');
    check((await page.locator('#kill-state').textContent()).includes('complete'), 'terminal opens crash model');
    await command('shed85');
    check((await page.locator('#rss-value').textContent()) === '85%', 'terminal sets Shed85');
    await command('__proto__');
    check((await page.locator('#screen').textContent()).includes("unknown: '__proto__'"), 'prototype names are not commands');
    await command('<img src=x onerror="window.INJECTED=true">');
    check(await page.locator('#screen img').count() === 0 && await page.evaluate(() => !window.INJECTED), 'terminal escapes input');
    check(requests.length === initialRequests, 'all experiments make zero new network requests');
    check(requests.every(url => new URL(url).origin === new URL(base).origin), 'no third-party assets fetched');
    check(await page.locator('img[alt="Made in India with love"]').evaluate(img => img.complete && img.naturalWidth > 0), 'India flag asset loads');
    check(await page.locator('a.coffee').getAttribute('href') === 'https://buymeacoffee.com/zuhayfaja', 'support URL is correct');

    // Real Tab navigation, without overriding focus or clicking a keyboard target.
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.keyboard.press('Tab');
    check(await page.evaluate(() => document.activeElement.classList.contains('skip')), 'skip link is the first keyboard target');
    await page.keyboard.press('Enter');
    check(await page.evaluate(() => location.hash === '#open'), 'skip link reaches content');
    check(await page.locator('.caret').evaluate(el => getComputedStyle(el).animationName === 'none'), 'reduced-motion caret is still');

    await page.addScriptTag({ path: require.resolve('axe-core/axe.min.js') });
    await page.locator('details').evaluateAll(elements => elements.forEach(el => { el.open = true; }));
    const audit = await page.evaluate(async () => {
      const results = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } });
      return results.violations.map(item => ({ id: item.id, impact: item.impact,
        nodes: item.nodes.map(node => ({ target: node.target, summary: node.failureSummary })) }));
    });
    assert.deepEqual(audit, [], 'Automated WCAG A/AA accessibility checks');
    await page.locator('details').evaluateAll(elements => elements.forEach(el => { el.open = false; }));
    checks++;

    for (const chapter of ['getting-started', 'architecture', 'verification', 'experiments', 'releases', 'security', 'changelog']) {
      const docResponse = await page.goto(new URL('docs/' + chapter + '.html', base).href, { waitUntil: 'domcontentloaded' });
      check(docResponse.status() === 200, 'docs chapter published: ' + chapter);
      check((await page.locator('main').textContent()).trim().length > 100, 'docs chapter has real content: ' + chapter);
    }

    // Normal-motion replay can be skipped; repeated clicks cannot interleave tapes.
    const normal = await browser.newPage({ viewport: { width: 375, height: 812 } });
    normal.on('pageerror', error => errors.push(error.message));
    await normal.goto(base, { waitUntil: 'domcontentloaded' });
    await normal.locator('#skip-tape').click();
    await normal.locator('#terminal-state').filter({ hasText: 'ready' }).waitFor();
    await normal.locator('#demo-play').click();
    await normal.locator('#demo-play').click();
    await normal.locator('#skip-tape').click();
    await normal.locator('#terminal-state').filter({ hasText: 'ready' }).waitFor();
    const tape = await normal.locator('#screen').textContent();
    check(tape.split('✓ 4 engines exercised in 3.1s').length - 1 === 1, 'replay skip works and concurrent clicks are guarded');
    check(await normal.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'normal-motion mobile has no horizontal overflow');
    if (process.env.BLACKBOX_SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.BLACKBOX_SCREENSHOT_DIR, { recursive: true });
      await normal.screenshot({ path: path.join(process.env.BLACKBOX_SCREENSHOT_DIR, 'mobile.png'), fullPage: true });
      await page.goto(base, { waitUntil: 'networkidle' });
      await page.screenshot({ path: path.join(process.env.BLACKBOX_SCREENSHOT_DIR, 'desktop.png'), fullPage: true });
    }
    assert.deepEqual(errors, [], 'No uncaught browser errors');
    assert.deepEqual(badResponses, [], 'No failed asset or chapter responses');
    console.log(`Browser smoke PASS: ${checks} checks, 4 viewports, WCAG A/AA audit, zero experiment requests / page errors`);
  } finally {
    if (browser) await browser.close();
    if (server) await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
