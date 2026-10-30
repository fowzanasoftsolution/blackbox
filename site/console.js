/* Open the Box — console.js
   A dependency-free terminal: typed boot sequence + interactive command loop.
   'demo' replays a MEASURED run of `blackbox demo --once` (v1.1.3, linux x86_64,
   captured verbatim from the built binary — the numbers are that run's, not invented).
   Everything runs locally; no network calls, no third-party code. */
(() => {
  'use strict';

  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (s) => document.getElementById(s);

  const screen = $('screen'), input = $('cmdline');
  if (!screen || !input) return;

  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const scrollBottom = () => { screen.scrollTop = screen.scrollHeight; };

  /* ---------- output primitives ---------- */
  function line(html, cls) {
    const d = document.createElement('div');
    d.className = 'ln' + (cls ? ' ' + cls : '');
    d.innerHTML = html === '' ? '&nbsp;' : html;
    screen.appendChild(d);
    if (screen.childElementCount > 350) screen.firstElementChild.remove();
    scrollBottom();
    return d;
  }
  const note = (cls, msg) => line(`<b>${esc(cls)}</b> ${esc(msg)}`, 'ev');

  /* Skip flag: 's' fast-forwards the active tape. */
  let skip = false, busy = true;
  const state = $('terminal-state'), skipButton = $('skip-tape');
  function ready() {
    busy = false; skip = false;
    state.textContent = 'ready · help lists commands';
    skipButton.disabled = true;
  }

  async function wait(ms) {
    if (skip || REDUCED) return;
    const step = 40;
    for (let left = ms; left > 0 && !skip; left -= step) {
      await new Promise(r => setTimeout(r, Math.min(step, left)));
    }
  }
  /* Type characters into a fresh line (instant when skipped / reduced motion). */
  async function type(text, cls, cps = 200) {
    const d = line('', cls);
    if (skip || REDUCED) { d.textContent = text; scrollBottom(); return d; }
    for (let i = 0; i < text.length; i++) {
      d.textContent += text[i];
      if (i % 4 === 0) scrollBottom();
      await new Promise(r => setTimeout(r, 1000 / cps));
      if (skip) { d.textContent = text; scrollBottom(); return d; }
    }
    scrollBottom();
    return d;
  }

  /* ---------- the measured demo transcript (verbatim capture, real values) ---------- */
  const DEMO_TRACE = '2b00f9a28cd80998fb91d8ab906df1f8';
  const DEMO_PARENT = '/tmp/blackbox-demo-17002-1881363777872788140';
  /* {p: phase label line, a: appended acknowledgement, w: pause before ack} */
  const DEMO = [
    { p: ['hdr', 'blackbox demo — the whole architecture in one shot'] },
    { p: ['diml', '─────────────────────────────────────────────────'] },
    { p: ['', '  <span class="k">ingress</span> 127.0.0.1:34029  <span class="k">upstream(app)</span> 127.0.0.1:43633  <span class="k">admin</span> 127.0.0.1:9690'] },
    { p: [''] },
    { p: ['accl', '  <span class="k">A</span> normal traffic …'], a: '<span class="g">ok</span>', w: 210 },
    { p: ['accl', '  <span class="k">A2</span> bulk uploads (segment rollovers) …'], a: '<span class="g">ok</span>', w: 260 },
    { p: ['accl', '  <span class="k">B</span> coalesced LLM calls …'], a: '<span class="g">ok</span> (1 upstream calls · <span class="y">3818</span> saved tokens)', w: 240 },
    { p: ['accl', '  <span class="k">C</span> webhook burst …'], a: '<span class="g">ok</span> (40/40 delivered · 0 lost)', w: 230 },
    { p: ['accl', '  <span class="k">D</span> checkout bug → Sentry crash …'], a: `<span class="g">ok</span> (trace <span class="diml">${DEMO_TRACE}</span> · IngressHttp 500 + SentryCrash)`, w: 260 },
    { p: ['accl', '  <span class="k">E</span> bit-rot self-heal …'], a: '<span class="y">WARN</span> <span class="diml">self-healing: local sealed segment corrupt (zstd/frame verification failed); restoring replica from cold tier</span>', w: 230 },
    { p: ['okl', 'ok (corrupt .zst → digest-verified cold restore → 1 records intact)'] },
    { p: [''] },
    { p: ['hdr', '  ┌──────────────────────── 4 ENGINES ────────────────────────┐'] },
    { p: ['', '  │ <span class="k">1 INGRESS      </span>  requests 112 · indexed 194 · traces 112 · shielded 0'] },
    { p: ['', '  │ <span class="k">2 QUEUE        </span>  webhooks 40/40 delivered · DLQ 0 · dedup on'] },
    { p: ['', '  │ <span class="k">3 EGRESS-FINOPS</span>  LLM calls 24 → 1 upstream · 95.8% saved · tokens <span class="y">saved 3818</span>'] },
    { p: ['', '  │ <span class="k">4 STORAGE      </span>  uploads 4 · bit-rot heals <span class="g">1</span> · compaction on · quota ring on'] },
    { p: ['boxl', '  └ ──────────────────────────────────────────────────────────'] },
    { p: [''] },
    { p: ['', '  <span class="k">dashboard</span>: <span class="fgl">http://127.0.0.1:9690</span>'] },
    { p: ['', `  <span class="k">replay</span>: trace inspector shows the crash → <span class="diml">blackbox replay ${DEMO_TRACE} --target http://127.0.0.1:34029 --data ${DEMO_PARENT}</span>`] },
    { p: ['', `  <span class="k">data</span>: <span class="diml">${DEMO_PARENT}</span> (delete any time)`] },
    { p: [''] },
    { p: ['okl', '  ✓ 4 engines exercised in 3.1s'] },
    { p: ['diml', '  (--once: verification mode — exiting 0)'] },
  ];

  async function runDemo() {
    line('replay — captured verbatim from a real run of <b>blackbox demo --once</b> (v1.1.3, linux x86_64). ports &amp; data dir vary per run; the values below are that run.', 'ev');
    note('skippable', 'use the skip tape button to fast-forward; keyboard commands render instantly');
    for (const entry of DEMO) {
      const [cls, html] = entry.p;
      if (html === undefined) { if (cls !== '') line('', cls); else line('&nbsp;'); continue; }
      if (cls === 'hdr' || cls === 'okl' || cls === 'diml') { await wait(220); line(html, cls); continue; }
      if (cls === '') { await wait(120); line(html); continue; }
      /* phase line: print the label, delay like the work took, append its ack */
      const d = line(html, cls);
      if (entry.a) { await wait(entry.w); d.innerHTML += ' ' + entry.a; scrollBottom(); }
    }
    await wait(260);
    line('measured on one box, one burst — re-run it on yours: <b>blackbox demo --once</b> (docs · getting started)', 'ev');
    await type('that is the pitch: four infra layers scraped into one binary. type \'open\' to peel it apart.', 'fgl', 85);
  }

  /* ---------- boot sequence (stylized; the quoted capabilities are the documented gates) ---------- */
  const BOOT = [
    ['hdr', 'blackbox v1.1.3 — booting the 4-engine node'],
    ['okl', '  ✓ ingress shield + TLS       WAF scanner · rate limit · rustls hot reload'],
    ['okl', '  ✓ durable queue              leases · reaper · idempotency sweep · DLQ'],
    ['okl', '  ✓ storage writer             CRC32C frames · zstd rollover · quota ring'],
    ['okl', '  ✓ egress finops proxy        singleflight · response + SimHash cache · ledger'],
    ['diml', '  audit chain … anchor ok'],
    ['diml', '  (boot text stylized; \'demo\' replays a measured run end-to-end)'],
    ['fgl', "interactive session. type 'help' — some commands are hidden."],
  ];
  async function boot() {
    for (const [cls, txt] of BOOT) {
      if (cls === 'hdr' || cls === 'fgl') await type(txt, cls, 125);
      else { await wait(cls === 'okl' ? 125 : 85); line(esc(txt), cls); }
    }
  }

  /* ---------- commands ---------- */
  const HELP =
    '<span class="fgl">commands</span>\n' +
    '  demo           replay the measured 4-engine boot (v1.1.3 · 3.1 s · exit 0)\n' +
    '  open [1-4]     peel a layer off the box (1 telemetry · 2 queue · 3 edge · 4 egress)\n' +
    '  trace [32hex]  inspect a recorded trace — the measured crash trace is preloaded\n' +
    '  kill -9        open the upstream-crash guided simulation\n' +
    '  corrupt        open the sealed-segment self-heal explanation\n' +
    '  flood          simulate 5,000 local event-ID dedup checks\n' +
    '  shed85         set the memory-policy model to 85%\n' +
    '  simhash        edit prompts in the real text-fingerprint playground\n' +
    '  scanners       evaluate local scanner rules (no HTTP requests)\n' +
    '  clear          wipe the tape\n' +
    '  <span class="diml">a few commands are hidden. the box rewards curiosity.</span>';

  function flashLayer(n) {
    const li = $('l' + n);
    if (!li) return;
    li.scrollIntoView({ behavior: REDUCED || skip ? 'auto' : 'smooth', block: 'center' });
    const face = li.querySelector('.l-face');
    if (face) {
      face.style.outline = '2px solid var(--accent)';
      setTimeout(() => { face.style.outline = ''; }, 1700);
    }
  }

  const CMD = {};
  CMD.help = () => line(HELP, 'diml');
  CMD.clear = () => { screen.replaceChildren(); };

  CMD.open = async (arg) => {
    if (/^[1-4]$/.test(arg || '')) {
      line(`peeling straight to layer ${arg} — the card carries its gate provenance.`, 'accl');
      document.getElementById('open').scrollIntoView({ behavior: REDUCED || skip ? 'auto' : 'smooth', block: 'start' });
      flashLayer(arg);
      await type("numbers on the chips are from gates re-runnable in-repo: cargo test --workspace --release.", 'diml', 110);
      return;
    }
    line('peeling the box layer by layer — telemetry → queue → edge → egress …', 'accl');
    document.getElementById('open').scrollIntoView({ behavior: REDUCED || skip ? 'auto' : 'smooth', block: 'start' });
    await type("each layer lands stamped with the gate that proves it. 'open 4' jumps straight to the money.", 'diml', 110);
  };

  CMD.demo = runDemo;

  const DEMO_PARENT_FULL = DEMO_PARENT;
  CMD.trace = async (hex) => {
    const id = (hex || '').trim().toLowerCase().replace(/^0x/, '');
    if (id === '') {
      line(`preloaded crash trace from the measured demo: <b>${DEMO_TRACE}</b>`, 'accl');
      note('trace', 'the mint: every ingest gets a 32-hex id, returned in the x-blackbox-trace-id response header');
      note('records', 'this trace carries the POST /api/checkout → 500, plus the captured Sentry envelope it triggered (SentryCrash)');
      note('replay', `blackbox replay ${DEMO_TRACE} --target http://127.0.0.1:34029 --data ${DEMO_PARENT_FULL} — deterministic: same requests, same bytes`);
      await type('On your own live node, GET /api/trace/<id> inspects recorded traces. This website only carries the one demo trace.', 'diml', 95);
      return;
    }
    if (!/^[0-9a-f]{32}$/.test(id)) {
      line('trace ids are 32 hex chars (x-blackbox-trace-id response header)', 'badl');
      return;
    }
    if (id !== DEMO_TRACE) {
      line(`'${esc(id)}' is not on this tape — this console replays one fixed measured run, nothing more.`, 'warnl');
      note('honest', 'a live node will answer for any of your ids: GET /api/trace/&lt;32hex&gt; → records + a ready-made blackbox replay command.');
      return;
    }
    line('trace <b>' + DEMO_TRACE + '</b> — the checkout bug from the measured demo', 'accl');
    note('record', 'POST /api/checkout → HTTP 500 (IngressHttp record)');
    note('record', 'its captured Sentry crash envelope (SentryCrash record) — same trace, same writer');
    note('chain', 'both records sit hash-linked on the audit chain; `blackbox audit current-anchor` pins the checkpoint');
    note('replay', `blackbox replay ${DEMO_TRACE} --target http://127.0.0.1:34029 --data ${DEMO_PARENT_FULL}`);
    await type('deterministic replay: refire, then diff. that is what "recorded flight tape" means here.', 'diml', 95);
  };

  /* Local experiments: never claim a process was killed or a request sent. */
  CMD.kill = (arg) => {
    if (arg === '-9') {
      note('simulation', 'opened the upstream-crash explanation; no process was killed. 0.203 / 0.257 s are historical soak measurements.');
      window.BlackboxExperiments.runProbe('kill');
      return;
    }
    line('(SIGKILL mid-append does not ask politely — try `kill -9`.)', 'diml');
  };

  for (const name of ['corrupt', 'flood', 'shed85']) CMD[name] = () => {
    note('local model', `opened ${name}; no disk, network or live-node operations.`);
    window.BlackboxExperiments.runProbe(name);
  };
  CMD.simhash = () => { note('local computation', '64-bit SimHash text fingerprints; cache control isolation is not modeled.'); window.BlackboxExperiments.openSimhash(); };
  CMD.scanners = () => { note('local computation', 'scanner rule range; no requests are sent.'); window.BlackboxExperiments.openScanners(); };

  CMD['sudo'] = () => line('nice try — the box opens for everyone. it all runs unprivileged; no root required.', 'fgl');
  CMD.why = () => line('because a "recorder" nobody can inspect is just another black box. gates &gt; claims — everything re-runs from the repo.', 'fgl');
  CMD.whoami = () => line('visitor. (Dr.wolfic built the recorder; fowzanasoftsolution ships it — Apache-2.0)', 'fgl');
  CMD.version = () => line('blackbox 1.1.3 — the version this site\'s playbook was measured against', 'fgl');
  CMD.thanks = () => line('run it on your box — that is the thanks: <b>blackbox demo --once</b>', 'okl');

  /* ---------- input handling ---------- */
  const history = [];
  let hIdx = -1;

  async function runRaw(raw, instant = false) {
    const v = raw.trim();
    if (!v) return;
    if (busy) { state.textContent = 'tape running · skip it before the next command'; return; }
    busy = true; skip = instant || REDUCED;
    state.textContent = 'running ' + v.split(/\s+/)[0];
    skipButton.disabled = false;
    line('<span class="okl">$</span> ' + esc(v));
    history.push(v);
    if (history.length > 100) history.shift();
    hIdx = -1;

    const parts = v.split(/\s+/);
    const head = parts[0].toLowerCase();
    const rest = parts.slice(1).join(' ');

    try {
      const fn = Object.hasOwn(CMD, head) ? CMD[head] : null;
      if (fn) await fn(rest);
      else if (head.startsWith('sudo')) CMD.sudo();
      else line(`unknown: '${esc(head)}' — try <span class="accl">help</span>`, 'warnl');
    } catch {
      note('error', 'the browser command could not finish; reload or try again. No live-node operation was performed.');
    } finally { ready(); }
  }

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const v = input.value; input.value = '';
      runRaw(v, true);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!history.length) return;
      hIdx = hIdx < 0 ? history.length - 1 : Math.max(0, hIdx - 1);
      input.value = history[hIdx];
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (hIdx < 0) return;
      hIdx += 1;
      if (hIdx >= history.length) { hIdx = -1; input.value = ''; }
      else input.value = history[hIdx];
    }
  });
  screen.addEventListener('click', () => input.focus());
  skipButton.addEventListener('click', () => { skip = true; });
  $('demo-play').addEventListener('click', event => runRaw('demo', event.detail === 0));

  /* 's' skips the active tape (only when the input is not focused) */
  document.addEventListener('keydown', (e) => {
    if (e.key !== 's' || e.metaKey || e.ctrlKey || e.altKey) return;
    if (/INPUT|TEXTAREA/.test(document.activeElement.tagName) && document.activeElement !== input) return;
    if (busy && document.activeElement !== input) skip = true;
  });

  /* The peel: dim covered layers; light the reveal panel. Sticky CSS does the
     stacking; this only tracks which layer is covered by the next. */
  const layers = Array.from(document.querySelectorAll('.layer'));
  const reveal = $('reveal');
  function peelCheck() {
    for (let i = 0; i < layers.length; i++) {
      const next = layers[i + 1];
      const covered = !!next &&
        next.getBoundingClientRect().top < layers[i].getBoundingClientRect().top + 40;
      layers[i].classList.toggle('past', covered);
    }
    if (reveal) {
      const r = reveal.getBoundingClientRect();
      if (r.top < window.innerHeight * .85) reveal.classList.add('shown');
    }
  }
  let peelTick = false;
  const onScroll = () => {
    if (peelTick) return;
    peelTick = true;
    requestAnimationFrame(() => { peelTick = false; peelCheck(); });
  };
  addEventListener('scroll', onScroll, { passive: true });
  addEventListener('resize', onScroll, { passive: true });
  peelCheck();

  $('year').textContent = new Date().getFullYear();

  /* go */
  if (REDUCED) {
    for (const [cls, txt] of BOOT) line(esc(txt), cls);
    line('reduced motion honored: typing disabled, everything the same.', 'ev');
    ready();
  } else {
    boot().catch(() => note('error', 'console boot interrupted; the docs remain available.')).finally(ready);
  }
})();
