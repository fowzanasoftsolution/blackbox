/* Open the Box — local experiments. User input is always rendered as text.
   Guided scenarios are explanations, NOT verbatim runtime logs. */
(() => {
  'use strict';
  const A = window.BlackboxLab;
  if (!A) return;
  const $ = id => document.getElementById(id);
  const put = (id, text) => { $(id).textContent = text; };

  // Keyboard actions stay instant; pointer presses retain subtle feedback.
  document.addEventListener('keydown', () => document.body.classList.add('keyboard-action'));
  document.addEventListener('pointerdown', () => document.body.classList.remove('keyboard-action'));

  const scenarios = {
    kill: [
      'MODEL · a request is in flight to the upstream app.',
      'MODEL · upstream app exits; supervisor observes the failure.',
      'MODEL · breaker holds the connection while restart backs off.',
      'MODEL · app respawns; the held request can resume.',
      'HISTORICAL · v1.1.2c soak measured 0.203 / 0.257 s recoveries. No clock or process ran here.'
    ],
    corrupt: [
      'MODEL · a sealed .zst has a cold-tier replica.',
      'MODEL · a read detects an unreadable frame and returns StorageError::Corrupt.',
      'MODEL · fetch the cold replica and verify its digest; reject an invalid replica.',
      'MODEL · atomically replace the local segment with the verified replica.',
      'RECORDED RESULT · demo phase E: 1 heal, 1 record intact. These steps explain the capture; they are not raw logs.'
    ]
  };
  const positions = { kill: 0, corrupt: 0 };

  function stepProbe(name, all = false) {
    const tape = $(name + '-tape'), steps = scenarios[name];
    if (positions[name] === steps.length) resetProbe(name);
    const limit = all ? steps.length : positions[name] + 1;
    while (positions[name] < limit) {
      const li = document.createElement('li');
      li.textContent = steps[positions[name]++];
      tape.appendChild(li);
    }
    const done = positions[name] === steps.length;
    put(name + '-state', done ? 'guided simulation · complete (not a live test)' :
      `guided simulation · step ${positions[name]} / ${steps.length}`);
    document.querySelector(`[data-probe="${name}"]`).textContent = done ? 'replay scenario' : 'next step';
  }

  function resetProbe(name) {
    if (name === 'flood') {
      $('flood-distinct').value = '1';
      put('flood-output', 'Choose a workload, then send the local flood.');
      put('flood-state', 'local simulation · ready');
      return;
    }
    positions[name] = 0;
    $(name + '-tape').replaceChildren();
    put(name + '-state', 'guided simulation · ready');
    document.querySelector(`[data-probe="${name}"]`).textContent = name === 'kill' ? 'simulate crash' : 'simulate bit-rot';
  }

  function flood() {
    const result = A.dedupFlood(5000, Number($('flood-distinct').value));
    put('flood-output', `LOCAL MODEL · ${result.total.toLocaleString('en-US')} requests\n` +
      `${result.queued.toLocaleString('en-US')} unique jobs queued\n` +
      `${result.duplicates.toLocaleString('en-US')} duplicate attempts suppressed\n` +
      '0 network requests · delivery / HMAC / disk persistence not exercised');
    put('flood-state', 'local simulation · complete; no webhooks sent');
  }

  function shed() {
    const percent = Number($('rss-level').value), level = A.ramLevel(percent);
    put('rss-value', percent + '%');
    put('shed-output', `POLICY MODEL · ${level}\n` +
      `healthy 2xx < 1 s: ${A.keepRate(percent, 200, 100) * 100}% keep probability\n` +
      `errors / slow traces: ${A.keepRate(percent, 500, 100) * 100}% sampling eligibility\n` +
      'crashes / durable queue jobs: outside this healthy-trace sampler');
    put('shed-state', level === 'Backpressure95' ?
      '95%+ · level published; no RAM-level HTTP traffic gate' : level === 'Warn75' ?
      '75%+ · cache / allocator purge; healthy sampling unchanged' : level === 'Shed85' ?
      '85%+ · healthy sampling active; actual counts are stochastic' : 'below 75% · no pressure sampling');
  }

  document.querySelectorAll('[data-probe]').forEach(button => button.addEventListener('click', () => {
    const name = button.dataset.probe;
    if (name === 'flood') flood(); else stepProbe(name);
  }));
  document.querySelectorAll('[data-reset]').forEach(button => button.addEventListener('click', () => resetProbe(button.dataset.reset)));
  $('rss-level').addEventListener('input', shed);
  // Changing workload invalidates the old output rather than displaying stale counts.
  $('flood-distinct').addEventListener('change', () => {
    put('flood-output', 'Workload changed. Run the local flood again.');
    put('flood-state', 'local simulation · ready');
  });
  shed();

  const base = 'Summarize the invoice for order 1042, then list the next steps.';
  const presets = {
    format: [base, 'SUMMARIZE the invoice for order 8080! Then list the next steps.'],
    near: [base, 'Summarize the receipt for order 1042, then list the next steps.'],
    different: [base, 'Write a poem about monsoon clouds over the mountains.'],
    numbers: ['Transfer 100 rupees to account 42.', 'Transfer 900 rupees to account 99.']
  };

  function drawBits(id, value, xor) {
    const fragment = document.createDocumentFragment();
    for (let i = 63; i >= 0; i--) {
      const bit = 1n << BigInt(i), cell = document.createElement('span');
      cell.className = 'bit' + (value & bit ? ' one' : '') + (xor & bit ? ' changed' : '');
      cell.title = `bit ${i}: ${value & bit ? 1 : 0}${xor & bit ? ' (different)' : ''}`;
      fragment.appendChild(cell);
    }
    $(id).replaceChildren(fragment);
  }

  function compare() {
    const left = $('prompt-a').value.slice(0, 2000), right = $('prompt-b').value.slice(0, 2000);
    const a = A.simhash(left), b = A.simhash(right), distance = A.hamming(a, b);
    const na = A.normalize(left), nb = A.normalize(right), empty = !na || !nb;
    put('sim-distance', distance + ' / 64 bits');
    put('hash-a', a.toString(16).padStart(16, '0'));
    put('hash-b', b.toString(16).padStart(16, '0'));
    put('normalized-a', na || '(empty after ASCII-oriented normalization)');
    put('normalized-b', nb || '(empty after ASCII-oriented normalization)');
    put('sim-result', empty ? 'No near-cache candidate: a normalized prompt is empty.' : distance <= 3 ?
      'Within d ≤ 3 · fingerprint candidate only, not a verified cache hit.' :
      'Outside d ≤ 3 · would miss this text-distance check.');
    $('sim-result').className = !empty && distance <= 3 ? 'result-hit' : 'result-miss';
    drawBits('bits-a', a, a ^ b); drawBits('bits-b', b, a ^ b);
  }

  // Small input cap bounds BigInt work; one update per animation frame, not a debounce delay.
  let compareQueued = false;
  function queueCompare() {
    if (compareQueued) return;
    compareQueued = true;
    requestAnimationFrame(() => { compareQueued = false; compare(); });
  }
  $('prompt-a').addEventListener('input', queueCompare);
  $('prompt-b').addEventListener('input', queueCompare);
  document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => {
    const [a, b] = presets[button.dataset.preset];
    $('prompt-a').value = a; $('prompt-b').value = b; compare();
  }));
  compare();

  let checks = 0, blocks = 0;
  function testPath() {
    const raw = $('scanner-path').value;
    if (!raw.startsWith('/') || raw.length > 2048) {
      put('scanner-verdict', 'Enter a raw path starting with /.');
      return;
    }
    const path = raw.split('?')[0], result = A.scanner(path);
    checks++; if (result.blocked) blocks++;
    put('scanner-verdict', result.blocked ? 'BLOCK · shield would return HTTP 404' : 'PASS · application decides the response');
    $('scanner-verdict').className = 'scanner-verdict ' + (result.blocked ? 'result-miss' : 'result-hit');
    put('scanner-output', `LOCAL EVALUATION · ${path}\n` +
      `match: ${result.rule || 'none'}\n` +
      `matched pass: ${result.pass}\n` +
      (result.blocked ? 'pipeline: drop before limiter → recorder → upstream' :
        'pipeline: shield passes; other defenses / app not evaluated') + '\n' +
      'network requests: 0' + (result.decoded === null && !result.blocked ? '\npercent decoding: invalid; raw-only result' : ''));
    put('scanner-total', checks); put('scanner-blocked', blocks); put('scanner-passed', checks - blocks);
  }

  $('scanner-form').addEventListener('submit', event => { event.preventDefault(); testPath(); });
  document.querySelectorAll('[data-path]').forEach(button => button.addEventListener('click', () => {
    $('scanner-path').value = button.dataset.path; testPath();
  }));
  $('scanner-path').addEventListener('input', () => {
    put('scanner-verdict', 'Path changed · test to evaluate');
    $('scanner-verdict').className = 'scanner-verdict';
    put('scanner-output', 'The previous result has been cleared. No request has been sent.');
  });
  $('scanner-reset').addEventListener('click', () => {
    checks = 0; blocks = 0; $('scanner-path').value = '/.env';
    put('scanner-total', 0); put('scanner-blocked', 0); put('scanner-passed', 0);
    put('scanner-verdict', 'Range reset · ready');
    $('scanner-verdict').className = 'scanner-verdict';
    put('scanner-output', 'Choose an example or enter a raw path. No network requests are sent.');
  });
  put('scanner-verdict', 'Ready · choose a path');
  put('scanner-output', 'Choose an example or enter a raw path. No network requests are sent.');

  function openSection(id, focusId) {
    $(id).scrollIntoView({ behavior: 'auto', block: 'start' });
    if (focusId) $(focusId).focus({ preventScroll: true });
  }
  window.BlackboxExperiments = Object.freeze({
    runProbe(name) {
      openSection('torture');
      if (name === 'kill' || name === 'corrupt') stepProbe(name, true);
      else if (name === 'flood') flood();
      else if (name === 'shed85') { $('rss-level').value = '85'; shed(); }
    },
    openSimhash() { openSection('simhash', 'prompt-b'); },
    openScanners() { openSection('scanners', 'scanner-path'); }
  });
})();
