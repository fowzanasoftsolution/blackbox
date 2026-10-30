# Browser experiments

The [OPEN THE BOX landing page](../) lets you inspect Blackbox without running
a node. It is a static website: no API backend, third-party scripts, cookies,
analytics, LLM calls, or outgoing test requests. Input stays in the page and
is rendered as text, not executable markup. The limits below are intentional.

## What is real?

| Experience | What happens | What does not happen |
|---|---|---|
| Terminal `demo` | Replays the captured output of a real v1.1.3 Linux demo | A node is not booted; playback is not a benchmark |
| Crash / self-heal steppers | Guided explanations of documented behavior | No process is killed and no file is corrupted |
| Duplicate flood | An in-memory JavaScript `Set` deduplicates 5,000 generated event IDs | No durable enqueue, HMAC check, retry delivery, or network request |
| Memory slider | Computes policy eligibility at the selected RSS percentage | No memory is allocated and no stochastic sample is drawn |
| SimHash playground | Computes the Rust text-fingerprint algorithm in JavaScript | No full near-key, cache lookup, semantic proof, or LLM response |
| Scanner range | Evaluates a JavaScript port of the Rust path matcher | No URL is fetched and no application security audit is performed |

Historical numbers are identified separately from local calculations.
The demo tape is a recorded run; the guided stepper text is **not** verbatim
runtime output. Press **skip tape** to render a replay immediately. Keyboard
terminal commands and reduced-motion playback are instant.

## Upstream crash

The crash model explains an upstream app exit: the supervisor observes the
failure, holds the connection behind its breaker, restarts the app with
backoff, and resumes traffic. The v1.1.2c soak recorded **0.203 / 0.257 s**
recoveries. Those are historical measurements, not a stopwatch in the browser.

This must not be confused with killing the Blackbox node mid-append. RAW
segments tolerate a torn tail; uncommitted bytes are not promised durable.
The [verification matrix](verification.md) separates the recovery gates.

## Sealed-segment self-heal

The guided sequence explains demo phase E: an unreadable frame in a sealed
`.zst` yields `StorageError::Corrupt`; Blackbox restores the cold-tier replica
only after verifying its digest and replaces the local file atomically.
The recorded demo ended with **1 heal and 1 intact record**. A missing or
invalid replica is not magically repaired by the browser model.

Source: [`demo.rs`](https://github.com/fowzanasoftsolution/blackbox/blob/main/crates/blackbox/src/demo.rs),
the sealed-segment reader, and phase 6 bit-rot gates.

## Duplicate flood

Choose 1, 100, or 5,000 distinct IDs in 5,000 requests. The local set yields:

| Distinct IDs | Unique modeled jobs | Suppressed repeats |
|---|---|---|
| 1 | 1 | 4,999 |
| 100 | 100 | 4,900 |
| 5,000 | 5,000 | 0 |

This is a dedup-window explanation, **not** the same experiment as the real
phase 3 delivery gate. That gate verifies delivery of **5,000 distinct
webhooks** with byte-exact HMACs. The production implementation has persistent
state, expiry, leases, retries, and failure modes absent from the local set.

## Memory watermarks

The slider models the source policy:

| Modeled RSS / budget | Level | Action |
|---|---|---|
| < 75% | `Normal` | No pressure sampling |
| ≥ 75%, < 85% | `Warn75` | Cache / allocator purge; sampling unchanged |
| ≥ 85%, < 95% | `Shed85` | Healthy 2xx traces under 1 s have a 1% keep probability |
| ≥ 95% | `Backpressure95` | Published level; continued shedding, **not an HTTP traffic gate** |

Non-2xx responses and slow traces are exempt from that healthy-fast sampling
rule. Crash records and durable queue jobs do not pass through this sampler.
"100% sampling eligibility" is not a guarantee against all resource or disk
failures. Real keep counts are stochastic; the slider displays probabilities.

Sources: [`tee.rs`](https://github.com/fowzanasoftsolution/blackbox/blob/main/crates/blackbox-ingress/src/tee.rs)
and [`memory.rs`](https://github.com/fowzanasoftsolution/blackbox/blob/main/crates/blackbox-supervisor/src/memory.rs).

## SimHash playground

The port follows [`simhash.rs`](https://github.com/fowzanasoftsolution/blackbox/blob/main/crates/blackbox-egress/src/simhash.rs):

1. Lowercase and use ASCII-oriented normalization; punctuation becomes space.
2. Collapse numeric runs to `#` and whitespace runs to a single space.
3. Form word 3-shingles, falling back to bigrams / unigrams for short text.
4. Join shingle tokens with byte `0x01` and compute wrapping 64-bit FNV-1a.
5. Majority-vote each bit (ties resolve to zero); cap at 4,096 shingles.
6. Count XOR bits for Hamming distance; default candidate budget is **≤ 3**.

The browser input limit is **2,000 characters per prompt** to bound work on
mobile devices. BigInt preserves 64-bit arithmetic; this is not a float-based
approximation. Empty normalized text is not a near-cache candidate.

### Safety limits

A candidate is **not a cache hit**. The real gateway also checks a
domain-separated key over tenant, authorization, method, URL, and non-text
request controls. This page does not implement those checks or the cache.

Digit collapse can equate different account IDs, amounts, or timestamps.
Try the **numeric collision** preset: two different transfers normalize to
the same text. Similarity is not semantic equivalence; use
`BLACKBOX_SIMHASH_MAXDIST=0` to disable the production near-cache when such
equivalence is inappropriate for your workload.

## Scanner range

The port follows [`waf.rs`](https://github.com/fowzanasoftsolution/blackbox/blob/main/crates/blackbox-ingress/src/waf.rs).
It checks the raw path before a single byte-wise percent-decoding pass:

- traversal fragments such as `../`, `..\\`, or a trailing `..`;
- blocked segments, including `.env`, `.git`, `wp-admin`, and `actuator`;
- dot-extensions of blocked segments, such as `.env.production`;
- backup/config suffixes: `.sql`, `.bak`, `.old`, `.orig`, and `.swp`.

Matching lowercases ASCII letters and splits on `/` and `\`. The range takes
a raw path beginning with `/`, capped at **2,048 characters**. Query strings
are removed, matching how the proxy supplies `uri.path()`; no URL parser
normalizes dot segments before evaluation.

Blocked paths would receive a bare **HTTP 404** before the limiter, recorder,
or app. Passing paths have **no predicted HTTP status**: the application and
other defenses decide what happens next.

Malformed escapes or invalid decoded UTF-8 fail open **after the raw check**.
Double encoding is not decoded recursively; `/%252Egit/config` can pass this
matcher. A pass is not a claim that a path is safe. This is a narrow scanner
shield, not authorization, a complete WAF, or a vulnerability scanner.

## Verify the ports

From the repo root, with Node.js 22+, Python 3, and `rustc` on PATH:

```sh
node --test site/test/*.test.cjs
python site/test/rust-parity.py
```

The parity check compiles the actual Rust normalization / fingerprint code
and scanner module, then compares JavaScript outputs over representative
inputs, encoded paths, malformed UTF-8, numeric drift, and the shingle cap.
It does not build or exercise the complete Linux node. The Pages workflow
runs both checks before publishing, alongside documentation/link checks.

Authored by **Dr.wolfic** for **fowzanasoftsolution** · made in India with love.
