// Node @sentry/node v8+ parity check — proves the OFFICIAL Node SDK accepts
// blackbox's injected `sentry-trace` + `baggage` headers and continues the
// EXACT same 128-bit trace id, via the same public API its HTTP middleware
// uses (Sentry.continueTrace). Run after `npm install @sentry/node`.
//
// Exit 0 = parity OK; exit 1 = regression; exit 2 = SDK not installed.
'use strict';

const TID = '4bf92f3577b34da6a3ce929d0e0e4736';
const SENTRACE = `${TID}-00f067aa0ba902b7-1`;
// blackbox injects exactly these entries (caller baggage must survive too).
const BAGGAGE = `sentry-trace_id=${TID},sentry-sampled=true,userId=42`;

let Sentry;
try {
  Sentry = require('@sentry/node');
} catch (e) {
  console.error('skip: @sentry/node is not installed');
  process.exit(2);
}

if (typeof Sentry.continueTrace !== 'function') {
  console.error('FAIL: @sentry/node has no continueTrace() — wrong major?');
  process.exit(1);
}

// v8's continueTrace(context, callback) REQUIRES the callback (the
// propagation context is set on a scope that only lives for the callback's
// duration); v9+ made the callback optional. Passing one works on both —
// and reading inside it mirrors exactly what the SDK's HTTP middleware does
// (the request handler runs inside that scope).
const readPc = () => {
  const scopes = [Sentry.getCurrentScope && Sentry.getCurrentScope(),
                  Sentry.getIsolationScope && Sentry.getIsolationScope()].filter(Boolean);
  return scopes
    .map((s) => (typeof s.getPropagationContext === 'function' ? s.getPropagationContext() : null))
    .find((p) => p && p.traceId) || null;
};

let pc = null;
Sentry.continueTrace({ sentryTrace: SENTRACE, baggage: BAGGAGE }, () => {
  pc = readPc();
});
if (!pc) pc = readPc(); // v9+ path (context persists past the callback)

if (!pc || !pc.traceId) {
  console.error('FAIL: continueTrace() produced no propagation context');
  process.exit(1);
}
if (pc.traceId !== TID) {
  console.error(`FAIL: trace id mismatch — SDK continued ${pc.traceId}, blackbox injected ${TID}`);
  process.exit(1);
}
console.log(`@sentry/node parity OK — continued trace ${pc.traceId} from sentry-trace + baggage`);
