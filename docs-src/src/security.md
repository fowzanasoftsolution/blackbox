# Security

Blackbox runs on the network edge of your server and by design sees everything
flowing through it. This chapter summarizes the reporting and verification
discipline; the canonical policy lives in [`SECURITY.md`](https://github.com/fowzanasoftsolution/blackbox/blob/main/SECURITY.md).

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub's [private vulnerability
reporting](https://github.com/fowzanasoftsolution/blackbox/security/advisories/new):
describe impact and a minimal reproduction (a failing test or a `blackbox`
command sequence is ideal), include the exact version and how you ran it.
Initial acknowledgement within 72 hours; coordinated disclosure, credit on
request.

## Exposure model

Data plane is local-first: telemetry stays in `<data>/` until you explicitly
attach an S3/R2 cold tier. If the box only runs Blackbox, the exposed surface
is the listeners you started (`--listen`, `--egress-listen`,
`--admin-listen`) plus `/proc` of the wrapped app.

## Hardening defaults worth knowing

- The admin API honors `BLACKBOX_ADMIN_TOKEN` (`x-admin-token`); bind it to
  localhost if you don't want it on the wire.
- The scanner shield drops `/.env`, `/.git/*`, `wp-admin`, traversal attempts
  and friends before the limiter or storage ever see them.
- Rate limiting on by default when configured (`--rps`/`--burst`; unlimited
  only at 0).
- TLS termination is rustls with bundled webpki roots; upstream calls always
  speak HTTPS; local termination is plain HTTP by design (loopback pattern).
- Telemetry records carry PII scrubbing at capture (JSON key redaction) — the
  recorder tries not to become the leak.
- The audit chain covers the storage record stream; see its documented
  truncation boundary in the Architecture chapter.
