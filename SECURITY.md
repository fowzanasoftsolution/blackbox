# Security Policy

Blackbox runs on the network edge of your own server and by design sees
everything flowing through it — request bodies, provider responses, webhook
signatures. If you find a vulnerability, we want to know about it before
anyone else does.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Use GitHub's [private vulnerability reporting](https://github.com/fowzanasoftsolution/blackbox/security/advisories/new):

1. Go to the repository's **Security** tab → **Advisories** →
   **New draft security advisory**.
2. Describe the issue, its impact, and (if possible) a minimal reproduction
   — a failing test or a `blackbox` command sequence is ideal.
3. Include the exact version (`blackbox --help` prints the version banner)
   and how you ran it (binary + flags, `run` vs `serve`, OS).

You will get an initial acknowledgement within 72 hours. The project does
not currently operate a security inbox alias or a bug bounty; triage happens
directly in the GitHub advisory thread.

Please include:

- What data is exposed or what behavior is broken, and to whom it matters.
- Whether the issue reproduces with the cold tier attached or detached.
- Any workarounds you already know about.

Please **not**:

- Do not test against servers you do not own or run what you find against
  third-party deployments.
- Do not publish, fork, or link the report anywhere else before a public
  advisory exists.

## Coordinated disclosure

- We confirm, fix and ship a patch release for confirmed vulnerabilities.
- The advisory is published on GitHub once a fixed release is available.
- Deterministic, well-understood hardening fixes are announced in the tenant
  release notes; you are never required to name yourself publicly — you may
  remain anonymous and the advisory will credit the reporter only if you ask.

## Supported versions

| Version | Support | Notes |
|---|---|---|
| 1.1.x | full | current line; get patches here |
| 1.0.x | security fixes only | upgrade recommended |
| < 1.0 | unsupported | — |

The data plane is local-first: telemetry stays in `<data>/` until you
explicitly *attach* an S3/R2 cold tier. If your box only runs Blackbox, the
exposed surface is the listeners you started (`--listen`, `--egress-listen`,
`--admin-listen`) plus `/proc` of the wrapped app.

## Releases, keys and verification

Release artifacts ship from GitHub Releases with a `SHA256SUMS` checksum
file — always `sha256sum -c SHA256SUMS` before running anything.

Where a release includes `blackbox.sig` and `blackbox.pub`, the binary is
Ed25519-signed with the project update key in the same format
`blackbox self-update` consumes; pin the published key:

```sh
export BLACKBOX_UPDATE_PUBKEY=$(tar -xOzf blackbox-x86_64-linux.tar.gz blackbox.pub)
```

Enterprise deployments can bake their *own* verifying key at build time with
`BLACKBOX_RELEASE_PUBKEY=<64 hex>`, or supply one at runtime via
`BLACKBOX_VERIFY_PUBKEY`. A candidate update that fails signature
verification is rejected immediately (exit 2); a *signed but broken*
candidate is caught by the isolated canary boot and rolled back (exit 3).

The compiled-in release verifying key (fingerprint only) is:

```
77b44dc4dd7f50fef3dc959963050fb490e78a15a438aed18418ce2109a1f153
```

Verification inside `blackbox audit verify` covers the local storage chain.
It has a documented boundary: an unanchored truncation that removes history
*below* every exported checkpoint is reported honestly as a shorter, clean
chain inside that truncated prefix. Export and pin the anchor
(`blackbox audit current-anchor`) when you need truncation detection — see
the README's [audit-chain section](README.md#pro-differentiators).

## Hardening defaults worth knowing

- The admin API can require `BLACKBOX_ADMIN_TOKEN` (`x-admin-token`); bind it
  to localhost if you do not want it on the wire.
- The scanner shield drops `/.env`, `/.git/*`, `wp-admin`, traversal attempts
  and friends before the limiter or storage ever see them.
- Rate limiting is on by default (`--rps`/`--burst`; unlimited only at 0).
- TLS termination uses rustls with bundled webpki roots; upstream calls speak
  HTTPS even though the local termination is plain HTTP by design.
