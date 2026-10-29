# Releases & update verification

Releases are cut from annotated `v*` tags and ship from GitHub Releases.
Before you run anything:

```sh
sha256sum -c SHA256SUMS
```

`SHA256SUMS` covers both release tarballs. Inside each tarball: the binary, the
Ed25519 `blackbox.pub` verifying key and a `blackbox.sig` signature.

## `blackbox self-update`

The updater consumes the same key format it publishes. Pin the published key:

```sh
export BLACKBOX_UPDATE_PUBKEY=$(tar -xOzf blackbox-x86_64-linux.tar.gz blackbox.pub)
```

Update flow: candidate is fetched for your triple → signature verified against
your pinned key (reject: exit 2) → canary boots from a **scratch data dir** and
must answer `/healthz` within the window — the production node stays untouched
while the candidate is judged (rollback: exit 3).

Enterprise deployments can bake their *own* verifying key at build time with
`BLACKBOX_RELEASE_PUBKEY=<64 hex>`, or supply one at runtime via
`BLACKBOX_VERIFY_PUBKEY` (or the legacy `BLACKBOX_UPDATE_PUBKEY`).

## The compiled-in key (fingerprint)

```
77b44dc4dd7f50fef3dc959963050fb490e78a15a438aed18418ce2109a1f153
```

This is the *verifying* key — the public half by design. The signing key lives
in the repository secrets, never in the source tree.

## Images

`blackbox-aarch64-linux.tar.gz` (cross-built, best-effort job) and
`blackbox-x86_64-linux.tar.gz` (primary support target, glibc 2.31+) pack a
stripped, statically-disposed ~17 MB binary.
