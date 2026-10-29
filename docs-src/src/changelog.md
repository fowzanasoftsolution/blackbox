# Changelog

The canonical changelog lives in the repository:
[CHANGELOG.md](https://github.com/fowzanasoftsolution/blackbox/blob/main/CHANGELOG.md).

Highlights of recent lines:

- **v1.1.3** — banner/`--version` drift fix (both derive from
  `CARGO_PKG_VERSION` now); sealed-read corruption surfaces
  (`StorageError::Corrupt`) so the cold-tier self-heal actually fires; admin
  console v2 (full snapshot rendering, sparklines, flight tape).
- **v1.1.2** — streaming sidecar indexing (bounded RAM through compaction);
  rollover guard; SIGINT/SIGTERM shutdown hardening; soak re-verification
  20/20.
