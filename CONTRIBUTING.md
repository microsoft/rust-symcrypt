# Contributing to rust-symcrypt

Thank you for your interest in contributing. This document covers how the repository is organized, where to send pull requests, and what to expect from the review process.

For technical details — generating bindings, adding new APIs, updating the SymCrypt submodule, and publishing — see [`rust-symcrypt/DEVELOPER.md`](rust-symcrypt/DEVELOPER.md).

---

## Branch Model

```
main                        ← published releases only (tagged)
release/X.Y.Z               ← staging for the next release
release/X.Y.x               ← maintenance branches for prior releases
experimental/static-linking ← long-lived experimental work (not yet released)
user/<alias>/<feature>      ← individual contributor branches
```

### `main`
Matches the latest published crate version exactly. Only updated when a release ships — never committed to directly. Every commit on `main` has a corresponding version tag (`0.5.1`, `0.6.0`, etc.).

### `release/X.Y.Z`
The active staging branch for the next release. This is where feature and fix PRs should be targeted. When the release is ready, this branch is merged into `main` and tagged.

**To find the current active release branch**, check the branch list — it will be the most recent `release/` branch.

### `release/X.Y.x`
Maintenance branches kept alive after a release ships, for backporting critical fixes. The project supports the **last two minor versions**. Older maintenance branches are archived and no longer accept changes.

### `experimental/static-linking`
Work-in-progress static linking support. Not part of any release yet. Contributions welcome, but expect periodic rebases onto `main`.

---

## How to Contribute

1. **Fork** the repository and create your branch from the active `release/X.Y.Z` branch:
   ```bash
   git checkout -b user/<your-alias>/<short-description> origin/release/X.Y.Z
   ```

2. **Make your changes.** Follow the FFI safety conventions and code style described in [`CLAUDE.md`](CLAUDE.md).

3. **Run the full test suite** on both Windows and Linux (WSL) before opening a PR:
   ```bash
   cargo test --all-features --locked
   cargo clippy --all-features -- -D warnings
   cargo fmt --check
   ```

4. **Open a PR** targeting the active `release/X.Y.Z` branch — not `main`.

5. Ensure all CI checks pass. The CI enforces:
   - Zero Clippy warnings (`-D warnings`)
   - Correct formatting (`cargo fmt --check`)
   - LF line endings
   - Bindings files match freshly generated output
   - Submodule commit matches `VERSION.md`

---

## Release Flow

Releases are managed by the maintainers. The general flow is:

```
feature PRs → release/X.Y.Z → PR into main → tag vX.Y.Z → publish to crates.io
```

If you are a maintainer cutting a release, follow the steps in [`rust-symcrypt/DEVELOPER.md`](rust-symcrypt/DEVELOPER.md#cargo-publishing-guidelines).

---

## Reporting Issues

Please open a GitHub issue. For security vulnerabilities, follow the process in [`SECURITY.md`](SECURITY.md).
