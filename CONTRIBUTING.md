# Contributing to rust-symcrypt

Thank you for your interest in contributing. This document covers how the repository is organized, where to send pull requests, and what to expect from the review process.

For technical details such asgenerating bindings, adding new APIs, updating the SymCrypt submodule, and publishing, see [`rust-symcrypt/DEVELOPER.md`](rust-symcrypt/DEVELOPER.md).

---

## Branch Model

| Branch | Purpose |
|---|---|
| `main` | Published releases only (tagged) |
| `release/X.Y.Z` | Staging for the next release. Kept alive after shipping for patch maintenance |
| `experimental/static-linking` | Long-lived experimental work (not yet released) |
| `user/<alias>/<feature>` | Individual contributor branches |

### `main`
Matches the latest published crate version exactly. Only updated when a release ships. `main` is never committed to directly. Every commit on `main` has a corresponding version tag (`0.5.1`, `0.6.0`, etc.).

### `release/X.Y.Z`
The active staging branch for the next release. Feature and fix PRs should target this branch. When the release is ready, it is merged into `main` and tagged. The branch is kept alive afterward for backporting critical fixes.

The project supports the **last two minor versions**. Older release branches are archived and no longer accept changes.

**To find the current active release branch**, check the branch list, it will be the most recent `release/` branch.

### `experimental/static-linking`
WIP static linking support. Not part of any release yet, periodic rebases onto `main`.

---

## How to Contribute

1. **Fork** the repository and create your branch from the active `release/X.Y.Z` branch:
   ```bash
   git checkout -b user/<your-alias>/<short-description> origin/release/X.Y.Z
   ```

2. **Make your changes.** Follow the existing code style and FFI safety conventions used throughout the codebase.

3. **Run the full test suite** on both Windows and Linux (WSL) before opening a PR:
   ```bash
   cargo test --all-features --locked
   cargo clippy --all-features -- -D warnings
   cargo fmt --check
   ```

4. **Open a PR** targeting the active `release/X.Y.Z` branch (not `main`).

5. Ensure all CI checks pass

---

## Release Flow

Releases are managed by the maintainers. The general flow is:

```
feature PRs -> release/X.Y.Z -> PR into main -> tag vX.Y.Z -> publish to crates.io
```

If you are a maintainer cutting a release, follow the steps in [`rust-symcrypt/DEVELOPER.md`](rust-symcrypt/DEVELOPER.md#cargo-publishing-guidelines).

---

## Support and Reporting Issues

If you have a question, bug report, or feature request, please [open a GitHub issue](https://github.com/microsoft/rust-symcrypt/issues). For security vulnerabilities, follow the process in [`SECURITY.md`](SECURITY.md).
