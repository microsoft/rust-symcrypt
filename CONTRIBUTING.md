# Contributing to rust-symcrypt

Thank you for your interest in contributing. This document covers the branch model, how to send pull requests, and technical workflows for maintainers.

---

## Branch Model

| Branch | Purpose |
|---|---|
| `main` | Published releases only (tagged) |
| `release/X.Y.Z` | Staging for the next release |
| `experimental/static-linking` | Long-lived experimental work (not yet released) |
| `user/<alias>/<feature>` | Individual contributor branches |

### `main`
Matches the latest published crate version exactly. Only updated when a release ships. `main` is never committed to directly. Every commit on `main` has a corresponding version tag (`0.5.1`, `0.6.0`, etc.).

### `release/X.Y.Z`
The active staging branch for the next release. Feature and fix PRs should target this branch. When the release is ready, it is merged into `main` and tagged. The branch is kept alive afterward for backporting critical fixes.

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

5. Ensure all CI checks pass.

---

## Repo Structure

This repo contains `symcrypt` and `symcrypt-sys` as a Cargo workspace, with the former depending on the latter. `symcrypt-bindgen` is a build tool for generating FFI bindings.

---

## Generating Bindings

Bindings can be generated two ways:

1. **With the `generate-all-bindings.ps1` script.** Requires build dependencies installed locally. See the script for installation instructions.

2. **Via GitHub Actions.** Create a PR with the `publish_new_bindings` label. This produces an artifact with bindings for each supported target triple. The action pulls SymCrypt from the GitHub submodule, not from the PR branch.

**Note:** CI validates that checked-in bindings match freshly generated ones. A mismatch fails the build.

### Adding New APIs

1. Ensure you have the correct SymCrypt submodule (see [Updating the SymCrypt Submodule](#updating-the-symcrypt-submodule) if needed).
2. Add the new SymCrypt APIs to `symcrypt-bindgen/src/main.rs`. Use regex semantics to expose only the needed symbols.
3. Generate new bindings via GitHub Actions or the `generate-all-bindings.ps1` script.
4. Implement safe wrappers in `rust-symcrypt/`. Document your changes and update the API list in `rust-symcrypt/README.md`.
5. Push and ensure all CI checks pass.
6. Depending on the change, you may need to bump the crate version (see [Publishing](#publishing)).

### Updating the SymCrypt Submodule

You may need to update the underlying SymCrypt version when:
- Adding bindings for newly released SymCrypt APIs
- Applying a security patch from SymCrypt

`symcrypt-sys` depends on SymCrypt via a GitHub submodule. The pinned commit is recorded in `symcrypt-sys/VERSION.md`, and CI validates the submodule matches it.

To update:
1. In `symcrypt-sys/symcrypt/`, check out the required commit (should be a tagged SymCrypt release).
2. Stage: `git add symcrypt-sys/symcrypt`.
3. Update `symcrypt-sys/VERSION.md` with the new commit hash.
4. Update `rust-symcrypt/README.md` with the new SymCrypt version.
5. Update `build_windows.yml` and `build_linux.yml` to download the matching SymCrypt release artifacts.
6. Push and ensure the `check-submodule` CI check passes.

---

## Release Flow

Releases are managed by the maintainers. The general flow is:

```
feature PRs -> release/X.Y.Z -> PR into main -> tag vX.Y.Z -> publish to crates.io
```

### Publishing

1. Branch: `user/<your-alias>/bump_version_0.X.X`.
2. Bump the version in the relevant `Cargo.toml`(s). Follow [semver](https://semver.org/).
3. Update `README.md` with the new version.
4. Test: `cargo test --all-features` on both Windows and WSL.
5. Open a PR against the active `release/X.Y.Z` branch. Wait for review and CI.
6. Once the release PR is merged into `main`, check out `main` and prep the Cargo release.
7. Ensure no uncommitted changes exist (they would be included in the publish).
8. Verify: `cargo package --list`.
9. Dry run: `cargo publish --dry-run`.
10. Publish: `cargo publish`.
11. Create a GitHub release tag. Highlight any breaking changes.
12. For critical bugs (dangling pointer, invalid memory), discuss a [cargo yank](https://doc.rust-lang.org/cargo/commands/cargo-yank.html) with the team.

---

## Support and Reporting Issues

If you have a question, bug report, or feature request, please [open a GitHub issue](https://github.com/microsoft/rust-symcrypt/issues).
