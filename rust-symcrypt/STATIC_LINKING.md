# Static Linking (Experimental)

> **This feature is experimental and lives on the `experimental/static-linking` branch.**
> It is not part of any released version of `symcrypt`. APIs and behavior may change.

> **NOTE: Static linking must not be used in production or release builds for Microsoft 1st Party.
> If you are a Microsoft employee please contact the SymCrypt team for more info.**

Static linking does not offer FIPS compliance and is intended for rapid development and testing only.

---

## Overview

Static linking works by building the `SymCrypt` library from source and linking against the resulting static library. This results in longer build times and larger binaries, but removes the requirement to distribute or locate a dynamic library at runtime.

Static linking is the default on this branch. To opt into dynamic linking instead, enable the `dynamic` feature flag (see below).

### Supported Configurations

| Operating Environment | Architecture | Static Linking |
| --------------------- | ------------ | -------------- |
| Windows user mode     | AMD64, ARM64 | ✅ ⚠️         |
| Ubuntu                | AMD64, ARM64 | ✅ ⚠️         |
| Azure Linux 3         | AMD64, ARM64 | ✅ ⚠️         |

---

## Usage

### Static linking (default on this branch)

```cargo
[dependencies]
symcrypt = "0.6.0"
hex = "0.4.3"
```

### Dynamic linking

If you need FIPS compliance or want to use a system-installed SymCrypt library, enable the `dynamic` feature:

```cargo
[dependencies]
symcrypt = { version = "0.6.0", features = ["dynamic"] }
hex = "0.4.3"
```

For dynamic linking setup instructions see `INSTALL.md`.

---

## Build Requirements

Static linking requires the SymCrypt source to be available as a submodule. The build script in `symcrypt-sys/build/static_link.rs` handles compilation. Refer to `DEVELOPER.md` for submodule setup and regenerating bindings.

### Windows

No additional setup is required beyond a standard Rust + MSVC toolchain.

### Linux

The following packages are required:

```bash
sudo apt-get install -y clang libclang-dev
```

For cross-compilation (ARM64):

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```
