# SymCrypt on Rust

## Introduction

Within this repository, there are 3 crates:

1. **symcrypt-sys**: Modified Rust/C FFI bindings over SymCrypt.
2. **symcrypt**: Provides friendly Rust wrappers over `symcrypt-sys`.
3. **symcrypt-bindgen**: Generates raw bindings for `symcrypt-sys` via Bindgen.

The purpose of these crates is to bring FIPS-compliant cryptography to the Rust Ecosystem. Currently, there is only binding support for Windows and Linux.

**Note:** As of version 0.1.0, only Windows AMD64 is supported.
