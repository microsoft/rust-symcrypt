# SymCrypt on Rust

Within this repository, there are 2 crates:

1. **symcrypt-sys**: Rust/C FFI bindings for [SymCrypt](https://github.com/microsoft/SymCrypt).
2. **symcrypt**: Friendly and idiomatic Rust wrappers over `symcrypt-sys`.

Additionally, the repository includes **`symcrypt-bindgen`**, tooling to generate the FFI bindings used by `symcrypt-sys`.

The purpose of these crates is to bring FIPS-compliant cryptography to the Rust ecosystem.

## Contributing

We welcome comments, suggestions, and contributions from vetted partners. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branch model, PR process, and developer workflows.
