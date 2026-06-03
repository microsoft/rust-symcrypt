# loader_poc — embed-and-extract POC for symcrypt.dll

A **stripped-down rust-symcrypt** that shows the embed-and-extract distribution

```
loader_poc/
├── Cargo.toml          (one dep: windows-sys for dll loading)
├── build.rs            (computes SHA-256 of the embedded DLL at build time)
├── symcrypt.dll        
├── src/
│   ├── lib.rs          (DLL loader: include_bytes + extract + LoadLibrary + GetProcAddress)
│   └── hash.rs         (friendly Rust API: sha256() + Sha256State)
└── tests/
    └── hash.rs         (8 tests proving the pipeline by hitting the public API)
```

The public API in `hash.rs` looks exactly like rust-symcrypt:

```rust
use rust_symcrypt_mini::hash::{sha256, Sha256State};

// One-shot:
let digest = sha256(b"hello world");

// Streaming:
let mut s = Sha256State::new();
s.append(b"hello ");
s.append(b"world");
let digest = s.result();
```
