//! Minimal example: pick a backend at startup, then SHA-256 "hello world".
//!
//! ```text
//! cargo run -p mscrypto-example                       # SymCrypt (default)
//! $env:MSCRYPTO_BACKEND = "bcrypt"; cargo run -p mscrypto-example   # BCrypt/CNG (Windows)
//! ```

use mscrypto_symcrypt::prelude::*;

#[cfg(windows)]
use mscrypto_bcrypt::BcryptProvider;

/// Holds whichever backend was chosen. Providers are concrete types (the contract
/// has no `dyn`), so a small enum is how a consumer keeps "either backend" in one
/// value and dispatches at runtime.
enum Backend {
    SymCrypt(SymCryptProvider),
    #[cfg(windows)]
    Bcrypt(BcryptProvider),
}

impl Backend {
    fn name(&self) -> &'static str {
        match self {
            Backend::SymCrypt(provider) => provider.info().name,
            #[cfg(windows)]
            Backend::Bcrypt(provider) => provider.info().name,
        }
    }

    fn sha256(&self, data: &[u8]) -> Digest {
        match self {
            Backend::SymCrypt(provider) => provider.digest(BaseHashAlgorithm::Sha256, data),
            #[cfg(windows)]
            Backend::Bcrypt(provider) => provider.digest(BaseHashAlgorithm::Sha256, data),
        }
    }
}

/// The decision point: choose a backend at startup. Here it is driven by an
/// environment variable and defaults to SymCrypt; BCrypt is Windows-only.
fn select_backend() -> Backend {
    match std::env::var("MSCRYPTO_BACKEND").as_deref() {
        #[cfg(windows)]
        Ok("bcrypt") => Backend::Bcrypt(BcryptProvider::new().expect("open CNG SHA-2 providers")),
        _ => Backend::SymCrypt(SymCryptProvider::new().expect("initialize SymCrypt module")),
    }
}

fn main() {
    let backend = select_backend();
    let digest = backend.sha256(b"hello world");
    println!("backend: {}", backend.name());
    println!("sha256(\"hello world\") = {}", to_hex(&digest));
}

fn to_hex(digest: &Digest) -> String {
    digest.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}
