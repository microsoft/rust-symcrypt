// Compute SHA-256 of the embedded symcrypt.dll at build time and expose it
// via the `DLL_SHA256_HEX` env var.  Used by `src/lib.rs` to build a
// content-addressed cache path so a patched DLL with the same version string
// can never silently reuse a stale cached copy.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dll = manifest_dir.join("symcrypt.dll");
    println!("cargo:rerun-if-changed={}", dll.display());

    let bytes = fs::read(&dll)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dll.display()));
    let digest = Sha256::digest(&bytes);
    let hex = digest.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    println!("cargo:rustc-env=DLL_SHA256_HEX={hex}");
}
