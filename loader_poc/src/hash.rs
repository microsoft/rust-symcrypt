//! Friendly Rust SHA-256 API, modelled on `symcrypt::hash` from the real
//! rust-symcrypt crate.  Two ways to hash:
//!
//! ```no_run
//! // Stateless one-shot:
//! let digest = loader_poc::hash::sha256(b"hello world");
//!
//! // Streaming:
//! use loader_poc::hash::Sha256State;
//! let mut s = Sha256State::new();
//! s.append(b"hello ");
//! s.append(b"world");
//! let digest = s.result();
//! ```
//!
//! Both paths go through `crate::api()` → resolved function pointers →
//! real SymCrypt code running from the extracted DLL.

pub const SHA256_RESULT_SIZE: usize = 32;

use crate::{api, Sha256RawState};

/// Stateless one-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; SHA256_RESULT_SIZE] {
    let mut out = [0u8; SHA256_RESULT_SIZE];
    // SAFETY: `data` is a valid slice we own; `out` is a fixed-size
    // 32-byte buffer.  `api().sha256` is the resolved SymCryptSha256.
    unsafe { (api().sha256)(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    out
}

/// Streaming SHA-256 state.  Equivalent to `symcrypt::hash::Sha256State` in
/// the real rust-symcrypt crate.
///
/// The state is heap-allocated so its address is stable for SymCrypt's
/// internal magic-field integrity checks.  We never move the state after
/// `new()` returns the Box.
pub struct Sha256State(Box<Sha256RawState>);

impl Sha256State {
    /// Create a fresh, initialized SHA-256 state.
    pub fn new() -> Self {
        let mut state = Box::new(Sha256RawState([0u8; 128]));
        // SAFETY: `state` is heap-allocated, properly aligned for the C struct,
        // and large enough.  Init overwrites the bytes with valid initial state.
        unsafe { (api().sha256_init)(&mut *state) };
        Sha256State(state)
    }

    /// Feed more bytes into the running hash.
    pub fn append(&mut self, data: &[u8]) {
        // SAFETY: `self.0` is the same heap allocation we initialized; `data`
        // is a valid slice we own.
        unsafe { (api().sha256_append)(&mut *self.0, data.as_ptr(), data.len()) };
    }

    /// Finalize and return the 32-byte digest.  Consumes the state.
    pub fn result(mut self) -> [u8; SHA256_RESULT_SIZE] {
        let mut out = [0u8; SHA256_RESULT_SIZE];
        // SAFETY: same alloc, fixed-size 32-byte output buffer.
        unsafe { (api().sha256_result)(&mut *self.0, out.as_mut_ptr()) };
        out
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}
