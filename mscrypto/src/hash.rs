//! Base hashing
use crate::algorithm::BaseHashAlgorithm;

pub trait Hash {
    type Hasher: HashOps;
    fn hash(&self, a: BaseHashAlgorithm) -> Self::Hasher;
    fn digest(&self, a: BaseHashAlgorithm, data: &[u8]) -> Digest;
}

pub trait HashOps {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Digest;
}

#[derive(Clone)]
pub struct Digest {
    bytes: [u8; Digest::MAX_LEN],
    len: u8,
}

impl Digest {
    pub const MAX_LEN: usize = 64;

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    // A digest has a fixed, nonzero length set by its algorithm, so an `is_empty`
    // companion would be dead API.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len as usize
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Provider-facing construction seam. Not part of the caller-facing API: provider
/// crates import `BuildDigest` to produce a `Digest` from a backend's output. It
/// lives here rather than as an inherent method so it stays off `Digest`'s public
/// surface; it is reachable cross-crate only because Rust has no friend-crate
/// visibility. Ordinary callers receive a `Digest` from `Hash::digest` /
/// `HashOps::finalize` and read it via `as_bytes` / `as_ref`.
#[doc(hidden)]
pub mod provider {
    use super::Digest;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for crate::hash::Digest {}
    }

    /// Builds a `Digest` by writing its `len` output bytes directly into the buffer
    /// via `fill`, with no intermediate copy. Maps onto the out-pointer C APIs
    /// (SymCrypt/BCrypt write straight into `fill`'s slice). `len` must be
    /// <= `Digest::MAX_LEN` or `fill` will panic. Sealed: only `Digest` implements it.
    pub trait BuildDigest: sealed::Sealed {
        fn from_fn(len: usize, fill: impl FnOnce(&mut [u8])) -> Self;
    }

    impl BuildDigest for Digest {
        fn from_fn(len: usize, fill: impl FnOnce(&mut [u8])) -> Self {
            let mut bytes = [0u8; Digest::MAX_LEN];
            fill(&mut bytes[..len]);
            Self {
                bytes,
                len: len as u8,
            }
        }
    }
}
