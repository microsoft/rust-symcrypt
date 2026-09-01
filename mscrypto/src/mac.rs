//! Message authentication codes (keyed hashing).
//!
//! A MAC is a keyed hash, so this mirrors [`Hash`](crate::hash::Hash): a
//! streaming form ([`Mac::mac`] plus [`MacOps`]) and a one-shot form
//! ([`Mac::mac_digest`]). The tag is a fixed-size [`Digest`], the same value
//! type a hash produces.

use crate::algorithm::MacAlgorithm;
use crate::error::MacError;
use crate::hash::Digest;

/// Keyed hashing.
///
/// Construction is infallible: any byte string is a valid MAC key, so the only
/// failure a backend can raise is catastrophic (for example an allocation
/// failure). That is handled the same way as base hashing, by panicking rather
/// than returning a recoverable error.
pub trait Mac {
    /// Concrete streaming MAC state produced by [`Mac::mac`].
    type MacState: MacOps;

    /// Starts a streaming MAC keyed by `key`. Feed data with [`MacOps::update`]
    /// and finish with [`MacOps::finalize`].
    fn mac(&self, algorithm: MacAlgorithm, key: &[u8]) -> Self::MacState;

    /// Computes the MAC of `data` under `key` in a single call.
    fn mac_digest(&self, algorithm: MacAlgorithm, key: &[u8], data: &[u8]) -> Digest;

    /// Verifies in constant time that `tag` is the MAC of `data` under `key`.
    ///
    /// Returns `Ok(())` only if `tag` exactly equals the computed tag; a tag of
    /// the wrong length or any differing byte yields [`MacError`]. The comparison
    /// runs in time independent of the tag contents, so it does not leak where a
    /// forged tag first diverges. Prefer this over comparing [`Mac::mac_digest`]
    /// with `==`, which short-circuits and is not constant time.
    fn verify(
        &self,
        algorithm: MacAlgorithm,
        key: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<(), MacError> {
        verify_tag(&self.mac_digest(algorithm, key, data), tag)
    }
}

/// Streaming MAC operations.
pub trait MacOps {
    /// Adds `data` to the running MAC. May be called repeatedly.
    fn update(&mut self, data: &[u8]);

    /// Consumes the state and returns the authentication tag.
    fn finalize(self) -> Digest;

    /// Consumes the state and verifies in constant time that `tag` matches the
    /// computed authentication tag. See [`Mac::verify`].
    fn verify(self, tag: &[u8]) -> Result<(), MacError>
    where
        Self: Sized,
    {
        verify_tag(&self.finalize(), tag)
    }
}

/// Constant-time tag comparison. The length check is not secret: a tag of the
/// wrong length can never be valid. The byte comparison folds every difference
/// into one accumulator with no early exit, so it runs in time independent of the
/// contents and does not reveal where a mismatch occurs.
fn verify_tag(computed: &Digest, tag: &[u8]) -> Result<(), MacError> {
    let computed = computed.as_bytes();
    if computed.len() != tag.len() {
        return Err(MacError::new());
    }
    let mut diff = 0u8;
    for (x, y) in computed.iter().zip(tag) {
        diff |= x ^ y;
    }
    if core::hint::black_box(diff) == 0 {
        Ok(())
    } else {
        Err(MacError::new())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hash::provider::BuildDigest;

    fn digest_of(bytes: &[u8]) -> Digest {
        Digest::from_fn(bytes.len(), |out| out.copy_from_slice(bytes))
    }

    #[test]
    fn verify_tag_accepts_exact_match() {
        let tag = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert!(verify_tag(&digest_of(&tag), &tag).is_ok());
    }

    #[test]
    fn verify_tag_rejects_differing_byte() {
        let computed = digest_of(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(verify_tag(&computed, &[1, 2, 3, 4, 5, 6, 7, 9]).is_err());
    }

    #[test]
    fn verify_tag_rejects_wrong_length() {
        let computed = digest_of(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(verify_tag(&computed, &[1, 2, 3, 4]).is_err());
    }
}
