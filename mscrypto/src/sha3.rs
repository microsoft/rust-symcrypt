//! SHA-3 hashing: the one fallible hash surface in v1.

use crate::algorithm::Sha3Algorithm;
use crate::error::Error;
use crate::hash::{Digest, HashOps};

// SHA-3 is fallible because it is version-variable: BCrypt returns STATUS_NOT_FOUND
// on older Windows. The Result gate is at construction only; update() and
// finalize() (via HashOps) are infallible.
pub trait Sha3 {
    type Sha3Hasher: HashOps;
    fn sha3(&self, a: Sha3Algorithm) -> Result<Self::Sha3Hasher, Error>;
    fn sha3_digest(&self, a: Sha3Algorithm, data: &[u8]) -> Result<Digest, Error>;
}
