//! Algorithm identifiers used across the backend-neutral contract.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Algorithm {
    Hash(BaseHashAlgorithm),
    #[cfg(feature = "sha3")]
    Sha3(Sha3Algorithm),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum BaseHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(feature = "sha3")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Sha3Algorithm {
    Sha3_256,
    Sha3_384,
    Sha3_512,
}
