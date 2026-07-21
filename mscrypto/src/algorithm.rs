//! Algorithm identifiers used across the backend-neutral contract.

// `Algorithm` is non_exhaustive because new algorithm families are added over
// time, so callers must handle an unknown family. The per-family enums below are
// exhaustive: their members are a fixed, known set, so adding one is a breaking
// change that forces every backend to handle it at compile time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Algorithm {
    Hash(BaseHashAlgorithm),
    Mac(MacAlgorithm),
    #[cfg(feature = "sha3")]
    Sha3(Sha3Algorithm),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BaseHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

// `Hmac(h)` denotes HMAC built on base hash `h`. Keeping the mechanism generic
// over the hash leaves room for other MAC constructions as sibling variants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacAlgorithm {
    Hmac(BaseHashAlgorithm),
}

#[cfg(feature = "sha3")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sha3Algorithm {
    Sha3_256,
    Sha3_384,
    Sha3_512,
}
