//! Error types for the contract.
use crate::algorithm::Algorithm;

// Provider construction (`build()`) failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProviderBuildError {
    UnsupportedAlgorithms {
        backend: &'static str,
        missing: Vec<Algorithm>,
    },
}

/// Runtime error for fallible crypto operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The requested algorithm is not available on this backend / OS
    /// (e.g. SHA-3 on older Windows).
    Unavailable,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unavailable => {
                f.write_str("requested algorithm is not available on this backend")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A MAC verification failed: the supplied tag did not match the computed tag.
///
/// Deliberately opaque. It carries no detail about the expected tag or where the
/// mismatch occurred, so nothing about the secret leaks through the error value.
#[derive(Debug)]
pub struct MacError(());

impl MacError {
    pub(crate) fn new() -> Self {
        MacError(())
    }
}

impl core::fmt::Display for MacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MAC verification failed")
    }
}

impl std::error::Error for MacError {}
