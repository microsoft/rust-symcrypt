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
    // Opaque low-level backend failure (e.g. a provider handle could not be
    // opened). `operation` names the failing step; the raw status is not exposed.
    Backend {
        backend: &'static str,
        operation: &'static str,
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
