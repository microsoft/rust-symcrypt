//! BCrypt backend for the `mscrypto` contract.
//!
//! Provides [`BcryptProvider`], a concrete [`CryptoProvider`] backed by Windows
//! (`bcryptprimitives.dll`). 

#![cfg(windows)]

mod hash;

pub use hash::BcryptHasher;

/// Everything needed to use this provider in one glob import:
/// `use mscrypto_bcrypt::prelude::*;`. It re-exports the provider and traits 
/// (whose methods are otherwise not in scope), and the shared
/// algorithm, error, and metadata types from the contract, so a consumer
/// does not need a separate dependency on `mscrypto` for the common path.
pub mod prelude {
    pub use crate::{BcryptHasher, BcryptProvider, BcryptProviderBuilder};

    pub use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm};
    pub use mscrypto::error::{Error, ProviderBuildError};
    pub use mscrypto::hash::{Digest, Hash, HashOps};
    pub use mscrypto::provider::{BackendInfo, BackendVersion, CryptoProvider, LinkMode};

    #[cfg(feature = "sha3")]
    pub use mscrypto::algorithm::Sha3Algorithm;
    #[cfg(feature = "sha3")]
    pub use mscrypto::sha3::Sha3;
}

use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm};
use mscrypto::error::ProviderBuildError;
use mscrypto::provider::{BackendInfo, BackendVersion, CryptoProvider, LinkMode};

#[cfg(feature = "sha3")]
use mscrypto::algorithm::Sha3Algorithm;

const BACKEND_NAME: &str = "bcrypt";

/// BCrypt cryptographic provider.
pub struct BcryptProvider {
    #[cfg(feature = "sha3")]
    sha3_256: bool,
    #[cfg(feature = "sha3")]
    sha3_384: bool,
    #[cfg(feature = "sha3")]
    sha3_512: bool,
    info: BackendInfo,
}

impl BcryptProvider {
    /// Builds a provider (probing SHA-3 availability under the `sha3` feature),
    /// requiring no specific algorithms.
    pub fn new() -> Result<Self, ProviderBuildError> {
        BcryptProvider::builder().build()
    }

    /// Starts a builder used to declare algorithms that must be present.
    pub fn builder() -> BcryptProviderBuilder {
        BcryptProviderBuilder::default()
    }
}

/// Builder for [`BcryptProvider`]. Collects a require-list checked at `build()`.
#[derive(Default)]
pub struct BcryptProviderBuilder {
    required: Vec<Algorithm>,
}

impl BcryptProviderBuilder {
    /// Records an algorithm that `build()` must confirm is supported.
    pub fn require(mut self, algorithm: Algorithm) -> Self {
        self.required.push(algorithm);
        self
    }

    /// Probes SHA-3 availability, then verifies the require-list. SHA-2 needs no
    /// setup (pseudo-handles), so it never fails here.
    pub fn build(self) -> Result<BcryptProvider, ProviderBuildError> {
        let provider = BcryptProvider {
            #[cfg(feature = "sha3")]
            sha3_256: hash::sha3_available(Sha3Algorithm::Sha3_256),
            #[cfg(feature = "sha3")]
            sha3_384: hash::sha3_available(Sha3Algorithm::Sha3_384),
            #[cfg(feature = "sha3")]
            sha3_512: hash::sha3_available(Sha3Algorithm::Sha3_512),
            info: backend_info(),
        };

        let missing: Vec<Algorithm> = self
            .required
            .into_iter()
            .filter(|algorithm| !provider.supports(*algorithm))
            .collect();
        if !missing.is_empty() {
            return Err(ProviderBuildError::UnsupportedAlgorithms {
                backend: BACKEND_NAME,
                missing,
            });
        }
        Ok(provider)
    }
}

impl CryptoProvider for BcryptProvider {
    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports(&self, algorithm: Algorithm) -> bool {
        match algorithm {
            Algorithm::Hash(
                BaseHashAlgorithm::Sha256 | BaseHashAlgorithm::Sha384 | BaseHashAlgorithm::Sha512,
            ) => true,
            #[cfg(feature = "sha3")]
            Algorithm::Sha3(variant) => match variant {
                Sha3Algorithm::Sha3_256 => self.sha3_256,
                Sha3Algorithm::Sha3_384 => self.sha3_384,
                Sha3Algorithm::Sha3_512 => self.sha3_512,
            },
            _ => false,
        }
    }
}

fn backend_info() -> BackendInfo {
    BackendInfo {
        name: BACKEND_NAME,
        // bcrypt ships with the OS and carries no independent crypto-library version.
        version: BackendVersion {
            major: 0,
            minor: 0,
            patch: 0,
        },
        link_mode: LinkMode::NotApplicable,
        fips: false,
    }
}

#[cfg(test)]
mod test {
    use super::BcryptProvider;
    use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm};
    use mscrypto::provider::{CryptoProvider, LinkMode};

    #[test]
    fn provider_metadata() {
        let provider = BcryptProvider::new().expect("SHA-2 providers open");
        let info = provider.info();
        assert_eq!(info.name, "bcrypt");
        assert!(!info.fips);
        assert!(matches!(info.link_mode, LinkMode::NotApplicable));
        assert!(provider.supports(Algorithm::Hash(BaseHashAlgorithm::Sha256)));
    }
}
