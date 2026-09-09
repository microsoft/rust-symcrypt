//! SymCrypt backend for the `mscrypto` contract.
//!
//! Provides [`SymCryptProvider`], a concrete [`CryptoProvider`] backed by the
//! `symcrypt` crate

mod hash;
mod mac;

pub use hash::SymCryptHasher;
#[cfg(feature = "sha3")]
pub use hash::SymCryptSha3Hasher;
pub use mac::SymCryptMac;

/// Everything needed to use this provider in one glob import:
/// `use mscrypto_symcrypt::prelude::*;`. It re-exports the provider. builder, and traits
/// (whose methods are otherwise not in scope), and the shared
/// algorithm, error, and metadata types from the contract, so a consumer
/// does not need a separate dependency on `mscrypto` for the common path.
pub mod prelude {
    pub use crate::{SymCryptHasher, SymCryptMac, SymCryptProvider, SymCryptProviderBuilder};

    pub use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm, MacAlgorithm};
    pub use mscrypto::error::{Error, ProviderBuildError};
    pub use mscrypto::hash::{Digest, Hash, HashOps};
    pub use mscrypto::mac::{Mac, MacOps};
    pub use mscrypto::provider::{BackendInfo, BackendVersion, CryptoProvider, LinkMode};

    #[cfg(feature = "sha3")]
    pub use crate::SymCryptSha3Hasher;
    #[cfg(feature = "sha3")]
    pub use mscrypto::algorithm::Sha3Algorithm;
    #[cfg(feature = "sha3")]
    pub use mscrypto::sha3::Sha3;
}

use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm, MacAlgorithm};
use mscrypto::error::ProviderBuildError;
use mscrypto::provider::{BackendInfo, BackendVersion, CryptoProvider, LinkMode};

#[cfg(feature = "sha3")]
use mscrypto::algorithm::Sha3Algorithm;

const BACKEND_NAME: &str = "symcrypt";

/// SymCrypt-backed cryptographic provider.
pub struct SymCryptProvider {
    info: BackendInfo,
}

impl SymCryptProvider {
    /// Builds a provider with no required algorithms.
    pub fn new() -> Result<Self, ProviderBuildError> {
        SymCryptProvider::builder().build()
    }

    /// Starts a builder used to declare algorithms that must be present.
    pub fn builder() -> SymCryptProviderBuilder {
        SymCryptProviderBuilder::default()
    }
}

/// Builder for [`SymCryptProvider`]. Collects a require-list checked at `build()`.
#[derive(Default)]
pub struct SymCryptProviderBuilder {
    required: Vec<Algorithm>,
}

impl SymCryptProviderBuilder {
    /// Records an algorithm that `build()` must confirm is supported.
    pub fn require(mut self, algorithm: Algorithm) -> Self {
        self.required.push(algorithm);
        self
    }

    /// Builds the provider, failing if any required algorithm is unsupported.
    pub fn build(self) -> Result<SymCryptProvider, ProviderBuildError> {
        initialize_module()?;
        let provider = SymCryptProvider {
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

impl CryptoProvider for SymCryptProvider {
    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports(&self, algorithm: Algorithm) -> bool {
        match algorithm {
            Algorithm::Hash(
                BaseHashAlgorithm::Sha256 | BaseHashAlgorithm::Sha384 | BaseHashAlgorithm::Sha512,
            ) => true,
            Algorithm::Mac(MacAlgorithm::Hmac(
                BaseHashAlgorithm::Sha256 | BaseHashAlgorithm::Sha384 | BaseHashAlgorithm::Sha512,
            )) => true,
            #[cfg(feature = "sha3")]
            Algorithm::Sha3(
                Sha3Algorithm::Sha3_256 | Sha3Algorithm::Sha3_384 | Sha3Algorithm::Sha3_512,
            ) => true,
            _ => false,
        }
    }
}

// Single point where SymCrypt module usability is verified when a provider is
// built. SymCrypt checks version compatibility during its lazy initialization on
// first use, which aborts on a mismatch, so there is no recoverable failure to
// report today. A graceful module-init entry point would let this surface an
// incompatible module as a `ProviderBuildError` instead of aborting.
fn initialize_module() -> Result<(), ProviderBuildError> {
    // SAFETY: FFI call to a stateless version check that aborts on an incompatible
    // module and is safe to call more than once (the symcrypt crate also calls it
    // lazily on first use). TODO: Change to SymCryptModuleInitEX.
    unsafe {
        symcrypt_sys::SymCryptModuleInit(
            symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
            symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
        );
    }
    Ok(())
}

fn backend_info() -> BackendInfo {
    BackendInfo {
        name: BACKEND_NAME,
        version: BackendVersion {
            major: symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
            minor: symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            patch: symcrypt_sys::SYMCRYPT_CODE_VERSION_PATCH,
        },
        link_mode: link_mode(),
        fips: false,
    }
}

fn link_mode() -> LinkMode {
    if cfg!(mscrypto_link = "prebuilt") {
        LinkMode::PrebuiltStatic
    } else {
        LinkMode::DynamicSystem
    }
}

#[cfg(test)]
mod test {
    use super::SymCryptProvider;
    use mscrypto::algorithm::{Algorithm, BaseHashAlgorithm};
    use mscrypto::provider::{CryptoProvider, LinkMode};

    #[test]
    fn provider_metadata() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let info = provider.info();
        assert_eq!(info.name, "symcrypt");
        assert_eq!(info.version.major, 103);
        assert!(!info.fips);
        assert!(matches!(
            info.link_mode,
            LinkMode::DynamicSystem | LinkMode::PrebuiltStatic
        ));
    }

    #[test]
    fn builder_requires_supported_algorithm() {
        let provider = SymCryptProvider::builder()
            .require(Algorithm::Hash(BaseHashAlgorithm::Sha256))
            .build()
            .expect("SHA-256 is supported by SymCrypt");
        assert!(provider.supports(Algorithm::Hash(BaseHashAlgorithm::Sha512)));
    }
}
