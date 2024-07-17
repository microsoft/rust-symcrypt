//! EcDh functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Secret agreement with `Nist256`, `Nist384` and `Curve25519`.
//! This calling pattern be similar for `Nist384`, and `Curve25519` except that `EcDh::new()`
//! will be called with the desired [`CurveType`]
//! ```rust
//! use symcrypt::ecdh::EcDh;
//! use symcrypt::eckey::CurveType;
//!
//! // Set up 2 separate EcDH structs with public/private key pair attached.
//! let ecdh_1_private = EcDh::new(CurveType::NistP256).unwrap();
//! let ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();
//!
//! // Assert that the CurveType matches NistP256.
//! assert_eq!(ecdh_1_private.get_curve(), CurveType::NistP256);
//!
//! // Get the public bytes from each EcDh struct generated.
//! let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
//! let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();
//!
//! // Calculates secret agreements between private/public keys of two EcDh structs. The result
//! // from each Secret agreement should be the same.
//! let ecdh_1_public =
//!     EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_1.as_slice()).unwrap();
//! let ecdh_2_public =
//!     EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_2.as_slice()).unwrap();
//!
//! let secret_agreement_1 =
//!     EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
//! let secret_agreement_2 =
//!     EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();
//!
//! assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
//! ```
//!
use crate::ecc::{EcKey, curve_to_num_format, EcKeyUsage, CurveType};
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

/// Wrapper for the EcDh secret agreement result value. This is in place to make the return clear to the caller.
#[derive(Debug)]
pub struct EcDhSecretAgreement(Vec<u8>);

impl EcDhSecretAgreement {
    /// `as_bytes` is an accessor that returns the secret agreement as a [`Vec<u8>`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Impl for EcDh struct.
impl EcKey {
    /// `ecdh_secret_agreement()` takes in two [`EcDh`] structs and returns the associated [`EcDhSecretAgreement`].
    /// 
    pub fn ecdh_secret_agreement(&self, public_key: EcKey) -> Result<EcDhSecretAgreement, SymCryptError> {
        let num_format = curve_to_num_format(self.get_curve_type());
        let secret_length = self.get_curve_size();
        let mut secret = vec![0u8; secret_length as usize];

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEcDhSecretAgreement(
                self.inner_key(),
                public_key.inner_key(),
                num_format,
                0,
                secret.as_mut_ptr(),
                secret.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(EcDhSecretAgreement(secret)),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // symcrypt_sys::SymCryptModuleInit() must be called via lib.rs in order to initialize the callbacks for
    // SymCryptEcurveAllocate, SymCryptEckeyAllocate, SymCryptCallbackAlloc, etc.

    #[test]
    fn test_ecdh_nist_p256() {

        let ecdh_1_private = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
        let ecdh_2_private = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();

        let public_bytes_1 = ecdh_1_private.export_public_key().unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();

        let ecdh_1_public =
            EcKey::set_public_key(CurveType::NistP256, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();
            let ecdh_2_public =
            EcKey::set_public_key(CurveType::NistP256, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();

        let secret_agreement_1 = ecdh_1_private.ecdh_secret_agreement(ecdh_2_public).unwrap();
        let secret_agreement_2 = ecdh_2_private.ecdh_secret_agreement(ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_nist_p384() {

        let ecdh_1_private = EcKey::generate_key_pair(CurveType::NistP384, EcKeyUsage::EcDh).unwrap();
        let ecdh_2_private = EcKey::generate_key_pair(CurveType::NistP384, EcKeyUsage::EcDh).unwrap();

        let public_bytes_1 = ecdh_1_private.export_public_key().unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();

        let ecdh_1_public =
            EcKey::set_public_key(CurveType::NistP384, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();

        let ecdh_2_public =
            EcKey::set_public_key(CurveType::NistP384, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();

        let secret_agreement_1 = ecdh_1_private.ecdh_secret_agreement(ecdh_2_public).unwrap();
        let secret_agreement_2 = ecdh_2_private.ecdh_secret_agreement(ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_curve_25519() {

        let ecdh_1_private = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh).unwrap();
        let ecdh_2_private = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh).unwrap();

        let public_bytes_1 = ecdh_1_private.export_public_key().unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();

        let ecdh_1_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();
            
        let ecdh_2_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();

        let secret_agreement_1 = ecdh_1_private.ecdh_secret_agreement(ecdh_2_public).unwrap();
        let secret_agreement_2 = ecdh_2_private.ecdh_secret_agreement(ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_different_curve_types() {

        let ecdh_1_private = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh).unwrap();
        let ecdh_2_private = EcKey::generate_key_pair(CurveType::NistP384, EcKeyUsage::EcDh).unwrap();

        let public_bytes_1 = ecdh_1_private.export_public_key().unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();

        let _ecdh_1_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();

        let ecdh_2_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap_err();

        assert_eq!(ecdh_2_public, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_ecdh_wrong_usage() {

        let ecdh_1_private = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();
        let ecdh_2_private = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();

        let public_bytes_1 = ecdh_1_private.export_public_key().unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();

        let _ecdh_1_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();
            
        let ecdh_2_public =
            EcKey::set_public_key(CurveType::Curve25519, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();

        let secret_agreement_1 = ecdh_1_private.ecdh_secret_agreement(ecdh_2_public).unwrap_err();

        assert_eq!(secret_agreement_1, SymCryptError::InvalidArgument);
    }
}
