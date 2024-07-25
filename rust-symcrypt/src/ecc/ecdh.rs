//! EcDh functions. For further documentation please refer to symcrypt.h
//!
//! # Example
//!
//! ## EcDh with generated keys
//! 
//! ```rust
//! use symcrypt::ecc::{EcKey, CurveType, EcKeyUsage};
//!
//! // Set up 2 separate EcDH structs with public/private key pair attached.
//! 
//! let key_1 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
//! let key_2 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
//!
//! // Assert that the CurveType matches NistP256.
//! assert_eq!(key_1.get_curve_type(), CurveType::NistP256);
//! assert_eq!(key_2.get_curve_type(), CurveType::NistP256);
//!
//! // Get the public bytes from each EcDh struct generated.
//! let public_bytes_1 = key_1.export_public_key().unwrap();
//! let public_bytes_2 = key_2.export_public_key().unwrap();
//!
//! // Calculates secret agreements between private/public keys of two EcKey structs. The result
//! // from each secret agreement should be the same.
//! let ecdh_1_public =
//! EcKey::set_public_key(CurveType::NistP256, &public_bytes_1.as_slice(), EcKeyUsage::EcDh).unwrap();
//! let ecdh_2_public =
//! EcKey::set_public_key(CurveType::NistP256, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();
//! 
//! let secret_agreement_1 = key_1.ecdh_secret_agreement(ecdh_2_public).unwrap();
//! let secret_agreement_2 = key_2.ecdh_secret_agreement(ecdh_1_public).unwrap();
//!
//! assert_eq!(secret_agreement_1, secret_agreement_2);
//! 
//! ```
//!
use crate::ecc::{EcKey, curve_to_num_format};
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

/// Impl for EcDh struct.
impl EcKey {
    /// `ecdh_secret_agreement()` returns a [`EcDhSecretAgreement`] that represents the secret agreement between the private key and the public key,
    ///  or a [`SymCryptError`] if the operation failed.
    /// 
    /// `public_key` is an [`EcKey`] that represents the public key that the secret agreement is being calculated with.
    /// 
    /// If the key usage is not [`EcKeyUsage::EcDh`], the function will return a [`SymCryptError::InvalidArgument`].
    pub fn ecdh_secret_agreement(&self, public_key: EcKey) -> Result<Vec<u8>, SymCryptError> {
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
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(secret),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecc::{EcKeyUsage, CurveType};

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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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

    #[test]
    fn test_ecdh_no_private_key_set() {
        let dummy_eckey = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
        let dummy_public_key_bytes = dummy_eckey.export_public_key().unwrap();
        let ecdh_1_no_private_key = EcKey::set_public_key(CurveType::NistP256, &dummy_public_key_bytes.as_slice(), EcKeyUsage::EcDh).unwrap();

        let ecdh_2_private = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
        let public_bytes_2 = ecdh_2_private.export_public_key().unwrap();
        let ecdh_2_public =
            EcKey::set_public_key(CurveType::NistP256, &public_bytes_2.as_slice(), EcKeyUsage::EcDh).unwrap();

        let secret_agreement_1 = ecdh_1_no_private_key.ecdh_secret_agreement(ecdh_2_public).unwrap_err();

        assert_eq!(SymCryptError::InvalidArgument, secret_agreement_1);
    }
}
