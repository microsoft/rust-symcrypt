//! EcDh functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Secret agreement with `Nist256`, `Nist384` and `Curve25519`.
//! This calling pattern be similar for `Nist384`, and `Curve25519` except that `EcDh::new()`
//! will be called with the desired [`CurveType`]
//! ```
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
use crate::eckey::*;
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

/// [`EcDh`] struct holds the public/private key pair as well as the related curve
pub struct EcDh {
    curve_type: CurveType,

    // EcKey holds the public/private key pair that is associated with the provided CurveType.
    // EcKey is owned by EcDh struct, and will drop when EcDh leaves scope.
    key: EcKey,
}

/// Impl for EcDh struct.
impl EcDh {
    /// `new()` takes in a curve and returns an [`EcDh`] struct with a private/public key pair assigned to it.
    pub fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        let ecdh_key = EcKey::new(curve)?;
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEckeySetRandom(
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                ecdh_key.inner(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let instance = EcDh {
                        curve_type: curve,
                        key: ecdh_key,
                    };
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }

    /// `get_curve` is an accessor that returns the [`CurveType`] associated wit the current [`EcDh`] struct.
    pub fn get_curve(&self) -> CurveType {
        self.curve_type
    }

    /// 'from_public_key_bytes()' takes in a `public_key` and creates an [`EcDh`] struct with only a public key attached.
    pub fn from_public_key_bytes(
        curve: CurveType,
        public_key: &[u8],
    ) -> Result<Self, SymCryptError> {
        let num_format = get_num_format(curve);
        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;
        let edch_key = EcKey::new(curve)?;

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEckeySetValue(
                std::ptr::null(), // private key set to null since none is generated
                0,
                public_key.as_ptr(), // only a public key is attached
                public_key.len() as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                edch_key.inner(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let instance = EcDh {
                        curve_type: curve,
                        key: edch_key,
                    };
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }

    /// `get_public_key_bytes()` returns a [`Vec<u8>`] that is the public key associated with the current [`EcDh`] struct.
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, SymCryptError> {
        let num_format = get_num_format(self.curve_type);
        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;

        unsafe {
            // SAFETY: FFI calls
            let pub_key_len = symcrypt_sys::SymCryptEckeySizeofPublicKey(
                self.key.inner(),
                symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY,
            );

            let mut pub_key_bytes = vec![0u8; pub_key_len as usize];

            match symcrypt_sys::SymCryptEckeyGetValue(
                self.key.inner(),
                std::ptr::null_mut(), // setting private key to null since we will only access public key
                0 as symcrypt_sys::SIZE_T,
                pub_key_bytes.as_mut_ptr(),
                pub_key_len as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                0, // No flags allowed
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(pub_key_bytes),
                err => Err(err.into()),
            }
        }
    }

    /// `ecdh_secret_agreement()` takes in two [`EcDh`] structs and returns the associated [`EcDhSecretAgreement`].
    pub fn ecdh_secret_agreement(
        private: &EcDh,
        public: &EcDh,
    ) -> Result<EcDhSecretAgreement, SymCryptError> {
        let num_format = get_num_format(private.curve_type);
        let secret_length = private.key.curve().get_size();
        let mut secret = vec![0u8; secret_length as usize];

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEcDhSecretAgreement(
                private.key.inner(),
                public.key.inner(),
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
    fn test_get_curve_type() {
        let ecdh = EcDh::new(CurveType::NistP256).unwrap();
        let curve = ecdh.get_curve();
        assert_eq!(curve, CurveType::NistP256);
    }

    #[test]
    fn test_ecdh_nist_p256() {
        let ecdh_1_private = EcDh::new(CurveType::NistP256).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_nist_p384() {
        let ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP384).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::NistP384, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP384, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_curve_25519() {
        let ecdh_1_private = EcDh::new(CurveType::Curve25519).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::Curve25519).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::Curve25519, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::Curve25519, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_failure() {
        let ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_2).unwrap();

        let secret_agreement_1 = EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public);
        assert_eq!(
            secret_agreement_1.unwrap_err(),
            SymCryptError::InvalidArgument
        );
    }
}
