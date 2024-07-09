//! PSS functions for [`RsaKey`]. For more info please refer to symcrypt.h
//!
//! # Example
//!
//! ## Sign and Verify with [`RsaKey`]
//!
//! ```rust
//! use symcrypt::rsa::{RsaKey, RsaKeyUsage};
//! use symcrypt::hash::{sha256, HashAlgorithm, SHA256_RESULT_SIZE};
//!
//! // Generate key pair
//! let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Set up message
//! let hashed_message = sha256(b"hello world");
//! let hash_algorithm = HashAlgorithm::Sha256;
//! let salt_length = SHA256_RESULT_SIZE; // 32 bytes for SHA256
//!
//! // Create and verify the signature
//! let signature = key_pair.pss_sign(&hashed_message, hash_algorithm, salt_length).unwrap();
//! let verify_result = key_pair.pss_verify(&hashed_message, &signature, hash_algorithm, salt_length);
//!
//! assert!(verify_result.is_ok());
//! ```
//!
use crate::errors::SymCryptError;
use crate::hash::HashAlgorithm;
use crate::rsa::RsaKey;
use crate::NumberFormat;

impl RsaKey {
    /// `pss_sign()` returns a `Vec<u8>` that represents the signature of the hashed message, or a [`SymCryptError`] if the operation failed.
    ///
    /// `hashed_message` is a `&[u8]` that represents the message that has been hashed using the hash algorithm specified in `hash_algorithm`.
    ///  
    /// `hash_algorithm` is a [`HashAlgorithm`] that represents the hash algorithm used to hash the message.
    ///
    /// `salt_length` is a `usize` that represents the length of the salt to be used in the PSS signature, this value is typically the length of the hash output.
    ///
    /// This function will fail with [`SymCryptError::InvalidArgument`] if [`RsaKey`] does not have a private key attached.
    pub fn pss_sign(
        &self,
        hashed_message: &[u8],
        hash_algorithm: HashAlgorithm,
        salt_length: usize,
    ) -> Result<Vec<u8>, SymCryptError> {
        let mut result_size = 0;
        let modulus_size = self.get_size_of_modulus();
        let mut signature = vec![0u8; modulus_size as usize];
        let hash_algorithm_ptr = hash_algorithm.to_symcrypt_hash();

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPssSign(
                self.inner(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                hash_algorithm_ptr,
                salt_length as symcrypt_sys::SIZE_T,
                0, // flags must be 0
                NumberFormat::MSB.to_symcrypt_format(),
                signature.as_mut_ptr(),
                modulus_size as symcrypt_sys::SIZE_T,
                &mut result_size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    // For signing the size of the output will always be the size of the modulus with the current padding modes.
                    Ok(signature)
                }
                err => Err(err.into()),
            }
        }
    }

    /// `pss_verify()` returns a [`SymCryptError`] if the signature verification fails and `Ok(())` if the verification is successful.
    ///
    /// Caller must check the return value to determine if the signature is valid before continuing.
    ///
    /// `hashed_message` is a `&[u8]` that represents the message that has been hashed using the hash algorithm specified in `hash_algorithm`.
    ///  
    /// `signature` is a `&[u8]` that represents the signature of the hashed message.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] that represents the hash algorithm used to hash the message.
    ///
    /// `salt_length` is a `usize` that represents the length of the salt to be used in the PSS signature, this value is typically the length of the hash output.
    pub fn pss_verify(
        &self,
        hashed_message: &[u8],
        signature: &[u8],
        hash_algorithm: HashAlgorithm,
        salt_length: usize,
    ) -> Result<(), SymCryptError> {
        let hash_algorithm_ptr = hash_algorithm.to_symcrypt_hash();

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPssVerify(
                self.inner(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                signature.as_ptr(),
                signature.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(),
                hash_algorithm_ptr,
                salt_length as symcrypt_sys::SIZE_T,
                0, // flags must be 0
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hash::{sha256, HashAlgorithm};
    use crate::rsa::{RsaKey, RsaKeyUsage};

    #[test]
    fn test_pss_sign_and_verify_with_key_pair() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let signature = key_pair
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap();

        let verify_result =
            key_pair.pss_verify(&hashed_message, &signature, hash_algorithm, salt_length);

        assert!(verify_result.is_ok());
    }
    #[test]
    fn test_pss_sign_and_verify_with_public_key_bytes() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let signature = key_pair
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap();

        let verify_result =
            public_key.pss_verify(&hashed_message, &signature, hash_algorithm, salt_length);

        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_pss_sign_and_verify_with_different_key() {
        let key_pair_1 =
            RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let key_pair_2 =
            RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let signature = key_pair_1
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap();

        let verify_result = key_pair_2
            .pss_verify(&hashed_message, &signature, hash_algorithm, salt_length)
            .unwrap_err();

        assert_eq!(verify_result, SymCryptError::SignatureVerificationFailure);
    }

    #[test]
    fn test_pss_sign_and_verify_tampered_signature() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let mut signature = key_pair
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap();

        // tamper with signature
        signature[0] = 0xFF;

        let verify_result = public_key
            .pss_verify(&hashed_message, &signature, hash_algorithm, salt_length)
            .unwrap_err();

        assert_eq!(verify_result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_pss_sign_and_verify_salt_too_large() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        // If the length of the hash + the size of the salt is larger than the size of the modulus, then generation should fail
        let salt_length = 1000;

        let signature = key_pair
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap_err();

        assert_eq!(signature, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_pss_sign_with_wrong_key_usage() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::Encrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let signature = key_pair
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap_err();

        assert_eq!(signature, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_pss_sign_with_public_key() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;
        let salt_length = 32;

        let result = public_key
            .pss_sign(&hashed_message, hash_algorithm, salt_length)
            .unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument)
    }
}
