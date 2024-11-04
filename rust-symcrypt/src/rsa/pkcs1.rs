//! # Examples
//!
//! ## Encrypt and Decrypt using RsaKey
//! 
//! ```rust
//! #[cfg(feature = "pkcs1-encrypt-decrypt")]
//! {
//! use symcrypt::rsa::{RsaKey, RsaKeyUsage};
//! use symcrypt::errors::SymCryptError;
//! 
//! // Generate key pair.
//! let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Set up message.
//! let message = b"example message";
//!
//! // Encrypt message.
//! let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();
//!
//! // Decrypt message.
//! let mut plaintext_buffer = vec![0u8; encrypted_message.len()]; // Buffer must be large enough to store the decrypted message.
//! let mut result_size = 0;
//! let res = key_pair.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);
//!
//! // Check if decryption was successful.
//! assert_eq!(res, SymCryptError::NoError);
//!
//! // Truncate buffer to the size of the decrypted message.
//! plaintext_buffer.truncate(result_size as usize);
//! assert_eq!(plaintext_buffer, message);
//! }
//! ```
//! 
use crate::errors::SymCryptError;
use crate::hash::HashAlgorithm;
use crate::rsa::RsaKey;
#[cfg(feature = "pkcs1-encrypt-decrypt")]
use crate::symcrypt_random;
use crate::NumberFormat;

/// Impl for Pkcs1 RSA via [`RsaKey`]
impl RsaKey {
    /// `pcks1_sign()` signs a hashed message using the private key of [`RsaKey`] and returns a `Vec<u8>` representing the signature,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// `hashed_message` is a `&[u8]` representing the hashed message to be signed.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] representing the hash algorithm used to hash the message.
    ///
    /// This function will fail with [`SymCryptError::InvalidArgument`] if [`RsaKey`] does not have a private key attached.
    pub fn pkcs1_sign(
        &self,
        hashed_message: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>, SymCryptError> {
        let mut result_size = 0;
        let modulus_size = self.get_size_of_modulus();
        let mut signature = vec![0u8; modulus_size as usize];
        let converted_hash_oids = hash_algorithm.to_oid_list();
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPkcs1Sign(
                self.inner(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                converted_hash_oids.as_ptr(),
                converted_hash_oids.len() as symcrypt_sys::SIZE_T,
                0, // Setting ASN.1 OID in previous parameters.
                NumberFormat::MSB.to_symcrypt_format(),
                signature.as_mut_ptr(),
                modulus_size as symcrypt_sys::SIZE_T,
                &mut result_size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(signature),
                err => Err(err.into()),
            }
        }
    }

    /// `pcks1_decrypt()` decrypts an encrypted message using the private key of [`RsaKey`] and returns [`SymCryptError`] which the caller must check before continuing.
    ///
    /// Pkcs1 decryption is weak crypto, is very fragile, and susceptible to padding attacks. It is recommended to use `RsaKey::oaep_decrypt` instead.
    /// Pkcs1 decryption should only be used for compatibility with legacy systems, to enable pkcs1 decryption, enable the `pkcs1-encrypt-decrypt` feature.
    ///
    /// `encrypted_message` is a `&[u8]` representing the encrypted message to be decrypted.
    ///
    /// `plaintext_buffer` takes in a `&mut [u8]` representing a mutable buffer to store the decrypted message. The buffer will be filled with the decrypted message if the operation is successful.
    /// This buffer will be randomized before `pcks1_decrypt` is called, you must extract your result from the buffer via the `result_size` parameter if the operation is successful.
    /// The size of the buffer should should be large enough to store the result of the decrypted message, if the buffer is to small, this function will return a [`SymCryptError::BufferTooSmall`].
    ///
    /// `result_size` is a `&mut u64` representing the size of the decrypted message. This value will be set to the size of the decrypted message if the operation is successful.
    ///
    /// This function will always return a `SymCryptError`, caller must check the return value to determine if the decryption was successful before using the `plaintext_buffer` or `result_size`.
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    pub fn pkcs1_decrypt(
        &self,
        encrypted_message: &[u8],
        plaintext_buffer: &mut [u8],
        result_size: &mut u64,
    ) -> SymCryptError {
        symcrypt_random(plaintext_buffer);
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsaPkcs1Decrypt(
                self.inner(),
                encrypted_message.as_ptr(),
                encrypted_message.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(),
                0, // No flags can be set
                plaintext_buffer.as_mut_ptr(),
                plaintext_buffer.len() as symcrypt_sys::SIZE_T,
                result_size,
            )
            .into()
        }
    }

    /// `pkcs1_verify()` returns a [`SymCryptError`] if the signature verification fails and `Ok(())` if the verification is successful.
    ///
    /// Caller must check the return value to determine if the signature is valid before continuing.
    ///
    /// `hashed_message` is a `&[u8]` representing the hashed message to be verified.
    ///
    /// `signature` is a `&[u8]` representing the signature to be verified.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] representing the hash algorithm used to hash the message.
    pub fn pkcs1_verify(
        &self,
        hashed_message: &[u8],
        signature: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Result<(), SymCryptError> {
        let converted_hash_oids = hash_algorithm.to_oid_list();
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPkcs1Verify(
                self.inner(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                signature.as_ptr(),
                signature.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(), // Only MSB is supported
                converted_hash_oids.as_ptr(),
                converted_hash_oids.len() as symcrypt_sys::SIZE_T,
                0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `pkcs1_encrypt()` encrypts a message using the public key of the key pair and returns a `Vec<u8>` representing the encrypted message,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// pkcs1 encryption is considered weak crypto, and should only be used for compatibility with legacy systems. To enable pkcs1 encryption, enable the `pkcs1-encrypt-decrypt` feature.
    ///
    /// `message` is a `&[u8]` representing the message to be encrypted.
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    pub fn pkcs1_encrypt(&self, message: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        let mut result_size = 0;
        let size_of_modulus = self.get_size_of_modulus();
        let mut encrypted_buffer = vec![0u8; size_of_modulus as usize];
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPkcs1Encrypt(
                self.inner(),
                message.as_ptr(),
                message.len() as symcrypt_sys::SIZE_T,
                0, // No flags can be set
                NumberFormat::MSB.to_symcrypt_format(),
                encrypted_buffer.as_mut_ptr(),
                size_of_modulus as symcrypt_sys::SIZE_T,
                &mut result_size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(encrypted_buffer),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{sha256, HashAlgorithm};
    use crate::rsa::{RsaKey, RsaKeyUsage};

    #[test]
    fn test_pkcs1_sign_verify() {
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

        let signature = key_pair
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap();
        let verify_result = public_key.pkcs1_verify(&hashed_message, &signature, hash_algorithm);

        assert!(verify_result.is_ok());
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_encrypt_decrypt() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();

        let mut plaintext_buffer = vec![0u8; encrypted_message.len()];
        let mut result_size = 0;
        let res =
            key_pair.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);
        assert_eq!(res, SymCryptError::NoError);
        plaintext_buffer.truncate(result_size as usize);
        assert_eq!(plaintext_buffer, message);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_encrypt_decrypt_big_buffer() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();

        let mut plaintext_buffer = vec![0u8; 100]; // very large buffer in relation to the provided message
        let mut result_size = 0;
        let res =
            key_pair.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);
        assert_eq!(res, SymCryptError::NoError);
        assert_eq!(result_size, message.len() as u64);
        assert_eq!(plaintext_buffer.len(), 100);
        plaintext_buffer.truncate(result_size as usize);
        assert_eq!(plaintext_buffer, message);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_encrypt_decrypt_buffer_too_small() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();

        let mut plaintext_buffer = vec![0u8; 5]; // buffer must be at least the size of the message.
        let mut result_size = 0;
        let res =
            key_pair.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);
        assert_eq!(res, SymCryptError::BufferTooSmall);
        plaintext_buffer.truncate(result_size as usize);
        assert_ne!(plaintext_buffer, message);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_encrypt_with_public_key() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::Encrypt,
        )
        .unwrap();

        let mut plaintext_buffer = vec![0u8; message.len()];
        let mut result_size = 0;
        let encrypted_message = public_key.pkcs1_encrypt(message).unwrap();
        let res =
            key_pair.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);
        assert_eq!(res, SymCryptError::NoError);
        plaintext_buffer.truncate(result_size as usize);
        assert_eq!(plaintext_buffer, message);
    }

    #[test]
    fn test_pkcs1_sign_verify_with_different_keys() {
        let signing_key_pair =
            RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let verifying_key_pair =
            RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        let signature = signing_key_pair
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap();

        let public_key_blob = verifying_key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let verify_result = public_key
            .pkcs1_verify(&hashed_message, &signature, hash_algorithm)
            .unwrap_err();

        assert!(matches!(
            verify_result,
            SymCryptError::SignatureVerificationFailure | SymCryptError::InvalidArgument
        ));
    }

    #[test]
    fn test_pkcs1_verify_with_tampered_message() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let mut hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        let signature = key_pair
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap();

        // tamper with message
        hashed_message[0] ^= 0xFF;

        let verify_result = public_key
            .pkcs1_verify(&hashed_message, &signature, hash_algorithm)
            .unwrap_err();

        assert_eq!(verify_result, SymCryptError::SignatureVerificationFailure);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_decrypt_with_invalid_data() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();

        let mut invalid_encrypted_message = encrypted_message.clone();
        invalid_encrypted_message[0] ^= 0xFF;

        let mut plaintext_buffer = vec![0u8; encrypted_message.len()];
        let mut result_size = 0;

        let res = key_pair.pkcs1_decrypt(
            &invalid_encrypted_message,
            &mut plaintext_buffer,
            &mut result_size,
        );
        assert_eq!(res, SymCryptError::InvalidArgument);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_encrypt_with_wrong_key_usage() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::Sign).unwrap();
        let message = b"example message";

        let encrypt_result = key_pair.pkcs1_encrypt(message).unwrap_err();
        assert_eq!(encrypt_result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_pkcs1_sign_with_wrong_key_usage() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::Encrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        let sign_result = key_pair
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap_err();
        assert_eq!(sign_result, SymCryptError::InvalidArgument);
    }

    #[test]
    #[cfg(feature = "pkcs1-encrypt-decrypt")]
    fn test_pkcs1_decrypt_with_public_key() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::Encrypt,
        )
        .unwrap();

        let mut plaintext_buffer = vec![0u8; message.len()];
        let mut result_size = 0;

        let encrypted_message = public_key.pkcs1_encrypt(message).unwrap();
        let result =
            public_key.pkcs1_decrypt(&encrypted_message, &mut plaintext_buffer, &mut result_size);

        assert_eq!(result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_pkcs1_sign_with_public_key() {
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::Encrypt,
        )
        .unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        let result = public_key
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument);
    }
}
