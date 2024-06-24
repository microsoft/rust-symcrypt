//! PKCS1 functions for [`RsaKeyPair`] and [`RsaPublicKey`]. For more info please refer to symcrypt.h
//!
//! Sign and Decrypt functionality are locked to only be usable from [`RsaKeyPair`], while
//! Verify and Encrypt functionality are usable from both [`RsaKeyPair`] and [`RsaPublicKey`].
//!
//! # Examples
//!
//! ## Sign and Verify using RsaKeyPair and RsaPublicKey
//!
//! ```rust
//! use symcrypt::{RsaKeyPair, RsaKeyUsage};
//! use symcrypt::hash::{sha256, HashAlgorithm};
//!
//! // Generate key pair.
//! let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Set up message.
//! let hashed_message = sha256(b"hello world");
//! let hash_algorithm = HashAlgorithm::Sha256;
//!
//! // Create signature.
//! let signature = key_pair.pkcs1_sign(&hashed_message, hash_algorithm).unwrap();
//!
//! // Create Public Key to verify signature.
//! let public_key_blob = key_pair.export_public_key_blob().unwrap();
//! let public_key = RsaPublicKey::set_public_key(&public_key_blob.modulus, &public_key_blob.pub_exp, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Verify signature.
//! let verify_result = public_key.pkcs1_verify(&hashed_message, &signature, hash_algorithm);
//! assert!(verify_result.is_ok());
//! ```
//!
//! ## Encrypt and Decrypt using RsaKeyPair
//!
//! ```rust
//! use symcrypt::{RsaKeyPair, RsaKeyUsage};
//!
//! // Generate key pair.
//! let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Set up message.
//! let message = b"example message";
//!
//! // Encrypt message.
//! let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();
//!
//! // Decrypt message.
//! let decrypted_message = key_pair.pkcs1_decrypt(&encrypted_message).unwrap();
//! assert_eq!(decrypted_message, message);
//! ```
//!
use crate::errors::SymCryptError;
use crate::hash::HashAlgorithm;
use crate::rsa::{RsaKeyPair, RsaPublicKey};
use crate::NumberFormat;

/// Impl for Pkcs1 RSA via [`RsaKeyPair`]
impl RsaKeyPair {
    /// `pcks1_sign()` is only available for [`RsaKeyPair`].
    ///
    /// This function signs a hashed message using the private key of the key pair and returns a `Vec<u8>` representing the signature,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// `hashed_message` is a `&[u8]` representing the hashed message to be signed.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] representing the hash algorithm used to hash the message.
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
            let error_code = symcrypt_sys::SymCryptRsaPkcs1Sign(
                self.inner(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                converted_hash_oids.as_ptr(),
                converted_hash_oids.len() as symcrypt_sys::SIZE_T,
                symcrypt_sys::SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
                NumberFormat::MSB.to_symcrypt_format(),
                signature.as_mut_ptr(),
                modulus_size as symcrypt_sys::SIZE_T,
                &mut result_size,
            );
            if error_code == symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                if (modulus_size as symcrypt_sys::SIZE_T) < result_size {
                    return Err(SymCryptError::MemoryAllocationFailure);
                }
                signature.truncate(result_size as usize);
                Ok(signature)
            } else {
                Err(error_code.into())
            }
        }
    }

    /// `pcks1_decrypt()` is only available for [`RsaKeyPair`].
    ///
    /// This function decrypts an encrypted buffer using the private key of the key pair and returns a `Vec<u8>` representing the decrypted buffer,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// `encrypted_buffer` is a `&[u8]` representing the encrypted buffer to be decrypted.
    pub fn pkcs1_decrypt(&self, encrypted_buffer: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        let mut result_size = 0;
        let modulus_size = self.get_size_of_modulus();
        let mut decrypted_buffer = vec![0u8; modulus_size as usize]; // Max size will be the size of the modulus.
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsaPkcs1Decrypt(
                self.inner(),
                encrypted_buffer.as_ptr(),
                encrypted_buffer.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(),
                0, // No flags can be set
                decrypted_buffer.as_mut_ptr(),
                modulus_size as symcrypt_sys::SIZE_T,
                &mut result_size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    // SymCrypt fills the buffer with info and returns the size of the signature in result_size
                    // for the caller to decide if they wish to truncate the buffer to the actual size of the signature.
                    // Max size for the buffer is the size of the modulus.
                    decrypted_buffer.truncate(result_size as usize);
                    Ok(decrypted_buffer)
                }
                err => Err(err.into()),
            }
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
        pkcs1_verify_helper(self.inner(), hashed_message, signature, hash_algorithm)
    }

    /// `pkcs1_encrypt()` encrypts a buffer using the public key of the key pair and returns a `Vec<u8>` representing the encrypted buffer,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// `buffer` is a `&[u8]` representing the buffer to be encrypted.
    pub fn pkcs1_encrypt(&self, message: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        pkcs1_encrypt_helper(self.inner(), message, self.get_size_of_modulus())
    }
}

impl RsaPublicKey {
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
        pkcs1_verify_helper(self.inner(), hashed_message, signature, hash_algorithm)
    }

    /// `pkcs1_encrypt()` encrypts a buffer using the public key of the key pair and returns a `Vec<u8>` representing the encrypted buffer,
    /// or a [`SymCryptError`] if the operation fails.
    ///
    /// `buffer` is a `&[u8]` representing the buffer to be encrypted.
    pub fn pkcs1_encrypt(&self, message: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        pkcs1_encrypt_helper(self.inner(), message, self.get_size_of_modulus())
    }
}

// private helper functions for pcks1 encryption. The underlying call to SymCrypt is the same since SymCrypt does not make any distinction between public / key pair.
fn pkcs1_encrypt_helper(
    symcrypt_key: symcrypt_sys::PSYMCRYPT_RSAKEY,
    buffer: &[u8],
    size_of_modulus: u32,
) -> Result<Vec<u8>, SymCryptError> {
    let mut result_size = 0;
    let mut encrypted_buffer = vec![0u8; size_of_modulus as usize];
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptRsaPkcs1Encrypt(
            symcrypt_key,
            buffer.as_ptr(),
            buffer.len() as symcrypt_sys::SIZE_T,
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

// private helper functions for pcks1 verify. The underlying call to SymCrypt is the same since SymCrypt does not make any distinction between public / key pair.
fn pkcs1_verify_helper(
    symcrypt_key: symcrypt_sys::PSYMCRYPT_RSAKEY,
    hashed_value: &[u8],
    signature: &[u8],
    hash_algorithm: HashAlgorithm,
) -> Result<(), SymCryptError> {
    let converted_hash_oids = hash_algorithm.to_oid_list();
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptRsaPkcs1Verify(
            symcrypt_key,
            hashed_value.as_ptr(),
            hashed_value.len() as symcrypt_sys::SIZE_T,
            signature.as_ptr(),
            signature.len() as symcrypt_sys::SIZE_T,
            NumberFormat::MSB.to_symcrypt_format(), // Only MSB is supported
            converted_hash_oids.as_ptr(),
            converted_hash_oids.len() as symcrypt_sys::SIZE_T,
            symcrypt_sys::SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{sha256, HashAlgorithm};
    use crate::rsa::{RsaKeyPair, RsaKeyUsage, RsaPublicKey};

    #[test]
    fn test_pkcs1_sign_verify() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaPublicKey::set_public_key(
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
    fn test_pkcs1_encrypt_decrypt() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();
        let decrypted_message = key_pair.pkcs1_decrypt(&encrypted_message).unwrap();

        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_pkcs1_encrypt_with_public_key() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"example message";

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaPublicKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::Encrypt,
        )
        .unwrap();

        let encrypted_message = public_key.pkcs1_encrypt(message).unwrap();
        let decrypted_message = key_pair.pkcs1_decrypt(&encrypted_message).unwrap();

        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_pkcs1_sign_verify_with_different_keys() {
        let signing_key_pair =
            RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let verifying_key_pair =
            RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let hashed_message = sha256(b"hello world");
        let hash_algorithm = HashAlgorithm::Sha256;

        let signature = signing_key_pair
            .pkcs1_sign(&hashed_message, hash_algorithm)
            .unwrap();

        let public_key_blob = verifying_key_pair.export_public_key_blob().unwrap();
        let public_key = RsaPublicKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();

        let verify_result = public_key
            .pkcs1_verify(&hashed_message, &signature, hash_algorithm)
            .unwrap_err();

        assert_eq!(verify_result, SymCryptError::SignatureVerificationFailure);
    }

    #[test]
    fn test_pkcs1_decrypt_with_invalid_data() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let message = b"example message";

        let encrypted_message = key_pair.pkcs1_encrypt(message).unwrap();

        let mut invalid_encrypted_message = encrypted_message.clone();
        invalid_encrypted_message[0] ^= 0xFF;

        let decrypt_result = key_pair.pkcs1_decrypt(&invalid_encrypted_message);

        assert!(decrypt_result.is_err());
    }
}
