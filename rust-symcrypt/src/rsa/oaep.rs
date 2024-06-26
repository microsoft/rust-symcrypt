//! OAEP functions for [`RsaKeyPair`] and [`RsaPublicKey`]. For more info please refer to symcrypt.h
//!
//! Decrypt functionality is locked to only be usable by [`RsaKeyPair`].
//! Encrypt functionality is provided by both [`RsaKeyPair`] and [`RsaPublicKey`].
//!
//! #Example
//!
//! ## Encrypt and Decrypt with [`RsaKeyPair`].
//! ```rust
//! use symcrypt::rsa::{RsaKeyPair, RsaKeyUsage};
//! use symcrypt::hash::HashAlgorithm;
//!
//! // Generate a new RSA key pair
//! let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
//!
//! // Set up message to encrypt
//! let message = b"example message";
//! let hash_algorithm = HashAlgorithm::Sha256;
//! let label = b"label";
//!
//! // Encrypt the message
//! let encrypted_message = key_pair.oaep_encrypt(message, hash_algorithm, label).unwrap();
//!
//! // Decrypt the message and verify it matches the original message
//! let decrypted_message = key_pair.oaep_decrypt(&encrypted_message, hash_algorithm, label).unwrap();
//! assert_eq!(decrypted_message, message);
//! ```
//!
use crate::errors::SymCryptError;
use crate::hash::HashAlgorithm;
use crate::rsa::{RsaKeyPair, RsaPublicKey};
use crate::NumberFormat;

impl RsaKeyPair {
    /// `oaep_decrypt()` is only available for [`RsaKeyPair`].
    ///
    /// This function returns a decrypted message as a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
    ///
    /// `encrypted_message` is a `&[u8]` that represents the message to decrypt.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] that represents the hash algorithm to use.
    ///
    /// `label` is a `&[u8]` that represents the label to use.
    pub fn oaep_decrypt(
        &self,
        encrypted_message: &[u8],
        hash_algorithm: HashAlgorithm,
        label: &[u8],
    ) -> Result<Vec<u8>, SymCryptError> {
        let mut result_size: symcrypt_sys::SIZE_T = 0;
        let modulus_size = self.get_size_of_modulus();
        let mut decrypted_buffer = vec![0u8; modulus_size as usize];
        let hash_algorithm_ptr = hash_algorithm.to_symcrypt_hash();

        unsafe {
            // SAFETY: FFI calls
            let error_code = symcrypt_sys::SymCryptRsaOaepDecrypt(
                self.inner(),
                encrypted_message.as_ptr(),
                encrypted_message.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(),
                hash_algorithm_ptr,
                label.as_ptr(),
                label.len() as symcrypt_sys::SIZE_T,
                0, // flags must be 0
                decrypted_buffer.as_mut_ptr(),
                modulus_size as symcrypt_sys::SIZE_T,
                &mut result_size,
            );

            if error_code == symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                // SymCrypt fills the buffer with info and returns the size of the decrypted data in result_size
                // for the caller to decide if they wish to truncate the buffer to the actual size of the decrypted data.
                // Max size for the buffer is the size of the modulus.
                decrypted_buffer.truncate(result_size as usize);
                Ok(decrypted_buffer)
            } else {
                Err(error_code.into())
            }
        }
    }

    /// `oaep_encrypt()` returns a encrypted message as a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
    ///
    /// `message` is a `&[u8]` that represents the message to encrypt.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] that represents the hash algorithm to use.
    ///
    /// `label` is a `&[u8]` that represents the label to use.
    pub fn oaep_encrypt(
        &self,
        message: &[u8],
        hash_algorithm: HashAlgorithm,
        label: &[u8],
    ) -> Result<Vec<u8>, SymCryptError> {
        oaep_encrypt_helper(
            self.inner(),
            self.get_size_of_modulus(),
            message,
            hash_algorithm,
            label,
        )
    }
}

impl RsaPublicKey {
    /// `oaep_encrypt()` returns a encrypted message as a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
    ///
    /// `message` is a `&[u8]` that represents the message to encrypt.
    ///
    /// `hash_algorithm` is a [`HashAlgorithm`] that represents the hash algorithm to use.
    ///
    /// `label` is a `&[u8]` that represents the label to use.
    pub fn oaep_encrypt(
        &self,
        message: &[u8],
        hash_algorithm: HashAlgorithm,
        label: &[u8],
    ) -> Result<Vec<u8>, SymCryptError> {
        oaep_encrypt_helper(
            self.inner(),
            self.get_size_of_modulus(),
            message,
            hash_algorithm,
            label,
        )
    }
}

// private helper functions for oaep encrypt. The underlying call to SymCrypt is the same since SymCrypt does not make any distinction between public / key pair.
fn oaep_encrypt_helper(
    symcrypt_key: symcrypt_sys::PSYMCRYPT_RSAKEY,
    modulus_size: u32,
    message: &[u8],
    hash_algorithm: HashAlgorithm,
    label: &[u8],
) -> Result<Vec<u8>, SymCryptError> {
    let mut result_size: symcrypt_sys::SIZE_T = 0;
    let mut encrypted = vec![0u8; modulus_size as usize];
    let hash_algorithm_ptr = hash_algorithm.to_symcrypt_hash();

    unsafe {
        // SAFETY: FFI calls
        let error_code = symcrypt_sys::SymCryptRsaOaepEncrypt(
            symcrypt_key,
            message.as_ptr(),
            message.len() as symcrypt_sys::SIZE_T,
            hash_algorithm_ptr,
            label.as_ptr(),
            label.len() as symcrypt_sys::SIZE_T,
            0, // flags must be 0
            NumberFormat::MSB.to_symcrypt_format(),
            encrypted.as_mut_ptr(),
            modulus_size as symcrypt_sys::SIZE_T,
            &mut result_size,
        );

        if error_code == symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
            Ok(encrypted)
        } else {
            Err(error_code.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::SymCryptError;
    use crate::hash::HashAlgorithm;
    use crate::rsa::{RsaKeyPair, RsaKeyUsage, RsaPublicKey};

    #[test]
    fn test_oaep_encrypt_decrypt() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let message = b"example message";
        let hash_algorithm = HashAlgorithm::Sha256;
        let label = b"label";

        let encrypted_message = key_pair
            .oaep_encrypt(message, hash_algorithm, label)
            .unwrap();
        let decrypted_message = key_pair
            .oaep_decrypt(&encrypted_message, hash_algorithm, label)
            .unwrap();

        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_oaep_encrypt_with_public_key() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let public_key_blob = key_pair.export_public_key_blob().unwrap();
        let public_key = RsaPublicKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::Encrypt,
        )
        .unwrap();

        // Message to encrypt
        let message = b"example message";
        let hash_algorithm = HashAlgorithm::Sha256;
        let label = b"label";

        let encrypted_message = public_key
            .oaep_encrypt(message, hash_algorithm, label)
            .unwrap();

        let decrypted_message = key_pair
            .oaep_decrypt(&encrypted_message, hash_algorithm, label)
            .unwrap();

        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_oaep_encrypt_decrypt_with_empty_label() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        // Message to encrypt
        let message = b"example message";
        let hash_algorithm = HashAlgorithm::Sha256;
        let label = b"";

        let encrypted_message = key_pair
            .oaep_encrypt(message, hash_algorithm, label)
            .unwrap();
        let decrypted_message = key_pair
            .oaep_decrypt(&encrypted_message, hash_algorithm, label)
            .unwrap();

        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_oaep_encrypt_decrypt_large_message() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();

        let encrypted_message = [0u8; 1000];
        let hash_algorithm = HashAlgorithm::Sha256;
        let label = b"";

        let decrypted_message = key_pair
            .oaep_decrypt(&encrypted_message, hash_algorithm, label)
            .unwrap_err();

        assert_eq!(decrypted_message, SymCryptError::InvalidArgument);
    }
}
