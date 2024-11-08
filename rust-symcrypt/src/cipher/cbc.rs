//! Functions for Cbc encryption and decryption. For more info please see symcrypt.h
//!
//! These functions are methods on the [AesExpandedKey] struct.
//!
//! # Examples
//!
//! ## AES-CBC Encryption in one go
//!
//! ```rust
//! use symcrypt::cipher::AesExpandedKey;
//! use hex::*;
//! use std::convert::TryInto;
//!
//! // Set up the key, chaining value, and plaintext
//! let key = hex::decode("9bceab233f4d2edc9220935664284525").unwrap();
//!
//! let mut iv = hex::decode("db5063420e5f843d457f0a3118405fb2").unwrap();
//! let mut plain_text = hex::decode("08d6fc05e8f7977fde2afc9508a6d55e").unwrap();
//! let mut cipher_text = vec![0u8; plain_text.len()];
//!
//! // Initialize AES key and IV
//! let mut chaining_value: [u8; 16] = iv.try_into().expect("IV should be 16 bytes long");
//! let aes_cbc = AesExpandedKey::new(&key).unwrap();
//!
//! // Encrypt the plaintext
//! aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text).unwrap();
//!
//! assert_eq!(hex::encode(cipher_text), "581506ac668b8f0b39d89d9a87a21c14");
//! ```
//!
//! ## AES-CBC Encryption block by block
//!
//! ```rust
//! use symcrypt::cipher::AesExpandedKey;
//! use hex;
//! use std::convert::TryInto;
//! use symcrypt::cipher::AES_BLOCK_SIZE;
//!
//! // Set up key, IV (chaining value), plaintext, and expected ciphertext
//! let key = hex::decode("5d98398b5e3b98d87e07ecf1332df4ac").unwrap();
//! let iv = hex::decode("db22065fb9302c4445151adc91310797").unwrap();
//! let plaintext = hex::decode("4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205").unwrap();
//! let expected_ciphertext = hex::decode("f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611").unwrap();
//!
//! // Initialize AES key and IV
//! let aes_cbc = AesExpandedKey::new(&key).unwrap();
//! let mut chaining_value: [u8; 16] = iv.try_into().expect("IV should be 16 bytes long");
//!
//! // Prepare the buffer for in-place encryption
//! let mut buffer = plaintext.clone();
//! let block_size = AES_BLOCK_SIZE as usize;
//!
//! // Encrypt the plaintext block by block in-place
//! for i in (0..buffer.len()).step_by(block_size) {
//!     let block = i + block_size;
//!     aes_cbc
//!         .aes_cbc_encrypt_in_place(&mut chaining_value, &mut buffer[i..block])
//!         .unwrap();
//! }
//!
//! assert_eq!(buffer, expected_ciphertext);
//! ```
//!
use crate::cipher::{AesExpandedKey, AES_BLOCK_SIZE};
use crate::errors::SymCryptError;
use symcrypt_sys;

impl AesExpandedKey {
    /// `aes_cbc_encrypt()` encrypts the `plain_text` using the AES-CBC algorithm and writes to the `cipher_text` buffer provided.
    /// You are able to run this function in one go, or block by block.
    ///
    /// `chaining_value` is a `mut &[u8; 16]` that represents the `IV` on the first call, and will be filled with the chaining value after the encryption is complete.
    /// If doing encryption block by block, you will need to keep track of the `chaining_value` and pass it in on the next block for encryption. This value must be 16 bytes long.
    ///
    /// `plain_text` is a `&[u8]` that represents the data to be encrypted.
    ///
    /// `cipher_text` is a `mut &[u8]` that will be filled with the encrypted data. The length of this buffer must be equal to the length of the `plain_text` buffer.
    ///
    /// This function will return a [`SymCryptError`] if the length of the `plain_text` and `cipher_text` buffers are not equal, or if they are not multiples of 16 bytes.
    pub fn aes_cbc_encrypt(
        &self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE as usize],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_aes_cbc_inputs(plain_text, cipher_text)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcEncrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                plain_text.as_ptr(),
                cipher_text.as_mut_ptr(),
                plain_text.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }

    /// aes_cbc_encrypt_in_place() encrypts the `buffer` using the AES-CBC algorithm and writes the encrypted data back to the `buffer` provided.
    /// You are able to run this function in one go or block by block.
    ///
    /// `chaining_value` is a `mut &[u8; 16]` that represents the `IV` on the first call, and will be filled with the chaining value after the encryption is complete.
    /// If doing decryption block by block, you will need to keep track of the `chaining_value` and pass it in on the next block for decryption. This value must be 16 bytes long.
    ///
    /// `buffer` is a `mut &[u8]` that will be filled with the encrypted data. The length of this buffer must be a multiple of 16 bytes.
    ///
    /// This function will return a [`SymCryptError`] if the length of the `buffer` is not a multiple of 16 bytes.
    pub fn aes_cbc_encrypt_in_place(
        &self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE as usize],
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_aes_cbc_inputs(buffer, buffer)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcEncrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }

    /// `aes_cbc_decrypt()` decrypts the `cipher_text` using the AES-CBC algorithm and writes to the `plain_text` buffer provided.
    /// You are able to run this function in one go or block by block.
    ///
    /// `chaining_value` is a `mut &[u8; 16]` that represents the `IV` on the first call, and will be filled with the chaining value after the decryption is complete.
    /// If doing decryption block by block, you will need to keep track of the `chaining_value` and pass it in on the next block for decryption. This value must be 16 bytes long.
    ///
    /// `cipher_text` is a `&[u8]` that represents the data to be decrypted.
    ///
    /// `plain_text` is a `mut &[u8]` that will be filled with the decrypted data. The length of this buffer must be equal to the length of the `cipher_text` buffer.
    ///
    /// This function will return an Error if the length of the `plain_text` and `cipher_text` buffers are not equal, or if they are not multiples of 16 bytes.
    pub fn aes_cbc_decrypt(
        &self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE as usize],
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_aes_cbc_inputs(plain_text, cipher_text)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcDecrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                cipher_text.as_ptr(),
                plain_text.as_mut_ptr(),
                plain_text.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }

    /// `aes_cbc_decrypt_in_place()` decrypts the `buffer` using the AES-CBC algorithm and writes the decrypted data back to the `buffer` provided.
    /// You are able to run this function in one go or block by block.
    ///
    /// `chaining_value` is a `mut &[u8; 16]` that represents the `IV` on the first call, and will be filled with the chaining value after the decryption is complete.
    /// If doing decryption block by block, you will need to keep track of the `chaining_value` and pass it in on the next block for decryption. This value must be 16 bytes long.
    ///
    /// `buffer` is a `mut &[u8]` that will be filled with the decrypted data. The length of this buffer must be a multiple of 16 bytes.
    ///
    /// This function will return a [`SymCryptError`] if the length of the `buffer` is not a multiple of 16 bytes.
    pub fn aes_cbc_decrypt_in_place(
        &self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE as usize],
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_aes_cbc_inputs(buffer, buffer)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcDecrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }
}

fn validate_aes_cbc_inputs(plain_text: &[u8], cipher_text: &[u8]) -> Result<(), SymCryptError> {
    if plain_text.len() != cipher_text.len() {
        return Err(SymCryptError::WrongDataSize);
    }

    // length of plain_text and cipher_text must be equal at this point.
    if plain_text.len() % AES_BLOCK_SIZE as usize != 0 {
        return Err(SymCryptError::WrongBlockSize);
    }

    Ok(())
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::cipher::AES_BLOCK_SIZE;
    use hex;
    use std::convert::TryInto;

    #[test]
    fn test_invalid_block_size() {
        let plain_text = vec![0u8; 15];
        let cipher_text = vec![0u8; 15];

        let result = validate_aes_cbc_inputs(&plain_text, &cipher_text).unwrap_err();
        assert_eq!(result, SymCryptError::WrongBlockSize);
    }

    #[test]
    fn test_mismatched_text_length() {
        let plain_text = vec![0u8; 32];
        let cipher_text = vec![0u8; 16];

        let result = validate_aes_cbc_inputs(&plain_text, &cipher_text).unwrap_err();
        assert_eq!(result, SymCryptError::WrongDataSize);
    }

    #[test]
    fn test_valid_block_size_and_length() {
        let plain_text = vec![0u8; 32];
        let cipher_text = vec![0u8; 32];

        let result = validate_aes_cbc_inputs(&plain_text, &cipher_text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_aes_cbc_encrypt() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value: [u8; 16] = hex::decode("00000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
        let plain_text = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
        let mut cipher_text = vec![0u8; plain_text.len()];

        aes_cbc
            .aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text)
            .unwrap();
        assert_eq!(hex::encode(cipher_text), "0336763e966d92595a567cc9ce537f5e");
    }

    #[test]
    fn test_aes_cbc_encrypt_single_and_piecewise() {
        let key_hex = "5d98398b5e3b98d87e07ecf1332df4ac";
        let iv_hex = "db22065fb9302c4445151adc91310797";
        let plaintext_hex = "4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205";
        let ciphertext_hex = "f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611";

        let key = hex::decode(key_hex).unwrap();
        let iv: [u8; 16] = hex::decode(iv_hex).unwrap().try_into().unwrap();
        let plaintext = hex::decode(plaintext_hex).unwrap();
        let expected_ciphertext = hex::decode(ciphertext_hex).unwrap();

        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = iv.clone();

        // Single encryption
        let mut single_encrypted = vec![0u8; plaintext.len()];
        aes_cbc
            .aes_cbc_encrypt(&mut chaining_value, &plaintext, &mut single_encrypted)
            .unwrap();
        assert_eq!(single_encrypted, expected_ciphertext);

        chaining_value = iv.clone();
        let mut piecewise_encrypted = vec![0u8; plaintext.len()];
        let mid = plaintext.len() / 2;

        // First half
        aes_cbc
            .aes_cbc_encrypt(
                &mut chaining_value,
                &plaintext[..mid],
                &mut piecewise_encrypted[..mid],
            )
            .unwrap();

        // Second half
        aes_cbc
            .aes_cbc_encrypt(
                &mut chaining_value,
                &plaintext[mid..],
                &mut piecewise_encrypted[mid..],
            )
            .unwrap();

        assert_eq!(piecewise_encrypted, expected_ciphertext);
        assert_eq!(single_encrypted, piecewise_encrypted);
    }

    #[test]
    fn test_aes_cbc_decrypt_single_and_block_by_block() {
        let key_hex = "5d98398b5e3b98d87e07ecf1332df4ac";
        let iv_hex = "db22065fb9302c4445151adc91310797";
        let plaintext_hex = "4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205";
        let ciphertext_hex = "f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611";

        let key = hex::decode(key_hex).unwrap();
        let iv: [u8; 16] = hex::decode(iv_hex).unwrap().try_into().unwrap();
        let expected_plaintext = hex::decode(plaintext_hex).unwrap();
        let ciphertext = hex::decode(ciphertext_hex).unwrap();

        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = iv.clone();

        // Single decryption
        let mut single_decrypted = vec![0u8; ciphertext.len()];
        aes_cbc
            .aes_cbc_decrypt(&mut chaining_value, &ciphertext, &mut single_decrypted)
            .unwrap();
        assert_eq!(single_decrypted, expected_plaintext);

        chaining_value = iv.clone();
        let mut block_by_block_decrypted = vec![0u8; ciphertext.len()];
        let block_size = AES_BLOCK_SIZE as usize;

        // Decrypt block by block
        for i in (0..ciphertext.len()).step_by(block_size) {
            let end = i + block_size;
            aes_cbc
                .aes_cbc_decrypt(
                    &mut chaining_value,
                    &ciphertext[i..end],
                    &mut block_by_block_decrypted[i..end],
                )
                .unwrap();
        }

        assert_eq!(block_by_block_decrypted, expected_plaintext);
        assert_eq!(single_decrypted, block_by_block_decrypted);
    }

    #[test]
    fn test_aes_cbc_decrypt_single_and_piecewise() {
        let key_hex = "5d98398b5e3b98d87e07ecf1332df4ac";
        let iv_hex = "db22065fb9302c4445151adc91310797";
        let plaintext_hex = "4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205";
        let ciphertext_hex = "f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611";

        let key = hex::decode(key_hex).unwrap();
        let iv: [u8; 16] = hex::decode(iv_hex).unwrap().try_into().unwrap();
        let expected_plaintext = hex::decode(plaintext_hex).unwrap();
        let ciphertext = hex::decode(ciphertext_hex).unwrap();

        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = iv.clone();

        // Single decryption
        let mut single_decrypted = vec![0u8; ciphertext.len()];
        aes_cbc
            .aes_cbc_decrypt(&mut chaining_value, &ciphertext, &mut single_decrypted)
            .unwrap();
        assert_eq!(single_decrypted, expected_plaintext);

        chaining_value = iv.clone();
        let mut piecewise_decrypted = vec![0u8; ciphertext.len()];
        let mid = ciphertext.len() / 2;

        // First half
        aes_cbc
            .aes_cbc_decrypt(
                &mut chaining_value,
                &ciphertext[..mid],
                &mut piecewise_decrypted[..mid],
            )
            .unwrap();

        // Second half
        aes_cbc
            .aes_cbc_decrypt(
                &mut chaining_value,
                &ciphertext[mid..],
                &mut piecewise_decrypted[mid..],
            )
            .unwrap();

        assert_eq!(piecewise_decrypted, expected_plaintext);
        assert_eq!(single_decrypted, piecewise_decrypted);
    }

    #[test]
    fn test_aes_cbc_decrypt() {
        let key = hex::decode("9bceab233f4d2edc9220935664284525").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value: [u8; 16] = hex::decode("db5063420e5f843d457f0a3118405fb2")
            .unwrap()
            .try_into()
            .unwrap();
        let cipher_text = hex::decode("581506ac668b8f0b39d89d9a87a21c14").unwrap();
        let mut plain_text = vec![0u8; cipher_text.len()];

        aes_cbc
            .aes_cbc_decrypt(&mut chaining_value, &cipher_text, &mut plain_text)
            .unwrap();
        assert_eq!(hex::encode(plain_text), "08d6fc05e8f7977fde2afc9508a6d55e");
    }

    #[test]
    fn test_aes_cbc_in_place_encryption_decryption() {
        let key = hex::decode("b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35").unwrap();
        let iv: [u8; 16] = hex::decode("00000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
        let expected_ciphertext = hex::decode("3cf5e1d21a17956d1dffad6a7c41c659").unwrap();

        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut buffer = plaintext.clone();

        // Encryption in-place
        let mut chaining_value = iv.clone();
        aes_cbc
            .aes_cbc_encrypt_in_place(&mut chaining_value, &mut buffer)
            .unwrap();
        assert_eq!(buffer, expected_ciphertext);

        // Decryption in-place
        chaining_value = iv.clone();
        aes_cbc
            .aes_cbc_decrypt_in_place(&mut chaining_value, &mut buffer)
            .unwrap();
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn test_aes_cbc_encrypt_in_place_block_by_block() {
        // Set up key, IV (chaining value), plaintext, and expected ciphertext
        let key = hex::decode("5d98398b5e3b98d87e07ecf1332df4ac").unwrap();
        let iv = hex::decode("db22065fb9302c4445151adc91310797").unwrap();
        let plaintext =
            hex::decode("4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205")
                .unwrap();
        let expected_ciphertext =
            hex::decode("f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611")
                .unwrap();

        // Initialize AES key and IV
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = iv.try_into().expect("IV should be 16 bytes long");

        let mut buffer = plaintext.clone();
        let block_size = AES_BLOCK_SIZE as usize;

        // Encrypt the plaintext block by block in-place
        for i in (0..buffer.len()).step_by(block_size) {
            let block = i + block_size;
            aes_cbc
                .aes_cbc_encrypt_in_place(&mut chaining_value, &mut buffer[i..block])
                .unwrap();
        }

        assert_eq!(buffer, expected_ciphertext);
    }
}
