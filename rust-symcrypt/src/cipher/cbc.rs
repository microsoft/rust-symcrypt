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
//! 
//! // Set up the key, chaining value, and plaintext
//! let key = hex::decode("00000000000000000000000000000000").unwrap();
//! let aes_cbc = AesExpandedKey::new(&key).unwrap();
//! let mut chaining_value = hex::decode("00000000000000000000000000000000").unwrap();
//! let mut plain_text = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap(); // mutable
//! let mut cipher_text = vec![0u8; plain_text.len()];
//! 
//! // Encrypt the plaintext
//! aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text).unwrap(); // Encrypt instead of decrypt
//! 
//! assert_eq!(hex::encode(cipher_text), "0336763e966d92595a567cc9ce537f5e");
//! ```
//! 
//! ## AES-CBC Encryption piecewise
//! 
//! ```rust 
//! use symcrypt::cipher::AesExpandedKey;
//! use hex::*;
//! 
//! // Set up the key, chaining value, and plaintext
//! let key = hex::decode("5d98398b5e3b98d87e07ecf1332df4ac").unwrap();
//! let mut chaining_value = hex::decode("db22065fb9302c4445151adc91310797").unwrap();
//! let plaintext = hex::decode("4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205").unwrap();
//! let expected_ciphertext = hex::decode("f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611").unwrap();
//! 
//! // Create the AES key
//! let aes_cbc = AesExpandedKey::new(&key).unwrap();
//!
//! // Setup piecewise encrypt
//! let mut piecewise_encrypted = vec![0u8; plaintext.len()];
//! let mid = plaintext.len() / 2;
//! 
//! // Encrypt first half
//! aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plaintext[..mid], &mut piecewise_encrypted[..mid]).unwrap();
//! 
//! // Encrypt second half with the chaining value from the first encryption
//! aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plaintext[mid..], &mut piecewise_encrypted[mid..]).unwrap();
//! 
//! assert_eq!(piecewise_encrypted, expected_ciphertext);
//! ```
//! 
use crate::cipher::{validate_block_size, AesExpandedKey};
use crate::errors::SymCryptError;
use symcrypt_sys;

impl AesExpandedKey {
    /// `aes_cbc_encrypt()` encrypts the `plain_text` using the AES-CBC algorithm and writes to the `cipher_text` buffer provided.
    /// You are able to run this function in one go or piecewise.
    /// 
    /// `chaining_value` is a `mut &[u8]` that represents the `IV` on the first call, and will be filled with the chaining value after the encryption is complete.
    /// If doing a piecewise encryption, you will need to keep track of the `chaining_value` and pass it in on the next block for encryption.
    /// 
    /// `plain_text` is a `&[u8]`  that represents the data to be encrypted.
    /// 
    /// `cipher_text` is a `mut &[u8]` that will be filled with the encrypted data. The length of this buffer must be equal to the length of the `plain_text` buffer.
    /// 
    /// This function will return an Error if the length of the `plain_text` and `cipher_text` buffers are not equal, or if they are not multiples of 16 bytes.
    pub fn aes_cbc_encrypt(
        &self,
        chaining_value: &mut [u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_block_size(plain_text, cipher_text)?;
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

    /// `aes_cbc_decrypt()` decrypts the `cipher_text` using the AES-CBC algorithm and writes to the `plain_text` buffer provided.
    /// You are able to run this function in one go or piecewise.
    /// 
    /// `chaining_value` is a `mut &[u8]` that represents the `IV` on the first call, and will be filled with the chaining value after the decryption is complete.
    /// If doing a piecewise decryption, you will need to keep track of the `chaining_value` and pass it in on the next block for decryption.
    /// 
    /// `cipher_text` is a `&[u8]`  that represents the data to be decrypted.
    /// 
    /// `plain_text` is a `mut &[u8]` that will be filled with the decrypted data. The length of this buffer must be equal to the length of the `cipher_text` buffer.
    /// 
    /// This function will return an Error if the length of the `plain_text` and `cipher_text` buffers are not equal, or if they are not multiples of 16 bytes.
    pub fn aes_cbc_decrypt(
        &self,
        chaining_value: &mut [u8],
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_block_size(plain_text, cipher_text)?;
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
}


#[cfg(test)]
pub mod test{
    use super::*;
    use hex;

    #[test]
    fn test_aes_cbc_encrypt() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = hex::decode("00000000000000000000000000000000").unwrap();
        let plain_text = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
        let mut cipher_text = vec![0u8; plain_text.len()];

        aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text).unwrap();
        assert_eq!(hex::encode(cipher_text), "0336763e966d92595a567cc9ce537f5e");
    }

    #[test]
    fn test_aes_cbc_encrypt_single_and_piecewise() {
        let key_hex = "5d98398b5e3b98d87e07ecf1332df4ac";
        let iv_hex = "db22065fb9302c4445151adc91310797";
        let plaintext_hex = "4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205";
        let ciphertext_hex = "f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611";

        let key = hex::decode(key_hex).unwrap();
        let iv = hex::decode(iv_hex).unwrap();
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
    fn test_aes_cbc_decrypt() {
        let key = hex::decode("9bceab233f4d2edc9220935664284525").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = hex::decode("db5063420e5f843d457f0a3118405fb2").unwrap();
        let cipher_text = hex::decode("581506ac668b8f0b39d89d9a87a21c14").unwrap();
        let mut plain_text = vec![0u8; cipher_text.len()];
        
        aes_cbc.aes_cbc_decrypt(&mut chaining_value, &cipher_text, &mut plain_text).unwrap();
        assert_eq!(hex::encode(plain_text), "08d6fc05e8f7977fde2afc9508a6d55e");
    }

    #[test]
    fn test_aes_cbc_decrypt_single_and_piecewise() {
        let key_hex = "72d5c5de43b76667a4da64779dbd949d";
        let iv_hex = "8afa034904220bf7eecb1ae607061245";
        let plaintext_hex = "83f00bc4e745c9949dfb65c631fa78a3a0db82b41ba0d41d08a3ad2d4acda332c208449215f7fe17b0e43c8b0afad28529b49b8268956037771afc26a3edbe70";
        let ciphertext_hex = "8478306b078ee5279862332b1f95de3bab28eb5ea5fc141d40efe3cc59fcf9c74d4034df16dec6e007a560fd5af9c0c3029254dffced41b5eb39f97932eb5ed1";

        let key = hex::decode(key_hex).unwrap();
        let iv = hex::decode(iv_hex).unwrap();
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

        // Piecewise decryption
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
    fn test_aes_cbc_encrypt_decrypt_with_cloned_keys() {
        let key_hex = "9bceab233f4d2edc9220935664284525";
        let iv_hex = "db5063420e5f843d457f0a3118405fb2";
        let plaintext_hex = "08d6fc05e8f7977fde2afc9508a6d55e";
        let expected_ciphertext_hex = "581506ac668b8f0b39d89d9a87a21c14";
    
        let key = hex::decode(key_hex).unwrap();
        let iv = hex::decode(iv_hex).unwrap();
        let plaintext = hex::decode(plaintext_hex).unwrap();
        let expected_ciphertext = hex::decode(expected_ciphertext_hex).unwrap();
    
        // Initialize the original AES key and clone it
        let original_aes_key = AesExpandedKey::new(&key).unwrap();
        let cloned_aes_key = original_aes_key.clone();
    
        // Encrypt

        // Original key 
        let mut chaining_value = iv.clone();
        let mut ciphertext_with_original = vec![0u8; plaintext.len()];
        original_aes_key
            .aes_cbc_encrypt(&mut chaining_value, &plaintext, &mut ciphertext_with_original)
            .unwrap();
    
        assert_eq!(ciphertext_with_original, expected_ciphertext);
    
        // Cloned key
        chaining_value = iv.clone();
        let mut ciphertext_with_clone = vec![0u8; plaintext.len()];
        cloned_aes_key
            .aes_cbc_encrypt(&mut chaining_value, &plaintext, &mut ciphertext_with_clone)
            .unwrap();
    
        assert_eq!(ciphertext_with_clone, expected_ciphertext);
        assert_eq!(ciphertext_with_original, ciphertext_with_clone);
    
        // Decrypt 

        // Original key
        chaining_value = iv.clone();
        let mut decrypted_plaintext_with_original = vec![0u8; ciphertext_with_original.len()];
        original_aes_key
            .aes_cbc_decrypt(
                &mut chaining_value,
                &ciphertext_with_original,
                &mut decrypted_plaintext_with_original,
            )
            .unwrap();
    
        assert_eq!(decrypted_plaintext_with_original, plaintext);
    
        // Cloned key
        chaining_value = iv;
        let mut decrypted_plaintext_with_clone = vec![0u8; ciphertext_with_clone.len()];
        cloned_aes_key
            .aes_cbc_decrypt(
                &mut chaining_value,
                &ciphertext_with_clone,
                &mut decrypted_plaintext_with_clone,
            )
            .unwrap();
    
        assert_eq!(decrypted_plaintext_with_clone, plaintext);
    }
    
}
