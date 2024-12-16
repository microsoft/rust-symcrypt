//! Block Cipher functions related to creating expanded keys. For further information please see symcrypt.h for more info
//!
//! This module provides a way to create and use Block Ciphers. Currently only AES is supported.
//! Once an ExpandedKey is created you are able to call Encrypt or Decrypt functions depending on your desired mode
//!
//! # Examples
//!
//! ## AES Expanded Key Creation
//! ```rust
//!
//! use symcrypt::cipher::AesExpandedKey;
//! use hex::*;
//!
//! let key = hex::decode("5d98398b5e3b98d87e07ecf1332df4ac").unwrap();
//! let aes_key = AesExpandedKey::new(&key).unwrap();
//!
//! ```
//!
use crate::errors::SymCryptError;
use crate::symcrypt_init;
use symcrypt_sys;

use std::marker::PhantomPinned;
use std::pin::Pin;

// export ciphers
pub mod cbc;

/// 16
pub const AES_BLOCK_SIZE: u32 = symcrypt_sys::SYMCRYPT_AES_BLOCK_SIZE;

/// `BlockCipherType` is an enum that enumerates all possible block ciphers that are supported.
/// Currently the only supported type is `AesBlock`.
pub enum BlockCipherType {
    AesBlock,
}
struct AesInnerKey {
    inner: symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY,
    _pinned: PhantomPinned,
}

impl AesInnerKey {
    pub(crate) fn new() -> Pin<Box<Self>> {
        Box::pin(AesInnerKey {
            inner: symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        })
    }

    pub(crate) fn get_inner_mut(
        self: Pin<&mut Self>,
    ) -> *mut symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data.
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    pub(crate) fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY {
        &self.inner as *const _
    }
}

/// `AesExpandedKey` is a struct that represents an expanded AES key. This struct holds no state and is used to encrypt and decrypt data.
pub struct AesExpandedKey {
    // Owned expanded key, this has no state, other calls will take reference to this key.
    expanded_key: Pin<Box<AesInnerKey>>,
}

impl AesExpandedKey {
    /// `new()` returns an `AesExpandedKey` or a [`SymCryptError`] if the operation fails.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut expanded_key = AesInnerKey::new();

        unsafe {
            // SAFETY: FFI call
            match symcrypt_sys::SymCryptAesExpandKey(
                expanded_key.as_mut().get_inner_mut(),
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(AesExpandedKey {
                    expanded_key,
                }),
                err => Err(err.into()),
            }
        }
    }

    pub fn get_block_size() -> u32 {
        AES_BLOCK_SIZE
    }
}

// No custom Send / Sync impl. needed for AesInnerKey and AesExpandedKey and BlockCipherType since the 
// underlying data is a pointer to a SymCrypt struct that is not modified after it is created.
unsafe impl Send for AesInnerKey {}
unsafe impl Sync for AesInnerKey {}
unsafe impl Send for AesExpandedKey {}
unsafe impl Sync for AesExpandedKey {}
unsafe impl Send for BlockCipherType {}
unsafe impl Sync for BlockCipherType {}

pub(crate) fn convert_cipher(cipher: BlockCipherType) -> symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER {
    match cipher {
        // SAFETY: FFI calls
        BlockCipherType::AesBlock => unsafe { symcrypt_sys::SymCryptAesBlockCipher },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes_expanded_key_creation_valid_key() {
        let key_hex = "00112233445566778899aabbccddeeff";
        let key = hex::decode(key_hex).unwrap();

        let result = AesExpandedKey::new(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_aes_expanded_key_creation_invalid_key() {
        let key = vec![0u8; 10]; // Invalid length for AES key

        let result = AesExpandedKey::new(&key);
        assert!(
            matches!(result, Err(SymCryptError::WrongKeySize)),
            "Expected WrongKeySize error"
        );
    }

    #[test]
    fn test_get_block_size() {
        assert_eq!(AesExpandedKey::get_block_size(), AES_BLOCK_SIZE);
    }
}
