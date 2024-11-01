//! Friendly rust types for BlockCipherTypes. Currently the only supported BlockCipherType is Aes.

use crate::errors::SymCryptError;
use crate::symcrypt_init;
use symcrypt_sys;

use std::marker::PhantomPinned;
use std::pin::Pin;
use std::sync::Arc;

// export cipher modes
pub mod cbc;
pub mod chacha;
pub mod gcm;

/// 16
pub const AES_BLOCK_SIZE: u32 = 16;

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
    pub(crate) expanded_key: Arc<Pin<Box<AesInnerKey>>>,
}

impl Clone for AesExpandedKey {
    fn clone(&self) -> Self {
        AesExpandedKey {
            expanded_key: Arc::clone(&self.expanded_key),
        }
    }
}

impl AesExpandedKey {
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
                    expanded_key: Arc::new(expanded_key),
                }),
                err => Err(err.into()),
            }
        }
    }
    
    pub fn get_block_size() -> u32 {
        AES_BLOCK_SIZE
    }
}

pub(crate) fn validate_block_size(
    plain_text: &[u8],
    cipher_text: &[u8],
) -> Result<(), SymCryptError> {
    if plain_text.len() != cipher_text.len() {
        return Err(SymCryptError::WrongDataSize);
    }

    // length of plain_text and cipher_text must be equal at this point.
    if plain_text.len() % AES_BLOCK_SIZE as usize != 0 {
        return Err(SymCryptError::WrongBlockSize);
    }

    Ok(())
}

unsafe impl Send for BlockCipherType {
    // TODO: discuss send/sync implementation for rustls.
}

unsafe impl Sync for BlockCipherType {
    // TODO: discuss send/sync implementation for rustls.
}

pub(crate) fn convert_cipher(cipher: BlockCipherType) -> symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER {
    match cipher {
        // SAFETY: FFI calls
        BlockCipherType::AesBlock => unsafe { symcrypt_sys::SymCryptAesBlockCipher },
    }
}
