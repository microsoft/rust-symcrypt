//! Friendly rust types for BlockCipherTypes. Currently the only supported BlockCipherType is Aes.

use symcrypt_sys;
use crate::errors::SymCryptError;
use crate::symcrypt_init;


// export cipher modes
pub mod gcm;
pub mod chacha;
pub mod cbc;

/// 16
pub const AES_BLOCK_SIZE: u32 = 16;

/// `BlockCipherType` is an enum that enumerates all possible block ciphers that are supported.
/// Currently the only supported type is `AesBlock`.
pub enum BlockCipherType {
    AesBlock,
}

/// `AesExpandedKey` is a struct that represents an expanded AES key. This struct holds no state and is used to encrypt and decrypt data.
pub struct AesExpandedKey {
    // Owned expanded key, this has no state, other calls will take reference to this key. 
    pub(crate) expanded_key: Arc<Pin<Box<AesInnerKey>>,
}

struct AesInnerKey { 
    inner: symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY,
    _pinned: PhantomPinned,
}

impl AesExpandedKey {
    pub fn new(key: &[u8]) -> Result<Self,SymCryptError>  {
        symcrypt_init();
        let mut expanded_key = symcrypt_sys::SYMCRYPT_AES_EXPANDED_KEY::default();
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptAesExpandKey(
                &mut expanded_key,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR =>  Ok(AesExpandedKey{expanded_key}),
                err => Err(err.into()),
            }
        }
    }
}

// symcrypt_init();
// let mut instance = Md5State(Box::pin(Md5InnerState {
//     inner: symcrypt_sys::SYMCRYPT_MD5_STATE::default(),
//     _pinned: PhantomPinned,
// }));
// unsafe {
//     // SAFETY: FFI calls
//     symcrypt_sys::SymCryptMd5Init(instance.get_inner_mut());
// }

// impl Default for _SYMCRYPT_AES_EXPANDED_KEY {
//     fn default() -> Self {
//         let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
//         unsafe {
//             ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
//             s.assume_init()
//         }
//     }
// }
// pub type SYMCRYPT_AES_EXPANDED_KEY = _SYMCRYPT_AES_EXPANDED_KEY;
// pub type PSYMCRYPT_AES_EXPANDED_KEY = *mut _SYMCRYPT_AES_EXPANDED_KEY;
// pub type PCSYMCRYPT_AES_EXPANDED_KEY = *const SYMCRYPT_AES_EXPANDED_KEY;

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
