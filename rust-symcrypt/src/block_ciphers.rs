//! Friendly rust types for BlockCipherTypes. Currently the only supported BlockCipherType is Aes.

use symcrypt_sys;

/// `BlockCipherType` is an enum that enumerates all possible block ciphers that are supported.
/// Currently the only supported type is `AesBlock`.
pub enum BlockCipherType {
    AesBlock,
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
