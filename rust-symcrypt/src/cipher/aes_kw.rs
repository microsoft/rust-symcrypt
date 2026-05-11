//! AES Key Wrap (KW) and AES Key Wrap with Padding (KWP). See symcrypt.h for more info.
//!
//! - **AES-KW**: wraps plaintext whose length is a multiple of 8 bytes and at least 16
//!   bytes. The output is always plaintext length + 8 bytes.
//! - **AES-KWP**: wraps plaintext of any non-zero length. Output is rounded up to the
//!   next multiple of 8 bytes plus 8 bytes for the integrity check value.
//!
//! The wrapping key passed to either constructor must be a valid AES key length: 16, 24, or 32
//! bytes. The wrapping key is independent of which mode is used.
//!
//! AES-KW(P) is significantly slower than other AES modes, use of this cipher is not recommended.
//!
//! # Examples
//!
//! ## AES-KW
//! ```rust
//! use symcrypt::cipher::aes_kw::AesKwKey;
//!
//! let wrapping_key = hex::decode("ABF3A659F6D4AF5EAB250BF05A0B623C").unwrap();
//! let plaintext = hex::decode("6B95ECAA3C712FACF175DD06FF88704A").unwrap();
//!
//! let kw = AesKwKey::new(&wrapping_key).unwrap();
//! let ciphertext = kw.encrypt(&plaintext).unwrap();
//! let recovered = kw.decrypt(&ciphertext).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## AES-KWP
//! ```rust
//! use symcrypt::cipher::aes_kw::AesKwpKey;
//!
//! let wrapping_key = hex::decode("A19C08545013B997639E7D4C227324AC").unwrap();
//! let plaintext = hex::decode("25").unwrap(); // arbitrary length, even 1 byte
//!
//! let kwp = AesKwpKey::new(&wrapping_key).unwrap();
//! let ciphertext = kwp.encrypt(&plaintext).unwrap();
//! let recovered = kwp.decrypt(&ciphertext).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```

use crate::cipher::AesInnerKey;
use crate::errors::SymCryptError;
use crate::symcrypt_init;
use std::pin::Pin;
use symcrypt_sys;

const KW_SEMIBLOCK: usize = 8;
const KW_MIN_PLAINTEXT_LEN: usize = 16;

/// [`AesKwKey`] wraps an expanded AES key for use with AES-KW.
pub struct AesKwKey {
    expanded_key: Pin<Box<AesInnerKey>>,
}

/// [`AesKwpKey`] wraps an expanded AES key for use with AES-KWP.
pub struct AesKwpKey {
    expanded_key: Pin<Box<AesInnerKey>>,
}

fn expand_aes_key(key: &[u8]) -> Result<Pin<Box<AesInnerKey>>, SymCryptError> {
    let mut expanded_key = AesInnerKey::new();
    unsafe {
        // SAFETY: FFI call. Returns WrongKeySize for non-AES key lengths.
        match symcrypt_sys::SymCryptAesExpandKey(
            expanded_key.as_mut().get_inner_mut(),
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
            err => Err(err.into()),
        }
    }
}

impl AesKwKey {
    /// `new()` returns an [`AesKwKey`] or a [`SymCryptError`] if the key is the wrong size.
    /// Accepted key sizes are 16, 24, or 32 bytes (AES-128/192/256).
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = expand_aes_key(key)?;
        Ok(AesKwKey { expanded_key })
    }

    /// `encrypt()` wraps `plaintext` using AES-KW and returns the ciphertext.
    ///
    /// `plaintext.len()` must be a multiple of 8 and at least 16. The returned `Vec` has length
    /// `plaintext.len() + 8`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        symcrypt_init();
        if plaintext.len() < KW_MIN_PLAINTEXT_LEN || plaintext.len() % KW_SEMIBLOCK != 0 {
            return Err(SymCryptError::WrongDataSize);
        }
        let mut ciphertext = vec![0u8; plaintext.len() + KW_SEMIBLOCK];
        let mut written: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call.
            match symcrypt_sys::SymCryptAesKwEncrypt(
                self.expanded_key.get_inner(),
                plaintext.as_ptr(),
                plaintext.len() as symcrypt_sys::SIZE_T,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
                &mut written,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    ciphertext.truncate(written as usize);
                    Ok(ciphertext)
                }
                err => Err(err.into()),
            }
        }
    }

    /// `decrypt()` unwraps `ciphertext` using AES-KW and returns the recovered plaintext.
    ///
    /// `ciphertext.len()` must be a multiple of 8 and at least 24. Returns
    /// [`SymCryptError::AuthenticationFailure`] if the integrity check fails.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        symcrypt_init();
        if ciphertext.len() < KW_MIN_PLAINTEXT_LEN + KW_SEMIBLOCK
            || ciphertext.len() % KW_SEMIBLOCK != 0
        {
            return Err(SymCryptError::WrongDataSize);
        }
        let mut plaintext = vec![0u8; ciphertext.len() - KW_SEMIBLOCK];
        let mut written: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call.
            match symcrypt_sys::SymCryptAesKwDecrypt(
                self.expanded_key.get_inner(),
                ciphertext.as_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
                plaintext.as_mut_ptr(),
                plaintext.len() as symcrypt_sys::SIZE_T,
                &mut written,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    plaintext.truncate(written as usize);
                    Ok(plaintext)
                }
                err => Err(err.into()),
            }
        }
    }
}

impl AesKwpKey {
    /// `new()` returns an [`AesKwpKey`] or a [`SymCryptError`] if the key is the wrong size.
    /// Accepted key sizes are 16, 24, or 32 bytes (AES-128/192/256).
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = expand_aes_key(key)?;
        Ok(AesKwpKey { expanded_key })
    }

    /// `encrypt()` wraps `plaintext` (any non-zero length) using AES-KWP and returns the ciphertext.
    ///
    /// The output length is `((plaintext.len() + 7) / 8) * 8 + 8`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        symcrypt_init();
        if plaintext.is_empty() {
            return Err(SymCryptError::WrongDataSize);
        }
        let padded_len = plaintext.len().next_multiple_of(KW_SEMIBLOCK);
        let mut ciphertext = vec![0u8; padded_len + KW_SEMIBLOCK];
        let mut written: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call.
            match symcrypt_sys::SymCryptAesKwpEncrypt(
                self.expanded_key.get_inner(),
                plaintext.as_ptr(),
                plaintext.len() as symcrypt_sys::SIZE_T,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
                &mut written,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    ciphertext.truncate(written as usize);
                    Ok(ciphertext)
                }
                err => Err(err.into()),
            }
        }
    }

    /// `decrypt()` unwraps `ciphertext` using AES-KWP and returns the recovered plaintext.
    ///
    /// `ciphertext.len()` must be a multiple of 8 and at least 16. Returns
    /// [`SymCryptError::AuthenticationFailure`] if the integrity check or padding check fails.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        symcrypt_init();
        if ciphertext.len() < KW_SEMIBLOCK * 2 || ciphertext.len() % KW_SEMIBLOCK != 0 {
            return Err(SymCryptError::WrongDataSize);
        }
        // The header guarantees the plaintext fits in cbSrc - 8 bytes; the actual length comes
        // back via pcbResult, after which we truncate.
        let mut plaintext = vec![0u8; ciphertext.len() - KW_SEMIBLOCK];
        let mut written: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call.
            match symcrypt_sys::SymCryptAesKwpDecrypt(
                self.expanded_key.get_inner(),
                ciphertext.as_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
                plaintext.as_mut_ptr(),
                plaintext.len() as symcrypt_sys::SIZE_T,
                &mut written,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    plaintext.truncate(written as usize);
                    Ok(plaintext)
                }
                err => Err(err.into()),
            }
        }
    }
}

// AesInnerKey carries the SymCrypt opaque state which is immutable after key expansion.
unsafe impl Send for AesKwKey {}
unsafe impl Sync for AesKwKey {}
unsafe impl Send for AesKwpKey {}
unsafe impl Sync for AesKwpKey {}

#[cfg(test)]
mod test {
    use super::*;

    // KAT vector from kat_keywrap.dat (AesKw section, AES-128 wrapping key, 16-byte plaintext).
    const KW_KEY_HEX: &str = "ABF3A659F6D4AF5EAB250BF05A0B623C";
    const KW_PT_HEX: &str = "6B95ECAA3C712FACF175DD06FF88704A";
    const KW_CT_HEX: &str = "7AD5368CC43D2EF691B666CE24C4B52DCEB1442A53EA1A16";

    // KAT vector from kat_keywrap.dat (AesKwp section, AES-128 wrapping key, 1-byte plaintext).
    const KWP_KEY_HEX: &str = "A19C08545013B997639E7D4C227324AC";
    const KWP_PT_HEX: &str = "25";
    const KWP_CT_HEX: &str = "E641A9489F50E6DBF21B29FA995AFCA4";

    // -------- AES-KW --------

    #[test]
    fn test_aes_kw_kat_encrypt() {
        let key = hex::decode(KW_KEY_HEX).unwrap();
        let pt = hex::decode(KW_PT_HEX).unwrap();
        let expected_ct = hex::decode(KW_CT_HEX).unwrap();
        let kw = AesKwKey::new(&key).unwrap();
        let ct = kw.encrypt(&pt).unwrap();
        assert_eq!(ct, expected_ct);
    }

    #[test]
    fn test_aes_kw_kat_decrypt() {
        let key = hex::decode(KW_KEY_HEX).unwrap();
        let ct = hex::decode(KW_CT_HEX).unwrap();
        let expected_pt = hex::decode(KW_PT_HEX).unwrap();
        let kw = AesKwKey::new(&key).unwrap();
        let pt = kw.decrypt(&ct).unwrap();
        assert_eq!(pt, expected_pt);
    }

    #[test]
    fn test_aes_kw_round_trip_aes_256() {
        let key = vec![0xA5u8; 32];
        let pt = vec![0x11u8; 32];
        let kw = AesKwKey::new(&key).unwrap();
        let ct = kw.encrypt(&pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 8);
        let recovered = kw.decrypt(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_aes_kw_wrong_key_size() {
        let key = vec![0u8; 17];
        match AesKwKey::new(&key) {
            Ok(_) => panic!("expected WrongKeySize"),
            Err(err) => assert_eq!(err, SymCryptError::WrongKeySize),
        }
    }

    #[test]
    fn test_aes_kw_plaintext_too_short() {
        let key = vec![0u8; 16];
        let pt = vec![0u8; 8]; // KW requires >=16
        let kw = AesKwKey::new(&key).unwrap();
        assert_eq!(kw.encrypt(&pt).unwrap_err(), SymCryptError::WrongDataSize);
    }

    #[test]
    fn test_aes_kw_plaintext_not_multiple_of_8() {
        let key = vec![0u8; 16];
        let pt = vec![0u8; 17];
        let kw = AesKwKey::new(&key).unwrap();
        assert_eq!(kw.encrypt(&pt).unwrap_err(), SymCryptError::WrongDataSize);
    }

    #[test]
    fn test_aes_kw_decrypt_corrupted_fails() {
        let key = hex::decode(KW_KEY_HEX).unwrap();
        let mut ct = hex::decode(KW_CT_HEX).unwrap();
        ct[0] ^= 0xFF; // corrupt the integrity check
        let kw = AesKwKey::new(&key).unwrap();
        assert_eq!(
            kw.decrypt(&ct).unwrap_err(),
            SymCryptError::AuthenticationFailure
        );
    }

    // -------- AES-KWP --------

    #[test]
    fn test_aes_kwp_kat_encrypt_one_byte() {
        let key = hex::decode(KWP_KEY_HEX).unwrap();
        let pt = hex::decode(KWP_PT_HEX).unwrap();
        let expected_ct = hex::decode(KWP_CT_HEX).unwrap();
        let kwp = AesKwpKey::new(&key).unwrap();
        let ct = kwp.encrypt(&pt).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(ct.len(), 16);
    }

    #[test]
    fn test_aes_kwp_kat_decrypt_one_byte() {
        let key = hex::decode(KWP_KEY_HEX).unwrap();
        let ct = hex::decode(KWP_CT_HEX).unwrap();
        let expected_pt = hex::decode(KWP_PT_HEX).unwrap();
        let kwp = AesKwpKey::new(&key).unwrap();
        let pt = kwp.decrypt(&ct).unwrap();
        assert_eq!(pt, expected_pt);
    }

    #[test]
    fn test_aes_kwp_round_trip_arbitrary_lengths() {
        let key = vec![0x5Au8; 32];
        let kwp = AesKwpKey::new(&key).unwrap();
        for len in [1usize, 7, 8, 9, 15, 16, 17, 31, 33, 100] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = kwp.encrypt(&pt).unwrap();
            // Output is the next multiple-of-8 of plaintext length, plus 8 bytes for the IV.
            let expected_ct_len = pt.len().next_multiple_of(8) + 8;
            assert_eq!(ct.len(), expected_ct_len, "len={}", len);
            let recovered = kwp.decrypt(&ct).unwrap();
            assert_eq!(recovered, pt, "round-trip mismatch at len={}", len);
        }
    }

    #[test]
    fn test_aes_kwp_empty_plaintext_fails() {
        let key = vec![0u8; 16];
        let kwp = AesKwpKey::new(&key).unwrap();
        assert_eq!(kwp.encrypt(&[]).unwrap_err(), SymCryptError::WrongDataSize);
    }

    #[test]
    fn test_aes_kwp_decrypt_corrupted_fails() {
        let key = hex::decode(KWP_KEY_HEX).unwrap();
        let mut ct = hex::decode(KWP_CT_HEX).unwrap();
        ct[0] ^= 0xFF;
        let kwp = AesKwpKey::new(&key).unwrap();
        assert_eq!(
            kwp.decrypt(&ct).unwrap_err(),
            SymCryptError::AuthenticationFailure
        );
    }
}
