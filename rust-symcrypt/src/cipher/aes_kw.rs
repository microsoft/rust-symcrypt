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
//! The plaintext recovered by [`AesKwKey::decrypt`] and [`AesKwpKey::decrypt`] is returned in a
//! plain [`Vec<u8>`]. The recovered bytes are sensitive key material, and it is the caller's
//! responsibility to wipe the buffer (for example with [`zeroize`](https://crates.io/crates/zeroize))
//! when it is no longer needed; simply dropping the `Vec` does **not** clear its memory.
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

use crate::cipher::{expand_aes_key, AesInnerKey};
use crate::errors::SymCryptError;
use std::pin::Pin;
use symcrypt_sys;

const KW_SEMIBLOCK: usize = 8;

/// Computes the AES-KW encrypt output buffer length: `plaintext_len + KW_SEMIBLOCK`.
/// Returns `InvalidArgument` if the addition would overflow `usize`.
#[inline]
fn kw_encrypt_buffer_len(plaintext_len: usize) -> Result<usize, SymCryptError> {
    plaintext_len
        .checked_add(KW_SEMIBLOCK)
        .ok_or(SymCryptError::InvalidArgument)
}

/// Computes the AES-KWP encrypt output buffer length:
/// `plaintext_len.next_multiple_of(KW_SEMIBLOCK) + KW_SEMIBLOCK`.
/// Returns `InvalidArgument` if either operation would overflow `usize`.
#[inline]
fn kwp_encrypt_buffer_len(plaintext_len: usize) -> Result<usize, SymCryptError> {
    let padded = plaintext_len
        .checked_next_multiple_of(KW_SEMIBLOCK)
        .ok_or(SymCryptError::InvalidArgument)?;
    padded
        .checked_add(KW_SEMIBLOCK)
        .ok_or(SymCryptError::InvalidArgument)
}

/// [`AesKwKey`] wraps an expanded AES key for use with AES-KW.
pub struct AesKwKey {
    expanded_key: Pin<Box<AesInnerKey>>,
}

/// [`AesKwpKey`] wraps an expanded AES key for use with AES-KWP.
pub struct AesKwpKey {
    expanded_key: Pin<Box<AesInnerKey>>,
}

impl AesKwKey {
    /// `new()` returns an [`AesKwKey`] or a [`SymCryptError`] if the key is the wrong size.
    /// Accepted key sizes are 16, 24, or 32 bytes (AES-128/192/256).
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        Ok(AesKwKey {
            expanded_key: expand_aes_key(key)?,
        })
    }

    /// `encrypt()` wraps `plaintext` using AES-KW and returns the ciphertext.
    ///
    /// `plaintext.len()` must be a multiple of 8 and at least 16. The returned `Vec` has length
    /// `plaintext.len() + 8`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        // Use checked_add so inputs cannot wrap and produce an undersized output buffer.
        let ct_len = kw_encrypt_buffer_len(plaintext.len())?;
        let mut ciphertext = vec![0u8; ct_len];
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
    ///
    /// The returned `Vec<u8>` holds sensitive key material. Dropping it does **not** wipe the
    /// underlying memory; callers should explicitly zero the buffer (e.g. with the
    /// [`zeroize`](https://crates.io/crates/zeroize) crate) once it is no longer needed.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        // SymCrypt's SymCryptAesKwDecrypt writes exactly `ciphertext.len() - 8` bytes on
        // success and requires `cbDst >= cbSrc - 8`.
        let mut plaintext = vec![0u8; ciphertext.len().saturating_sub(KW_SEMIBLOCK)];
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
        Ok(AesKwpKey {
            expanded_key: expand_aes_key(key)?,
        })
    }

    /// `encrypt()` wraps `plaintext` (any non-zero length) using AES-KWP and returns the ciphertext.
    ///
    /// The output length is `plaintext.len().next_multiple_of(8) + 8`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        // Use checked_add so inputs cannot wrap and produce an undersized output buffer.
        let ct_len = kwp_encrypt_buffer_len(plaintext.len())?;
        let mut ciphertext = vec![0u8; ct_len];
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
    ///
    /// The returned `Vec<u8>` holds sensitive key material. Dropping it does **not** wipe the
    /// underlying memory; callers should explicitly zero the buffer (e.g. with the
    /// [`zeroize`](https://crates.io/crates/zeroize) crate) once it is no longer needed.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        // SymCrypt's SymCryptAesKwpDecrypt requires `cbDst >= cbSrc - 15`, and the actual
        // plaintext length is always `<= cbSrc - 8`. Allocate that upper bound; the buffer
        // is truncated to the real plaintext length on success.
        let mut plaintext = vec![0u8; ciphertext.len().saturating_sub(KW_SEMIBLOCK)];
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

    const KW_KEY_HEX: &str = "ABF3A659F6D4AF5EAB250BF05A0B623C";
    const KW_PT_HEX: &str = "6B95ECAA3C712FACF175DD06FF88704A";
    const KW_CT_HEX: &str = "7AD5368CC43D2EF691B666CE24C4B52DCEB1442A53EA1A16";

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
        assert_eq!(kw.encrypt(&pt).unwrap_err(), SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_aes_kw_plaintext_not_multiple_of_8() {
        let key = vec![0u8; 16];
        let pt = vec![0u8; 17];
        let kw = AesKwKey::new(&key).unwrap();
        assert_eq!(kw.encrypt(&pt).unwrap_err(), SymCryptError::InvalidArgument);
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
        assert_eq!(
            kwp.encrypt(&[]).unwrap_err(),
            SymCryptError::InvalidArgument
        );
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

    // -------- output buffer sizing helpers --------

    #[test]
    fn test_kw_encrypt_buffer_len_basic() {
        assert_eq!(kw_encrypt_buffer_len(0).unwrap(), 8);
        assert_eq!(kw_encrypt_buffer_len(16).unwrap(), 24);
        assert_eq!(kw_encrypt_buffer_len(4096).unwrap(), 4104);
    }

    #[test]
    fn test_kw_encrypt_buffer_len_overflow() {
        // usize::MAX - 7 + 8 wraps; usize::MAX + 8 wraps.
        for len in [usize::MAX - 7, usize::MAX - 1, usize::MAX] {
            assert_eq!(
                kw_encrypt_buffer_len(len).unwrap_err(),
                SymCryptError::InvalidArgument,
                "len={}",
                len
            );
        }
    }

    #[test]
    fn test_kwp_encrypt_buffer_len_basic() {
        assert_eq!(kwp_encrypt_buffer_len(1).unwrap(), 16);
        assert_eq!(kwp_encrypt_buffer_len(8).unwrap(), 16);
        assert_eq!(kwp_encrypt_buffer_len(9).unwrap(), 24);
        assert_eq!(kwp_encrypt_buffer_len(100).unwrap(), 112);
    }

    #[test]
    fn test_kwp_encrypt_buffer_len_overflow() {
        // next_multiple_of(8) overflows for any len in (usize::MAX - 7 ..= usize::MAX) that
        // isn't already a multiple of 8.
        for len in [usize::MAX, usize::MAX - 1, usize::MAX - 7] {
            assert_eq!(
                kwp_encrypt_buffer_len(len).unwrap_err(),
                SymCryptError::InvalidArgument,
                "len={}",
                len
            );
        }
    }

    // -------- decrypt output buffer trimming --------

    #[test]
    fn test_aes_kw_decrypt_buffer_len_is_trimmed() {
        let key = vec![0xA5u8; 32];
        let pt = vec![0x11u8; 32];
        let kw = AesKwKey::new(&key).unwrap();
        let ct = kw.encrypt(&pt).unwrap();
        let recovered = kw.decrypt(&ct).unwrap();
        // KW always produces exactly cbSrc - 8 bytes of plaintext.
        assert_eq!(recovered.len(), ct.len() - KW_SEMIBLOCK);
    }

    #[test]
    fn test_aes_kwp_decrypt_buffer_len_is_at_most_ct_minus_8() {
        let key = vec![0x5Au8; 32];
        let kwp = AesKwpKey::new(&key).unwrap();
        for len in [1usize, 7, 8, 9, 15, 16, 17, 100] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = kwp.encrypt(&pt).unwrap();
            let recovered = kwp.decrypt(&ct).unwrap();
            // KWP plaintext is always <= cbSrc - 8.
            assert!(
                recovered.len() <= ct.len() - KW_SEMIBLOCK,
                "len={}: recovered.len() = {}, ct.len() - 8 = {}",
                len,
                recovered.len(),
                ct.len() - KW_SEMIBLOCK
            );
            assert_eq!(recovered.len(), pt.len(), "len={}", len);
        }
    }
}
