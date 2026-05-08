//! XTS-AES-256 (NIST SP 800-38E) functions. For further documentation please refer to symcrypt.h
//!
//! XTS-AES is the IEEE 1619 / SP 800-38E disk-encryption mode. It operates on equal-sized
//! "data units" (typically a 512-byte sector), with each unit deterministically encrypted using a
//! 64-bit tweak that is incremented for every subsequent unit in a contiguous run.
//!
//! Only XTS-AES-256 is exposed here: the key passed to [`XtsAes256Key::new`] must be exactly
//! 64 bytes (two AES-256 keys concatenated).
//!
//! # Example
//!
//! ```rust
//! use symcrypt::xts::XtsAes256Key;
//!
//! // Two AES-256 keys concatenated. Per FIPS, the two halves must be unequal.
//! let key = hex::decode("\
//!     2718281828459045235360287471352662497757247093699959574966967627\
//!     3141592653589793238462643383279502884197169399375105820974944592"
//! ).unwrap();
//!
//! let xts = XtsAes256Key::new(&key).unwrap();
//!
//! // Encrypt a single 32-byte data unit in place using tweak = 0.
//! let mut buffer = [0u8; 32];
//! xts.encrypt_in_place(32, 0, &mut buffer).unwrap();
//!
//! // Round-trip back to the original.
//! xts.decrypt_in_place(32, 0, &mut buffer).unwrap();
//! assert_eq!(buffer, [0u8; 32]);
//! ```

use crate::errors::SymCryptError;
use crate::symcrypt_init;
use core::ffi::c_void;
use std::marker::PhantomPinned;
use std::mem;
use std::pin::Pin;
use std::ptr;
use symcrypt_sys;

const XTS_AES_256_KEY_LEN: usize = 64;
const XTS_DATA_UNIT_MIN: u64 = 16;
const XTS_DATA_UNIT_MAX: u64 = 1 << 24;

/// [`XtsAes256Key`] holds the expanded XTS-AES-256 key from SymCrypt.
///
/// The expanded key is `Pin<Box<>>`'d because SymCrypt requires the underlying state to remain at a
/// fixed address for its lifetime — moving it (e.g. via `memcpy`) would invalidate internal pointers.
pub struct XtsAes256Key {
    expanded_key: Pin<Box<XtsAes256InnerKey>>,
}

/// [`XtsAes256InnerKey`] wraps the raw SymCrypt XTS expanded key.
struct XtsAes256InnerKey {
    inner: symcrypt_sys::SYMCRYPT_XTS_AES_EXPANDED_KEY,
    _pinned: PhantomPinned,
}

impl XtsAes256InnerKey {
    fn new() -> Pin<Box<Self>> {
        Box::pin(XtsAes256InnerKey {
            inner: symcrypt_sys::SYMCRYPT_XTS_AES_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        })
    }

    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_XTS_AES_EXPANDED_KEY {
        // SAFETY: Accessing the inner state of the pinned data; the pointer must not be used to move out of self.
        unsafe { &mut self.get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_XTS_AES_EXPANDED_KEY {
        &self.inner as *const _
    }
}

impl Drop for XtsAes256InnerKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner) as *mut c_void,
                mem::size_of_val(&self.inner) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

impl XtsAes256Key {
    /// `new()` returns a new [`XtsAes256Key`] or a [`SymCryptError`] if the operation fails.
    ///
    /// `key` must be exactly 64 bytes — two AES-256 keys concatenated. Per FIPS, the two halves
    /// must be unequal; if they are equal, [`SymCryptError::FipsFailure`] is returned.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        if key.len() != XTS_AES_256_KEY_LEN {
            return Err(SymCryptError::WrongKeySize);
        }
        let mut expanded_key = XtsAes256InnerKey::new();
        unsafe {
            // SAFETY: FFI call. Passing flags = 0 selects the FIPS-approved path
            // (the equality check on the two key halves).
            match symcrypt_sys::SymCryptXtsAesExpandKeyEx(
                expanded_key.as_mut().get_inner_mut(),
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
                0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(XtsAes256Key { expanded_key }),
                err => Err(err.into()),
            }
        }
    }

    /// `encrypt_in_place` encrypts `buffer` in place using XTS-AES-256 with a 64-bit tweak.
    ///
    /// `data_unit_size` is the size in bytes of each data unit (typically 512 for disk sectors);
    /// it must be at least 16 and at most 2^24. `buffer.len()` must be a multiple of `data_unit_size`.
    /// `tweak` is the tweak for the first data unit; it is incremented for each subsequent data unit
    /// in `buffer`.
    pub fn encrypt_in_place(
        &self,
        data_unit_size: u64,
        tweak: u64,
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_xts_args(data_unit_size, buffer.len())?;
        symcrypt_init();
        unsafe {
            // SAFETY: FFI call. The src and dst pointers are allowed to alias per
            // SymCryptXtsAesEncrypt's contract — this is the in-place case.
            symcrypt_sys::SymCryptXtsAesEncrypt(
                self.expanded_key.get_inner(),
                data_unit_size as symcrypt_sys::SIZE_T,
                tweak as symcrypt_sys::UINT64,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }

    /// `decrypt_in_place` decrypts `buffer` in place using XTS-AES-256 with a 64-bit tweak.
    ///
    /// `data_unit_size`, `tweak`, and `buffer` follow the same contract as [`Self::encrypt_in_place`].
    pub fn decrypt_in_place(
        &self,
        data_unit_size: u64,
        tweak: u64,
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_xts_args(data_unit_size, buffer.len())?;
        symcrypt_init();
        unsafe {
            // SAFETY: FFI call; in-place decryption (src == dst is allowed).
            symcrypt_sys::SymCryptXtsAesDecrypt(
                self.expanded_key.get_inner(),
                data_unit_size as symcrypt_sys::SIZE_T,
                tweak as symcrypt_sys::UINT64,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }
}

// No custom Send / Sync impl needed beyond marking the wrapper types — the underlying SymCrypt
// state is an opaque struct that is not modified after key expansion.
unsafe impl Send for XtsAes256Key {}
unsafe impl Sync for XtsAes256Key {}

fn validate_xts_args(data_unit_size: u64, data_len: usize) -> Result<(), SymCryptError> {
    if !(XTS_DATA_UNIT_MIN..=XTS_DATA_UNIT_MAX).contains(&data_unit_size) {
        return Err(SymCryptError::InvalidArgument);
    }
    if (data_len as u64) % data_unit_size != 0 {
        return Err(SymCryptError::WrongDataSize);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    // Two AES-256 keys (e and pi as 32-byte big-endian decimals). Keys are unequal so the FIPS
    // check passes.
    const KEY_HEX: &str = "\
        2718281828459045235360287471352662497757247093699959574966967627\
        3141592653589793238462643383279502884197169399375105820974944592";

    #[test]
    fn test_xts_aes_256_round_trip_single_unit() {
        let key = hex::decode(KEY_HEX).unwrap();
        let xts = XtsAes256Key::new(&key).unwrap();

        let original: Vec<u8> = (0..64u8).collect();
        let mut buffer = original.clone();

        xts.encrypt_in_place(64, 0xff, &mut buffer).unwrap();
        assert_ne!(buffer, original);

        xts.decrypt_in_place(64, 0xff, &mut buffer).unwrap();
        assert_eq!(buffer, original);
    }

    #[test]
    fn test_xts_aes_256_round_trip_multiple_units() {
        let key = hex::decode(KEY_HEX).unwrap();
        let xts = XtsAes256Key::new(&key).unwrap();

        let original: Vec<u8> = (0..=255u8).collect(); // 256 bytes
        let mut buffer = original.clone();

        xts.encrypt_in_place(64, 0, &mut buffer).unwrap();
        xts.decrypt_in_place(64, 0, &mut buffer).unwrap();
        assert_eq!(buffer, original);
    }

    #[test]
    fn test_xts_aes_256_different_tweaks_produce_different_ciphertext() {
        let key = hex::decode(KEY_HEX).unwrap();
        let xts = XtsAes256Key::new(&key).unwrap();

        let plaintext: Vec<u8> = (0..64u8).collect();
        let mut a = plaintext.clone();
        let mut b = plaintext.clone();

        xts.encrypt_in_place(64, 0, &mut a).unwrap();
        xts.encrypt_in_place(64, 1, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_xts_aes_256_wrong_key_size() {
        let key = vec![0u8; 32]; // XTS-AES-128 length, not allowed here
        match XtsAes256Key::new(&key) {
            Ok(_) => panic!("expected WrongKeySize"),
            Err(err) => assert_eq!(err, SymCryptError::WrongKeySize),
        }
    }

    #[test]
    fn test_xts_aes_256_equal_key_halves_fail_fips() {
        let mut key = vec![0u8; 64];
        // Two equal halves — FIPS check rejects this.
        for i in 0..32 {
            key[i] = i as u8;
            key[i + 32] = i as u8;
        }
        match XtsAes256Key::new(&key) {
            Ok(_) => panic!("expected FIPS-related failure on equal key halves"),
            Err(err) => assert!(
                matches!(
                    err,
                    SymCryptError::FipsFailure | SymCryptError::InvalidArgument
                ),
                "got {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_xts_aes_256_invalid_data_unit_size() {
        let key = hex::decode(KEY_HEX).unwrap();
        let xts = XtsAes256Key::new(&key).unwrap();
        let mut buffer = [0u8; 64];

        // data_unit_size below 16
        let r = xts.encrypt_in_place(8, 0, &mut buffer);
        assert_eq!(r.unwrap_err(), SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_xts_aes_256_buffer_not_multiple_of_data_unit() {
        let key = hex::decode(KEY_HEX).unwrap();
        let xts = XtsAes256Key::new(&key).unwrap();
        let mut buffer = [0u8; 80]; // 80 is not a multiple of 64

        let r = xts.encrypt_in_place(64, 0, &mut buffer);
        assert_eq!(r.unwrap_err(), SymCryptError::WrongDataSize);
    }
}
