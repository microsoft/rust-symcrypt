//! XTS-AES-256 (NIST SP 800-38E) functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Encrypt in place
//!
//! ```rust
//! use symcrypt::cipher::xts::XtsAes256Key;
//!
//! // Set up input. Two AES-256 keys concatenated; per FIPS the halves must be unequal.
//! let key = hex::decode("\
//!     2718281828459045235360287471352662497757247093699959574966967627\
//!     3141592653589793238462643383279502884197169399375105820974944592"
//! ).unwrap();
//!
//! let mut buffer = [0u8; 32];
//! hex::decode_to_slice(
//!     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
//!     &mut buffer,
//! ).unwrap();
//! let plaintext = buffer;
//!
//! // Perform encryption in place with data_unit_size = 32 and tweak = 0xff.
//! let xts = XtsAes256Key::new(&key).unwrap();
//! xts.encrypt_in_place(32, 0xff, &mut buffer).unwrap();
//!
//! ```
//!
//! ## Decrypt in place
//! ```rust
//! use symcrypt::cipher::xts::XtsAes256Key;
//!
//! // Set up input
//! let key = hex::decode("\
//!     2718281828459045235360287471352662497757247093699959574966967627\
//!     3141592653589793238462643383279502884197169399375105820974944592"
//! ).unwrap();
//! let expected_result = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
//!
//! // Produce a ciphertext by encrypting the expected plaintext under the same
//! // (data_unit_size, tweak) so we have something to decrypt.
//! let mut buffer = [0u8; 32];
//! hex::decode_to_slice(expected_result, &mut buffer).unwrap();
//! let xts = XtsAes256Key::new(&key).unwrap();
//! xts.encrypt_in_place(32, 0xff, &mut buffer).unwrap();
//!
//! // Perform the decryption in place
//! xts.decrypt_in_place(32, 0xff, &mut buffer).unwrap();
//! assert_eq!(hex::encode(buffer), expected_result);
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
/// fixed address for its lifetime.
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

    /// Provides a mutable pointer to the inner SymCrypt state.
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// The pointer returned is pinned and cannot be moved
    /// This function returns pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_XTS_AES_EXPANDED_KEY {
        // SAFETY: Accessing the inner state of the pinned data
        unsafe { &mut self.get_unchecked_mut().inner as *mut _ }
    }

    /// Safe method to access the inner state immutably
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
    /// `key` must be exactly 64 bytes, two AES-256 keys concatenated. The two halves
    /// must be unequal; if they are equal, [`SymCryptError::FipsFailure`] is returned.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        if key.len() != XTS_AES_256_KEY_LEN {
            return Err(SymCryptError::WrongKeySize);
        }
        let mut expanded_key = XtsAes256InnerKey::new();
        unsafe {
            // SAFETY: FFI call.
            match symcrypt_sys::SymCryptXtsAesExpandKeyEx(
                expanded_key.as_mut().get_inner_mut(),
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
                0, // FIPS mode on. Enforces the key-halves-not-equal check.
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(XtsAes256Key { expanded_key }),
                err => Err(err.into()),
            }
        }
    }

    /// `encrypt_in_place` encrypts `buffer` in place using XTS-AES-256 with a 64-bit tweak.
    ///
    /// `data_unit_size` is the size in bytes of each data unit, typically 512.
    /// It must be at least 16 and at most 2^24. `buffer.len()` must be a multiple of `data_unit_size`.
    /// `tweak` is the tweak for the first data unit; it is incremented for each subsequent data unit
    /// in `buffer`.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    pub fn encrypt_in_place(
        &self,
        data_unit_size: u64,
        tweak: u64,
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_xts_args(data_unit_size, buffer.len())?;
        symcrypt_init();
        unsafe {
            // SAFETY: FFI call.
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
    /// `data_unit_size` is the size in bytes of each data unit, typically 512.
    /// It must be at least 16 and at most 2^24. `buffer.len()` must be a multiple of `data_unit_size`.
    /// `tweak` is the tweak for the first data unit; it is incremented for each subsequent data unit
    /// in `buffer`.
    ///
    /// `buffer` is a `&mut [u8]` that contains the cipher text data to be decrypted. After the decryption has been completed,
    /// `buffer` will be over-written to contain the plain text data.
    pub fn decrypt_in_place(
        &self,
        data_unit_size: u64,
        tweak: u64,
        buffer: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_xts_args(data_unit_size, buffer.len())?;
        symcrypt_init();
        unsafe {
            // SAFETY: FFI call.
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

// No custom Send / Sync impl. needed for XtsAes256Key since the
// underlying data is a pointer to a SymCrypt struct that is not modified after it is created.
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

    const KEY_HEX: &str = "\
        2718281828459045235360287471352662497757247093699959574966967627\
        3141592653589793238462643383279502884197169399375105820974944592";

    const KAT_PLAINTEXT_HEX: &str = "\
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f\
        303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f\
        909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
        f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\
        505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    const KAT_CIPHERTEXT_HEX: &str = "\
        1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44\
        680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0\
        c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7d\
        e8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f\
        93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6\
        dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1\
        505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b\
        11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac\
        6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493\
        c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa\
        773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";

    #[test]
    fn test_xts_aes_256_kat_ieee_1619_tweak_0xff() {
        let key = hex::decode(KEY_HEX).unwrap();
        let plaintext = hex::decode(KAT_PLAINTEXT_HEX).unwrap();
        let expected_ciphertext = hex::decode(KAT_CIPHERTEXT_HEX).unwrap();
        assert_eq!(plaintext.len(), 512);
        assert_eq!(expected_ciphertext.len(), 512);

        let xts = XtsAes256Key::new(&key).unwrap();

        let mut buffer = plaintext.clone();
        xts.encrypt_in_place(512, 0xff, &mut buffer).unwrap();
        assert_eq!(buffer, expected_ciphertext);

        xts.decrypt_in_place(512, 0xff, &mut buffer).unwrap();
        assert_eq!(buffer, plaintext);
    }

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
        // Two equal halves. FIPS check rejects this.
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
