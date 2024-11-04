//! HKDF functions. For more info please refer to symcrypt.h
//!
//! # Example
//!
//! ## Hkdf with Sha256 and with no salt or info
//!
//!  ```rust
//! use symcrypt::hkdf::hkdf;
//! use symcrypt::hmac::HmacAlgorithm;
//! use hex::*;
//!
//! // Setup initial keying material (IKM)
//! let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//! let hmac_algorithm = HmacAlgorithm::HmacSha256;
//!    
//! let expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
//! let res = hkdf(hmac_algorithm, &key_material, &[], &[], 42).unwrap();
//! assert_eq!(res.len(), 42);
//! assert_eq!(expected, hex::encode(res));
//! ```
//!
//! ## Hkdf with Sha384 and with salt and info
//!
//! ```rust
//! use symcrypt::hkdf::hkdf;
//! use symcrypt::hmac::HmacAlgorithm;
//! use hex::*;
//!
//! // Setup initial keying material (IKM)
//! let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//! let salt = hex::decode("000102030405060708090a0b0c").unwrap();
//! let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
//! let hmac_algorithm = HmacAlgorithm::HmacSha384;
//!
//! let expected = "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5";
//! let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
//! assert_eq!(res.len(), 42);
//! assert_eq!(expected, hex::encode(res));
//! ```
//!
use crate::errors::SymCryptError;
use crate::hmac::HmacAlgorithm;
use symcrypt_sys;

/// `hkdf()` derives a key using the HKDF algorithm and returns a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
///
/// `hmac_algorithm` is an [`HmacAlgorithm`] that represents the HMAC algorithm to use.
///
/// `key_material` is a `&[u8]` that represents the initial keying material (IKM), which is the primary source input for HKDF.
///
/// `salt` is a `&[u8]` that represents an optional, random value used to enhance security during the extraction phase. If you do not
/// wish to use a salt, you can pass an empty slice.
///
/// `info` is a `&[u8]` that represents an optional application-specific context that customizes the derived key. If you do not
/// wish to use a salt, you can pass an empty slice.
///
/// `output_key_size` is an `u64` that represents the desired length of the derived key in bytes, the `Vec<u8>` returned will be of this length.
pub fn hkdf(
    hmac_algorithm: HmacAlgorithm,
    key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_key_size: u64,
) -> Result<Vec<u8>, SymCryptError> {
    let mut hmac_res = vec![0u8; output_key_size as usize];
    unsafe {
        // UNSAFE: FFI calls
        match symcrypt_sys::SymCryptHkdf(
            hmac_algorithm.to_symcrypt_hmac_algorithm(),
            key_material.as_ptr(),
            key_material.len() as symcrypt_sys::SIZE_T,
            salt.as_ptr(),
            salt.len() as symcrypt_sys::SIZE_T,
            info.as_ptr(),
            info.len() as symcrypt_sys::SIZE_T,
            hmac_res.as_mut_ptr(),
            hmac_res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(hmac_res),
            err => return Err(SymCryptError::from(err)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    #[test]
    fn test_hkdf_256() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha256;

        let expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }

    #[test]
    fn test_hkdf_256_very_small_output_key_size() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha256;

        let expected = "3cb25f25faac";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 6).unwrap();
        assert_eq!(res.len(), 6);
        assert_eq!(expected, hex::encode(res));
    }

    #[test]
    fn test_hkdf_sha256_long() {
        let key_material = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha256;

        let expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 82).unwrap();
        assert_eq!(res.len(), 82);
        assert_eq!(expected, hex::encode(res));
    }

    #[test]
    fn test_hkdf_sha256_no_salt_no_info() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha256;

        let expected =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
        let res = hkdf(hmac_algorithm, &key_material, &[], &[], 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }

    #[test]
    fn test_hkdf_sha384() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha384;

        let expected =
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }

    #[test]
    fn test_hkdf_sha512() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha512;

        let expected =
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_hkdf_sha1() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha1;

        let expected =
            "d6000ffb5b50bd3970b260017798fb9c8df9ce2e2c16b6cd709cca07dc3cf9cf26d6c6d750d0aaf5ac94";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }

    #[cfg(feature = "md5")]
    #[test]
    fn test_hkdf_md5() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacMd5;

        let expected =
            "b222c9db38d17b2fea8b3bb511c0d6d86049ef481ba7065ca5c6422618ed9cc9144900e2c72b6a863a31";
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info, 42).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }
}
