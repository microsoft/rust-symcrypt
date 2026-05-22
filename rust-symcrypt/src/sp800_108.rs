//! SP800-108 Counter-Mode KDF functions. For more info please refer to symcrypt.h
//!
//! # Example
//!
//! ## SP800-108 Counter Mode with HmacSha256
//!
//! ```rust
//! use symcrypt::sp800_108::sp800_108_counter_mode;
//! use symcrypt::hmac::HmacAlgorithm;
//! use hex::*;
//!
//! // Setup the initial keying material.
//! let key = hex::decode("0001020304050607").unwrap();
//! let label = b"Label";
//!
//! let context = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
//! let hmac_algorithm = HmacAlgorithm::HmacSha256;
//!
//! let expected = "00264bbb14974054";
//! let res = sp800_108_counter_mode(hmac_algorithm, &key, label, &context, 8).unwrap();
//! assert_eq!(res.len(), 8);
//! assert_eq!(expected, hex::encode(res));
//! ```
//!
//! ## SP800-108 Counter Mode with empty label and context
//!
//! `label` and `context` are both optional and may be passed as empty slices when not used.
//!
//! ```rust
//! use symcrypt::sp800_108::sp800_108_counter_mode;
//! use symcrypt::hmac::HmacAlgorithm;
//! use hex::*;
//!
//! // Setup the initial keying material (KI)
//! let key = hex::decode("0001020304050607").unwrap();
//! let hmac_algorithm = HmacAlgorithm::HmacSha256;
//!
//! let res = sp800_108_counter_mode(hmac_algorithm, &key, &[], &[], 32).unwrap();
//! assert_eq!(res.len(), 32);
//! ```
//!
use crate::errors::SymCryptError;
use crate::hmac::HmacAlgorithm;
use crate::symcrypt_init;
use symcrypt_sys;

/// `sp800_108_counter_mode()` derives a key using the NIST SP800-108 Counter Mode KDF and returns
/// a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
///
/// `hmac_algorithm` is an [`HmacAlgorithm`] selecting the HMAC PRF used internally by the KDF.
///
/// `key_material` is a `&[u8]` containing the secret key.
///
/// `label` is a `&[u8]` containing an application-specific label. You can pass an empty slice.
///
/// `context` is a `&[u8]` containing application-specific context bytes. You can pass an empty slice.
///
/// `output_key_size` is a `usize` specifying the desired length of the derived key in bytes.
/// The returned `Vec<u8>` will have exactly this length.
pub fn sp800_108_counter_mode(
    hmac_algorithm: HmacAlgorithm,
    key_material: &[u8],
    label: &[u8],
    context: &[u8],
    output_key_size: usize,
) -> Result<Vec<u8>, SymCryptError> {
    symcrypt_init();
    let mut result = vec![0u8; output_key_size];
    unsafe {
        // UNSAFE: FFI calls
        match symcrypt_sys::SymCryptSp800_108(
            hmac_algorithm.to_symcrypt_hmac_algorithm(),
            key_material.as_ptr(),
            key_material.len() as symcrypt_sys::SIZE_T,
            label.as_ptr(),
            label.len() as symcrypt_sys::SIZE_T,
            context.as_ptr(),
            context.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
            result.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(result),
            err => Err(SymCryptError::from(err)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    #[test]
    fn test_sp800_108_hmac_sha256_kat() {
        let key = hex::decode("0001020304050607").unwrap();
        let context = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let expected = "00264bbb14974054";
        let res =
            sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, b"Label", &context, 8).unwrap();
        assert_eq!(hex::encode(res), expected);
    }

    #[test]
    fn test_sp800_108_hmac_sha384_kat() {
        let key = hex::decode("0001020304050607").unwrap();
        let context = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let expected = "c7102787d896bc89";
        let res =
            sp800_108_counter_mode(HmacAlgorithm::HmacSha384, &key, b"Label", &context, 8).unwrap();
        assert_eq!(hex::encode(res), expected);
    }

    #[test]
    fn test_sp800_108_hmac_sha512_kat() {
        let key = hex::decode("0001020304050607").unwrap();
        let context = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let expected = "db3a18d96c4ad41e";
        let res =
            sp800_108_counter_mode(HmacAlgorithm::HmacSha512, &key, b"Label", &context, 8).unwrap();
        assert_eq!(hex::encode(res), expected);
    }

    #[test]
    fn test_sp800_108_deterministic() {
        let key = hex::decode("0001020304050607").unwrap();
        let context = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let res1 = sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, b"Label", &context, 64)
            .unwrap();
        let res2 = sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, b"Label", &context, 64)
            .unwrap();
        assert_eq!(res1, res2);
        assert_eq!(res1.len(), 64);
    }

    #[test]
    fn test_sp800_108_different_context_differs() {
        let key = hex::decode("0001020304050607").unwrap();
        let res1 =
            sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, b"Label", b"A", 32).unwrap();
        let res2 =
            sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, b"Label", b"B", 32).unwrap();
        assert_ne!(res1, res2);
    }

    #[test]
    fn test_sp800_108_empty_label_and_context() {
        let key = hex::decode("0001020304050607").unwrap();
        let res = sp800_108_counter_mode(HmacAlgorithm::HmacSha256, &key, &[], &[], 32).unwrap();
        assert_eq!(res.len(), 32);
    }
}
