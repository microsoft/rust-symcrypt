//! SP800-108 Counter-Mode KDF functions. For more info please refer to symcrypt.h
//!
//! # Example
//!
//! ## SP800-108 Counter Mode with HmacSha256
//!
//! ```rust
//! use symcrypt::sp800_108::sp800_108_counter_mode;
//! use symcrypt::hmac::HmacAlgorithm;
//!
//! let key_material = [0x0bu8; 32];
//! let label = b"test-label";
//! let context = b"test-context";
//!
//! let res = sp800_108_counter_mode(
//!     HmacAlgorithm::HmacSha256,
//!     &key_material,
//!     label,
//!     context,
//!     32,
//! ).unwrap();
//! assert_eq!(res.len(), 32);
//!
//! // SP800-108 is deterministic: identical inputs produce identical output.
//! let res2 = sp800_108_counter_mode(
//!     HmacAlgorithm::HmacSha256,
//!     &key_material,
//!     label,
//!     context,
//!     32,
//! ).unwrap();
//! assert_eq!(res, res2);
//! ```
//!
//! ## SP800-108 with HmacSha384, empty label and context
//!
//! ```rust
//! use symcrypt::sp800_108::sp800_108_counter_mode;
//! use symcrypt::hmac::HmacAlgorithm;
//!
//! let key_material = [0x0bu8; 32];
//! let res = sp800_108_counter_mode(
//!     HmacAlgorithm::HmacSha384,
//!     &key_material,
//!     &[],
//!     &[],
//!     48,
//! ).unwrap();
//! assert_eq!(res.len(), 48);
//! ```
//!
use crate::errors::SymCryptError;
use crate::hmac::HmacAlgorithm;
use symcrypt_sys;

/// `sp800_108_counter_mode()` derives a key using the NIST SP800-108 Counter Mode KDF and returns
/// a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
///
/// `hmac_algorithm` is an [`HmacAlgorithm`] selecting the HMAC PRF used internally by the KDF.
///
/// `key_material` is a `&[u8]` containing the secret key (KI in NIST terminology).
///
/// `label` is a `&[u8]` containing an application-specific label. May be empty.
///
/// `context` is a `&[u8]` containing application-specific context bytes. May be empty.
///
/// `output_key_size` is a `u64` specifying the desired length of the derived key in bytes.
/// The returned `Vec<u8>` will have exactly this length.
pub fn sp800_108_counter_mode(
    hmac_algorithm: HmacAlgorithm,
    key_material: &[u8],
    label: &[u8],
    context: &[u8],
    output_key_size: u64,
) -> Result<Vec<u8>, SymCryptError> {
    let mut result = vec![0u8; output_key_size as usize];
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

    #[test]
    fn test_sp800_108_sha256_basic() {
        let key_material = [0x0bu8; 32];
        let label = b"label";
        let context = b"context";

        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            label,
            context,
            32,
        )
        .unwrap();
        assert_eq!(res.len(), 32);
    }

    #[test]
    fn test_sp800_108_sha256_deterministic() {
        let key_material = [0x42u8; 16];
        let label = b"derive-key";
        let context = b"session-1";

        let res1 = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            label,
            context,
            64,
        )
        .unwrap();
        let res2 = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            label,
            context,
            64,
        )
        .unwrap();
        assert_eq!(res1, res2);
        assert_eq!(res1.len(), 64);
    }

    #[test]
    fn test_sp800_108_sha256_different_context_differs() {
        let key_material = [0x42u8; 16];
        let label = b"derive-key";

        let res1 = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            label,
            b"session-1",
            32,
        )
        .unwrap();
        let res2 = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            label,
            b"session-2",
            32,
        )
        .unwrap();
        assert_ne!(res1, res2);
    }

    #[test]
    fn test_sp800_108_sha384() {
        let key_material = [0x0bu8; 48];
        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha384,
            &key_material,
            b"label",
            b"context",
            48,
        )
        .unwrap();
        assert_eq!(res.len(), 48);
    }

    #[test]
    fn test_sp800_108_sha512() {
        let key_material = [0x0bu8; 64];
        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha512,
            &key_material,
            b"label",
            b"context",
            64,
        )
        .unwrap();
        assert_eq!(res.len(), 64);
    }

    #[test]
    fn test_sp800_108_empty_label_and_context() {
        let key_material = [0x0bu8; 32];
        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            &[],
            &[],
            32,
        )
        .unwrap();
        assert_eq!(res.len(), 32);
    }

    #[test]
    fn test_sp800_108_short_output() {
        let key_material = [0x0bu8; 32];
        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha256,
            &key_material,
            b"label",
            b"context",
            8,
        )
        .unwrap();
        assert_eq!(res.len(), 8);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_sp800_108_sha1() {
        let key_material = [0x0bu8; 20];
        let res = sp800_108_counter_mode(
            HmacAlgorithm::HmacSha1,
            &key_material,
            b"label",
            b"context",
            20,
        )
        .unwrap();
        assert_eq!(res.len(), 20);
    }
}
