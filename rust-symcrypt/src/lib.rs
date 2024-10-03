//! # SymCrypt Rust Wrapper
//!
//! This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.
//!
//! This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.
//!
//! **Note:** As of version `0.2.0`, only `Windows AMD64`, and [`Azure Linux`](https://github.com/microsoft/azurelinux) are fully supported, with partial support for other Linux distros such as `Ubuntu`.
//!
//! ## Changelog
//! To view a detailed list of changes please see the [releases page](https://github.com/microsoft/rust-symcrypt/releases/).
//!
//! ## Quick Start Guide
//! Please refer to the [rust-symcrypt Quick Start Guide](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide) to download and configure the required binaries.
//!
//! ## Supported APIs
//!
//! Hashing:
//! - Md5 ( stateful/stateless )
//! - Sha1 ( stateful/stateless )
//! - Sha256 ( stateful/stateless )
//! - Sha384 ( stateful/stateless )
//! - Sha512 ( stateful/stateless )
//! - Sha3_256 ( stateful/stateless )
//! - Sha3_384 ( stateful/stateless )
//! - Sha3_512 ( stateful/stateless )
//!
//! HMAC:
//! - HmacMd5 ( stateful/stateless )
//! - HmacSha1 ( stateful/stateless )
//! - HmacSha256 ( stateful/stateless )
//! - HmacSha384 ( stateful/stateless )
//! - HmacSha512 ( stateful/stateless )
//!
//! GCM:
//! - Encryption ( in place )
//! - Decryption ( in place )
//!
//! ChaCha:
//! - Encryption ( in place )
//! - Decryption ( in place )
//!
//! ECC:
//! - ECDH Secret Agreement
//! - ECDSA (Sign / Verify)
//!
//! RSA:
//! - PKCS1 ( Sign, Verify, Encrypt, Decrypt )
//! - PSS ( Sign, Verify )
//! - OAEP ( Encrypt, Decrypt )
//!
//! **Note**: `Md5` and `Sha1` are considered weak crypto, and are only added for interop purposes.
//! To enable either `Md5` or `Sha1` pass the `md5` or `sha1` flag into your `Cargo.toml`
//! To enable all weak crypto, you can instead pass `weak-crypto` into your `Cargo.toml` instead.
//!
//! ## Usage
//! There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash.
//!
//! **Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.
//!
//! ### Instructions:
//!
//! add symcrypt to your `Cargo.toml` file.
//!
//! `symcrypt = "0.2.0"`
//!
//! include symcrypt in your code
//!
//! ```rust
//! use symcrypt::hash::sha256;
//!
//! fn  main() {
//!     let data = hex::decode("641ec2cf711e").unwrap();
//!     let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
//!
//!     let result = sha256(&data);
//!     assert_eq!(hex::encode(result), expected);
//! }
//! ```

use std::sync::Once;

pub mod block_ciphers;
pub mod chacha;
pub mod ecc;
pub mod errors;
pub mod gcm;
pub mod hash;
pub mod hmac;
pub mod rsa;

// `symcrypt_init()` must be called before any other function in the library. `symcrypt_init()` can be called multiple times,
// BREAKING CHANGE WILL REMOVE THIS AS A PUB, KEEP IT AS JUST A PRIVATE FUNCTION
fn symcrypt_init() {
    // Subsequent calls to `symcrypt_init()` after the first will not be invoked per .call_once docs https://doc.rust-lang.org/std/sync/struct.Once.html
    static SYMCRYPT_MODULE_INIT: Once = Once::new();

    #[cfg(feature = "static")]
    static SYMCRYPT_INIT: Once = Once::new();
    
    unsafe {
        // SAFETY: FFI calls, blocking from being run again.
        
        // SymCryptInit() is called in the DllMain for dynamic libs, but needs to be implicitly
        // called for the static scenario.
        #[cfg(feature = "static")]
        SYMCRYPT_INIT.call_once(|| {
            symcrypt_sys::SymCryptInit()
        });

        SYMCRYPT_MODULE_INIT.call_once(|| {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        });
    }
}

/// Takes in a a buffer called `buff` and fills it with random bytes. This function cannot fail.
pub fn symcrypt_random(buff: &mut [u8]) {
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptRandom(buff.as_mut_ptr(), buff.len() as symcrypt_sys::SIZE_T);
    }
}

/// `NumberFormat` is an enum that contains a friendly representation of endianess
///
/// `LSB`: Bytes are ordered from the least significant to the most significant, commonly referred to as "little-endian".
///
/// `MSB`: Bytes are ordered from the most significant to the least significant, commonly referred to as "big-endian".
pub enum NumberFormat {
    LSB,
    MSB,
}

impl NumberFormat {
    /// Converts `NumberFormat` to the corresponding `SYMCRYPT_NUMBER_FORMAT`
    fn to_symcrypt_format(&self) -> symcrypt_sys::SYMCRYPT_NUMBER_FORMAT {
        match self {
            NumberFormat::LSB => {
                symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_LSB_FIRST
            }
            NumberFormat::MSB => {
                symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_symcrypt_random() {
        let mut buff_1 = [0u8; 10];
        let mut buff_2 = [0u8; 10];

        symcrypt_random(&mut buff_1);
        symcrypt_random(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
