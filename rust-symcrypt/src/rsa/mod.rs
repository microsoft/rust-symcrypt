//! Rsa functions. For further documentation please refer to symcrypt.h
//!
//! This module provides a way to create and use RSA keys.
//!
//! There are two types of key objects, [`RsaKeyPair`] and [`RsaPublicKey`].
//! From these objects you can sign, encrypt, decrypt, and verify data via pkcs1, pss, or oaep.
//!
//! For more information on [`pkcs1`], [`pss`], and [`oaep`] please refer to their respective modules.
//!
//! # Examples
//!
//! ## Generating a random RsaKeyPair object.
//!
//! ```rust
//! use symcrypt::rsa::{RsaKeyPair, RsaKeyUsage};
//!
//! // Generate a new RsaKeyPair object with a 2048 bit modulus and default public exponent.
//! let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Sign).unwrap();
//!
//! // key_pair can now be used via pkcs1, pss, or oaep.
//!
//! // Get the size of the modulus, size of the public exponent, and size of the primes.
//! let modulus_size = key_pair.get_size_of_modulus();
//! let pub_exp_size = key_pair.get_size_of_public_exponent();
//! let primes = key_pair.get_size_of_primes();
//!
//! // Export the key pair to a blob.
//! let key_pair_blob = key_pair.export_key_pair_blob().unwrap();
//! ```
//!
//! ## Setting a RsaPublicKey object from parameters.
//!
//! ```rust
//! use symcrypt::rsa::{RsaPublicKey, RsaKeyUsage};
//!
//! // Set an RsaPublicKey based on the modulus, public exponent, and key usage.
//! let modulus = [
//!     215, 145, 16, 194, 78, 246, 213, 23, 173, 178, 123, 179, 152, 238, 67, 16, 25, 20, 102,
//!     36, 142, 210, 5, 164, 214, 122, 56, 206, 61, 65, 121, 44, 248, 241, 176, 72, 104, 251,
//!     188, 59, 107, 251, 214, 238, 237, 49, 27, 224, 96, 114, 82, 54, 116, 238, 151, 56, 73,
//!     216, 107, 88, 226, 27, 176, 247, 180, 48, 165, 127, 156, 133, 148, 69, 67, 191, 196,
//!     148, 115, 123, 86, 185, 169, 42, 111, 109, 121, 21, 9, 174, 183, 126, 219, 3, 32, 83,
//!     183, 63, 98, 253, 243, 108, 26, 9, 75, 68, 33, 248, 71, 223, 51, 231, 153, 194, 233,
//!     245, 53, 86, 243, 164, 94, 123, 146, 75, 161, 99, 5, 145, 85, 165, 187, 146, 243, 196,
//!     181, 223, 232, 32, 247, 253, 217, 211, 170, 187, 32, 23, 177, 11, 241, 133, 141, 8, 38,
//!     124, 133, 88, 81, 230, 110, 200, 219, 28, 149, 77, 25, 163, 18, 75, 183, 210, 68, 0,
//!     126, 3, 182, 196, 126, 207, 27, 92, 144, 174, 178, 203, 200, 146, 45, 180, 202, 3, 76,
//!     22, 202, 37, 87, 215, 183, 83, 159, 65, 144, 9, 172, 137, 75, 17, 51, 31, 176, 6, 168,
//!     197, 156, 195, 253, 36, 71, 64, 125, 253, 126, 155, 169, 79, 180, 233, 157, 193, 100,
//!     239, 237, 129, 4, 165, 38, 112, 247, 253, 174, 21, 245, 71, 236, 229, 56, 123, 134, 45,
//!     17, 124, 191, 60, 163, 218, 149, 209, 207, 181,
//! ];
//!
//! let pub_exp = [0, 0, 0, 0, 0, 1, 0, 1];
//! let public_key = RsaPublicKey::set_public_key(&modulus, &pub_exp, RsaKeyUsage::Sign).unwrap();
//!    
//! // public_key can now be used via pkcs1, pss, or oaep.
//!
//! // get the size of the modulus and the size of the public exponent.
//! let modulus_size = public_key.get_size_of_modulus();
//! let pub_exp_size = public_key.get_size_of_public_exponent();
//!
//! ```
//!
use crate::errors::SymCryptError;
use crate::NumberFormat;
use std::ptr;

pub mod oaep;
pub mod pkcs1;
pub mod pss;

/// !Review: Can we revisit RsaKeyUsage? It seems like it is not really needed since we dont actually do anything under the covers for it.
/// Should we pre-append the 0 if MSB is not set?
/// !Review: allow SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID? for PKCS1?
///  When the flag is set, this function will do signature verification by not using hash OID when needed
/// What is cbSalt? can we just always assume it will be the hash length of the HashAlgorithm?
/// what is the label for OAEP? what can I put in the example?
/// do we need to export the public key for RsaPublicKey?

// InnerRsaKey is a wrapper around symcrypt_sys::PSYMCRYPT_RSAKEY.
#[derive(Debug)]
pub(crate) struct InnerRsaKey(pub(crate) symcrypt_sys::PSYMCRYPT_RSAKEY);

// Must free inner key rather than the outer struct.
impl Drop for InnerRsaKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeyFree(self.0);
        }
    }
}

/// Rsa Public and Private Key State.
///
/// [`RsaKeyPair`] represents an Rsa key pair and also contains the [`RsaKeyUsage`].
#[derive(Debug)]
pub struct RsaKeyPair {
    inner: InnerRsaKey,
    key_usage: RsaKeyUsage,
}

/// Rsa Public Key State
///
/// [`RsaPublicKey`] represents an Rsa public key and also contains the [`RsaKeyUsage`].
#[derive(Debug)]
pub struct RsaPublicKey {
    inner: InnerRsaKey,
    key_usage: RsaKeyUsage,
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// `RsaKeyUsage` will indicate if the [`RsaKeyPair`] or [`RsaPublicKey`] will be used for [`RsaKeyUsage::Sign`] or [`RsaKeyUsage::Encrypt`], or [`RsaKeyUsage::SignAndEncrypt`].
/// This is to maintain interop with legacy Windows code and does not enforce any checks under the covers. The caller is responsible for ensuring the key is used correctly.
pub enum RsaKeyUsage {
    // When using [`RsaKeyUsage::Sign`], the intended usage for the key will be only Signing.
    Sign,

    /// When using [`RsaKeyUsage::Encrypt`], the intended usage for the key will be only Encryption.
    Encrypt,

    /// When using [RsaKeyUsage::SignAndEncrypt`], the intended usage for the key can be either Signing or Encryption.
    SignAndEncrypt,
}

// to_symcrypt_flag converts the RsaKeyUsage to the corresponding SymCrypt flag and only needed internally.
impl RsaKeyUsage {
    pub(crate) fn to_symcrypt_flag(&self) -> symcrypt_sys::UINT32 {
        match self {
            RsaKeyUsage::Sign => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN,
            RsaKeyUsage::Encrypt => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
            RsaKeyUsage::SignAndEncrypt => {
                symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT | symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN
            }
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
/// [`RsaKeyPairExportBlob`] holds the values of the `[RsaKeyPair]` when the key pair is exported.  
/// NOTE: SymCrypt does not pre-append leading 0's if the MSB is set.
pub struct RsaKeyPairExportBlob {
    pub modulus: Vec<u8>,
    pub pub_exp: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub d_p: Vec<u8>,
    pub d_q: Vec<u8>,
    pub crt_coefficient: Vec<u8>,
    pub private_exp: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
/// [`RsaPublicKeyExportBlob`] holds the values of the `[RsaPublicKey]` when the key is exported.
/// NOTE: SymCrypt does not pre-append leading 0's if the MSB is set.
pub struct RsaPublicKeyExportBlob {
    pub modulus: Vec<u8>,
    pub pub_exp: Vec<u8>,
}

/// Impl for RsaKeyPair struct.
impl RsaKeyPair {
    /// `generate_new()` generates a random Rsa key based on the provided parameters.
    ///
    /// `n_bits_mod` represents a `u32` that is the desired bit length of the Rsa key, `n_bits_mod` must be at least 1024 bits.
    ///
    ///
    /// `pub_exp` takes in an `Option<u64>` that is the public exponent. If `None` is provided, the default `2^16 +1` will be used.
    ///  
    /// `key_usage` takes in a [`RsaKeyUsage`] and will indicate if this key will be used for [`RsaKeyUsage::Sign`], or [`RsaKeyUsage::Encrypt`], or [`RsaKeyUsage::SignAndEncrypt`]
    pub fn generate_new(
        n_bits_mod: u32,
        pub_exp: Option<&[u8]>,
        key_usage: RsaKeyUsage,
    ) -> Result<Self, SymCryptError> {
        let (pub_exp_ptr, pub_exp_count) = match pub_exp {
            Some(exp) => {
                let u64_pub_exp = load_msb_first_u64(exp)?;
                ([u64_pub_exp].as_ptr(), 1) // This array has a length of 1.
            }
            None => (ptr::null(), 0), // If no public exponent is provided, use null and count 0 which will notify SymCrypt to use their default exponent.
        };

        let rsa_key = allocate_rsa(2, n_bits_mod)?;

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsakeyGenerate(
                rsa_key.0,
                pub_exp_ptr,   // Pointer to the public exponent array or null.
                pub_exp_count, // Count of public exponents. Will be 1 if Some() is provided, else 0.
                key_usage.to_symcrypt_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaKeyPair {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `set_key_pair()` sets both the public and private key information onto [`RsaKeyPair`].
    ///
    /// `modulus_buffer` takes in a `&[u8]` reference to a byte array that contains the modulus of the Rsa key.
    ///
    /// `pub_exp` takes in a `&[u8]` that is the public exponent represented by an array of bytes.
    ///
    /// `p` takes in a `&[u8]` reference to a byte array that contains the first prime.
    ///
    /// `q` takes in a `&[u8]` reference to a byte array that contains the second prime.
    pub fn set_key_pair(
        modulus_buffer: &[u8],
        pub_exp: &[u8],
        p: &[u8],
        q: &[u8],
        key_usage: RsaKeyUsage,
    ) -> Result<Self, SymCryptError> {
        let n_bits_mod = (modulus_buffer.len() as u32) * 8; // Convert the size from bytes to bits.
        let rsa_key = allocate_rsa(2, n_bits_mod)?;
        let u64_pub_exp = load_msb_first_u64(pub_exp)?;

        // Construct the primes_ptr and primes_len_ptr for SymCryptRsakeyValue consumption
        let primes_ptr = [p.as_ptr(), q.as_ptr()].as_mut_ptr();
        let primes_len_ptr = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ]
        .as_mut_ptr();
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [u64_pub_exp].as_ptr(),    // This array has a length of 1.
                1 as symcrypt_sys::UINT32, // Must be 1.
                primes_ptr,
                primes_len_ptr,
                2 as symcrypt_sys::UINT32,
                NumberFormat::MSB.to_symcrypt_format(),
                key_usage.to_symcrypt_flag(),
                rsa_key.0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaKeyPair {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `get_size_of_primes()` returns a tuple of type `u32` containing the sizes, in bytes, of byte arrays large enough to store each of the two primes of the RSA key.
    pub fn get_size_of_primes(&self) -> (u32, u32) {
        unsafe {
            // SAFETY: FFI calls
            // Currently, only two prime RSA is supported, i.e. the only valid indexes are 0 and 1
            let prime_1 = symcrypt_sys::SymCryptRsakeySizeofPrime(self.inner.0, 0);
            let prime_2 = symcrypt_sys::SymCryptRsakeySizeofPrime(self.inner.0, 1);
            (prime_1, prime_2)
        }
    }

    /// `export_key_pair_blob()` returns a [`RsaKeyPairExportBlob`] value.
    pub fn export_key_pair_blob(&self) -> Result<RsaKeyPairExportBlob, SymCryptError> {
        // Get size of primes only once
        let (size_p, size_q) = self.get_size_of_primes();

        // Allocate buffers for filling RsaKeyPairExportBlob
        let mut modulus_buffer = vec![0u8; self.get_size_of_modulus() as usize];
        let mut pub_exp = vec![0u64; 1];
        let mut p = vec![0u8; size_p as usize];
        let mut q = vec![0u8; size_q as usize];

        let mut d_p = vec![0u8; size_p as usize];
        let mut d_q = vec![0u8; size_q as usize];

        let mut crt_coefficient = vec![0u8; size_p as usize];
        let mut private_exponent = vec![0u8; self.get_size_of_modulus() as usize];

        let mut primes_len = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ];
        let mut crt_lens = [
            d_p.len() as symcrypt_sys::SIZE_T,
            d_q.len() as symcrypt_sys::SIZE_T,
        ];

        unsafe {
            // SAFETY: FFI calls
            let result = symcrypt_sys::SymCryptRsakeyGetValue(
                self.inner.0,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                1 as symcrypt_sys::UINT32,
                [p.as_mut_ptr(), q.as_mut_ptr()].as_mut_ptr(),
                primes_len.as_mut_ptr(),
                2 as symcrypt_sys::UINT32,
                NumberFormat::MSB.to_symcrypt_format(),
                self.key_usage.to_symcrypt_flag(),
            );
            if result != symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                return Err(result.into());
            }

            let result = symcrypt_sys::SymCryptRsakeyGetCrtValue(
                self.inner.0,
                [d_p.as_mut_ptr(), d_q.as_mut_ptr()].as_mut_ptr(),
                crt_lens.as_mut_ptr(),
                2,
                crt_coefficient.as_mut_ptr(),
                crt_coefficient.len() as symcrypt_sys::SIZE_T,
                private_exponent.as_mut_ptr(),
                private_exponent.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_symcrypt_format(),
                self.key_usage.to_symcrypt_flag(),
            );
            if result != symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                return Err(result.into());
            }
        }

        let pub_exp_bytes = store_msb_first_u64(pub_exp[0], self.get_size_of_public_exponent())?;

        Ok(RsaKeyPairExportBlob {
            modulus: modulus_buffer,
            pub_exp: pub_exp_bytes,
            p,
            q,
            d_p,
            d_q,
            crt_coefficient,
            private_exp: private_exponent,
        })
    }

    /// `export_public_key_blob()` will export a [`RsaPublicKeyExportBlob`].
    pub fn export_public_key_blob(&self) -> Result<RsaPublicKeyExportBlob, SymCryptError> {
        let mut modulus_buffer = vec![0u8; self.get_size_of_modulus() as usize];
        let mut pub_exp = vec![0u64; 1];
        unsafe {
            // SAFETY: FFI calls
            // When only getting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0.
            match symcrypt_sys::SymCryptRsakeyGetValue(
                self.inner.0,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                1 as symcrypt_sys::UINT32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                NumberFormat::MSB.to_symcrypt_format(),
                self.key_usage.to_symcrypt_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaPublicKeyExportBlob {
                    modulus: modulus_buffer,
                    pub_exp: store_msb_first_u64(pub_exp[0], self.get_size_of_public_exponent())?,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `get_size_of_modulus()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the modulus of the key.
    pub fn get_size_of_modulus(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeySizeofModulus(self.inner.0)
        }
    }

    /// `get_size_of_public_exponent()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the public exponent of the key.
    pub fn get_size_of_public_exponent(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Only one public exponent is supported, so the only valid index is 0.
            symcrypt_sys::SymCryptRsakeySizeofPublicExponent(self.inner.0, 0)
        }
    }

    /// `get_key_usage` returns the intended usage for the RSA key pair.
    pub fn get_key_usage(&self) -> RsaKeyUsage {
        self.key_usage
    }

    // `inner` gives crate access to the inner symcrypt Rsa Key struct.
    pub(crate) fn inner(&self) -> symcrypt_sys::PSYMCRYPT_RSAKEY {
        self.inner.0
    }
}

impl RsaPublicKey {
    /// `set_public_key()` sets only the public key information onto the [`RsaPublicKey`].
    ///
    /// `modulus_buffer` takes in a `&[u8]` reference to a byte array that contains the modulus of the Rsa key.
    ///
    /// `pub_exp` takes in a `&[u8]` that is an array of bytes representing the public exponent.
    ///
    /// `key_usage` takes in a [`RsaKeyUsage`] and will indicate if this key will be used for [`RsaKeyUsage::Sign`], or [`RsaKeyUsage::Encrypt`], or [`RsaKeyUsage::SignAndEncrypt`]
    pub fn set_public_key(
        modulus_buffer: &[u8],
        pub_exp: &[u8],
        key_usage: RsaKeyUsage,
    ) -> Result<Self, SymCryptError> {
        let n_bits_mod = (modulus_buffer.len() as u32) * 8; // Convert the size from bytes to bits
        let rsa_key = allocate_rsa(0, n_bits_mod)?;
        let u64_pub_exp = load_msb_first_u64(pub_exp)?;
        unsafe {
            // SAFETY: FFI calls
            // When only setting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [u64_pub_exp].as_ptr(), // This array has a length of 1.
                1 as symcrypt_sys::UINT32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                NumberFormat::MSB.to_symcrypt_format(),
                key_usage.to_symcrypt_flag(),
                rsa_key.0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaPublicKey {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `get_size_of_modulus()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the modulus of the key.
    pub fn get_size_of_modulus(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeySizeofModulus(self.inner.0)
        }
    }

    /// `get_size_of_public_exponent()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the public exponent of the key.
    pub fn get_size_of_public_exponent(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Only one public exponent is supported, so the only valid index is 0.
            symcrypt_sys::SymCryptRsakeySizeofPublicExponent(self.inner.0, 0)
        }
    }

    /// `get_key_usage` returns the intended usage for the RSA public key.
    pub fn get_key_usage(&self) -> RsaKeyUsage {
        self.key_usage
    }

    // `inner` gives crate access to the inner symcrypt Rsa Key struct.
    pub(crate) fn inner(&self) -> symcrypt_sys::PSYMCRYPT_RSAKEY {
        self.inner.0
    }
}

// Utility function to reduce common RSA allocation call
fn allocate_rsa(n_primes: u32, n_bits_mod: u32) -> Result<InnerRsaKey, SymCryptError> {
    let rsa_params = symcrypt_sys::SYMCRYPT_RSA_PARAMS {
        version: 1 as symcrypt_sys::UINT32, // No other version aside from version 1 is specified
        nBitsOfModulus: n_bits_mod as symcrypt_sys::UINT32,
        nPrimes: n_primes as symcrypt_sys::UINT32, // To generate a only a public key, 0 must be passed.
        nPubExp: 1 as symcrypt_sys::UINT32,        // Value must be 1.
    };
    unsafe {
        // SAFETY: FFI calls
        let result = symcrypt_sys::SymCryptRsakeyAllocate(&rsa_params, 0);
        if result == ptr::null_mut() {
            return Err(SymCryptError::AuthenticationFailure);
        }
        Ok(InnerRsaKey(result))
    }
}

// Utility function to store a `u64` into a new byte vector in big-endian format.
fn store_msb_first_u64(value: u64, size: u32) -> Result<Vec<u8>, SymCryptError> {
    let mut dst = vec![0u8; size as usize]; // Allocate tight size in bytes for storing public exponent
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptStoreMsbFirstUint64(value, dst.as_mut_ptr(), size as u64) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(SymCryptError::from(err)),
        }
    }
}

/// Load a `u64` from a byte slice assuming big-endian order.
fn load_msb_first_u64(src: &[u8]) -> Result<u64, SymCryptError> {
    let mut dst = 0u64;
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptLoadMsbFirstUint64(
            src.as_ptr(),
            src.len() as u64,
            &mut dst as *mut u64,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(SymCryptError::from(err)),
        }
    }
}

// Test invalid keys

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_new_default_exponent() {
        let result = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.get_key_usage(), RsaKeyUsage::Sign);
    }

    #[test]
    fn test_generate_get_then_set() {
        let result = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.get_key_usage(), RsaKeyUsage::Sign);

        let blob = key_pair.export_key_pair_blob().unwrap();
        let new_key_pair = RsaKeyPair::set_key_pair(
            &blob.modulus,
            &blob.pub_exp,
            &blob.p,
            &blob.q,
            key_pair.key_usage,
        )
        .unwrap();
        let blob_2 = new_key_pair.export_key_pair_blob().unwrap();
        assert_eq!(blob_2.crt_coefficient, blob.crt_coefficient);
    }

    #[test]
    fn test_set_and_get_key_pair() {
        let modulus = [
            215, 145, 16, 194, 78, 246, 213, 23, 173, 178, 123, 179, 152, 238, 67, 16, 25, 20, 102,
            36, 142, 210, 5, 164, 214, 122, 56, 206, 61, 65, 121, 44, 248, 241, 176, 72, 104, 251,
            188, 59, 107, 251, 214, 238, 237, 49, 27, 224, 96, 114, 82, 54, 116, 238, 151, 56, 73,
            216, 107, 88, 226, 27, 176, 247, 180, 48, 165, 127, 156, 133, 148, 69, 67, 191, 196,
            148, 115, 123, 86, 185, 169, 42, 111, 109, 121, 21, 9, 174, 183, 126, 219, 3, 32, 83,
            183, 63, 98, 253, 243, 108, 26, 9, 75, 68, 33, 248, 71, 223, 51, 231, 153, 194, 233,
            245, 53, 86, 243, 164, 94, 123, 146, 75, 161, 99, 5, 145, 85, 165, 187, 146, 243, 196,
            181, 223, 232, 32, 247, 253, 217, 211, 170, 187, 32, 23, 177, 11, 241, 133, 141, 8, 38,
            124, 133, 88, 81, 230, 110, 200, 219, 28, 149, 77, 25, 163, 18, 75, 183, 210, 68, 0,
            126, 3, 182, 196, 126, 207, 27, 92, 144, 174, 178, 203, 200, 146, 45, 180, 202, 3, 76,
            22, 202, 37, 87, 215, 183, 83, 159, 65, 144, 9, 172, 137, 75, 17, 51, 31, 176, 6, 168,
            197, 156, 195, 253, 36, 71, 64, 125, 253, 126, 155, 169, 79, 180, 233, 157, 193, 100,
            239, 237, 129, 4, 165, 38, 112, 247, 253, 174, 21, 245, 71, 236, 229, 56, 123, 134, 45,
            17, 124, 191, 60, 163, 218, 149, 209, 207, 181,
        ];

        let p = [
            243, 178, 90, 72, 143, 170, 126, 153, 156, 252, 2, 217, 218, 162, 40, 248, 110, 231,
            75, 107, 164, 216, 9, 203, 46, 234, 147, 154, 112, 197, 201, 4, 78, 28, 113, 170, 16,
            158, 111, 112, 209, 122, 73, 27, 228, 243, 16, 3, 87, 192, 183, 117, 30, 182, 231, 141,
            133, 103, 158, 180, 108, 186, 122, 14, 106, 15, 191, 28, 14, 239, 230, 122, 7, 121, 35,
            193, 127, 144, 25, 74, 185, 137, 60, 61, 181, 24, 55, 189, 45, 182, 96, 75, 53, 72,
            110, 249, 43, 175, 22, 130, 120, 144, 208, 121, 160, 92, 4, 86, 232, 74, 190, 228, 69,
            250, 240, 241, 19, 86, 223, 128, 164, 229, 4, 71, 19, 228, 152, 143,
        ];
        let q = [
            226, 115, 37, 192, 38, 148, 58, 223, 39, 192, 252, 148, 226, 240, 202, 224, 60, 234,
            242, 101, 85, 118, 66, 240, 20, 255, 38, 215, 219, 83, 181, 233, 147, 234, 237, 195,
            154, 94, 117, 100, 234, 9, 79, 200, 86, 157, 206, 186, 117, 146, 221, 20, 185, 202,
            129, 156, 81, 86, 171, 16, 66, 229, 67, 158, 157, 117, 226, 203, 148, 83, 191, 41, 100,
            55, 168, 76, 170, 43, 109, 76, 137, 167, 154, 154, 84, 251, 91, 91, 60, 217, 94, 142,
            236, 33, 136, 48, 146, 122, 8, 61, 231, 185, 247, 29, 165, 191, 167, 203, 177, 219, 74,
            208, 196, 13, 208, 32, 97, 145, 242, 21, 5, 81, 101, 118, 207, 14, 205, 123,
        ];

        let pub_exp: u64 = 65537;

        let result =
            RsaKeyPair::set_key_pair(&modulus, &pub_exp.to_be_bytes(), &p, &q, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.get_key_usage(), RsaKeyUsage::Sign);
        assert_eq!(key_pair.get_size_of_primes(), (128, 128));
        assert_eq!(key_pair.get_size_of_modulus(), 256);
        assert_eq!(key_pair.get_size_of_public_exponent(), 3);
        let key_blob = key_pair.export_key_pair_blob().unwrap();
        assert_eq!(key_blob.modulus, modulus.to_vec());
        assert_eq!(key_blob.p, p);
        assert_eq!(key_blob.q, q);
    }

    #[test]
    fn test_set_and_get_public_key() {
        let modulus = [
            215, 145, 16, 194, 78, 246, 213, 23, 173, 178, 123, 179, 152, 238, 67, 16, 25, 20, 102,
            36, 142, 210, 5, 164, 214, 122, 56, 206, 61, 65, 121, 44, 248, 241, 176, 72, 104, 251,
            188, 59, 107, 251, 214, 238, 237, 49, 27, 224, 96, 114, 82, 54, 116, 238, 151, 56, 73,
            216, 107, 88, 226, 27, 176, 247, 180, 48, 165, 127, 156, 133, 148, 69, 67, 191, 196,
            148, 115, 123, 86, 185, 169, 42, 111, 109, 121, 21, 9, 174, 183, 126, 219, 3, 32, 83,
            183, 63, 98, 253, 243, 108, 26, 9, 75, 68, 33, 248, 71, 223, 51, 231, 153, 194, 233,
            245, 53, 86, 243, 164, 94, 123, 146, 75, 161, 99, 5, 145, 85, 165, 187, 146, 243, 196,
            181, 223, 232, 32, 247, 253, 217, 211, 170, 187, 32, 23, 177, 11, 241, 133, 141, 8, 38,
            124, 133, 88, 81, 230, 110, 200, 219, 28, 149, 77, 25, 163, 18, 75, 183, 210, 68, 0,
            126, 3, 182, 196, 126, 207, 27, 92, 144, 174, 178, 203, 200, 146, 45, 180, 202, 3, 76,
            22, 202, 37, 87, 215, 183, 83, 159, 65, 144, 9, 172, 137, 75, 17, 51, 31, 176, 6, 168,
            197, 156, 195, 253, 36, 71, 64, 125, 253, 126, 155, 169, 79, 180, 233, 157, 193, 100,
            239, 237, 129, 4, 165, 38, 112, 247, 253, 174, 21, 245, 71, 236, 229, 56, 123, 134, 45,
            17, 124, 191, 60, 163, 218, 149, 209, 207, 181,
        ];
        let pub_exp: u64 = 65537;
        let result =
            RsaPublicKey::set_public_key(&modulus, &pub_exp.to_be_bytes(), RsaKeyUsage::Encrypt);

        assert!(result.is_ok());
        let pub_key = result.unwrap();

        assert_eq!(pub_key.get_key_usage(), RsaKeyUsage::Encrypt);
        assert_eq!(pub_key.get_size_of_modulus(), 256);
        assert_eq!(pub_key.get_size_of_public_exponent(), 3);
    }

    /// new
    #[test]
    fn test_export_public_key_blob_on_key_pair() {
        let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Encrypt).unwrap();
        let public_key_blob = key_pair.export_public_key_blob().unwrap();

        assert_eq!(
            public_key_blob.modulus.len(),
            key_pair.get_size_of_modulus() as usize
        );
        assert_eq!(
            public_key_blob.pub_exp.len(),
            key_pair.get_size_of_public_exponent() as usize
        );
    }

    #[test]
    fn test_set_invalid_key_pair() {
        let invalid_modulus = vec![0u8; 256]; // Invalid modulus
        let invalid_pub_exp = vec![0u8; 3]; // Invalid public exponent
        let invalid_prime = vec![0u8; 128]; // Invalid prime p
        let invalid_prime_q = vec![0u8; 128]; // Invalid prime q

        let result = RsaKeyPair::set_key_pair(
            &invalid_modulus,
            &invalid_pub_exp,
            &invalid_prime,
            &invalid_prime_q,
            RsaKeyUsage::SignAndEncrypt,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_invalid_public_key() {
        let invalid_modulus = vec![0u8; 256]; // Invalid modulus
        let invalid_pub_exp = vec![0u8; 3]; // Invalid public exponent

        let result =
            RsaPublicKey::set_public_key(&invalid_modulus, &invalid_pub_exp, RsaKeyUsage::Encrypt);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_usage_conversion() {
        let key_usage_sign = RsaKeyUsage::Sign;
        let key_usage_encrypt = RsaKeyUsage::Encrypt;
        let key_usage_both = RsaKeyUsage::SignAndEncrypt;

        assert_eq!(
            key_usage_sign.to_symcrypt_flag(),
            symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN
        );
        assert_eq!(
            key_usage_encrypt.to_symcrypt_flag(),
            symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT
        );
        assert_eq!(
            key_usage_both.to_symcrypt_flag(),
            symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT | symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN
        );
    }

    #[test]
    fn test_generate_with_boundary_key_sizes() {
        let result = RsaKeyPair::generate_new(512, None, RsaKeyUsage::Sign).unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument);

        let result = RsaKeyPair::generate_new(4096, None, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair_4096 = result.unwrap();
        assert_eq!(key_pair_4096.get_size_of_modulus(), 4096 / 8);
    }

    #[test]
    fn test_key_deletion() {
        {
            let key_pair = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Encrypt).unwrap();
            let public_key_blob = key_pair.export_public_key_blob().unwrap();
            assert_eq!(
                public_key_blob.modulus.len(),
                key_pair.get_size_of_modulus() as usize
            );
        } // Key pair should be dropped here
          // If no memory leaks or segmentation faults occur, the test passes.
    }
}
