//! Hashing functions.
//!
//! # Supported Hashing functions
//! ```ignore
//! Md5 // Note: Md5 is disabled by default, to enable pass the md5 flag
//! Sha1 // Note: Sha1 is disabled by default, to enable pass the sha1 flag
//! Sha256
//! Sha384
//! Sha512
//! Sha3_256
//! Sha3_384
//! Sha3_512
//! ```
//!
//! # Examples
//!
//! ## Stateless Sha256
//! ```rust
//! use symcrypt::hash::*;
//!
//! let data = hex::decode("641ec2cf711e").unwrap();
//! let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
//!
//! let result = sha256(&data);
//! assert_eq!(hex::encode(result), expected);
//! ```
//!
//! ## Stateful Hashing
//! ```rust
//! use symcrypt::hash::*;
//!
//! let data = hex::decode("").unwrap();
//! let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
//!
//! let mut sha256_state = Sha256State::new();
//! sha256_state.append(&data);
//! let result = sha256_state.result();
//! assert_eq!(hex::encode(result), expected);
//! ```

// Result size constants - hardcoded, no backend dependency
pub const SHA256_RESULT_SIZE: usize = 32;
pub const SHA384_RESULT_SIZE: usize = 48;
pub const SHA512_RESULT_SIZE: usize = 64;
pub const SHA3_256_RESULT_SIZE: usize = 32;
pub const SHA3_384_RESULT_SIZE: usize = 48;
pub const SHA3_512_RESULT_SIZE: usize = 64;

/// Hashing algorithms supported by the crate.
#[derive(Copy, Clone, Debug)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    pub fn get_result_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => SHA256_RESULT_SIZE,
            HashAlgorithm::Sha384 => SHA384_RESULT_SIZE,
            HashAlgorithm::Sha512 => SHA512_RESULT_SIZE,
            HashAlgorithm::Sha3_256 => SHA3_256_RESULT_SIZE,
            HashAlgorithm::Sha3_384 => SHA3_384_RESULT_SIZE,
            HashAlgorithm::Sha3_512 => SHA3_512_RESULT_SIZE,
        }
    }
}

#[cfg(not(windows))]
impl HashAlgorithm {
    pub(crate) fn get_oid_list(&self) -> &[symcrypt_sys::_SYMCRYPT_OID] {
        unsafe {
            match self {
                HashAlgorithm::Sha256 => &symcrypt_sys::SymCryptSha256OidList,
                HashAlgorithm::Sha384 => &symcrypt_sys::SymCryptSha384OidList,
                HashAlgorithm::Sha512 => &symcrypt_sys::SymCryptSha512OidList,
                HashAlgorithm::Sha3_256 => &symcrypt_sys::SymCryptSha3_256OidList,
                HashAlgorithm::Sha3_384 => &symcrypt_sys::SymCryptSha3_384OidList,
                HashAlgorithm::Sha3_512 => &symcrypt_sys::SymCryptSha3_512OidList,
            }
        }
    }

    pub(crate) fn get_symcrypt_hash(&self) -> symcrypt_sys::PCSYMCRYPT_HASH {
        unsafe {
            match self {
                HashAlgorithm::Sha256 => symcrypt_sys::SymCryptSha256Algorithm,
                HashAlgorithm::Sha384 => symcrypt_sys::SymCryptSha384Algorithm,
                HashAlgorithm::Sha512 => symcrypt_sys::SymCryptSha512Algorithm,
                HashAlgorithm::Sha3_256 => symcrypt_sys::SymCryptSha3_256Algorithm,
                HashAlgorithm::Sha3_384 => symcrypt_sys::SymCryptSha3_384Algorithm,
                HashAlgorithm::Sha3_512 => symcrypt_sys::SymCryptSha3_512Algorithm,
            }
        }
    }
}

/// Generic trait for stateful hashing.
///
/// `append()` appends data to the state. Can be called multiple times.
///
/// `result()` returns the hash. The state is reset and ready for reuse.
pub trait HashState: Clone {
    type Result;

    fn append(&mut self, data: &[u8]);

    fn result(&mut self) -> Self::Result;

    fn get_hash_algorithm(&self) -> HashAlgorithm;
}

// Backend-selected implementations
#[cfg(windows)]
use crate::backend::bcrypt::hash as imp;
#[cfg(not(windows))]
use crate::backend::symcrypt::hash as imp;

// Re-export backend types as the public types
pub use imp::Sha256State;
pub use imp::Sha384State;
pub use imp::Sha512State;
pub use imp::sha256;
pub use imp::sha384;
pub use imp::sha512;

// Breaking change (0.6.0): SHA-3 new() returns Result and one-shot functions return Result.
// BCrypt may not support SHA-3 on older Windows; callers must handle the error.
pub use imp::Sha3_256State;
pub use imp::Sha3_384State;
pub use imp::Sha3_512State;
pub use imp::sha3_256;
pub use imp::sha3_384;
pub use imp::sha3_512;

#[cfg(test)]
mod test {
    use super::*;

    fn test_generic_hash_state<H: HashState>(mut hash_state: H, data: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(data);
        let result = hash_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    fn test_generic_state_clone<H: HashState>(mut hash_state: H, data: &[u8])
    where
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(data);
        let mut new_hash_state = hash_state.clone();
        let result = new_hash_state.result();
        assert_eq!(hex::encode(result), hex::encode(hash_state.result()));
    }

    fn test_generic_state_multiple_append<H: HashState>(
        mut hash_state: H,
        data_1: &[u8],
        data_2: &[u8],
        expected: &str,
    ) where
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(data_1);
        hash_state.append(data_2);
        let result = hash_state.result();
        assert_eq!(
            hash_state.get_hash_algorithm().get_result_size(),
            result.as_ref().len()
        );
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha256_hash() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
        let result = sha256(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha384_hash() {
        let data = hex::decode("").unwrap();
        let expected = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
        let result = sha384(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha512_hash() {
        let data = hex::decode("").unwrap();
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let result = sha512(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_state_sha256_hash() {
        let data = hex::decode("").unwrap();
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        test_generic_hash_state(Sha256State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha384_hash() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let expected = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";
        test_generic_hash_state(Sha384State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha512_hash() {
        let data = hex::decode("3a1a5486014b6d78b3defd").unwrap();
        let expected = "22219e717adaa5c6ded0ebd3bb4d4a00459afaa6fc112cf9e937fe5bb335abea3e2a2d171084c228b55e60701abb27a4107a2d4059523a3c4605d337d72e44e9";
        test_generic_hash_state(Sha512State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha256_clone() {
        let data = hex::decode("641ec2cf711e").unwrap();
        test_generic_state_clone(Sha256State::new(), &data);
    }

    #[test]
    fn test_state_sha384_clone() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        test_generic_state_clone(Sha384State::new(), &data);
    }

    #[test]
    fn test_state_sha512_clone() {
        let data = hex::decode("7834dc7a4a8e9b17281ac472d3").unwrap();
        test_generic_state_clone(Sha512State::new(), &data);
    }

    #[test]
    fn test_state_sha256_multiple_append() {
        let data_1 = hex::decode("641ec2").unwrap();
        let data_2 = hex::decode("cf711e").unwrap();
        let expected = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
        test_generic_state_multiple_append(Sha256State::new(), &data_1, &data_2, expected);
    }

    #[test]
    fn test_state_sha256_result_reuse() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        let mut state = Sha256State::new();
        state.append(&data);
        let r1 = state.result();
        assert_eq!(hex::encode(r1), expected);

        state.append(&data);
        let r2 = state.result();
        assert_eq!(hex::encode(r2), expected);
    }

    #[test]
    fn test_stateless_sha3_256_hash() {
        let data = hex::decode("").unwrap();
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        let result = sha3_256(&data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_state_sha3_256_hash() {
        let data = hex::decode("71fbacdbf8541779c24a").unwrap();
        let expected = "cc4e5a216b01f987f24ab9cad5eb196e89d32ed4aac85acb727e18e40ceef00e";
        test_generic_hash_state(Sha3_256State::new().unwrap(), &data, expected);
    }

    #[test]
    fn test_state_sha3_256_clone() {
        let data = hex::decode("5c56a6b18c39e66e1b7a993a").unwrap();
        test_generic_state_clone(Sha3_256State::new().unwrap(), &data);
    }
}
