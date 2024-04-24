//! Hashing functions. For further documentation please refer to symcrypt.h
//!
//!
//! # Supported Hashing functions
//! ```ignore
//! Md5 // Note: Md5 is disabled by default, to enable pass the md5 flag
//! Sha1 // Note: Sha1 is disabled by default, to enable pass the sha1 flag
//! Sha256
//! Sha384
//! Sha512
//! ```
//!
//! `Md5` and `Sha1` are considered weak crypto, and are only added for interop purposes.
//! To enable either `Md5` or `Sha1` pass the `md5` or `sha1` flag into your `Cargo.toml`
//! To enable all weak crypto, you can instead pass `weak-crypto` into your `Cargo.toml` instead.
//!
//! In your `Cargo.toml`
//!
//! `symcrypt = {version = "0.2.0", features = ["weak-crypto"]}`
//!
//!
//! # Examples
//!
//! ## Stateless Sha256
//! ```rust
//! use symcrypt::hash::*;
//! use hex::*;
//!
//! // Setup input
//! let data = hex::decode("641ec2cf711e").unwrap();
//! let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
//!
//! // Perform hash
//! let result = sha256(&data); // Cannot fail
//! assert_eq!(hex::encode(result), expected);
//! ```
//!
//! ## Stateless Sha384
//! ```rust
//! use symcrypt::hash::*;
//! use hex::*;
//!
//! // Setup input
//! let data = hex::decode("").unwrap();
//! let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
//!
//! // Perform hash
//! let result = sha384(&data); // Cannot fail
//! assert_eq!(hex::encode(result), expected);
//! ```
//!
//! ## Stateful Hashing
//! Hashing via state uses the [`HashState`] trait. All of the supported hashing algorithms will implement the [`HashState`].
//! Usage across each hash state will be very similar.
//!
//! ```rust
//! use symcrypt::hash::*;
//! use hex::*;
//!
//! // Setup input
//! let data = hex::decode("").unwrap();
//! let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
//!
//! // Perform state-full hash on with Sha256. The call pattern for Sha384 is identical.
//! let mut sha256_state = Sha256State::new();
//! sha256_state.append(&data); // This can called multiple times on the same state.
//! let mut result = sha256_state.result();
//! assert_eq!(hex::encode(result), expected);
//! ```
use core::ffi::c_void;
use std::mem;
use std::pin::Pin;
use std::ptr;
use symcrypt_sys;

/// 16
#[cfg(feature = "md5")]
pub const MD5_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_MD5_RESULT_SIZE as usize;
/// 20
#[cfg(feature = "sha1")]
pub const SHA1_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA1_RESULT_SIZE as usize;
/// 32
pub const SHA256_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
/// 48
pub const SHA384_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;
/// 64
pub const SHA512_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA512_RESULT_SIZE as usize;

/// Generic trait for stateful hashing
///
/// `Result` will be dependent on the which [`HashState`] you use.
///
/// `append()` appends to be hashed data to the state, this operation can be done multiple times on the same state.
///
/// `result()` returns the result of the hash. The state is wiped and re-initialized and ready for re-use; you
/// do not need to re-run a `new()` call. This call cannot fail.
pub trait HashState: Clone {
    type Result;

    fn append(&mut self, data: &[u8]);

    fn result(&mut self) -> Self::Result;
}

/// [`Md5State`] is a struct that represents a stateful md5 hash and implements the [`HashState`] trait.
#[cfg(feature = "md5")]
pub struct Md5State(Pin<Box<symcrypt_sys::SYMCRYPT_MD5_STATE>>);
// Md5State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Md5State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.
#[cfg(feature = "md5")]
impl Md5State {
    pub fn new() -> Self {
        let mut instance = Md5State(Box::pin(symcrypt_sys::SYMCRYPT_MD5_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptMd5Init(&mut *instance.0);
        }
        instance
    }
}

#[cfg(feature = "md5")]
impl HashState for Md5State {
    type Result = [u8; MD5_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptMd5Append(
                &mut *self.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; MD5_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptMd5Result(&mut *self.0, result.as_mut_ptr());
        }
        result
    }
}

#[cfg(feature = "md5")]
impl Clone for Md5State {
    fn clone(&self) -> Self {
        let mut new_state = Md5State(Box::pin(symcrypt_sys::SYMCRYPT_MD5_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptMd5StateCopy(&*self.0, &mut *new_state.0);
        }
        new_state
    }
}

#[cfg(feature = "md5")]
impl Drop for Md5State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.0) as *mut c_void,
                mem::size_of_val(&mut self.0) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for MD5.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `MD5_RESULT_SIZE`, which is 16 bytes. This call cannot fail.
#[cfg(feature = "md5")]
pub fn md5(data: &[u8]) -> [u8; MD5_RESULT_SIZE] {
    let mut result = [0; MD5_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptMd5(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

/// [`Sha1State`] is a struct that represents a stateful sha1 hash and implements the [`HashState`] trait.
#[cfg(feature = "sha1")]
pub struct Sha1State(Pin<Box<symcrypt_sys::SYMCRYPT_SHA1_STATE>>);
// Sha1State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Sha1State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.

#[cfg(feature = "sha1")]
impl Sha1State {
    pub fn new() -> Self {
        let mut instance = Sha1State(Box::pin(symcrypt_sys::SYMCRYPT_SHA1_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha1Init(&mut *instance.0);
        }
        instance
    }
}

#[cfg(feature = "sha1")]
impl HashState for Sha1State {
    type Result = [u8; SHA1_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha1Append(
                &mut *self.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA1_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha1Result(&mut *self.0, result.as_mut_ptr());
        }
        result
    }
}

#[cfg(feature = "sha1")]
impl Clone for Sha1State {
    fn clone(&self) -> Self {
        let mut new_state = Sha1State(Box::pin(symcrypt_sys::SYMCRYPT_SHA1_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha1StateCopy(&*self.0, &mut *new_state.0);
        }
        new_state
    }
}

#[cfg(feature = "sha1")]
impl Drop for Sha1State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.0) as *mut c_void,
                mem::size_of_val(&mut self.0) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA1.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA1_RESULT_SIZE`, which is 20 bytes. This call cannot fail.
#[cfg(feature = "sha1")]
pub fn sha1(data: &[u8]) -> [u8; SHA1_RESULT_SIZE] {
    let mut result = [0; SHA1_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha1(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

/// [`Sha256State`] is a struct that represents a stateful sha256 hash and implements the [`HashState`] trait.
pub struct Sha256State(Pin<Box<symcrypt_sys::SYMCRYPT_SHA256_STATE>>);
// Sha256State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Sha256State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.

impl Sha256State {
    pub fn new() -> Self {
        let mut instance = Sha256State(Box::pin(symcrypt_sys::SYMCRYPT_SHA256_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Init(&mut *instance.0);
        }
        instance
    }
}

impl HashState for Sha256State {
    type Result = [u8; SHA256_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Append(
                &mut *self.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA256_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Result(&mut *self.0, result.as_mut_ptr());
        }
        result
    }
}

impl Clone for Sha256State {
    fn clone(&self) -> Self {
        let mut new_state = Sha256State(Box::pin(symcrypt_sys::SYMCRYPT_SHA256_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256StateCopy(&*self.0, &mut *new_state.0);
        }
        new_state
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.0) as *mut c_void,
                mem::size_of_val(&mut self.0) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA256.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA256_RESULT_SIZE`, which is 32 bytes. This call cannot fail.
pub fn sha256(data: &[u8]) -> [u8; SHA256_RESULT_SIZE] {
    let mut result = [0; SHA256_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha256(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

/// [`Sha384State`] is a struct that represents a stateful sha384 hash and implements the [`HashState`] trait.
pub struct Sha384State(Pin<Box<symcrypt_sys::SYMCRYPT_SHA384_STATE>>);
// Sha384State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Sha384State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.

impl Sha384State {
    pub fn new() -> Self {
        let mut instance = Sha384State(Box::pin(symcrypt_sys::SYMCRYPT_SHA384_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Init(&mut *instance.0);
        }
        instance
    }
}

impl HashState for Sha384State {
    type Result = [u8; SHA384_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Append(
                &mut *self.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA384_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Result(&mut *self.0, result.as_mut_ptr());
        }
        result
    }
}

impl Clone for Sha384State {
    fn clone(&self) -> Self {
        let mut new_state = Sha384State(Box::pin(symcrypt_sys::SYMCRYPT_SHA384_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384StateCopy(&*self.0, &mut *new_state.0);
        }
        new_state
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.0) as *mut c_void,
                mem::size_of_val(&mut self.0) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA384.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA384_RESULT_SIZE`, which is 48 bytes. This call cannot fail.
pub fn sha384(data: &[u8]) -> [u8; SHA384_RESULT_SIZE] {
    let mut result = [0; SHA384_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha384(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

/// [`Sha512State`] is a struct that represents a stateful sha512 hash and implements the [`HashState`] trait.
pub struct Sha512State(Pin<Box<symcrypt_sys::SYMCRYPT_SHA512_STATE>>);
// Sha512State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Sha512State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.

impl Sha512State {
    pub fn new() -> Self {
        let mut instance = Sha512State(Box::pin(symcrypt_sys::SYMCRYPT_SHA512_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Init(&mut *instance.0);
        }
        instance
    }
}

impl HashState for Sha512State {
    type Result = [u8; SHA512_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Append(
                &mut *self.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA512_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Result(&mut *self.0, result.as_mut_ptr());
        }
        result
    }
}

impl Clone for Sha512State {
    fn clone(&self) -> Self {
        let mut new_state = Sha512State(Box::pin(symcrypt_sys::SYMCRYPT_SHA512_STATE::default()));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512StateCopy(&*self.0, &mut *new_state.0);
        }
        new_state
    }
}

impl Drop for Sha512State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.0) as *mut c_void,
                mem::size_of_val(&mut self.0) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA512.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA512_RESULT_SIZE`, which is 64 bytes. This call cannot fail.
pub fn sha512(data: &[u8]) -> [u8; SHA512_RESULT_SIZE] {
    let mut result = [0; SHA512_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha512(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

#[cfg(test)]
mod test {
    // Note: by default sha1 and md5 are turned off, to enable for testing you can use:
    // cargo test --features "weak-crypto"
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
        hash_state.append(&data);
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
        hash_state.append(&data_1);
        hash_state.append(&data_2);

        let result = hash_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    #[cfg(feature = "md5")]
    #[test]
    fn test_stateless_md5_hash() {
        let data = hex::decode("d5976f79d83d3a0dc9806c3c66f3efd8").unwrap();
        let expected: &str = "00f913260f0ba7ba8652bf012c2b8af6";

        let result = md5(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_stateless_sha1_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

        let result = sha1(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha256_hash() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        let result = sha256(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha384_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

        let result = sha384(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha512_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

        let result = sha512(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[cfg(feature = "md5")]
    #[test]
    fn test_state_md5_hash() {
        let data = hex::decode("abcd").unwrap();
        let expected: &str = "7838496fd0586421bbb500bb6f472f13";

        test_generic_hash_state(Md5State::new(), &data, expected);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_state_sha1_hash() {
        let data = hex::decode("0572ba293b54cb").unwrap();
        let expected: &str = "47e3410eb833b589790aee07daf473d9c3d2327d";

        test_generic_hash_state(Sha1State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha256_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        test_generic_hash_state(Sha256State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha384_hash() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let expected: &str = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";

        test_generic_hash_state(Sha384State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha512_hash() {
        let data = hex::decode("3a1a5486014b6d78b3defd").unwrap();
        let expected: &str = "22219e717adaa5c6ded0ebd3bb4d4a00459afaa6fc112cf9e937fe5bb335abea3e2a2d171084c228b55e60701abb27a4107a2d4059523a3c4605d337d72e44e9";

        test_generic_hash_state(Sha512State::new(), &data, expected);
    }

    #[cfg(feature = "md5")]
    #[test]
    fn test_state_md5_clone() {
        let data = hex::decode("b2e5753cb450").unwrap();
        test_generic_state_clone(Md5State::new(), &data);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_state_sha1_clone() {
        let data = hex::decode("b2e5753cb4501fb8").unwrap();
        test_generic_state_clone(Sha1State::new(), &data);
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

    #[cfg(feature = "md5")]
    #[test]
    fn test_state_md5_multiple_append() {
        let data_1 = hex::decode("ab").unwrap();
        let data_2 = hex::decode("cd").unwrap();
        let expected: &str = "7838496fd0586421bbb500bb6f472f13";

        test_generic_state_multiple_append(Md5State::new(), &data_1, &data_2, expected);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_state_sha1_multiple_append() {
        let data_1 = hex::decode("516074a3438e1575e8").unwrap();
        let data_2 = hex::decode("8b9f9c68").unwrap();
        let expected: &str = "ab5bdc9a47aaee3c40d74658425dfddb2ff0b0ea";

        test_generic_state_multiple_append(Sha1State::new(), &data_1, &data_2, expected);
    }

    #[test]
    fn test_state_sha256_multiple_append() {
        let data_1 = hex::decode("641ec2").unwrap();
        let data_2 = hex::decode("cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        test_generic_state_multiple_append(Sha256State::new(), &data_1, &data_2, expected);
    }

    #[test]
    fn test_state_sha384_multiple_append() {
        let data_1 = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let data_2 = hex::decode("").unwrap();
        let expected: &str = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";

        test_generic_state_multiple_append(Sha384State::new(), &data_1, &data_2, expected);
    }

    #[test]
    fn test_state_sha512_multiple_append() {
        let data_1 = hex::decode("02b4bd7930f8").unwrap();
        let data_2 = hex::decode("cdf5f5379b25").unwrap();
        let expected: &str = "490aa49d4fcb8d229a9848f803b78b18e7fc59d12e76ab6d2712cc3ae37dcb1f1dfe28d551d11b957622f622a9b43979f6ec6cd3f2ac605b947b05cc0df272e0";

        test_generic_state_multiple_append(Sha512State::new(), &data_1, &data_2, expected);
    }
}
