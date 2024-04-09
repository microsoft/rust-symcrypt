//! Hashing functions. For further documentation please refer to symcrypt.h
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
//!
//! ## Stateful Hash for Sha256, Sha384, Sha512 and Sha1
//! Hashing via state uses the [`HashState`] trait. [`Sha256State`], [`Sha384State`], [`Sha512State`] and [`Sha1State`] will implement the [`HashState`].
//! Usage of across all of the [`HashState`]'s will be very similar.
//!
//! ```
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

/// 20
pub const SHA1_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA1_RESULT_SIZE as usize;
/// 32
pub const SHA256_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
/// 48
pub const SHA384_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;
/// 64
pub const SHA512_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA512_RESULT_SIZE as usize;

/// Generic trait for stateful hashing
///
/// `type Result` will be dependent on the which [`HashState`] you use.
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

/// [`Sha1State`] is a struct that represents a stateful sha256 hash and implements the [`HashState`] trait.
pub struct Sha1State(Pin<Box<symcrypt_sys::SYMCRYPT_SHA1_STATE>>);
// Sha1State needs to have a heap allocated inner state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
// around when returning from Sha1State::new(). Box<> heap allocates the memory and ensures that it does not move
//
// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// doing so would lead to use-after-free and inconsistent states.

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
/// `result` is an array of size `SHA512_RESULT_SIZE`, which is 60 bytes. This call cannot fail.
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


    /// add the statefull hash
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
}
