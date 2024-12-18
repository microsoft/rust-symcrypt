//! Hmac functions. For further documentation please refer to symcrypt.h
//!
//!
//! # Supported Hashing functions
//! ```ignore
//! HmacMd5 // Note: Md5 is disabled by default, to enable pass the md5 flag
//! HmacSha1 // Note: Sha1 is disabled by default, to enable pass the sha1 flag
//! HmacSha256
//! HmacSha384
//! HmacSha512
//! ```
//! `HmacMd5` and `HmacSha1` are considered weak crypto, and are only added for interop purposes.
//! To enable either `Md5` or `Sha1` pass the `md5` or `sha1` flag into your `Cargo.toml`
//! To enable all weak crypto, you can instead pass `weak-crypto` into your `Cargo.toml` instead.
//!
//! In your `Cargo.toml`
//!
//! `symcrypt = {version = "0.2.0", features = ["weak-crypto"]}`
//!
//! # Examples
//!
//! ## Stateless Hmac for HmacSha256
//! ```rust
//! use symcrypt::hmac::hmac_sha256;
//!
//! // Set up input
//! let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
//! let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();
//! let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";
//!
//! // Perform stateless HmacSh256
//! let result = hmac_sha256(&p_key, &data).unwrap();
//! assert_eq!(hex::encode(result), expected);
//! ```
//!
//! ## Stateless Hmac for HmacSha384
//! ```rust
//! use symcrypt::hmac::hmac_sha384;
//!
//! // Set up input
//! let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//! let data = hex::decode("").unwrap();
//! let expected = "ad88735f29e167dabded11b57e168f0b773b2985f4c2d2234c8d7a6bf01e2a791590bc0165003f9a7e47c4c687622fd6";
//!
//! // Perform stateless HmacSha384
//! let result = hmac_sha384(&p_key, &data).unwrap();
//! assert_eq!(hex::encode(result), expected);
//! ```
//!
//! ## Stateful Hmac for HmacSha256 and HmacSha384
//!
//! Hmac via state uses the [`HmacState`] trait. All of the supported hmac algorithms will implement the [`HmacState`].
//! Usage across each hash state will be very similar.
//!
//! ```rust
//! use symcrypt::hmac::HmacSha256State;
//! use crate::symcrypt::hmac::HmacState;
//!
//! // Set up input
//! let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//! let data = hex::decode("").unwrap();
//! let expected = "915cb2c078aaf5dfb3560cf6d96997e987b2de5cd46f9a2ef92493bfc34bab16";
//!
//! // Perform stateful HmacSha256
//! let mut hmac_test = HmacSha256State::new(&p_key).unwrap();
//! hmac_test.append(&data);
//!
//! let result = hmac_test.result();
//! assert_eq!(hex::encode(result), expected);
//! ```

use crate::errors::SymCryptError;
use crate::symcrypt_init;
use core::ffi::c_void;
use std::marker::PhantomPinned;
use std::mem;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use symcrypt_sys;

/// 16
#[cfg(feature = "md5")]
pub const MD5_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_MD5_RESULT_SIZE as usize;
/// 20
#[cfg(feature = "sha1")]
pub const SHA1_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA1_RESULT_SIZE as usize;
/// 32
pub const SHA256_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
/// 48
pub const SHA384_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;
/// 64
pub const SHA512_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA512_RESULT_SIZE as usize;

/// Hmac Algorithms that are supported by SymCrypt
#[derive(Copy, Clone, Debug)]
pub enum HmacAlgorithm {
    #[cfg(feature = "md5")]
    HmacMd5,
    #[cfg(feature = "sha1")]
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl HmacAlgorithm {
    /// Returns the symcrypt_sys::PCSYMCRYPT_MAC for calling underlying SymCrypt functions, hidden from the user.   
    pub(crate) fn to_symcrypt_hmac_algorithm(self) -> symcrypt_sys::PCSYMCRYPT_MAC {
        match self {
            #[cfg(feature = "md5")]
            HmacAlgorithm::HmacMd5 => unsafe { symcrypt_sys::SymCryptHmacMd5Algorithm }, // UNSAFE FFI calls
            #[cfg(feature = "sha1")]
            HmacAlgorithm::HmacSha1 => unsafe { symcrypt_sys::SymCryptHmacSha1Algorithm }, // UNSAFE FFI calls
            HmacAlgorithm::HmacSha256 => unsafe { symcrypt_sys::SymCryptHmacSha256Algorithm }, // UNSAFE FFI calls
            HmacAlgorithm::HmacSha384 => unsafe { symcrypt_sys::SymCryptHmacSha384Algorithm }, // UNSAFE FFI calls
            HmacAlgorithm::HmacSha512 => unsafe { symcrypt_sys::SymCryptHmacSha512Algorithm }, // UNSAFE FFI calls
        }
    }

    /// Returns the result size as a `usize`. This is the size of the Hmac result in bytes.
    pub fn get_result_size(&self) -> usize {
        match self {
            #[cfg(feature = "md5")]
            HmacAlgorithm::HmacMd5 => MD5_HMAC_RESULT_SIZE,
            #[cfg(feature = "sha1")]
            HmacAlgorithm::HmacSha1 => SHA1_HMAC_RESULT_SIZE,
            HmacAlgorithm::HmacSha256 => SHA256_HMAC_RESULT_SIZE,
            HmacAlgorithm::HmacSha384 => SHA384_HMAC_RESULT_SIZE,
            HmacAlgorithm::HmacSha512 => SHA512_HMAC_RESULT_SIZE,
        }
    }
}

/// Generic trait for stateful Hmac functions
///
/// `Result` will depend on what HmacState is used.
///
/// `append()` appends data to the `HmacShaXXXState`, this operation can be done multiple times.
///
/// `result()` returns the result of the Hmac. Once `result()` is called, the lifetime of the `HmacShaXXXState` is
/// finished and `HmacShaXXState` will be drop()'d. To perform other stateful hash operations you must create
/// a new hash object via `HmacShaXXXState::new()`.
pub trait HmacState: Clone {
    type Result;

    fn append(&mut self, data: &[u8]);

    // The state cannot be reused after result has been called. This behaviour is different from Hashing. The hash states are re-initialized
    // by ShaXXXState Result routine. This difference is by design; re-initializing a hash state is a safe operation. Re-initializing a
    // MAC state puts keying information in the state, and callers would have to wipe the MAC state explicitly.
    fn result(self) -> Self::Result;
}

#[cfg(feature = "md5")]
/// `HmacMd5ExpandedKey` is a struct that represents the expanded key for the [`HmacMd5State`].
/// The key wrapping so that it can be independently dropped after its ref count has gone to 0.
struct HmacMd5ExpandedKey {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_MD5_EXPANDED_KEY,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

#[cfg(feature = "md5")]
impl HmacMd5ExpandedKey {
    fn new(key: &[u8]) -> Result<Pin<Box<Self>>, SymCryptError> {
        let mut expanded_key = Box::pin(HmacMd5ExpandedKey {
            inner: symcrypt_sys::SYMCRYPT_HMAC_MD5_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        });

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacMd5ExpandKey(
                &mut expanded_key.as_mut().get_unchecked_mut().inner,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
                err => Err(err.into()),
            }
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_MD5_EXPANDED_KEY {
        &self.inner as *const _
    }
}

#[cfg(feature = "md5")]
// Since HmacMd5ExpandedKey can be referenced multiple times, HmacMd5ExpandedKey must be ref counted and there needs to be a separate drop().
impl Drop for HmacMd5ExpandedKey {
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

#[cfg(feature = "md5")]
/// `HmacMd5State` is a struct that represents a stateful HMAC using MD5 and implements the [`HmacState`] trait.
pub struct HmacMd5State {
    // SymCrypt expects the address for its structs to stay static through the struct's lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.

    // Using an `HmacMd5Inner` state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
    // around when returning from `HmacMd5State::new()`. Box<> heap allocates the memory and ensures that it does not move
    // within its lifetime.
    state: Pin<Box<HmacMd5Inner>>,

    // Must Arc<> the expanded_key field since it must be ref counted; clones of HmacMd5State will reference the same expanded key.
    // Arc<T> pointer can move, but its reference T is Pin<Box<>>'d to ensure that the address does not move during its lifetime.
    key: Arc<Pin<Box<HmacMd5ExpandedKey>>>,
}

#[cfg(feature = "md5")]

struct HmacMd5Inner {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_MD5_STATE,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

#[cfg(feature = "md5")]
impl HmacMd5Inner {
    fn new() -> Pin<Box<Self>> {
        Box::pin(HmacMd5Inner {
            inner: symcrypt_sys::SYMCRYPT_HMAC_MD5_STATE::default(),
            _pinned: PhantomPinned,
        })
    }

    /// Get a mutable pointer to the inner SymCrypt state.
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// This function returns a pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_HMAC_MD5_STATE {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data.
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_MD5_STATE {
        &self.inner as *const _
    }
}

#[cfg(feature = "md5")]
impl HmacMd5State {
    /// `new()` takes in a `&[u8]` reference to a key and can return a [`SymCryptError`] that is propagated back to the caller.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = HmacMd5ExpandedKey::new(key)?;
        let mut inner_state = HmacMd5Inner::new();

        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacMd5Init(
                inner_state.as_mut().get_inner_mut(),
                expanded_key.get_inner(),
            );
        }

        Ok(HmacMd5State {
            state: inner_state,
            key: Arc::new(expanded_key),
        })
    }
}

#[cfg(feature = "md5")]
impl HmacState for HmacMd5State {
    type Result = [u8; MD5_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacMd5Append(
                self.state.as_mut().get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; MD5_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacMd5Result(
                self.state.as_mut().get_inner_mut(),
                result.as_mut_ptr(),
            );
        }
        result
    }
}

#[cfg(feature = "md5")]
/// Creates a clone of the current `HmacMd5State`. Clone will create a new state field but will reference the same
/// `expanded_key` of the current `HmacMd5State`.
impl Clone for HmacMd5State {
    // Clone will increase the refcount on the expanded_key field.
    fn clone(&self) -> Self {
        let mut new_state = HmacMd5State {
            state: HmacMd5Inner::new(),
            key: Arc::clone(&self.key), // Clone to increase ref count.
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacMd5StateCopy(
                self.state.get_inner(),
                new_state.key.get_inner(), // Use new ref counted key.
                new_state.state.as_mut().get_inner_mut(),
            );
        }
        new_state
    }
}

#[cfg(feature = "md5")]
impl Drop for HmacMd5State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.state.as_mut().get_inner_mut() as *mut c_void,
                mem::size_of_val(&self.state.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

#[allow(clippy::unnecessary_mut_passed)]
#[cfg(feature = "md5")]
/// Stateless HMAC function for HmacMd5.
///
/// `key` is a reference to a key.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `MD5_HMAC_RESULT_SIZE`. This call can fail with a `SymCryptError`.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; MD5_HMAC_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0u8; MD5_HMAC_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacMd5ExpandedKey::new(key)?;
        match symcrypt_sys::SymCryptHmacMd5ExpandKey(
            &mut expanded_key.as_mut().get_unchecked_mut().inner,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacMd5(
                    &mut expanded_key.as_mut().get_unchecked_mut().inner,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(result)
            }
            err => Err(err.into()),
        }
    }
}

#[cfg(feature = "sha1")]
/// `HmacSha1ExpandedKey` is a struct that represents the expanded key for the [`HmacSha1State`].
/// The key wrapping so that it can be independently dropped after its ref count has gone to 0.
struct HmacSha1ExpandedKey {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA1_EXPANDED_KEY,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

#[cfg(feature = "sha1")]
impl HmacSha1ExpandedKey {
    fn new(key: &[u8]) -> Result<Pin<Box<Self>>, SymCryptError> {
        let mut expanded_key = Box::pin(HmacSha1ExpandedKey {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA1_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        });

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha1ExpandKey(
                &mut expanded_key.as_mut().get_unchecked_mut().inner,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
                err => Err(err.into()),
            }
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA1_EXPANDED_KEY {
        &self.inner as *const _
    }
}

#[cfg(feature = "sha1")]
// Since HmacSha1ExpandedKey can be referenced multiple times, HmacSha1ExpandedKey must be ref counted and there needs to be a separate drop().
impl Drop for HmacSha1ExpandedKey {
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

#[cfg(feature = "sha1")]
/// `HmacSha1State` is a struct that represents a stateful HMAC using SHA1 and implements the [`HmacState`] trait.
pub struct HmacSha1State {
    // SymCrypt expects the address for its structs to stay static through the struct's lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.

    // Using an `HmacSha1Inner` state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
    // around when returning from `HmacSha1State::new()`. Box<> heap allocates the memory and ensures that it does not move
    // within its lifetime.
    state: Pin<Box<HmacSha1Inner>>,

    // Must Arc<> the expanded_key field since it must be ref counted; clones of HmacSha1State will reference the same expanded key.
    // Arc<T> pointer can move, but its reference T is Pin<Box<>>'d to ensure that the address does not move during its lifetime.
    key: Arc<Pin<Box<HmacSha1ExpandedKey>>>,
}

#[cfg(feature = "sha1")]
struct HmacSha1Inner {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA1_STATE,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

#[cfg(feature = "sha1")]
impl HmacSha1Inner {
    fn new() -> Pin<Box<Self>> {
        Box::pin(HmacSha1Inner {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA1_STATE::default(),
            _pinned: PhantomPinned,
        })
    }

    /// Get a mutable pointer to the inner SymCrypt state.
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// This function returns a pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_HMAC_SHA1_STATE {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data.
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA1_STATE {
        &self.inner as *const _
    }
}

#[cfg(feature = "sha1")]
impl HmacSha1State {
    /// `new()` takes in a `&[u8]` reference to a key and can return a [`SymCryptError`] that is propagated back to the caller.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = HmacSha1ExpandedKey::new(key)?;
        let mut inner_state = HmacSha1Inner::new();

        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha1Init(
                inner_state.as_mut().get_inner_mut(),
                expanded_key.get_inner(),
            );
        }

        Ok(HmacSha1State {
            state: inner_state,
            key: Arc::new(expanded_key),
        })
    }
}

#[cfg(feature = "sha1")]
impl HmacState for HmacSha1State {
    type Result = [u8; SHA1_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha1Append(
                self.state.as_mut().get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA1_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha1Result(
                self.state.as_mut().get_inner_mut(),
                result.as_mut_ptr(),
            );
        }
        result
    }
}

#[cfg(feature = "sha1")]
/// Creates a clone of the current `HmacSha1State`. Clone will create a new state field but will reference the same
/// `expanded_key` of the current `HmacSha1State`.
impl Clone for HmacSha1State {
    // Clone will increase the refcount on the expanded_key field.
    fn clone(&self) -> Self {
        let mut new_state = HmacSha1State {
            state: HmacSha1Inner::new(),
            key: Arc::clone(&self.key), // Clone to increase ref count.
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha1StateCopy(
                self.state.get_inner(),
                new_state.key.get_inner(), // Use new ref counted key.
                new_state.state.as_mut().get_inner_mut(),
            );
        }
        new_state
    }
}

#[cfg(feature = "sha1")]
impl Drop for HmacSha1State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.state.as_mut().get_inner_mut() as *mut c_void,
                mem::size_of_val(&self.state.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

#[cfg(feature = "sha1")]
#[allow(clippy::unnecessary_mut_passed)]
/// Stateless HMAC function for HmacSha1.
///
/// `key` is a reference to a key.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA1_HMAC_RESULT_SIZE`. This call can fail with a `SymCryptError`.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; SHA1_HMAC_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0u8; SHA1_HMAC_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha1ExpandedKey::new(key)?;
        match symcrypt_sys::SymCryptHmacSha1ExpandKey(
            &mut expanded_key.as_mut().get_unchecked_mut().inner,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha1(
                    &mut expanded_key.as_mut().get_unchecked_mut().inner,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(result)
            }
            err => Err(err.into()),
        }
    }
}

/// `HmacSha256ExpandedKey` is a struct that represents the expanded key for the [`HmacSha256State`].
/// The key wrapping so that it can be independently dropped after it's ref count has gone to 0
struct HmacSha256ExpandedKey {
    // inner represents the actual hmac state from SymCrypt
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    //  This prevents the struct from implementing the Unpin trait, enforcing that any
    //  references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha256ExpandedKey {
    fn new(key: &[u8]) -> Result<Pin<Box<Self>>, SymCryptError> {
        let mut expanded_key = Box::pin(HmacSha256ExpandedKey {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        });

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha256ExpandKey(
                &mut expanded_key.as_mut().get_unchecked_mut().inner,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
                err => Err(err.into()),
            }
        }
    }

    /// Safe method to access the inner state immutably
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY {
        &self.inner as *const _
    }
}

// Since HmacSha256ExpandedKey can be referenced multiple times, HmacSha256ExpandedKey must be ref counted and there needs to be a separate drop()
impl Drop for HmacSha256ExpandedKey {
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

/// `HmacSha256State` is a struct that represents a stateful HMAC using SHA256 and implements the [`HmacState`] trait.
pub struct HmacSha256State {
    // SymCrypt expects the address for its structs to stay static through the struct's lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.

    // Using an `HmacSha256Inner` state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
    // around when returning from `HmacSha256State::new()`. Box<> heap allocates the memory and ensures that it does not move
    // within its lifetime.
    state: Pin<Box<HmacSha256Inner>>,

    // Must Arc<> the expanded_key field since it must be ref counted, clones of HmacSha265State will reference the same expanded key.
    // Arc<T> pointer can move, but its reference T is Pin<Box<>>'d to ensure that the address does not move during its lifetime.
    key: Arc<Pin<Box<HmacSha256ExpandedKey>>>,
}
struct HmacSha256Inner {
    // inner represents the actual HMAC state from SymCrypt
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    //  This prevents the struct from implementing the Unpin trait, enforcing that any
    //  references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha256Inner {
    fn new() -> Pin<Box<Self>> {
        Box::pin(HmacSha256Inner {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE::default(),
            _pinned: PhantomPinned,
        })
    }

    /// Get a mutable pointer to the inner SymCrypt state
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// This function returns pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    /// Safe method to access the inner state immutably
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE {
        &self.inner as *const _
    }
}

// No custom Send / Sync impl. needed for HmacSha256Inner since the
// underlying data is a pointer to an owned SymCrypt HmacState that is follows Rust's ownership rules
unsafe impl Send for HmacSha256Inner {}
unsafe impl Sync for HmacSha256Inner {}

impl HmacSha256State {
    /// `new()` takes in a `&[u8]` reference to a key and can return a [`SymCryptError`] that is propagated back to the caller.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = HmacSha256ExpandedKey::new(key)?;
        let mut inner_state = HmacSha256Inner::new();

        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256Init(
                inner_state.as_mut().get_inner_mut(),
                expanded_key.get_inner(),
            );
        }

        Ok(HmacSha256State {
            state: inner_state,
            key: Arc::new(expanded_key),
        })
    }
}

impl HmacState for HmacSha256State {
    type Result = [u8; SHA256_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256Append(
                self.state.as_mut().get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA256_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256Result(
                self.state.as_mut().get_inner_mut(),
                result.as_mut_ptr(),
            );
        }
        result
    }
}

/// Creates a clone of the current `HmacSha256State`. Clone will create a new state field but will reference the same
/// `expanded_key` of the current `HmacSha256State`.
impl Clone for HmacSha256State {
    // Clone will increase the refcount on expanded_key field
    fn clone(&self) -> Self {
        let mut new_state = HmacSha256State {
            state: HmacSha256Inner::new(),
            key: Arc::clone(&self.key), // clone to increase ref count
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256StateCopy(
                self.state.get_inner(),
                new_state.key.get_inner(), // use new ref counted key
                new_state.state.as_mut().get_inner_mut(),
            );
        }
        new_state
    }
}

impl Drop for HmacSha256State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.state.as_mut().get_inner_mut() as *mut c_void,
                mem::size_of_val(&self.state.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

#[allow(clippy::unnecessary_mut_passed)]
/// Stateless HMAC function for HmacSha256.
///
/// `key` is a reference to a key.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA256_HMAC_RESULT_SIZE`. This call can fail with a `SymCryptError`.
pub fn hmac_sha256(
    key: &[u8],
    data: &[u8],
) -> Result<[u8; SHA256_HMAC_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0u8; SHA256_HMAC_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha256ExpandedKey::new(key)?;
        match symcrypt_sys::SymCryptHmacSha256ExpandKey(
            &mut expanded_key.as_mut().get_unchecked_mut().inner,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha256(
                    &mut expanded_key.as_mut().get_unchecked_mut().inner,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(result)
            }
            err => Err(err.into()),
        }
    }
}

/// `HmacSha384ExpandedKey` is a struct that represents the expanded key for the [`HmacSha384State`].
/// The key wrapping so that it can be independently dropped after its ref count has gone to 0.
struct HmacSha384ExpandedKey {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha384ExpandedKey {
    fn new(key: &[u8]) -> Result<Pin<Box<Self>>, SymCryptError> {
        let mut expanded_key = Box::pin(HmacSha384ExpandedKey {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        });

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha384ExpandKey(
                &mut expanded_key.as_mut().get_unchecked_mut().inner,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
                err => Err(err.into()),
            }
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY {
        &self.inner as *const _
    }
}

// Since HmacSha384ExpandedKey can be referenced multiple times, HmacSha384ExpandedKey must be ref counted and there needs to be a separate drop().
impl Drop for HmacSha384ExpandedKey {
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

/// `HmacSha384State` is a struct that represents a stateful HMAC using SHA384 and implements the [`HmacState`] trait.
pub struct HmacSha384State {
    // SymCrypt expects the address for its structs to stay static through the struct's lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.

    // Using an `HmacSha384Inner` state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
    // around when returning from `HmacSha384State::new()`. Box<> heap allocates the memory and ensures that it does not move
    // within its lifetime.
    state: Pin<Box<HmacSha384Inner>>,

    // Must Arc<> the expanded_key field since it must be ref counted; clones of HmacSha384State will reference the same expanded key.
    // Arc<T> pointer can move, but its reference T is Pin<Box<>>'d to ensure that the address does not move during its lifetime.
    key: Arc<Pin<Box<HmacSha384ExpandedKey>>>,
}

struct HmacSha384Inner {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha384Inner {
    fn new() -> Pin<Box<Self>> {
        Box::pin(HmacSha384Inner {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE::default(),
            _pinned: PhantomPinned,
        })
    }

    /// Get a mutable pointer to the inner SymCrypt state.
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// This function returns a pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data.
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE {
        &self.inner as *const _
    }
}

// No custom Send / Sync impl. needed for HmacSha384Inner since the
// underlying data is a pointer to an owned SymCrypt HmacState that is follows Rust's ownership rules
unsafe impl Send for HmacSha384Inner {}
unsafe impl Sync for HmacSha384Inner {}

impl HmacSha384State {
    /// `new()` takes in a `&[u8]` reference to a key and can return a [`SymCryptError`] that is propagated back to the caller.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = HmacSha384ExpandedKey::new(key)?;
        let mut inner_state = HmacSha384Inner::new();

        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384Init(
                inner_state.as_mut().get_inner_mut(),
                expanded_key.get_inner(),
            );
        }

        Ok(HmacSha384State {
            state: inner_state,
            key: Arc::new(expanded_key),
        })
    }
}

impl HmacState for HmacSha384State {
    type Result = [u8; SHA384_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384Append(
                self.state.as_mut().get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA384_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384Result(
                self.state.as_mut().get_inner_mut(),
                result.as_mut_ptr(),
            );
        }
        result
    }
}

/// Creates a clone of the current `HmacSha384State`. Clone will create a new state field but will reference the same
/// `expanded_key` of the current `HmacSha384State`.
impl Clone for HmacSha384State {
    // Clone will increase the refcount on the expanded_key field.
    fn clone(&self) -> Self {
        let mut new_state = HmacSha384State {
            state: HmacSha384Inner::new(),
            key: Arc::clone(&self.key), // Clone to increase ref count.
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384StateCopy(
                self.state.get_inner(),
                new_state.key.get_inner(), // Use new ref counted key.
                new_state.state.as_mut().get_inner_mut(),
            );
        }
        new_state
    }
}

impl Drop for HmacSha384State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.state.as_mut().get_inner_mut() as *mut c_void,
                mem::size_of_val(&self.state.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

#[allow(clippy::unnecessary_mut_passed)]
/// Stateless HMAC function for HmacSha384.
///
/// `key` is a reference to a key.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA384_HMAC_RESULT_SIZE`. This call can fail with a `SymCryptError`.
pub fn hmac_sha384(
    key: &[u8],
    data: &[u8],
) -> Result<[u8; SHA384_HMAC_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0u8; SHA384_HMAC_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha384ExpandedKey::new(key)?;
        match symcrypt_sys::SymCryptHmacSha384ExpandKey(
            &mut expanded_key.as_mut().get_unchecked_mut().inner,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha384(
                    &mut expanded_key.as_mut().get_unchecked_mut().inner,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(result)
            }
            err => Err(err.into()),
        }
    }
}

/// `HmacSha512ExpandedKey` is a struct that represents the expanded key for the [`HmacSha512State`].
/// The key wrapping so that it can be independently dropped after its ref count has gone to 0.
struct HmacSha512ExpandedKey {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA512_EXPANDED_KEY,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha512ExpandedKey {
    fn new(key: &[u8]) -> Result<Pin<Box<Self>>, SymCryptError> {
        let mut expanded_key = Box::pin(HmacSha512ExpandedKey {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA512_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        });

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha512ExpandKey(
                &mut expanded_key.as_mut().get_unchecked_mut().inner,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
                err => Err(err.into()),
            }
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA512_EXPANDED_KEY {
        &self.inner as *const _
    }
}

// Since HmacSha512ExpandedKey can be referenced multiple times, HmacSha512ExpandedKey must be ref counted and there needs to be a separate drop().
impl Drop for HmacSha512ExpandedKey {
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

/// `HmacSha512State` is a struct that represents a stateful HMAC using SHA512 and implements the [`HmacState`] trait.
pub struct HmacSha512State {
    // SymCrypt expects the address for its structs to stay static through the struct's lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.

    // Using an `HmacSha512Inner` state that is Pin<Box<>>'d. Memory allocation is not handled by SymCrypt and Self is moved
    // around when returning from `HmacSha512State::new()`. Box<> heap allocates the memory and ensures that it does not move
    // within its lifetime.
    state: Pin<Box<HmacSha512Inner>>,

    // Must Arc<> the expanded_key field since it must be ref counted; clones of HmacSha512State will reference the same expanded key.
    // Arc<T> pointer can move, but its reference T is Pin<Box<>>'d to ensure that the address does not move during its lifetime.
    key: Arc<Pin<Box<HmacSha512ExpandedKey>>>,
}

struct HmacSha512Inner {
    // inner represents the actual HMAC state from SymCrypt.
    inner: symcrypt_sys::SYMCRYPT_HMAC_SHA512_STATE,

    // _pinned is a marker to ensure that instances of the inner state cannot be moved once pinned.
    // This prevents the struct from implementing the Unpin trait, enforcing that any
    // references to this structure remain valid throughout its lifetime.
    _pinned: PhantomPinned,
}

impl HmacSha512Inner {
    fn new() -> Pin<Box<Self>> {
        Box::pin(HmacSha512Inner {
            inner: symcrypt_sys::SYMCRYPT_HMAC_SHA512_STATE::default(),
            _pinned: PhantomPinned,
        })
    }

    /// Get a mutable pointer to the inner SymCrypt state.
    ///
    /// This is primarily meant to be used while making calls to the underlying SymCrypt APIs.
    /// This function returns a pointer to pinned data, which means callers must not use the pointer to move the data out of its location.
    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_HMAC_SHA512_STATE {
        unsafe {
            // SAFETY: Accessing the inner state of the pinned data.
            &mut self.get_unchecked_mut().inner as *mut _
        }
    }

    /// Safe method to access the inner state immutably.
    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_HMAC_SHA512_STATE {
        &self.inner as *const _
    }
}

impl HmacSha512State {
    /// `new()` takes in a `&[u8]` reference to a key and can return a [`SymCryptError`] that is propagated back to the caller.
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let expanded_key = HmacSha512ExpandedKey::new(key)?;
        let mut inner_state = HmacSha512Inner::new();

        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha512Init(
                inner_state.as_mut().get_inner_mut(),
                expanded_key.get_inner(),
            );
        }

        Ok(HmacSha512State {
            state: inner_state,
            key: Arc::new(expanded_key),
        })
    }
}

impl HmacState for HmacSha512State {
    type Result = [u8; SHA512_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha512Append(
                self.state.as_mut().get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA512_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha512Result(
                self.state.as_mut().get_inner_mut(),
                result.as_mut_ptr(),
            );
        }
        result
    }
}

/// Creates a clone of the current `HmacSha512State`. Clone will create a new state field but will reference the same
/// `expanded_key` of the current `HmacSha512State`.
impl Clone for HmacSha512State {
    // Clone will increase the refcount on the expanded_key field.
    fn clone(&self) -> Self {
        let mut new_state = HmacSha512State {
            state: HmacSha512Inner::new(),
            key: Arc::clone(&self.key), // Clone to increase ref count.
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha512StateCopy(
                self.state.get_inner(),
                new_state.key.get_inner(), // Use new ref counted key.
                new_state.state.as_mut().get_inner_mut(),
            );
        }
        new_state
    }
}

impl Drop for HmacSha512State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.state.as_mut().get_inner_mut() as *mut c_void,
                mem::size_of_val(&self.state.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

#[allow(clippy::unnecessary_mut_passed)]
/// Stateless HMAC function for HmacSha512.
///
/// `key` is a reference to a key.
///
/// `data` is a reference to an array of arbitrary length.
///
/// `result` is an array of size `SHA512_HMAC_RESULT_SIZE`. This call can fail with a `SymCryptError`.
pub fn hmac_sha512(
    key: &[u8],
    data: &[u8],
) -> Result<[u8; SHA512_HMAC_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0u8; SHA512_HMAC_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha512ExpandedKey::new(key)?;
        match symcrypt_sys::SymCryptHmacSha512ExpandKey(
            &mut expanded_key.as_mut().get_unchecked_mut().inner,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha512(
                    &mut expanded_key.as_mut().get_unchecked_mut().inner,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(result)
            }
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    // Note: by default sha1 and md5 are turned off, to enable for testing you can use:
    // cargo test --features sha1,md5
    use super::*;

    fn test_generic_hmac_state<H: HmacState>(mut hmac_state: H, data: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(data);
        let result = hmac_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    fn test_generic_state_clone<H: HmacState>(mut hmac_state: H, data: &[u8])
    where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(&data);
        let new_hmac_state = hmac_state.clone();

        let result = new_hmac_state.result();
        assert_eq!(hex::encode(result), hex::encode(hmac_state.result()));
    }

    fn test_generic_state_multiple_append<H: HmacState>(
        mut hmac_state: H,
        data_1: &[u8],
        data_2: &[u8],
        expected: &str,
    ) where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(&data_1);
        hmac_state.append(&data_2);

        let result = hmac_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    #[cfg(feature = "md5")]
    #[test]
    pub fn test_hmac_md5() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "c9e99a43cd8fa24a840aa85c7cca0061";

        let hmac_test = HmacMd5State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected)
    }

    #[cfg(feature = "md5")]
    #[test]
    pub fn test_hmac_md5_state_clone() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("68656c6c6f20776f726c64").unwrap();

        let hmac_state = HmacMd5State::new(&p_key).unwrap();
        test_generic_state_clone(hmac_state, &data);
    }

    #[cfg(feature = "md5")]
    #[test]
    fn test_hmac_md5_multiple_append() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data_1 = hex::decode("68656c6c6f").unwrap();
        let data_2 = hex::decode("20776f726c64").unwrap();
        let expected = "42a97a3f45d7fef6108e02f6ee71f49b";

        test_generic_state_multiple_append(
            HmacMd5State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[cfg(feature = "md5")]
    #[test]
    pub fn test_stateless_hmac_md5() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("68656c6c6f20776f726c64").unwrap();
        let expected = "b109c0856bad128a6b615e3418b08181";

        let result = hmac_md5(&p_key, &data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[cfg(feature = "sha1")]
    #[test]
    pub fn test_hmac_sha1() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "a040bd89759c8e9bd034445344436956b6af1635";

        let hmac_test = HmacSha1State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected)
    }

    #[cfg(feature = "sha1")]
    #[test]
    pub fn test_hmac_sha1_state_clone() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("68656c6c6f20776f726c64").unwrap();

        let hmac_state = HmacSha1State::new(&p_key).unwrap();
        test_generic_state_clone(hmac_state, &data);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_hmac_sha1_multiple_append() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data_1 = hex::decode("68656c6c6f").unwrap();
        let data_2 = hex::decode("20776f726c64").unwrap();
        let expected = "3fc1da114bca53529bcf5eabe16418a4027c6e7f";

        test_generic_state_multiple_append(
            HmacSha1State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[cfg(feature = "sha1")]
    #[test]
    pub fn test_stateless_hmac_sha1() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("73796d637279707420697320636f6f6c").unwrap();
        let expected = "de5b35480010f91338befde41808f4b50caa40d1";

        let result = hmac_sha1(&p_key, &data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_sha256() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "915cb2c078aaf5dfb3560cf6d96997e987b2de5cd46f9a2ef92493bfc34bab16";

        let hmac_test = HmacSha256State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected)
    }

    #[test]
    pub fn test_hmac_sha256_state_clone() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();

        let hmac_state = HmacSha256State::new(&p_key).unwrap();
        test_generic_state_clone(hmac_state, &data);
    }

    #[test]
    fn test_hmac_sha256_multiple_append() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data_1 = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bf").unwrap();
        let data_2 = hex::decode("d8beaa80dc").unwrap();
        let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";

        test_generic_state_multiple_append(
            HmacSha256State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[test]
    pub fn test_stateless_hmac_sha256() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();
        let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";

        let result = hmac_sha256(&p_key, &data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_sha384() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212ed65d33a").unwrap();
        let expected = "864c0a933ee2fe540e4444399add1cd94ff6e4e14248eaf6df7127cd12c7a9e0f7bd92b303715c06d1c6481114d22167";

        let hmac_test = HmacSha384State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected);
    }

    #[test]
    pub fn test_hmac_sha384_state_clone() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212ed65d33a").unwrap();

        let hmac_state = HmacSha384State::new(&p_key).unwrap();
        test_generic_state_clone(hmac_state, &data);
    }

    #[test]
    fn test_hmac_sha384_multiple_append() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data_1 = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212").unwrap();
        let data_2 = hex::decode("ed65d33a").unwrap();
        let expected = "864c0a933ee2fe540e4444399add1cd94ff6e4e14248eaf6df7127cd12c7a9e0f7bd92b303715c06d1c6481114d22167";

        test_generic_state_multiple_append(
            HmacSha384State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[test]
    pub fn test_stateless_hmac384() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "ad88735f29e167dabded11b57e168f0b773b2985f4c2d2234c8d7a6bf01e2a791590bc0165003f9a7e47c4c687622fd6";

        let result = hmac_sha384(&p_key, &data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_512() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "61152f47382fe24ac39daf80f66a76c7e74678cc5670035ec6a2a3d179aebd4eadc0d2a640e30e37d05a3942a7a3e192ce812e7e77c8549abdb7bfc153f5fa87";

        let hmac_test = HmacSha512State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected)
    }

    #[test]
    pub fn test_hmac_sha512_state_clone() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("68656c6c6f20776f726c64").unwrap();

        let hmac_state = HmacSha512State::new(&p_key).unwrap();
        test_generic_state_clone(hmac_state, &data);
    }

    #[test]
    fn test_hmac_sha512_multiple_append() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data_1 = hex::decode("68656c6c6f").unwrap();
        let data_2 = hex::decode("20776f726c64").unwrap();
        let expected = "2665c2835d7759b0be0485f0a6c9538378e4edfa27e985935990c3d92378060d6022e48b8ee7f07ba0369690ac7f51e484bfea37908b3d001a1f344cc15483b7";

        test_generic_state_multiple_append(
            HmacSha512State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[test]
    pub fn test_stateless_hmac_sha512() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("68656c6c6f20776f726c64").unwrap();
        let expected = "2665c2835d7759b0be0485f0a6c9538378e4edfa27e985935990c3d92378060d6022e48b8ee7f07ba0369690ac7f51e484bfea37908b3d001a1f344cc15483b7";

        let result = hmac_sha512(&p_key, &data).unwrap();
        assert_eq!(hex::encode(result), expected);
    }
}
