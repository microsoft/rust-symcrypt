use crate::errors::SymCryptError;
use crate::hash::{HashAlgorithm, HashState, SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE};
use crate::hash::{SHA3_256_RESULT_SIZE, SHA3_384_RESULT_SIZE, SHA3_512_RESULT_SIZE};
use crate::symcrypt_init;
use core::ffi::c_void;
use std::marker::PhantomPinned;
use std::mem;
use std::pin::Pin;

// --- SHA-256 ---

pub struct Sha256State(Pin<Box<Sha256InnerState>>);

struct Sha256InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA256_STATE,
    _pinned: PhantomPinned,
}

impl Sha256State {
    pub fn new() -> Self {
        symcrypt_init();
        let mut instance = Sha256State(Box::pin(Sha256InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA256_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Init(instance.get_inner_mut());
        }
        instance
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA256_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA256_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl HashState for Sha256State {
    type Result = [u8; SHA256_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA256_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

impl Clone for Sha256State {
    fn clone(&self) -> Self {
        let mut new_state = Sha256State(Box::pin(Sha256InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA256_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_RESULT_SIZE] {
    symcrypt_init();
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

// --- SHA-384 ---

pub struct Sha384State(Pin<Box<Sha384InnerState>>);

struct Sha384InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA384_STATE,
    _pinned: PhantomPinned,
}

impl Sha384State {
    pub fn new() -> Self {
        symcrypt_init();
        let mut instance = Sha384State(Box::pin(Sha384InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA384_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Init(instance.get_inner_mut());
        }
        instance
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA384_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA384_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl Default for Sha384State {
    fn default() -> Self {
        Self::new()
    }
}

impl HashState for Sha384State {
    type Result = [u8; SHA384_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA384_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

impl Clone for Sha384State {
    fn clone(&self) -> Self {
        let mut new_state = Sha384State(Box::pin(Sha384InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA384_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn sha384(data: &[u8]) -> [u8; SHA384_RESULT_SIZE] {
    symcrypt_init();
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

// --- SHA-512 ---

pub struct Sha512State(Pin<Box<Sha512InnerState>>);

struct Sha512InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA512_STATE,
    _pinned: PhantomPinned,
}

impl Sha512State {
    pub fn new() -> Self {
        symcrypt_init();
        let mut instance = Sha512State(Box::pin(Sha512InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA512_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Init(instance.get_inner_mut());
        }
        instance
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA512_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA512_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl Default for Sha512State {
    fn default() -> Self {
        Self::new()
    }
}

impl HashState for Sha512State {
    type Result = [u8; SHA512_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA512_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

impl Clone for Sha512State {
    fn clone(&self) -> Self {
        let mut new_state = Sha512State(Box::pin(Sha512InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA512_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha512StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha512State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn sha512(data: &[u8]) -> [u8; SHA512_RESULT_SIZE] {
    symcrypt_init();
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

// --- SHA3-256 ---
// Breaking change (0.6.0): new() returns Result for cross-platform consistency with BCrypt backend.

pub struct Sha3_256State(Pin<Box<Sha3_256InnerState>>);

struct Sha3_256InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA3_256_STATE,
    _pinned: PhantomPinned,
}

impl Sha3_256State {
    pub fn new() -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut instance = Sha3_256State(Box::pin(Sha3_256InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_256_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_256Init(instance.get_inner_mut());
        }
        Ok(instance)
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA3_256_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA3_256_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl HashState for Sha3_256State {
    type Result = [u8; SHA3_256_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_256Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_256_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_256Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_256
    }
}

impl Clone for Sha3_256State {
    fn clone(&self) -> Self {
        let mut new_state = Sha3_256State(Box::pin(Sha3_256InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_256_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_256StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha3_256State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_256(data: &[u8]) -> Result<[u8; SHA3_256_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0; SHA3_256_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha3_256(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    Ok(result)
}

// --- SHA3-384 ---
// Breaking change (0.6.0): new() returns Result for cross-platform consistency with BCrypt backend.

pub struct Sha3_384State(Pin<Box<Sha3_384InnerState>>);

struct Sha3_384InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA3_384_STATE,
    _pinned: PhantomPinned,
}

impl Sha3_384State {
    pub fn new() -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut instance = Sha3_384State(Box::pin(Sha3_384InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_384_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_384Init(instance.get_inner_mut());
        }
        Ok(instance)
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA3_384_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA3_384_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl HashState for Sha3_384State {
    type Result = [u8; SHA3_384_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_384Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_384_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_384Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_384
    }
}

impl Clone for Sha3_384State {
    fn clone(&self) -> Self {
        let mut new_state = Sha3_384State(Box::pin(Sha3_384InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_384_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_384StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha3_384State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_384(data: &[u8]) -> Result<[u8; SHA3_384_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0; SHA3_384_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha3_384(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    Ok(result)
}

// --- SHA3-512 ---
// Breaking change (0.6.0): new() returns Result for cross-platform consistency with BCrypt backend.

pub struct Sha3_512State(Pin<Box<Sha3_512InnerState>>);

struct Sha3_512InnerState {
    inner: symcrypt_sys::SYMCRYPT_SHA3_512_STATE,
    _pinned: PhantomPinned,
}

impl Sha3_512State {
    pub fn new() -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut instance = Sha3_512State(Box::pin(Sha3_512InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_512_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_512Init(instance.get_inner_mut());
        }
        Ok(instance)
    }

    fn get_inner_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_SHA3_512_STATE {
        unsafe { &mut self.0.as_mut().get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_SHA3_512_STATE {
        &self.0.as_ref().get_ref().inner as *const _
    }
}

impl HashState for Sha3_512State {
    type Result = [u8; SHA3_512_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_512Append(
                self.get_inner_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_512_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_512Result(self.get_inner_mut(), result.as_mut_ptr());
        }
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_512
    }
}

impl Clone for Sha3_512State {
    fn clone(&self) -> Self {
        let mut new_state = Sha3_512State(Box::pin(Sha3_512InnerState {
            inner: symcrypt_sys::SYMCRYPT_SHA3_512_STATE::default(),
            _pinned: PhantomPinned,
        }));
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha3_512StateCopy(self.get_inner(), new_state.get_inner_mut());
        }
        new_state
    }
}

impl Drop for Sha3_512State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                self.get_inner_mut() as *mut c_void,
                mem::size_of_val(&*self.get_inner()) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_512(data: &[u8]) -> Result<[u8; SHA3_512_RESULT_SIZE], SymCryptError> {
    symcrypt_init();
    let mut result = [0; SHA3_512_RESULT_SIZE];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha3_512(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    Ok(result)
}
