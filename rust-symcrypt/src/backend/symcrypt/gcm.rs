use crate::errors::SymCryptError;
use crate::symcrypt_init;
use core::ffi::c_void;
use std::marker::PhantomPinned;
use std::mem;
use std::pin::Pin;
use std::ptr;

struct GcmInnerKey {
    inner: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
    _pinned: PhantomPinned,
}

impl GcmInnerKey {
    fn new() -> Pin<Box<Self>> {
        Box::pin(GcmInnerKey {
            inner: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default(),
            _pinned: PhantomPinned,
        })
    }

    fn get_inner_mut(self: Pin<&mut Self>) -> *mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY {
        unsafe { &mut self.get_unchecked_mut().inner as *mut _ }
    }

    fn get_inner(&self) -> *const symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY {
        &self.inner as *const _
    }
}

impl Drop for GcmInnerKey {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner) as *mut c_void,
                mem::size_of_val(&self.inner) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub struct GcmExpandedKey {
    expanded_key: Pin<Box<GcmInnerKey>>,
    key_length: usize,
}

impl std::fmt::Debug for GcmExpandedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcmExpandedKey")
            .field("key_length", &self.key_length)
            .finish_non_exhaustive()
    }
}

unsafe impl Send for GcmExpandedKey {}
unsafe impl Sync for GcmExpandedKey {}

impl GcmExpandedKey {
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut expanded_key = GcmInnerKey::new();
        let block_cipher = unsafe { symcrypt_sys::SymCryptAesBlockCipher };
        let status = unsafe {
            symcrypt_sys::SymCryptGcmExpandKey(
                expanded_key.as_mut().get_inner_mut(),
                block_cipher,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            )
        };
        match status {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(GcmExpandedKey {
                expanded_key,
                key_length: key.len(),
            }),
            err => Err(err.into()),
        }
    }

    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        symcrypt_init();
        unsafe {
            symcrypt_sys::SymCryptGcmEncrypt(
                self.expanded_key.get_inner(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        symcrypt_init();
        let status = unsafe {
            symcrypt_sys::SymCryptGcmDecrypt(
                self.expanded_key.get_inner(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            )
        };
        match status {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }

    pub fn key_len(&self) -> usize {
        self.key_length
    }
}
