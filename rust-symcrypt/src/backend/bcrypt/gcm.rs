use crate::errors::SymCryptError;
use std::sync::LazyLock;
use windows_sys::Win32::Security::Cryptography::*;

struct AlgHandle(BCRYPT_ALG_HANDLE);

// SAFETY: BCrypt algorithm handles are thread-safe for concurrent use after opening.
unsafe impl Send for AlgHandle {}
unsafe impl Sync for AlgHandle {}

impl Drop for AlgHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

// BCrypt can fail here (NTSTATUS); SymCrypt has no equivalent 
fn open_algorithm(alg_id: *const u16, flags: u32) -> AlgHandle {
    let mut handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    let _status = unsafe {
        BCryptOpenAlgorithmProvider(&mut handle, alg_id, std::ptr::null(), flags)
    };
    AlgHandle(handle)
}

static AES_GCM_ALG: LazyLock<AlgHandle> = LazyLock::new(|| {
    let handle = open_algorithm(BCRYPT_AES_ALGORITHM, 0);
    // BCrypt can fail here (NTSTATUS); SymCrypt has no equivalent, block cipher is a static pointer.
    let gcm_mode_bytes = 32u32;
    let _status = unsafe {
        BCryptSetProperty(
            handle.0,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_GCM as *const u8,
            gcm_mode_bytes,
            0,
        )
    };
    handle
});

#[derive(Debug)]
pub struct GcmExpandedKey {
    key_handle: BCRYPT_KEY_HANDLE,
    key_length: usize,
}

// SAFETY: BCrypt key handles are thread-safe for concurrent encrypt/decrypt (read-only on key state).
unsafe impl Send for GcmExpandedKey {}
unsafe impl Sync for GcmExpandedKey {}

impl Drop for GcmExpandedKey {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.key_handle);
        }
    }
}

fn make_auth_info(
    nonce: &[u8],
    auth_data: &[u8],
    tag: &mut [u8],
) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        pbNonce: nonce.as_ptr() as *mut u8,
        cbNonce: nonce.len() as u32,
        pbAuthData: auth_data.as_ptr() as *mut u8,
        cbAuthData: auth_data.len() as u32,
        pbTag: tag.as_mut_ptr(),
        cbTag: tag.len() as u32,
        pbMacContext: std::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    }
}

impl GcmExpandedKey {
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(SymCryptError::WrongKeySize);
        }

        let mut key_handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
        let status = unsafe {
            BCryptGenerateSymmetricKey(
                AES_GCM_ALG.0,
                &mut key_handle,
                std::ptr::null_mut(),
                0,
                key.as_ptr() as *mut u8,
                key.len() as u32,
                0,
            )
        };
        if status < 0 {
            return Err(crate::errors::map_ntstatus(status));
        }
        Ok(GcmExpandedKey {
            key_handle,
            key_length: key.len(),
        })
    }

    // BCrypt can fail here (NTSTATUS); SymCrypt equivalent (SymCryptGcmEncrypt) is VOID.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        let mut auth_info = make_auth_info(nonce.as_slice(), auth_data, tag);
        let mut bytes_written: u32 = 0;
        let _status = unsafe {
            BCryptEncrypt(
                self.key_handle,
                buffer.as_ptr(),
                buffer.len() as u32,
                &mut auth_info as *mut _ as *mut _,
                std::ptr::null_mut(),
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut bytes_written,
                0,
            )
        };
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        let mut tag_copy = vec![0u8; tag.len()];
        tag_copy.copy_from_slice(tag);
        let mut auth_info = make_auth_info(nonce.as_slice(), auth_data, &mut tag_copy);
        let mut bytes_written: u32 = 0;
        let status = unsafe {
            BCryptDecrypt(
                self.key_handle,
                buffer.as_ptr(),
                buffer.len() as u32,
                &mut auth_info as *mut _ as *mut _,
                std::ptr::null_mut(),
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut bytes_written,
                0,
            )
        };
        if status < 0 {
            return Err(crate::errors::map_ntstatus(status));
        }
        Ok(())
    }

    pub fn key_len(&self) -> usize {
        self.key_length
    }
}
