use crate::errors::SymCryptError;
use crate::hash::{
    HashAlgorithm, HashState,
    SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE,
    SHA3_256_RESULT_SIZE, SHA3_384_RESULT_SIZE, SHA3_512_RESULT_SIZE,
};
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

// BCrypt can fail here (NTSTATUS); SymCrypt has no equivalent, init is VOID.
fn open_algorithm(alg_id: *const u16, flags: u32) -> AlgHandle {
    let mut handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    let _status = unsafe {
        BCryptOpenAlgorithmProvider(&mut handle, alg_id, std::ptr::null(), flags)
    };
    AlgHandle(handle)
}

static SHA256_ALG: LazyLock<AlgHandle> = LazyLock::new(|| {
    open_algorithm(BCRYPT_SHA256_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG)
});

static SHA384_ALG: LazyLock<AlgHandle> = LazyLock::new(|| {
    open_algorithm(BCRYPT_SHA384_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG)
});

static SHA512_ALG: LazyLock<AlgHandle> = LazyLock::new(|| {
    open_algorithm(BCRYPT_SHA512_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG)
});

// BCrypt SHA-3 algorithm IDs — not in windows-sys, requires Windows 11 24H2+
const BCRYPT_SHA3_256_ALGORITHM: &[u16] = &[0x53, 0x48, 0x41, 0x33, 0x2D, 0x32, 0x35, 0x36, 0x00];
const BCRYPT_SHA3_384_ALGORITHM: &[u16] = &[0x53, 0x48, 0x41, 0x33, 0x2D, 0x33, 0x38, 0x34, 0x00];
const BCRYPT_SHA3_512_ALGORITHM: &[u16] = &[0x53, 0x48, 0x41, 0x33, 0x2D, 0x35, 0x31, 0x32, 0x00];

fn try_open_algorithm(alg_id: *const u16, flags: u32) -> Result<AlgHandle, i32> {
    let mut handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut handle, alg_id, std::ptr::null(), flags)
    };
    if status < 0 {
        return Err(status);
    }
    Ok(AlgHandle(handle))
}

static SHA3_256_ALG: LazyLock<Result<AlgHandle, i32>> = LazyLock::new(|| {
    try_open_algorithm(BCRYPT_SHA3_256_ALGORITHM.as_ptr(), BCRYPT_HASH_REUSABLE_FLAG)
});

static SHA3_384_ALG: LazyLock<Result<AlgHandle, i32>> = LazyLock::new(|| {
    try_open_algorithm(BCRYPT_SHA3_384_ALGORITHM.as_ptr(), BCRYPT_HASH_REUSABLE_FLAG)
});

static SHA3_512_ALG: LazyLock<Result<AlgHandle, i32>> = LazyLock::new(|| {
    try_open_algorithm(BCRYPT_SHA3_512_ALGORITHM.as_ptr(), BCRYPT_HASH_REUSABLE_FLAG)
});

struct BcryptHashHandle(BCRYPT_HASH_HANDLE);

// SAFETY: BCrypt hash handles are opaque OS resources. All mutation requires &mut self.
unsafe impl Send for BcryptHashHandle {}
unsafe impl Sync for BcryptHashHandle {}

impl Drop for BcryptHashHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyHash(self.0);
        }
    }
}

impl BcryptHashHandle {
    // BCrypt can fail here (NTSTATUS); SymCrypt equivalent (SymCryptSha*Init) is VOID.
    fn new(alg: &LazyLock<AlgHandle>) -> Self {
        let mut handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let _status = unsafe {
            BCryptCreateHash(
                alg.0,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                BCRYPT_HASH_REUSABLE_FLAG,
            )
        };
        BcryptHashHandle(handle)
    }

    // BCrypt can fail here (NTSTATUS); SymCrypt equivalent (SymCryptSha*Append) is VOID.
    fn append(&mut self, data: &[u8]) {
        let _status = unsafe {
            BCryptHashData(self.0, data.as_ptr(), data.len() as u32, 0)
        };
    }

    // BCrypt can fail here (NTSTATUS); SymCrypt equivalent (SymCryptSha*Result) is VOID.
    fn finish(&mut self, output: &mut [u8]) {
        let _status = unsafe {
            BCryptFinishHash(self.0, output.as_mut_ptr(), output.len() as u32, 0)
        };
    }

    // BCrypt can fail here (NTSTATUS); SymCrypt equivalent (SymCryptSha*StateCopy) is VOID.
    fn duplicate(&self) -> Self {
        let mut new_handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let _status = unsafe {
            BCryptDuplicateHash(self.0, &mut new_handle, std::ptr::null_mut(), 0, 0)
        };
        BcryptHashHandle(new_handle)
    }
}

// --- SHA-256 ---

pub struct Sha256State {
    handle: BcryptHashHandle,
}

impl Sha256State {
    pub fn new() -> Self {
        Sha256State {
            handle: BcryptHashHandle::new(&SHA256_ALG),
        }
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
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA256_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

impl Clone for Sha256State {
    fn clone(&self) -> Self {
        Sha256State {
            handle: self.handle.duplicate(),
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_RESULT_SIZE] {
    let mut result = [0u8; SHA256_RESULT_SIZE];
    let _status = unsafe {
        BCryptHash(
            SHA256_ALG.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    result
}

// --- SHA-384 ---

pub struct Sha384State {
    handle: BcryptHashHandle,
}

impl Sha384State {
    pub fn new() -> Self {
        Sha384State {
            handle: BcryptHashHandle::new(&SHA384_ALG),
        }
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
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA384_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

impl Clone for Sha384State {
    fn clone(&self) -> Self {
        Sha384State {
            handle: self.handle.duplicate(),
        }
    }
}

pub fn sha384(data: &[u8]) -> [u8; SHA384_RESULT_SIZE] {
    let mut result = [0u8; SHA384_RESULT_SIZE];
    let _status = unsafe {
        BCryptHash(
            SHA384_ALG.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    result
}

// --- SHA-512 ---

pub struct Sha512State {
    handle: BcryptHashHandle,
}

impl Sha512State {
    pub fn new() -> Self {
        Sha512State {
            handle: BcryptHashHandle::new(&SHA512_ALG),
        }
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
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA512_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

impl Clone for Sha512State {
    fn clone(&self) -> Self {
        Sha512State {
            handle: self.handle.duplicate(),
        }
    }
}

pub fn sha512(data: &[u8]) -> [u8; SHA512_RESULT_SIZE] {
    let mut result = [0u8; SHA512_RESULT_SIZE];
    let _status = unsafe {
        BCryptHash(
            SHA512_ALG.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    result
}

// --- SHA3-256 ---
// Breaking change (0.6.0): new() returns Result — BCrypt SHA-3 requires Windows 11 24H2+.

pub struct Sha3_256State {
    handle: BcryptHashHandle,
}

impl Sha3_256State {
    pub fn new() -> Result<Self, SymCryptError> {
        let alg = match SHA3_256_ALG.as_ref() {
            Ok(h) => h,
            Err(&status) => return Err(crate::errors::map_ntstatus(status)),
        };
        let mut handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let status = unsafe {
            BCryptCreateHash(
                alg.0,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                BCRYPT_HASH_REUSABLE_FLAG,
            )
        };
        if status < 0 {
            return Err(crate::errors::map_ntstatus(status));
        }
        Ok(Sha3_256State {
            handle: BcryptHashHandle(handle),
        })
    }
}

impl HashState for Sha3_256State {
    type Result = [u8; SHA3_256_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_256_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_256
    }
}

impl Clone for Sha3_256State {
    fn clone(&self) -> Self {
        Sha3_256State {
            handle: self.handle.duplicate(),
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_256(data: &[u8]) -> Result<[u8; SHA3_256_RESULT_SIZE], SymCryptError> {
    let alg = match SHA3_256_ALG.as_ref() {
        Ok(h) => h,
        Err(&status) => return Err(crate::errors::map_ntstatus(status)),
    };
    let mut result = [0u8; SHA3_256_RESULT_SIZE];
    let status = unsafe {
        BCryptHash(
            alg.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    if status < 0 {
        return Err(crate::errors::map_ntstatus(status));
    }
    Ok(result)
}

// --- SHA3-384 ---
// Breaking change (0.6.0): new() returns Result — BCrypt SHA-3 requires Windows 11 24H2+.

pub struct Sha3_384State {
    handle: BcryptHashHandle,
}

impl Sha3_384State {
    pub fn new() -> Result<Self, SymCryptError> {
        let alg = match SHA3_384_ALG.as_ref() {
            Ok(h) => h,
            Err(&status) => return Err(crate::errors::map_ntstatus(status)),
        };
        let mut handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let status = unsafe {
            BCryptCreateHash(
                alg.0,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                BCRYPT_HASH_REUSABLE_FLAG,
            )
        };
        if status < 0 {
            return Err(crate::errors::map_ntstatus(status));
        }
        Ok(Sha3_384State {
            handle: BcryptHashHandle(handle),
        })
    }
}

impl HashState for Sha3_384State {
    type Result = [u8; SHA3_384_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_384_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_384
    }
}

impl Clone for Sha3_384State {
    fn clone(&self) -> Self {
        Sha3_384State {
            handle: self.handle.duplicate(),
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_384(data: &[u8]) -> Result<[u8; SHA3_384_RESULT_SIZE], SymCryptError> {
    let alg = match SHA3_384_ALG.as_ref() {
        Ok(h) => h,
        Err(&status) => return Err(crate::errors::map_ntstatus(status)),
    };
    let mut result = [0u8; SHA3_384_RESULT_SIZE];
    let status = unsafe {
        BCryptHash(
            alg.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    if status < 0 {
        return Err(crate::errors::map_ntstatus(status));
    }
    Ok(result)
}

// --- SHA3-512 ---
// Breaking change (0.6.0): new() returns Result — BCrypt SHA-3 requires Windows 11 24H2+.

pub struct Sha3_512State {
    handle: BcryptHashHandle,
}

impl Sha3_512State {
    pub fn new() -> Result<Self, SymCryptError> {
        let alg = match SHA3_512_ALG.as_ref() {
            Ok(h) => h,
            Err(&status) => return Err(crate::errors::map_ntstatus(status)),
        };
        let mut handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        let status = unsafe {
            BCryptCreateHash(
                alg.0,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                BCRYPT_HASH_REUSABLE_FLAG,
            )
        };
        if status < 0 {
            return Err(crate::errors::map_ntstatus(status));
        }
        Ok(Sha3_512State {
            handle: BcryptHashHandle(handle),
        })
    }
}

impl HashState for Sha3_512State {
    type Result = [u8; SHA3_512_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        self.handle.append(data);
    }

    fn result(&mut self) -> Self::Result {
        let mut result = [0u8; SHA3_512_RESULT_SIZE];
        self.handle.finish(&mut result);
        result
    }

    fn get_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha3_512
    }
}

impl Clone for Sha3_512State {
    fn clone(&self) -> Self {
        Sha3_512State {
            handle: self.handle.duplicate(),
        }
    }
}

// Breaking change (0.6.0): returns Result instead of bare array.
pub fn sha3_512(data: &[u8]) -> Result<[u8; SHA3_512_RESULT_SIZE], SymCryptError> {
    let alg = match SHA3_512_ALG.as_ref() {
        Ok(h) => h,
        Err(&status) => return Err(crate::errors::map_ntstatus(status)),
    };
    let mut result = [0u8; SHA3_512_RESULT_SIZE];
    let status = unsafe {
        BCryptHash(
            alg.0,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            result.as_mut_ptr(),
            result.len() as u32,
        )
    };
    if status < 0 {
        return Err(crate::errors::map_ntstatus(status));
    }
    Ok(result)
}
