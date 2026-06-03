//! * `lib.rs` (this file) does the DLL loading: embedded bytes, extract to
//!   `%LOCALAPPDATA%`, `LoadLibraryExW`, resolve a small `Api` struct of
//!   function pointers via `GetProcAddress`.
//! * `hash.rs` exposes a friendly Rust API (`sha256()` free fn,
//!   `Sha256State` streaming) that calls through the resolved function
//!   pointers.
//!
//! `tests/hash.rs` hits the `hash` module to prove `include_bytes!` →
//! extract → LoadLibrary → GetProcAddress → call all work end-to-end.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

pub mod hash;

use std::ffi::{c_void, CStr};
use std::fs;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};

// 1) The embedded DLL.
const DLL_BYTES: &[u8] = include_bytes!("../symcrypt.dll");
const SYMCRYPT_VERSION: &str = "103.11.0";

// SHA-256 of `DLL_BYTES`, computed by `build.rs` from the same file.
// Included in the cache directory name so a patched DLL with the same
// `SYMCRYPT_VERSION` string can never silently reuse a stale cached copy.
const DLL_SHA256_HEX: &str = env!("DLL_SHA256_HEX");

// 2) Typed function pointers for the SymCrypt exports we use.


/// Opaque SymCrypt SHA-256 state.  Size + alignment match the C struct
/// `SYMCRYPT_SHA256_STATE` (128 bytes, 16-byte aligned).
#[repr(C, align(16))]
pub(crate) struct Sha256RawState(pub(crate) [u8; 128]);

pub(crate) struct Api {
    _handle: HMODULE,
    pub(crate) sha256: unsafe extern "C" fn(*const u8, usize, *mut u8),
    pub(crate) sha256_init: unsafe extern "C" fn(*mut Sha256RawState),
    pub(crate) sha256_append: unsafe extern "C" fn(*mut Sha256RawState, *const u8, usize),
    pub(crate) sha256_result: unsafe extern "C" fn(*mut Sha256RawState, *mut u8),
}

// SAFETY: the function pointers live for the lifetime of the loaded DLL
// (which is the lifetime of the process — we never unload).
unsafe impl Sync for Api {}
unsafe impl Send for Api {}

// 3) Lazy init: extract DLL, LoadLibrary, resolve the Api struct.

static API: OnceLock<Api> = OnceLock::new();

pub(crate) fn api() -> &'static Api {
    API.get_or_init(|| {
        let handle = extract_and_load();
        unsafe {
            Api {
                _handle: handle,
                sha256: mem::transmute::<*const c_void, unsafe extern "C" fn(*const u8, usize, *mut u8)>(
                    get_proc(handle, c"SymCryptSha256"),
                ),
                sha256_init: mem::transmute::<*const c_void, unsafe extern "C" fn(*mut Sha256RawState)>(
                    get_proc(handle, c"SymCryptSha256Init"),
                ),
                sha256_append: mem::transmute::<*const c_void, unsafe extern "C" fn(*mut Sha256RawState, *const u8, usize)>(
                    get_proc(handle, c"SymCryptSha256Append"),
                ),
                sha256_result: mem::transmute::<*const c_void, unsafe extern "C" fn(*mut Sha256RawState, *mut u8)>(
                    get_proc(handle, c"SymCryptSha256Result"),
                ),
            }
        }
    })
}

fn extract_and_load() -> HMODULE {
    // Cache layout: %LOCALAPPDATA%\Microsoft\SymCrypt\<version>\<sha256>\symcrypt.dll
    //
    // The sha256 segment makes the path content-addressed: if `DLL_BYTES`
    // changes (e.g. a patched DLL shipped under the same version string),
    // the cache directory name changes too, so we extract fresh bytes
    // instead of silently reusing stale ones.
    let cache = PathBuf::from(
        std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA env var must be set"),
    )
    .join("Microsoft")
    .join("SymCrypt")
    .join(SYMCRYPT_VERSION)
    .join(DLL_SHA256_HEX)
    .join("symcrypt.dll");

    if !cache.exists() {
        fs::create_dir_all(cache.parent().unwrap()).expect("create cache dir");
        fs::write(&cache, DLL_BYTES).expect("write embedded DLL to cache");
    }

    // SEARCH_SYSTEM32 + SEARCH_DLL_LOAD_DIR: dep DLLs (bcrypt, KERNEL32,
    // ntdll, api-ms-win-crt-*) resolve from System32; only the cache dir is
    // searched for the loaded DLL itself.  PATH, CWD, and user-added DLL
    // directories are NOT searched — hardens against DLL-planting in those
    // locations.  Confirmed via `dumpbin /dependents` that the embedded
    // symcrypt.dll only needs System32 deps.
    let mut wide: Vec<u16> = cache.as_os_str().encode_wide().collect();
    wide.push(0);
    const FLAGS: u32 = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
    let handle = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), FLAGS) };
    assert!(
        !handle.is_null(),
        "LoadLibraryExW failed for {}",
        cache.display()
    );
    handle
}

unsafe fn get_proc(handle: HMODULE, name: &CStr) -> *const c_void {
    let raw = unsafe { GetProcAddress(handle, name.as_ptr().cast()) }
        .unwrap_or_else(|| panic!("GetProcAddress NULL for {}", name.to_string_lossy()));
    raw as *const c_void
}
