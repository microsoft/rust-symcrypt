#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate libc;

// Include bindings depending on which OS and architecture we are compiling for. 
// Current supported are:

// Windows:
// windows amd64 x86_64-pc-windows-msvc 
// windows arm64 aarch64-pc-windows-msvc

// Linux:
// linux amd64 x86_64-unknown-linux-gnu
// linux arm64 aarch64-unknown-linux-gnu

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/windows_amd64_symcrypt_bindings.rs"));

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/linux_amd64_symcrypt_bindings.rs"));

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/linux_arm64_symcrypt_bindings.rs"));

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/windows_arm64_symcrypt_bindings.rs"));
