#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate libc;

// Include bindings depending on which OS and architecture we are compiling for. 
// If static feature is enabled, we will use bindgen to compile new bindings and include them.
// Current supported are:

// Windows:
// windows amd64 x86_64-pc-windows-msvc 
// windows arm64 aarch64-pc-windows-msvc

// Linux:
// linux arm64 aarch64-unknown-linux-gnu
// linux amd64 x86_64-unknown-linux-gnu


#[cfg(all(feature = "dynamic", target_os = "windows", target_arch = "x86_64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/windows_amd64_symcrypt_bindings.rs"));

#[cfg(feature = "static")] 
include!(concat!(env!("OUT_DIR"), "/symcrypt_static_generated_bindings.rs"));

