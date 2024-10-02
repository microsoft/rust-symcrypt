#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate libc;
use std::sync::Once;
use ctor::ctor;
// mod symcrypt_bindings;

// if "dynamic" use this:
#[cfg(all(feature = "dynamic", target_os = "windows", target_arch = "x86_64"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/windows_amd64_symcrypt_bindings.rs"));

// if static use the static bindings.
#[cfg(feature = "static")] 
include!(concat!(env!("OUT_DIR"), "/symcrypt_static_generated_bindings.rs"));

