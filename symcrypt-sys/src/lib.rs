#![doc = include_str!("../README.md")]
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
pub(crate) mod bindings;

pub use bindings::consts::*;
pub use bindings::fns_source::*;
pub use bindings::types::*;
