#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate libc;
use std::sync::Once;
use ctor::ctor;
mod symcrypt_bindings;

// // if "dynamic" use this:
// #[cfg(feature = "dynamic")]
// pub use symcrypt_bindings::*;



// if static use the static bindings.
#[cfg(feature = "static")] 
// include!(concat!(env!("OUT_DIR"), "/symcrypt_static_generated_bindings.rs"));

pub use symcrypt_bindings::*;

// if "static": use this: 
// pub use symcrypt_static_generated_bindings;

// #[ctor]
// fn symcrypt_init() {
//     static INIT: Once = Once::new();
//     println!("################ running init()");
//     unsafe { 
//         INIT.call_once(|| {
//             // Initialize SymCrypt
//             symcrypt_bindings::SymCryptInit();
//             // Initialize SymCrypt module
//             symcrypt_bindings::SymCryptModuleInit(
//                 SYMCRYPT_CODE_VERSION_API,
//                 SYMCRYPT_CODE_VERSION_MINOR,
//             );
//         });
//     }
// }
