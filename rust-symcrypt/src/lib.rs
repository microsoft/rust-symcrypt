//! # SymCrypt Rust Wrapper
//!
//! This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.
//!
//! This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.
//!
//! **Note:** As of version `0.1.3`, only `Windows AMD64`, and [`Linux Mariner`](https://github.com/microsoft/CBL-Mariner) are fully supported, with partial support for other linux distros such as `Ubuntu`.
//!
//! For ease of use, we have included a `symcrypttestmodule.dll` and `symcrypttestmodule.lib` in the `C:\Users\<your-user>\.cargo\registry\src\github.com-****\symcrypt-0.1.3\bin\amd64` folder for users on Windows. This will only work on computers using an `AMD64 (x86_64)` architecture.
//!
//! We have also included the required `libsymcrypt.so` files needed for Linux users. These `.so` files have been built for the [Mariner](https://github.com/microsoft/CBL-Mariner) distro, but have been tested and confirmed working on `Ubuntu 22.04.3` via WSL. Support for other distros aside from Mariner is not guaranteed. 
//! These files are included in the `~/.cargo/registry/src/github.com-****/symcrypt-0.1.3\bin\linux` folder for users on Linux. 
//! 
//! If you are using a different architecture, you will have to continue with the install and build steps outlined in the `BUILD.md` file.
//!
//! ## Quick Start Guide
//!
//! ### Windows:
//! Copy the `symcrypttestmodule.dll` and `symcrypttestmodule.lib` from the `C:\Users\<your-user>\.cargo\registry\src\github.com-****\symcrypt-0.1.3\bin\amd64` folder and place it into your `C:/Windows/System32` folder. 
//!
//! For more information please see the `BUILD.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page
//!
//! ### Linux:
//! Copy all of the `libsymcrypt.so*` files from the `~/.cargo/registry/src/github.com-****/symcrypt-0.1.3\bin\linux` folder and place it into your `/usr/bin/x86_64-linux-gnu/` folder. 
//!
//! For more information please see the `BUILD.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page
//!
//! **Note:** This path may be different depending on your flavour of linux. The goal is to place the `libsymcrypt.so*` files in a location where the your linux distro can find the required libs at build/run time.
//!
//! ## Supported APIs
//!
//! Hashing:
//! - Sha256 ( statefull/stateless )
//! - Sha384 ( statefull/stateless )
//!
//! HMAC:
//! - HmacSha256 ( statefull/stateless )
//! - HmacSha384 ( statefull/stateless )
//!
//! GCM:
//! - Encryption ( in place )
//! - Decryption ( in place )
//!
//! ChaCha:
//! - Encryption ( in place )
//! - Decryption ( in place )
//!
//! ECDH:
//! - ECDH Secret Agreement
//!
//! ## Usage
//! There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash. `symcrypt_init()` must be run before any other calls to the underlying symcrypt code.
//!
//! **Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.
//!
//! ### Instructions:
//!
//! add symcrypt to your `Cargo.toml` file.
//!
//! `symcrypt = "0.1.3"`
//! 
//! include symcrypt in your code
//!
//! ```rust
//! use symcrypt::hash::sha256;
//! use symcrypt::symcrypt_init;
//! 
//! fn  main() {
//!     symcrypt_init();
//!     let data = hex::decode("641ec2cf711e").unwrap();
//!     let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
//!
//!     let result = sha256(&data);
//!     assert_eq!(hex::encode(result), expected);
//! }
//! ```

use std::sync::Once;

pub mod block_ciphers;
pub mod chacha;
pub mod ecdh;
pub mod eckey;
pub mod errors;
pub mod gcm;
pub mod hash;
pub mod hmac;

/// `symcrypt_init()` must be called before any other function in the library. `symcrypt_init()` can be called multiple times,
///  all subsequent calls will be no-ops
pub fn symcrypt_init() {
    // Subsequent calls to `symcrypt_init()` after the first will not be invoked per .call_once docs https://doc.rust-lang.org/std/sync/struct.Once.html
    static INIT: Once = Once::new();
    unsafe {
        // SAFETY: FFI calls, blocking from being run again.
        INIT.call_once(|| {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        });
    }
}

/// Takes in a a buffer called buff and fills it with random bytes. This function cannot fail.
pub fn symcrypt_random(buff: &mut [u8]) {
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptRandom(buff.as_mut_ptr(), buff.len() as u64);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_symcrypt_random(){
        let mut buff_1 = [0u8; 10];
        let mut buff_2 = [0u8; 10];

        symcrypt_random(&mut buff_1);
        symcrypt_random(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}


