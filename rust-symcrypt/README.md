# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**Note:** As of version `0.2.0`, only `Windows AMD64`, and [`Linux Mariner`](https://github.com/microsoft/CBL-Mariner) are fully supported, with partial support for other linux distros such as `Ubuntu`.

For ease of use, we have included a `symcrypt.dll` and `symcrypt.lib` in the `bin/amd64/` folder for users on Windows. This will only work on computers using an `AMD64 (x86_64)` architecture.

We have also included the required `libsymcrypt.so` files needed for Linux users. These `.so` files have been built for the [Mariner](https://github.com/microsoft/CBL-Mariner) distro, but have been tested and confirmed working on `Ubuntu 22.04.3` via WSL. Support for other distros aside from Mariner is not guaranteed. 

If you are using a different architecture, you will have to continue with the install and build steps outlined in the `BUILD.md` file.

## Quick Start Guide
**Note:** At the moment the provided symcrypt.dll is not production signed and not FIPS compliant and should only be used in the interm until an official production signed symcrypt.dll is available.

### Windows:
Copy the `symcrypt.dll` and `symcrypt.lib` from the `/bin/amd64` folder and place it into your `C:/Windows/System32` folder. 

For more information please see the `BUILD.md` file

### Linux:
Copy all of the `libsymcrypt.so*` files from the `/bin/linux` folder and place it into your `/usr/bin/x86_64-linux-gnu/` folder. 

For more information please see the `BUILD.md` file

**Note:** This path may be different depending on your flavour of linux. The goal is to place the `libsymcrypt.so*` files in a location where the your linux distro can find the required libs at build/run time.


## Supported APIs

Hashing:
- Sha256 ( statefull/stateless )
- Sha384 ( statefull/stateless )

HMAC:
- HmacSha256 ( statefull/stateless )
- HmacSha384 ( statefull/stateless )

GCM:
- Encryption ( in place )
- Decryption ( in place )

ChaCha:
- Encryption ( in place )
- Decryption ( in place )

ECDH:
- ECDH Secret Agreement

## Usage
There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash. `symcrypt_init()` must be run before any other calls to the underlying symcrypt code.

**Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.

### Instructions:  

add symcrypt to your `Cargo.toml` file.

```rust
[dependencies]
symcrypt = "0.2.0"
hex = "0.4.3"
```

include symcrypt in your code  

```rust
use symcrypt::hash::sha256; 
use symcrypt::symcrypt_init();
use hex;
fn main() {
    symcrpyt_init();
    let data = hex::decode("641ec2cf711e").unwrap();
    let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

    let result = sha256(&data);
    assert_eq!(hex::encode(result), expected);
}
```
