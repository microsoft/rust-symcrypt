# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**Note:** As of version `0.2.0`, only `Windows AMD64`, and [`Linux Azure Linux`](https://github.com/microsoft/azurelinux) are fully supported, with partial support for other Linux distros such as `Ubuntu`.

## Quick Start Guide

### Windows:
Download and copy the `symcrypt.dll` and `symcrypt.lib` for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases/tag/v103.4.2) and place them in your `C:/Windows/System32` folder.

For more information please see the `BUILD.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

### Linux:
Download and copy all of the `libsymcrypt.so*` files for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases/tag/v103.4.2) and place them into your `/usr/bin/x86_64-linux-gnu/` folder.

For more information please see the `BUILD.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

**Note:** This path may be different depending on your flavour of Linux. The goal is to place the `libsymcrypt.so*` files in a location where the your Linux distro can find the required libs at build/run time.


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
