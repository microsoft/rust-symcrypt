# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**`symcrypt` version `0.3.0` is based off of `SymCrypt v103.5.0.1`.**

To view a detailed list of changes please see the [releases page](https://github.com/microsoft/rust-symcrypt/releases/).


### Supported Configurations

| Operating Environment | Architecture      | Dynamic Linking |
| --------------------- | ----------------- | ----------- |
| Windows user mode     | AMD64, ARM64      | ✅          | 
| Ubuntu (Tested via WSL)       | AMD64, ARM64      | ✅          | 
| Azure Linux 3         | AMD64, ARM64      | ✅          |
| Azure Linux 2         | AMD64, ARM64      | ❌          |


## Supported APIs

Hashing:
- Md5 ( stateful/stateless )
- Sha1 ( stateful/stateless )
- Sha256 ( stateful/stateless )
- Sha384 ( stateful/stateless )
- Sha512 ( stateful/stateless )
- Sha3_256 ( stateful/stateless )
- Sha3_384 ( stateful/stateless )
- Sha3_512 ( stateful/stateless )

HMAC:
- HmacMd5 ( stateful/stateless )
- HmacSha1 ( stateful/stateless )
- HmacSha256 ( stateful/stateless )
- HmacSha384 ( stateful/stateless )
- HmacSha512 ( stateful/stateless )

GCM:
- Encryption ( in place )
- Decryption ( in place )

ChaCha:
- Encryption ( in place )
- Decryption ( in place )

ECC:
- ECDH Secret Agreement ( NistP256, NistP384, NistP521, Curve25519)
- ECDSA Sign / Verify ( NistP256, NistP384 )

RSA: 
- PKCS1 ( Sign, Verify, Encrypt, Decrypt )
- PSS ( Sign, Verify )
- OAEP ( Encrypt, Decrypt )

**Note**: `Md5` and `Sha1` are considered weak crypto, and are only added for interop purposes.
To enable either `Md5` or `Sha1` pass the `md5` or `sha1` flag into your `Cargo.toml`
To enable all weak crypto, you can instead pass `weak-crypto` into your `Cargo.toml` instead.

---


## Quick Start Guide

`symcrypt` requires the `SymCrypt` library to be present during build, and subsequently run time. The configuration of this dynamic link will differ from Windows/Linux.

### Windows:
Download the latest `symcrypt.dll` and `symcrypt.lib` for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases) and place them somewhere accessible on your machine.

Set the required `SYMCRYPT_LIB_PATH` environment variable. You can do this by using the following command:

`setx SYMCRYPT_LIB_PATH "<your-path-to-symcrypt-lib-folder>"`

You will need to restart `terminal` / `cmd` after setting the environment variable.

For more information please see the `INSTALL.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

### Linux:

#### Azure Linux 3:
SymCrypt is pre-installed on Azure Linux 3 machines. Please ensure that you have the most up to date version of SymCrypt by updating via `tdnf`


#### Other distros:

Download the latest `libsymcrypt.so*` files for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases) and place them in your machines `$LD_LIBRARY_PATH`.


Support for `Debian` and `Ubuntu` via package manager is in the works, for now you must place the `libsymcrypt.so*` files into linker load path. The way that this is set will vary between distros. On most distros it set via the environment variable `$LD_LIBRARY_PATH`. 



For more information please see the `INSTALL.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

**Note:** This path may be different depending on your flavour of Linux, and architecture. The goal is to place the `libsymcrypt.so*` files in a location where the your Linux distro can find the required libs at build/run time.

---

## Usage
There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash. 

**Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.

### Instructions:  

add symcrypt to your `Cargo.toml` file.

```rust
[dependencies]
symcrypt = "0.3.0"
hex = "0.4.3"
```

include symcrypt in your code  

```rust
use symcrypt::hash::sha256; 
use hex;
fn main() {
    let data = hex::decode("641ec2cf711e").unwrap();
    let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

    let result = sha256(&data);
    assert_eq!(hex::encode(result), expected);
}
```
