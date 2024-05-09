# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**Note:** As of version `0.2.0`, only `Windows AMD64`, and [`Azure Linux`](https://github.com/microsoft/azurelinux) are fully supported, with partial support for other Linux distros such as `Ubuntu`.

## Quick Start Guide

### Windows:
Download the `symcrypt.dll` and `symcrypt.lib` for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases/tag/v103.4.2) and place them somewhere accessible on your machine.

Set the required `SYMCRYPT_LIB_PATH` environment variable. You can do this by using the following command:

`setx SYMCRYPT_LIB_PATH "<your-path-to-symcrypt-lib-folder>"`

During runtime, Windows will handle finding all needed `dll`'s in order to run the intended program, this includes our `symcrypt.dll` file.

Here are 2 recommended options to ensure your `symcrypt.dll` is found by Windows during runtime, for more info please see [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order).

1. Put the `symcrypt.dll` in the same folder as your output `.exe` file. If you are doing development (not release), the common path will be: `C:\your-project\target\debug\`.
2. Permanently add the `symcrypt.dll` path into your System PATH environment variable. Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypt.lib`

For more information please see the `INSTALL.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

### Linux:
Download and all of the `libsymcrypt.so*` files for you corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases/tag/v103.4.2).

Support for `Debian` and `Ubuntu` via package manager is in the works, for now you must place the `libsymcrypt.so*` files into linker load path. The way that this is set will vary between distros. On most distros it set via the environment variable `$LD_LIBRARY_PATH`. 

Package manager support is already available if you are using `Azure Linux` via `tdnf install symcrypt`.

For more information please see the `INSTALL.md` file on the [`rust-symcrypt`](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt) page

**Note:** This path may be different depending on your flavour of Linux. The goal is to place the `libsymcrypt.so*` files in a location where the your Linux distro can find the required libs at build/run time.


## Supported APIs

 Hashing:
- Md5 ( statefull/stateless )
- Sha1 ( statefull/stateless )
- Sha256 ( statefull/stateless )
- Sha384 ( statefull/stateless )
- Sha512 ( statefull/stateless )

HMAC:
- HmacMd5 ( statefull/stateless )
- HmacSha1 ( statefull/stateless )
- HmacSha256 ( statefull/stateless )
- HmacSha384 ( statefull/stateless )
- HmacSha512 ( statefull/stateless )

GCM:
- Encryption ( in place )
- Decryption ( in place )

ChaCha:
- Encryption ( in place )
- Decryption ( in place )

ECDH:
- ECDH Secret Agreement

**Note**: `Md5` and `Sha1` are considered weak crypto, and are only added for interop purposes.
To enable either `Md5` or `Sha1` pass the `md5` or `sha1` flag into your `Cargo.toml`
To enable all weak crypto, you can instead pass `weak-crypto` into your `Cargo.toml` instead.

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
