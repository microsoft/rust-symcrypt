# SymCrypt Rust Wrapper
This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**`symcrypt` version `0.6.0` is based off of `SymCrypt v103.8.0`.** You must use a version that is greater than or equal to `SymCrypt v103.8.0`. 

To view a detailed list of changes please see the [releases page](https://github.com/microsoft/rust-symcrypt/releases/).


### Supported Configurations
| Operating Environment | Architecture      | Dynamic Linking | Static Linking |
| --------------------- | ----------------- | --------------- | -------------- |
| Windows user mode     | AMD64, ARM64      | ✅              | ✅  ⚠️       |
| Ubuntu                | AMD64, ARM64      | ✅              | ✅  ⚠️       |
| Azure Linux 3         | AMD64, ARM64      | ✅              | ✅  ⚠️       |

**Note:** ⚠️ Static linking **only** meant to be used for rapid development and testing. Static linking is highly experimental, not optimized, does not offer FIPS and is **not to be used in production or release builds.** For more information please see the `Quick Start Guide` below. 

---

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

HKDF:
- HmacMd5
- HmacSha1
- HmacSha256
- HmacSha384
- HmacSha512

Encryption: 
- AES-GCM Encrypt/Decrypt
- ChaCha20-Poly1305 Encrypt/Decrypt
- AES-CBC Encrypt/Decrypt

ECC:
- ECDH Secret Agreement ( NistP256, NistP384, NistP521, Curve25519)
- ECDSA Sign / Verify ( NistP256, NistP384, NistP521 )

RSA: 
- PKCS1 ( Sign, Verify, Encrypt, Decrypt )
- PSS ( Sign, Verify )
- OAEP ( Encrypt, Decrypt )

**Note**: `Md5` and `Sha1`, and `PKCS1 Encrypt/Decrypt` are considered weak crypto, and are only added for interop purposes.
To enable either `Md5` or `Sha1`, or `Pkcs1 Encrypt/Decrypt` pass the `md5` or `sha1` or `pkcs1-encrypt-decrypt` flag into your `Cargo.toml`. 

---

## Quick Start Guide

As of version `0.6.0`,  the `symcrypt` crate can take advantage of both static and dynamic linking. Dynamic linking is enabled by default.

---
## Dynamic Linking:


Dynamic linking is set by default, meaning if you do not explicitly set the `static` feature, the `symcrypt` crate will operate under the assumption that you have followed following instructions for configuring your system to do a dynamic link of the `SymCrypt` library. 


### Windows:
Download the latest `symcrypt.dll` and `symcrypt.lib` for your corresponding CPU architecture from the [SymCrypt Releases Page](https://github.com/microsoft/SymCrypt/releases) and place them somewhere accessible on your machine.
Set the required `SYMCRYPT_LIB_PATH` environment variable. You can do this by using the following command:
`setx SYMCRYPT_LIB_PATH "<your-path-to-symcrypt-lib-folder>"`

You will need to restart `terminal` / `cmd` after setting the environment variable.

For more information please see `INSTALL.md`.

### Linux:

#### Azure Linux 3:
SymCrypt is pre-installed on Azure Linux 3 machines. Please ensure that you have the most up to date version of SymCrypt by updating via `tdnf`.

#### Other distros:

For Ubuntu, you can install SymCrypt via package manager by connecting to PMC ( Example shown for Ubuntu `24.04` ):

1. `curl -sSL -O https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb` 
2. `sudo dpkg -i packages-microsoft-prod.deb`
3. `sudo apt-get update`
4. `sudo apt-get install symcrypt`

For more info on connecting to PMC please see: [Connecting to PMC](https://learn.microsoft.com/en-us/linux/packages) 

If you want to try connecting with another flavour of Linux, or for more info please see `INSTALL.md`

---
## Static Linking:

**NOTE: Static linking is highly experimental and should not be used in production and or release builds. If you are Microsoft employee please contact the SymCrypt team for more info.**

Static linking works by building the `SymCrypt` library from source and static linking to lib that is produced, this will result in longer build times and larger binaries but gives the added benefit of not worrying about the distribution of a dynamic library. 

If you want to enable the `static` feature for rapid development and ease of use, please add the `static` feature in your `Cargo.toml`

```cargo
[dependencies]
symcrypt = {vesrion = "0.6.0", features = ["static"]}
hex = "0.4.3"
``` 
---

## Usage
There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash. 
**Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.

### Instructions:  

Add symcrypt to your `Cargo.toml` file.

If static linking:
```cargo
[dependencies]
symcrypt = {vesrion = "0.6.0", features = ["static"]}
hex = "0.4.3"
```


If dynamic linking:
```cargo
[dependencies]
symcrypt = {vesrion = "0.6.0"}
hex = "0.4.3"
```

Include symcrypt in your code  

```rust
use symcrypt::hash::sha256; 
use hex;
let data = hex::decode("641ec2cf711e").unwrap();
let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";
let result = sha256(&data);
assert_eq!(hex::encode(result), expected);
```
