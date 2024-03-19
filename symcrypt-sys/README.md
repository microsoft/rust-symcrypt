# SymCrypt Rust/C FFI Bindings
symcrypt-sys provides Rust/C FFI bindings for the [SymCrypt](https://github.com/microsoft/SymCrypt) library. 

This crate is supplementary to the `symcrypt`crate.

The bindings are checked into this crate in order to have better control over the binding generation as well as the exposed APIs from SymCrypt. To speed up the common case build process, the binding generation has been separated to `symcrypt-bindgen`

## Changelog

To view a detailed list of changes please see the [releases page](https://github.com/microsoft/rust-symcrypt/releases/).


## Usage 

Recommended usage is to take advantage of the `symcrypt` crate, which provides safe and rust idiomatic wrappers over the bindings.

However, If you want to access the bindings directly, you can add `symcrypt-sys` as a dependency in your rust project.

In your `Cargo.toml`
```Rust
symcrypt-sys = "0.2.0"
```
Then you can call the underlying SymCrypt code directly via the FFIs.
```Rust
unsafe {
    // SAFETY: FFI calls
	symcrypt_sys::SymCryptSha384(
	data.as_ptr(),
	data.len() as  symcrypt_sys::SIZE_T,
	result.as_mut_ptr(),
	);
}
```