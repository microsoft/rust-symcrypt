
# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

**Note:** As of version 0.1.0, only Windows AMD64 (x86_64) is supported.

## Installation
To use the SymCrypt crate, you must have a local version of [SymCrypt](https://github.com/microsoft/SymCrypt) downloaded.

Please follow the [Build Instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md) that is provided by SymCrypt to install SymCrypt for your target architecture.

Once SymCrypt is installed and built locally on your machine, we must configure your machine so that the SymCrypt crate's build script can easily find `symcrypttestmodule.dll` and `symcrypttestmodule.lib` 
which are both requirements for the SymCrypt crate. 

### Configure symcrypttestmodule.lib location
The `symcrypttestmodule.lib` can be found in the the following path after SymCrypt has been successfully downloaded and built. 

`C:\Your-Path-To-SymCrypt\SymCrypt\bin\lib`
 
The SymCrypt crate needs a static lib to link to during its build/link time. You must configure your system so that the SymCrypt crate's build script can easily find the needed `symcrypttestmodule.lib` file.

You can configure your system one of 3 ways.

1. Add the lib path as a one time cargo environment variable.
    ```powershell
    $env:RUSTFLAGS='-L C:\Your-Path-To-SymCrypt\SymCrypt\bin\lib'
    ```
    **Note:** This change will only persist within the current process, and you must re-set the PATH environment variable after closing the PowerShell window.

2. Manually copy the `symcrypttestmodule.lib` to `C:\Windows\System32`
    Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`

3. Permanently add the lib path into your system PATH environment variable. Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`
    This can be done manually or via powershell:
    ```Powershell
    [Environment]::SetEnvironmentVariable("RUSTFLAGS", "-L C:\Your-Path-To-SymCrypt\SymCrypt\bin\lib", [EnvironmentVariableTarget]::Machine)
    ```
**Option 1 or Option 2 is what is recommended for ease of use.**

### Configure symcrypttesmodule.dll location

The symcrypttestmodule.dll can be found in the the following path after SymCrypt has been successfully downloaded and built. 

`C:\Your-Path-To-SymCrypt\SymCrypt\bin\exe`

During runtime, Windows will handle finding all needed `dll`'s in order to run the intended program, this includes our `symcrypttestmodule.dll` file. The places Windows will look are:

1. The folder from which the application loaded.
2. The system folder. Use the `GetSystemDirectory` function to retrieve the path of this folder.
3. The Windows folder. Use the `GetWindowsDirectory` function to get the path of this folder.
4. The current folder.
5. The directories listed in the PATH environment variable.

For more info please see: [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

Here are 4 recommended options to ensure your `symcrypttestmodule.dll` is found by Windows during runtime.

1. Put the symcrypttesmodule.dll in the same folder as your output `.exe` file. If you are doing development (not release), the common path will be: `C:\your-project\target\debug\`.
2. Add the symcrypttestmoudle.dll path as a one time environment variable. 
    ```powershell
    $env:PATH = "C:\Your-Path-To-SymCrypt\SymCrypt\bin\exe;$env:PATH"
    ```
    **Note:** This change will only persist within the current process, and you must re-set the PATH environment variable after closing the PowerShell window.

3. Manually copy `symcrypttestmodule.dll` into your `C:/Windows/System32/` 
    Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.dll`
4. Permanently add the `symcrypttestmodule.dll` path into your System PATH environment variable.
    Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`
    This can be done manually or via powershell:
    ```Powershell
        [Environment]::SetEnvironmentVariable("PATH", "C:\Your-Path-To-SymCrypt\SymCrypt\bin\exe", [EnvironmentVariableTarget]::Machine)
    ```
**Option 3 or Option 4 is what is recommended for ease of use.** 


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
symcrypt = "0.1.0"
```

include symcrypt in your code  

```rust
use symcrypt::hash::sha256; 
use symcrpt::symcrypt_init;
fn  main() {
    symcrpyt_init();
    let data = hex::decode("641ec2cf711e").unwrap();
    let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

    let result = sha256(&data);
    assert_eq!(hex::encode(result), expected);
}
```
