#[cfg(target_os = "windows")]
use std::env;

fn main() {
    #[cfg(target_os = "windows")]
    {
        // Look for the .lib file during link time. We are searching the PATH for symcrypt.dll
        let lib_path = env::var("SYMCRYPT_LIB_PATH")
            .unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set, for more information please see: https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide"));
        println!("cargo:rustc-link-search=native={}", lib_path);

        println!("cargo:rustc-link-lib=dylib=symcrypt");

        // During run time, the OS will handle finding the symcrypt.dll file. The places Windows will look will be:
        // 1. The folder from which the application loaded.
        // 2. The system folder. Use the GetSystemDirectory function to retrieve the path of this folder.
        // 3. The Windows folder. Use the GetWindowsDirectory function to get the path of this folder.
        // 4. The current folder.
        // 5. The directories that are listed in the PATH environment variable.

        // For more info please see: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the "lib" prefix for libsymcrypt is implied on Linux

        // If you are using Azure Linux 3, you can get the required symcrypt.so via tdnf.
        // If you are using Ubuntu, you can get the required symcrypt.so via PMC.
        // Please see the quick start guide for more information.

        // If you are using a different Linux distro, you will need to configure your distro's
        // LD linker to find the required symcrypt.so files.
    }
}
