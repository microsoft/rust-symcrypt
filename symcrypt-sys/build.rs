use std::env;

fn main() {
    #[cfg(target_os = "windows")]
    {
        // Look for the .lib file during link time. We are searching the Windows/System32 path which is set as a current default to match
        // the long term placement of a Windows shipped symcrypt.dll 
        // println!("cargo:rustc-link-search=native=C:/Windows/System32/"); 

        let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
        println!("cargo:rustc-link-search=native={}", lib_path);

        println!("cargo:rustc-link-lib=static=symcrypt");

        // During run time, the OS will handle finding the symcrypt.dll file. The places Windows will look will be:
        // 1. The folder from which the application loaded.
        // 2. The system folder. Use the GetSystemDirectory function to retrieve the path of this folder.
        // 3. The Windows folder. Use the GetWindowsDirectory function to get the path of this folder.
        // 4. The current folder.
        // 5. The directories that are listed in the PATH environment variable. 

        // For more info please see: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

        // For the least invasive usage, we suggest putting the symcrypt.dll inside of same folder as the .exe file.

        // Note: This process is a band-aid. Long-term SymCrypt will be shipped with Windows which will make this process much more
        // streamlined. 
    }

    #[cfg(target_os = "linux")]
    {
        // Note: Linux support is based off of the Azure Linux distro.
        // This has been tested on Ubuntu 22.04.03 LTS on WSL and has confirmed working but support for other distros 
        // aside from Azure Linux is not guaranteed so YMMV. 
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the "lib" prefix for libsymcrypt is implied on Linux

        // You must put the included symcrypt.so files in your usr/lib/x86_64-linux-gnu/ path.
        // This is where the Linux ld linker will look for the symcrypt.so files.

        // Note: This process is a band-aid. Long-term, our long term solution is to package manage SymCrypt for a subset of
        // Linux distros. 
    }
}
