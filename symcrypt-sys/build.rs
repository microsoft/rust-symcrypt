use std::env;
extern crate cmake;
use std::path::Path;
use std::process::Command;
mod generate_bindings;


fn main() {
    #[cfg(target_os = "windows")]
    {
        // Look for the .lib file during link time. We are searching the Windows/System32 path which is set as a current default to match
        // the long term placement of a Windows shipped symcrypt.dll 
        // println!("cargo:rustc-link-search=native=C:/Windows/System32/"); 


        #[cfg(feature = "dynamic")]
        {
            // if "dynamic" use this:
            let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
            println!("cargo:rustc-link-search=native={}", lib_path);

            println!("cargo:rustc-link-lib=dylib=symcrypt");

            
            // if "dynamic", we need to change the windows.h file to get the .h file from the release page. 
            // the bindings will be need to be combed through to add the dylink, also need to add a check for AZL2 since it does not have updated stuff. 
        }

        #[cfg(feature = "static")]
        {
            // if "static" use this: // make static default? 
            // add path to the out dir of symcrypt build
            // add seatch path to the env whtat we make  
        
            // set the lib path
            // let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
            // println!("cargo:rustc-link-search=native={}", lib_path);


            // check if the build exists, if not then build it.

            build_symcrypt();
            build_windows_static_lib_env();
            generate_bindings::generate_bindings(); // generate the bindings for the static library.

            let out_dir = env::var("OUT_DIR").unwrap();
            let lib_path = Path::new(&out_dir).join("symcrypt_build/lib/");
            let lib_path_2 = Path::new(&out_dir).join("windows_env_build/lib/");

            println!("cargo:rustc-link-search=native={}", lib_path.display());
            println!("cargo:rustc-link-search=native={}", lib_path_2.display());

            println!("cargo:rustc-link-lib=static=symcrypt_common");
            println!("cargo:rustc-link-lib=static=symcrypt_usermodewin8_1");
            println!("cargo:rustc-link-lib=static=win_8_env");
            println!("cargo:rustc-link-lib=bcrypt");
        }
    }

    #[cfg(target_os = "linux")]
    {

        #[cfg(feature = "static")]
        {
            let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
            let out_dir = env::var("OUT_DIR").unwrap();

            // Construct the path to the 'inc' directory
            //let inc_path = Path::new(&manifest_dir).join("inc");


            //let lib_path = Path::new(&out_dir).join("symcrypt_build/lib/");
            let lib_path_2 = Path::new(&out_dir).join("linux_env_build/lib/");
            let jitter_path = Path::new(&manifest_dir).join("SymCrypt/3rdparty/jitterentropy-library/");

            // // Make sure that the 'inc' directory is valid
            // if inc_path.exists() {
            //     println!("cargo:rustc-link-search=native={}", inc_path.display());
            // } else {
            //     panic!("inc directory not found: {}", inc_path.display());
            // }


            //build_symcrypt();
            test();
            //build_linux_env();
            //println!("cargo:rustc-link-search=native={}", lib_path.display());
           // println!("cargo:rustc-link-search=native={}", lib_path_2.display());
            println!("cargo:rustc-link-search=native={}", jitter_path.display());

            println!("cargo:rustc-link-lib=static=symcrypt_common");
            println!("cargo:rustc-link-lib=static=jitterentropy");
            println!("cargo:rustc-link-lib=static=linux_env");
            
        }


        // Note: Linux support is based off of the Azure Linux distro.
        // This has been tested on Ubuntu 22.04.03 LTS on WSL and has confirmed working but support for other distros 
        // aside from Azure Linux is not guaranteed so YMMV. 

        #[cfg(feature = "dynamic")]
        {
            println!("cargo:rustc-link-lib=dylib=symcrypt"); // the "lib" prefix for libsymcrypt is implied on Linux

            // You must put the included symcrypt.so files in your usr/lib/x86_64-linux-gnu/ path.
            // This is where the Linux ld linker will look for the symcrypt.so files.

            // Note: This process is a band-aid. Long-term, our long term solution is to package manage SymCrypt for a subset of
            // Linux distros. 
        }
        
    }
}


fn test() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let test_path = Path::new(&manifest_dir).join("inc/arm64");

    println!("cargo:rustc-link-search=native={}", test_path.display());
}

fn build_symcrypt() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let symcrypt_build_dir = Path::new(&out_dir).join("symcrypt_build");
    
    if symcrypt_build_dir.exists() {
        println!("SymCrypt library already built, skipping CMake build.");
        return;
    }

    // Step 1: Run CMake configure
    
    #[cfg(target_os = "linux")]
    let cmake_configure = Command::new("cmake")
        .arg("-S")
        .arg("SymCrypt")  // Source directory
        .arg("-B")
        .arg(symcrypt_build_dir.display().to_string())  // Build directory
        //.arg("--toolchain=cmake-configs/Toolchain-Clang-ARM64.cmake")
        .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
        .output()
        .expect("Failed to run CMake configure");

    #[cfg(target_os = "windows")]

        // --toolchain=cmake-configs/Toolchain-Clang-ARM64.cmake

    // Output any stdout or stderr for debugging
    println!("CMake Configure Output: {}", String::from_utf8_lossy(&cmake_configure.stdout));
    println!("CMake Configure Error: {}", String::from_utf8_lossy(&cmake_configure.stderr));

    // Step 2: Run CMake build
    let cmake_build = Command::new("cmake")
        .arg("--build")
        .arg(symcrypt_build_dir.display().to_string())  // Build directory
        .arg("--config")
        .arg("Release")  // Build configuration
        .output()
        .expect("Failed to run CMake build");

    // Output any stdout or stderr for debugging
    println!("CMake Build Output: {}", String::from_utf8_lossy(&cmake_build.stdout));
    println!("CMake Build Error: {}", String::from_utf8_lossy(&cmake_build.stderr));
}

fn build_linux_env() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let linux_env_build = Path::new(&out_dir).join("linux_env_build");

    if linux_env_build.exists() {
        println!("Windows Env library already built, skipping CMake build.");
        return;
    }

    // Step 3: Run CMake configure for windows_env
    let cmake_configure_windows_env = Command::new("cmake")
        .arg("-S")
        .arg("linux_env")  // Source directory
        .arg("-B")
        .arg(linux_env_build.display().to_string())  // Build directory
        .output()
        .expect("Failed to run CMake configure for linux_env");

    // Output any stdout or stderr for debugging
    println!("Windows Env Configure Output: {}", String::from_utf8_lossy(&cmake_configure_windows_env.stdout));
    println!("Windows Env Configure Error: {}", String::from_utf8_lossy(&cmake_configure_windows_env.stderr));

    // Step 4: Run CMake build for windows_env
    let cmake_build_windows_env = Command::new("cmake")
        .arg("--build")
        .arg(linux_env_build.display().to_string())  // Build directory
        .output()
        .expect("Failed to run CMake build for linux_env");

    // Output any stdout or stderr for debugging
    println!("Windows Env Build Output: {}", String::from_utf8_lossy(&cmake_build_windows_env.stdout));
    println!("Windows Env Build Error: {}", String::from_utf8_lossy(&cmake_build_windows_env.stderr));
}

fn build_windows_static_lib_env() { 
    let out_dir = env::var("OUT_DIR").unwrap();
    let windows_env_build_dir = Path::new(&out_dir).join("windows_env_build");

    if windows_env_build_dir.exists() {
        println!("Windows Env library already built, skipping CMake build.");
        return;
    }

    // Step 3: Run CMake configure for windows_env
    let cmake_configure_windows_env = Command::new("cmake")
        .arg("-S")
        .arg("windows_env")  // Source directory
        .arg("-B")
        .arg(windows_env_build_dir.display().to_string())  // Build directory
        .output()
        .expect("Failed to run CMake configure for windows_env");

    // Output any stdout or stderr for debugging
    println!("Windows Env Configure Output: {}", String::from_utf8_lossy(&cmake_configure_windows_env.stdout));
    println!("Windows Env Configure Error: {}", String::from_utf8_lossy(&cmake_configure_windows_env.stderr));

    // Step 4: Run CMake build for windows_env
    let cmake_build_windows_env = Command::new("cmake")
        .arg("--build")
        .arg(windows_env_build_dir.display().to_string())  // Build directory
        .output()
        .expect("Failed to run CMake build for windows_env");

    // Output any stdout or stderr for debugging
    println!("Windows Env Build Output: {}", String::from_utf8_lossy(&cmake_build_windows_env.stdout));
    println!("Windows Env Build Error: {}", String::from_utf8_lossy(&cmake_build_windows_env.stderr));
}
