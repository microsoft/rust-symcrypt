use std::env;
extern crate cmake;
use cmake::Config;
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

            build_windows();
            // also need to run bindgen to generate the bindings for the symcrypt.h file.
            // println!("cargo:rustc-link-lib=static=symcrypt_common");
            // println!("cargo:rustc-link-lib=static=symcrypt_usermodewin8_1");
            // // println!("cargo:rustc-link-lib=static=win_8_env");
            // println!("cargo:rustc-link-lib=dylib=bcrypt");

            // check if bindings exists, if not then generate them.
            
            generate_bindings::generate_bindings();
            let out_dir = env::var("OUT_DIR").unwrap();
            let lib_path = Path::new(&out_dir).join("symcrypt_build/build/lib/");
            let lib_path_2 = Path::new(&out_dir).join("windows_env_build/");


            println!("cargo:rustc-link-search=native={}", lib_path.display());
            println!("cargo:rustc-link-search=native={}", lib_path_2.display());


            println!("cargo:rustc-link-lib=static=symcrypt_common");
            println!("cargo:rustc-link-lib=static=symcrypt_usermodewin8_1");
            println!("cargo:rustc-link-lib=static=win_8_env");
            println!("cargo:rustc-link-lib=bcrypt");


        }

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

// check if static lib exists already:
// if not then build... 



fn build_windows() { 
    // Builds the project in the directory located in `libfoo`, installing it
    // into $OUT_DIR
    let out_dir = env::var("OUT_DIR").unwrap();
    let lib_path = Path::new(&out_dir).join("symcrypt_build/build/lib/");

     // Set cargo to only rerun if specific files change
    println!("cargo:rerun-if-changed=SymCrypt");
    println!("cargo:rerun-if-changed=wrapper.h");

    
    if lib_path.exists() {
        println!("SymCrypt library already built, skipping CMake build.");
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        return;
    }
    println!("inside build_windows()");

     // Step 1: Configure and generate the build system for SymCrypt
    let dst = Config::new("SymCrypt")
        .out_dir(format!("{}/symcrypt_build", out_dir))  // Append 'symcrypt_build' to OUT_DIR
        .define("CMAKE_INSTALL_PREFIX", env::var("OUT_DIR").unwrap())
        .generator("Visual Studio 16 2019")
        .define("CMAKE_BUILD_TYPE", "Debug")
        .define("CMAKE_VERBOSE_MAKEFILE", "ON")
        .define("CMAKE_C_FLAGS", "/WX- /EHsc /wd4530")
        .define("CMAKE_CXX_FLAGS", "/EHsc /WX- /wd4530")
        .define("CMAKE_ASM_FLAGS", "/WX- /EHsc /wd4530")
        .very_verbose(true)
        .no_build_target(true)  // Do not invoke any target automatically
        .build();

 // Step 2: Manually invoke `cmake --build` to build the project
    let build_result = Command::new("cmake")
        .arg("--build")
        .arg(dst.display().to_string())  // Specify the build directory
        .arg("--config")
        .arg("Debug")  // Build the Debug configuration
        .output()
        .expect("Failed to execute cmake build");

 // Print any output from the build process (useful for debugging)
    println!("Build output: {}", String::from_utf8_lossy(&build_result.stdout));
    println!("Build error: {}", String::from_utf8_lossy(&build_result.stderr));
//     let dst_2 = Config::new("windows_env")
// //        .build_target("all")  // Use the default 'all' target instead of 'install'
//         .out_dir(format!("{}/windows_env_build", out_dir))  // Append 'inc_build' to OUT_DIR
//         .build();

    let symcrypt_lib_dir = Path::new(&dst).join("build/lib");
    println!("path: {:?}", symcrypt_lib_dir);

    build_windows_static_lib_env();
    println!("cargo:rustc-link-search=native={}", symcrypt_lib_dir.display());
    // println!("cargo:rustc-link-search=native={}", dst_2.display());
    

}


fn build_windows_static_lib_env() { 
    let out_dir = env::var("OUT_DIR").unwrap();
    let lib_path = Path::new(&out_dir).join("windows_env_build/");

    if lib_path.exists() {
        println!("SymCrypt library already built, skipping CMake build.");
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        return;
    }

    let dst_2 = Config::new("windows_env")
        .out_dir(format!("{}/windows_env_build", out_dir))  // Append 'windows_env_build' to OUT_DIR
        .build();

    println!("cargo:rustc-link-search=native={}", dst_2.display());
}