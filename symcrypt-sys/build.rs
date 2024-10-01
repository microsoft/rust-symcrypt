use std::env;
extern crate cmake;
use std::path::Path;
use std::process::Command;
mod generate_bindings;
use std::path::PathBuf;
use std::fs;
use std::io;


// get all the targets, spefically the rustup target names:
// windows amd64 x86_64-pc-windows-msvc 
// windows arm64 aarch64-pc-windows-msvc

// linux arm64 aarch64-unknown-linux-gnu
// linux amd64 x86_64-unknown-linux-gnu


// caller must add the toolchain to their rustconfig. 

// check if the build mode is static/

// if static: check the what feature flag for target was passed in.
// even if the target is not specificed, set target to the current OS target.
// match to that target and cross compile the symcrypt library for that target.
// if the target is not found, then return an error saying that the target is not supported .
// then use builder pattern to create a builder for specified target.
// the builder pattern will have a build function that will build the symcrypt library for the target.
// the build function will be different for each architecture. But will force build symcrypt based on the passed target
// ie: if you are on amd64, it will force put target as amd64, and not rely on the default. This is fine because we know 
// what the target is meant to be based on the feature flag.
// if passed dynamic, then do not build, just link to the symcrypt library.
// if dynamic is passed, and the target arch is passed, then dynamic link based on those params.
// ie: compile on windows, but set the target to linux dynamic, then we will dynamically link to the linux library.
// we dont have to be specific between arch. because that is assumd that the target machine will have the appropriate dynamic library installed
// if the target is not found, when dynamic linking, error out that there is no dynamic library for that target.


///// Get dirs 


fn cargo_env<N: AsRef<str>>(name: N) -> String {
    let name = name.as_ref();
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name:?}"))
}

fn out_dir() -> PathBuf {
    PathBuf::from(cargo_env("OUT_DIR"))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(cargo_env("CARGO_MANIFEST_DIR"))
}

/// Retrieves the target architecture (e.g., "x86_64", "aarch64").
fn target_arch() -> String {
    cargo_env("CARGO_CFG_TARGET_ARCH")
}

/// Retrieves the target operating system (e.g., "windows", "linux", "macos").
fn target_os() -> String {
    cargo_env("CARGO_CFG_TARGET_OS")
}

/// Retrieves the target environment (e.g., "gnu", "msvc", "musl").
fn target_env() -> String {
    cargo_env("CARGO_CFG_TARGET_ENV")
}

/// Retrieves the host architecture (e.g., "x86_64-unknown-linux-gnu").
fn host_arch() -> String {
    cargo_env("HOST")
}


fn symcrypt_lib_out_dir() -> PathBuf { // will be the same across both windows and linux.
    let out_dir = out_dir();
    out_dir.join("symcrypt_build")
}

fn windows_env_lib_out_dir() -> PathBuf {
    let out_dir = out_dir();
    out_dir.join("windows_env_build")
}

fn linux_env_lib_out_dir() -> PathBuf {
    let out_dir = out_dir();
    out_dir.join("linux_env_build")
}

#[derive(PartialEq)]
pub(crate) enum TargetArch {
    X86_64,
    ARM64,
}
impl TargetArch {
    fn to_string(&self) -> String {
        match self {
            TargetArch::X86_64 => "x86_64".to_string(),
            TargetArch::ARM64 => "aarch64".to_string(),
        }
    }

    fn from_string(arch: &str) -> Self {
        match arch {
            "x86_64" => TargetArch::X86_64,
            "aarch64" => TargetArch::ARM64,
            _ => panic!("Unsupported target architecture: {}", arch),
        }
    }
    fn to_symcrypt_arch(&self) -> String {
        match self {
            TargetArch::X86_64 => "AMD64".to_string(),
            TargetArch::ARM64 => "ARM64".to_string(),
        }
    }
}

#[derive(PartialEq)]
pub(crate) enum TargetOS {
    Windows,
    Linux,
}

impl TargetOS {
    fn to_string(&self) -> String {
        match self {
            TargetOS::Windows => "windows".to_string(),
            TargetOS::Linux => "linux".to_string(),
        }
    }

    fn from_string(os: &str) -> Self {
        match os {
            "windows" => TargetOS::Windows,
            "linux" => TargetOS::Linux,
            _ => panic!("Unsupported target OS: {}", os),
        }
    }

    fn output_dir(&self) -> PathBuf {
        match self {
            TargetOS::Windows => windows_env_lib_out_dir(),
            TargetOS::Linux => linux_env_lib_out_dir(),
        }
    }
}

#[derive(PartialEq)]
pub(crate) enum TargetEnv {
    MSVC,
    GNU,
}

impl TargetEnv { 
    fn to_string(&self) -> String {
        match self {
            TargetEnv::MSVC => "msvc".to_string(),
            TargetEnv::GNU => "gnu".to_string(),
        }
    }

    fn from_string(env: &str) -> Self {
        match env {
            "msvc" => TargetEnv::MSVC,
            "gnu" => TargetEnv::GNU,
            _ => panic!("Unsupported target environment: {}", env),
        }
    }
}



struct BuildConfig {
    target_arch: TargetArch,
    target_os: TargetOS,
    target_env: TargetEnv,
    host_arch: String,
}

impl BuildConfig {
    fn new() -> Self {
        Self {
            target_arch: TargetArch::from_string(&target_arch()),
            target_os: TargetOS::from_string(&target_os()),
            target_env: TargetEnv::from_string(&target_env()),
            host_arch: host_arch(),
        }
    }

    // fn get_target_arch(&self) -> String {
    //     //self.target_arch.clone()
    // }
}


fn print_config(config: BuildConfig) {
    println!("cargo:warning=Target Arch: {}", config.target_arch.to_string());
    println!("cargo:warning=Target OS: {}", config.target_os.to_string());
    println!("cargo:warning=Target Env: {}", config.target_env.to_string());
    println!("cargo:warning=Host Arch: {}", config.host_arch.to_string());
}

// write function that gets current arch.
// write function that gets supplied target arch.
// write function that compares and sets the target arch.
// if no supplied target arch, then we default to the current arch.
// else we use the target arch.

// make enums to match the target arch to the "windows_env_build" or "linux_env_build"



//// Utility functions
fn already_built(path: &PathBuf) -> bool {
    path.exists()
}




fn move_lib(lib_path: PathBuf, targets: Vec<String>, target_path: PathBuf) -> io::Result<()> {

    for target in targets {
        let source = lib_path.join(&target);
        let destination = target_path.join(&target);

        // Use fs::copy to copy the file to the new location
        match fs::copy(&source, &destination) {
            Ok(bytes) => {
                println!("Successfully copied {} to {} ({} bytes)", source.display(), destination.display(), bytes);
            }
            Err(e) => {
                eprintln!("Failed to copy {} to {}: {}", source.display(), destination.display(), e);
            }
        }
    }

    Ok(()) 
}

trait Builder {
    fn configure(&self);
    fn build(&self);
    fn link(&self);
    //fn clean(&self);
}

struct CmakeBuilder { // can include the target OS here. 
    build_manifest_dir: PathBuf,
    output_lib_dir: PathBuf,
    config_flags: Option<Vec<String>>, // Optional flags to configure, using &'static str
    targets: Vec<String>, // the targets that we want to move
}

impl CmakeBuilder { 
    fn new(build_manifest_dir: PathBuf, output_lib_dir: PathBuf, config_flags: Option<Vec<String>>, targets: Vec<&str>) -> Self {
        Self {
            build_manifest_dir: build_manifest_dir,
            output_lib_dir: output_lib_dir,
            config_flags: config_flags,
            targets: targets.into_iter().map(String::from).collect(),
        }
    }

    fn lib_out_dir(&self) -> PathBuf {
        let out_dir = out_dir();
        out_dir.join("symcrypt_build")
    }
}

impl Builder for CmakeBuilder { 
    fn configure(&self) {
        let manifest_dir_str = self.build_manifest_dir.display().to_string();
        let output_lib_dir = self.output_lib_dir.display().to_string();

        let mut configure_command = vec![
            "cmake",
            "-S", 
            &manifest_dir_str, // Source dir
            "-B", 
            &output_lib_dir , // Out dir for lib
            ];// cmake not needed, kept to be clear
        if let Some(flags) = &self.config_flags {
            configure_command.extend(flags.iter().map(|flag| flag.as_str()));
        }
        println!("cargo:warning=Configuring with: {:?}", configure_command);
        let status = Command::new("cmake")
            .args(&configure_command[1..]) // cmake is used before but keeping in the configure for completion.
            .output()
            .expect("Failed to run CMake configure");

        // if !status.success() {
        //     eprintln!("Failed to configure the project");
        //     "Failed to Build".to_string()
        // } else {
        //     println!("Configuration completed successfully");
        //     Ok(())
        // }
    }

    // let build_cmd = vec!["cmake", "--build", &build_dir, "--config", "Release"];

    fn build(&self) {
        let output_lib_dir_str = self.output_lib_dir.display().to_string(); 

        let build_command = vec!["cmake", "--build", &output_lib_dir_str, "--config", "Release"];
        println!("cargo:warning=Configuring with: {:?}", build_command);

        let status = Command::new("cmake")
            .args(&build_command[1..])
            .output()
            .expect("Failed to run CMake build");

            // if !status.success() {
            //     eprintln!("Failed to build the project");
            //     "Failed to Build".to_string()
            // } else {
            //     println!("Build completed successfully");
            //     Ok(())
            // }
        // move_lib(self.lib_path.clone(), self.targets.clone(), out_dir());
    }

    fn link(&self) {
        // link the library to the rust project.
        let lib_path = self.output_lib_dir.join("lib");
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:warning=Linking with: {:?}", self.targets);
        let targets = self.targets.clone();
        for target in targets {
            println!("cargo:rustc-link-lib=static={}", target);
            println!("cargo:warning=Linking with: {:?}", target);
        }
    }
}

fn test_2() {
    let symcrypt_build_dir = symcrypt_lib_out_dir(); // out/symcrypt_build/

    // if target arch == "amd64", then we set the paths 
    let build_config = BuildConfig::new();

    let d_symcrypt_target_arch = String::from("-DSYMCRYPT_TARGET_ARCH=") + &build_config.target_arch.to_symcrypt_arch();

    let mut symcrypt_build_flags = vec![String::from("-DCMAKE_BUILD_TYPE=RelWithDebInfo"), d_symcrypt_target_arch]; // owned String vec

    if build_config.target_os == TargetOS::Linux && build_config.target_arch == TargetArch::ARM64 {
        symcrypt_build_flags.push(String::from("--toolchain=cmake-configs/Toolchain-Clang-ARM64.cmake"));
    }

    let symcrypt_targets = match build_config.target_os {
        TargetOS::Windows => vec!["symcrypt_common", "symcrypt_usermodewin8_1"],
        TargetOS::Linux => vec!["symcrypt_common", "jitterentropy"],
    };

    // Create a new CmakeBuilder instance with these commands
    let symcrypt_builder = CmakeBuilder::new(
        PathBuf::from("SymCrypt"),
        symcrypt_build_dir.clone(),
        Some(symcrypt_build_flags),
        symcrypt_targets); // can take in target instead 
    
    // Use the Builder trait methods
    if !already_built(&symcrypt_build_dir) {
        symcrypt_builder.configure();
        symcrypt_builder.build();
    }
    symcrypt_builder.link(); // have to run this every time even if its already built.
    



    let env_targets = match build_config.target_os {
        TargetOS::Windows => vec!["win_8_env"],
        TargetOS::Linux => vec!["linux_env"],
    };
    let env_src_dir = match build_config.target_os {
        TargetOS::Windows => PathBuf::from("windows_env"),
        TargetOS::Linux => PathBuf::from("linux_env"),
    };
    
    let env_output_dir = build_config.target_os.output_dir().clone();
    let windows_env_build_dir = windows_env_lib_out_dir();   
    let env_builder = CmakeBuilder::new(
        env_src_dir, // can match based on OS. 
        env_output_dir.clone(),
        None,
        env_targets); // can match this based on OS.

    if !already_built(&env_output_dir) {
        env_builder.configure();
        env_builder.build();
    } 
    env_builder.link();  
}




fn main() {

    let config = BuildConfig::new();


    // if dynamic:


    // if static:
    print_config(config);
    test_2();

    let config = BuildConfig::new();

    if config.target_os == TargetOS::Linux {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        let jitter_path = Path::new(&manifest_dir).join("SymCrypt/3rdparty/jitterentropy-library/");
        println!("cargo:rustc-link-search=native={}", jitter_path.display());
    }

    if config.target_os == TargetOS::Windows {
        println!("cargo:rustc-link-lib=bcrypt");
    }
    
    // do config = BuildConfig::new();
    // if config.target_os == BuildType::Windows{ 
    // do windows stuff}
    // if config.buildmode == BuildMode::Static { do the static code
    // in static code check do the check for OS family type for the linker. }
    // else { do the dynamic code } ! implied since we do not have any other enum type. 
    // #[cfg(target_os = "windows")]
    // {
    //     // Look for the .lib file during link time. We are searching the Windows/System32 path which is set as a current default to match
    //     // the long term placement of a Windows shipped symcrypt.dll 
    //     // println!("cargo:rustc-link-search=native=C:/Windows/System32/"); 


    //     #[cfg(feature = "dynamic")]
    //     {
    //         // if "dynamic" use this:
    //         let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
    //         println!("cargo:rustc-link-search=native={}", lib_path);

    //         println!("cargo:rustc-link-lib=dylib=symcrypt");

            
    //         // if "dynamic", we need to change the windows.h file to get the .h file from the release page. 
    //         // the bindings will be need to be combed through to add the dylink, also need to add a check for AZL2 since it does not have updated stuff. 
    //     }

    //     #[cfg(feature = "static")]
    //     {
    //         // if "static" use this: // make static default? 
    //         // add path to the out dir of symcrypt build
    //         // add seatch path to the env whtat we make  
        
    //         // set the lib path
    //         // let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
    //         // println!("cargo:rustc-link-search=native={}", lib_path);


    //         // check if the build exists, if not then build it.

    //         //build_symcrypt();
    //         test_2();
    //         //build_windows_static_lib_env();
    //         //generate_bindings::generate_bindings(); // generate the bindings for the static library.

    //         // let out_dir = env::var("OUT_DIR").unwrap();
    //         // let lib_path = Path::new(&out_dir).join("symcrypt_build/lib/");
    //         // let lib_path_2 = Path::new(&out_dir).join("windows_env_build/lib/");

    //         // println!("cargo:rustc-link-search=native={}", lib_path.display());
    //         // println!("cargo:rustc-link-search=native={}", lib_path_2.display());

    //         // println!("cargo:rustc-link-lib=static=symcrypt_common");
    //         // println!("cargo:rustc-link-lib=static=symcrypt_usermodewin8_1");
    //         // println!("cargo:rustc-link-lib=static=win_8_env");
    //         println!("cargo:rustc-link-lib=bcrypt");
    //     }
    // }

    // #[cfg(target_os = "linux")]
    // {

    //     #[cfg(feature = "static")]
    //     {
    //         let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    //         let out_dir = env::var("OUT_DIR").unwrap();

    //         // Construct the path to the 'inc' directory
    //         //let inc_path = Path::new(&manifest_dir).join("inc");


    //         //let lib_path = Path::new(&out_dir).join("symcrypt_build/lib/");
    //         let lib_path_2 = Path::new(&out_dir).join("linux_env_build/lib/");
    //         let jitter_path = Path::new(&manifest_dir).join("SymCrypt/3rdparty/jitterentropy-library/");

    //         // // Make sure that the 'inc' directory is valid
    //         // if inc_path.exists() {
    //         //     println!("cargo:rustc-link-search=native={}", inc_path.display());
    //         // } else {
    //         //     panic!("inc directory not found: {}", inc_path.display());
    //         // }


    //         //build_symcrypt();
    //         //test();
    //         test_2();
    //         //build_linux_env();
    //         //println!("cargo:rustc-link-search=native={}", lib_path.display());
    //        // println!("cargo:rustc-link-search=native={}", lib_path_2.display());
    //         println!("cargo:rustc-link-search=native={}", jitter_path.display());

    //         println!("cargo:rustc-link-lib=static=symcrypt_common");
    //         println!("cargo:rustc-link-lib=static=jitterentropy");
    //         println!("cargo:rustc-link-lib=static=linux_env");
            
    //     }


    //     // Note: Linux support is based off of the Azure Linux distro.
    //     // This has been tested on Ubuntu 22.04.03 LTS on WSL and has confirmed working but support for other distros 
    //     // aside from Azure Linux is not guaranteed so YMMV. 

    //     #[cfg(feature = "dynamic")]
    //     {
    //         println!("cargo:rustc-link-lib=dylib=symcrypt"); // the "lib" prefix for libsymcrypt is implied on Linux

    //         // You must put the included symcrypt.so files in your usr/lib/x86_64-linux-gnu/ path.
    //         // This is where the Linux ld linker will look for the symcrypt.so files.

    //         // Note: This process is a band-aid. Long-term, our long term solution is to package manage SymCrypt for a subset of
    //         // Linux distros. 
    //     }
        
    // }
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
