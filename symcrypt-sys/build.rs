use std::env;
extern crate cmake;
use std::path::Path;
use std::process::Command;
mod generate_bindings;
use std::path::PathBuf;

// Currently supported triples: 
// Cross compile not supported at the moment.
// windows amd64 x86_64-pc-windows-msvc 
// windows arm64 aarch64-pc-windows-msvc

// linux arm64 aarch64-unknown-linux-gnu
// linux amd64 x86_64-unknown-linux-gnu

// Convert cargo env variables to a String
fn cargo_env<N: AsRef<str>>(name: N) -> String {
    let name = name.as_ref();
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name:?}"))
}

// Get out dir
fn out_dir() -> PathBuf {
    PathBuf::from(cargo_env("OUT_DIR"))
}

// Get root of cargo directory.
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

// SymCrypt lib output path will be the same across both windows and linux.
fn symcrypt_lib_out_dir() -> PathBuf { 
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

#[derive(Debug, PartialEq)]
enum LinkType {
    Static,
    Dynamic,
}

impl LinkType {
    fn new() -> Self {
        #[cfg(feature = "dynamic")]
        {
            return LinkType::Dynamic;
        }
        
        #[cfg(feature = "static")]
        {
            return LinkType::Static;
        }
        
        // Fallback if no feature is provided (you could choose a default or panic)
        LinkType::Static
    }
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
    link_type: LinkType,
    host_arch: String,
}

impl BuildConfig {
    fn new() -> Self {
        Self {
            target_arch: TargetArch::from_string(&target_arch()),
            target_os: TargetOS::from_string(&target_os()),
            target_env: TargetEnv::from_string(&target_env()),
            link_type: LinkType::new(),
            host_arch: host_arch(),
        }
    }
    fn print_build_config(&self) {
        println!("cargo:warning=Target Arch: {}", self.target_arch.to_string());
        println!("cargo:warning=Target OS: {}", self.target_os.to_string());
        println!("cargo:warning=Target Env: {}", self.target_env.to_string());
        println!("cargo:warning=Link Type: {:?}", self.link_type);
        println!("cargo:warning=Host Arch: {}", self.host_arch);
    }
}

//// Utility functions
fn already_built(path: &PathBuf) -> bool {
    path.exists()
}

trait Builder {
    fn configure(&self);
    fn build(&self);
    fn link(&self);
}

// Builder for Cmake, covers most cases, but having builder trait for option to add MSBuild at a later time
struct CmakeBuilder {  
    build_manifest_dir: PathBuf,
    output_lib_dir: PathBuf, // 
    config_flags: Option<Vec<String>>, // Config flags to pass to Cmake
    targets: Vec<String>, // Targets to link to
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

fn symcrypt_static_build(build_config: &BuildConfig) {
    let symcrypt_build_dir = symcrypt_lib_out_dir(); // out/symcrypt_build/

    let symcrypt_build_flags = vec![String::from("-DCMAKE_BUILD_TYPE=RelWithDebInfo")]; // Release build 

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
    let env_builder = CmakeBuilder::new(
        env_src_dir, // can match based on OS. 
        env_output_dir.clone(),
        None, // No additional flags for building env.
        env_targets); // can match this based on OS.

    if !already_built(&env_output_dir) {
        env_builder.configure();
        env_builder.build();
    } 
    env_builder.link();  

    if build_config.target_os == TargetOS::Linux {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        let jitter_path = Path::new(&manifest_dir).join("SymCrypt/3rdparty/jitterentropy-library/");
        println!("cargo:rustc-link-search=native={}", jitter_path.display());
    }

    if build_config.target_os == TargetOS::Windows {
        println!("cargo:rustc-link-lib=bcrypt");
    }
}

fn main() {
    let config = BuildConfig::new();
    config.print_build_config();
    // let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
    // println!("cargo:rustc-link-search=native={}", lib_path);

    // println!("cargo:rustc-link-lib=dylib=symcrypt");
    match config.link_type {
        LinkType::Static => {
            println!("cargo:warning=Building static library");
            generate_bindings::generate_bindings(); // generate the bindings for the static library.
            symcrypt_static_build(&config);
        },
        LinkType::Dynamic => {
            println!("cargo:warning=Linking to dynamic library");
            match config.target_os {
                TargetOS::Windows => {
                    println!("cargo:warning=blah");
                    let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set"));
                    println!("cargo:rustc-link-search=native={}", lib_path);
                    println!("cargo:rustc-link-lib=dylib=symcrypt");
                }
                TargetOS::Linux => {
                    println!("cargo:rustc-link-lib=dylib=symcrypt"); // the "lib" prefix for libsymcrypt is implied on Linux
                }        
            };
        }
    };
}
