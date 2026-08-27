fn env_var_for_target(name: &str) -> Option<String> {
    let prefix = std::env::var("TARGET")
        .unwrap()
        .to_uppercase()
        .replace('-', "_");
    let prefixed = format!("{prefix}_{name}");

    fn env_inner(name: &str) -> Option<String> {
        let var = std::env::var_os(name);
        let var = var.map(|x| x.to_string_lossy().into());
        println!("cargo:rerun-if-env-changed={name}");
        // Debug prints
        match var {
            Some(ref v) => println!("{} = {}", name, v),
            None => println!("{name} unset"),
        }
        var
    }

    env_inner(&prefixed).or_else(|| env_inner(name))
}

fn main() {
    // Optionally allow callers to override where the linker/loader looks for
    // libsymcrypt by setting SYMCRYPT_LIB_PATH (or the target-specific
    // variant, e.g. X86_64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH). This is
    // useful when libsymcrypt is not installed in a default library
    // search path, or when cross-compiling.
    if let Some(lib_path) = env_var_for_target("SYMCRYPT_LIB_PATH") {
        println!("cargo:rustc-link-search=native={}", lib_path);
    } else {
        #[cfg(windows)]
        panic!("SYMCRYPT_LIB_PATH environment variable not set, for more information please see: https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide")
    }

    println!("cargo:rustc-link-lib=dylib=symcrypt");
}
