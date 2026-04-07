fn main() {
    // Declare custom_lib_name as a valid cfg so rustc doesn't warn about it.
    println!("cargo:rustc-check-cfg=cfg(custom_lib_name)");

    #[cfg(target_os = "windows")]
    {
        // raw-dylib handles Windows linking via #[link] attributes in the bindings.
        // No .lib file or SYMCRYPT_LIB_PATH needed.

        // When SYMCRYPT_LIB_NAME is set, generate modified bindings with custom DLL name.
        println!("cargo:rerun-if-env-changed=SYMCRYPT_LIB_NAME");
        if let Ok(lib_name) = std::env::var("SYMCRYPT_LIB_NAME") {
            let out_dir = std::env::var("OUT_DIR").unwrap();
            let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

            let binding_filename = match target_arch.as_str() {
                "x86_64" => "x86_64_pc_windows_msvc.rs",
                "aarch64" => "aarch64_pc_windows_msvc.rs",
                _ => panic!("Unsupported Windows architecture: {}", target_arch),
            };

            let src_path = format!(
                "{}/src/bindings/{}",
                std::env::var("CARGO_MANIFEST_DIR").unwrap(),
                binding_filename
            );
            let content = std::fs::read_to_string(&src_path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", src_path, e));
            let modified = content.replace(
                "name = \"symcrypt\"",
                &format!("name = \"{}\"", lib_name),
            );
            let dest_path = format!("{}/bindings.rs", out_dir);
            std::fs::write(&dest_path, modified).unwrap();
            println!("cargo:rustc-env=SYMCRYPT_BINDINGS_PATH={}", dest_path);
            println!("cargo:rustc-cfg=custom_lib_name");
        }
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=symcrypt");
    }
}
