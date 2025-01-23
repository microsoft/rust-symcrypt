use super::triple::Triple;

pub fn compile_and_link_jitterentropy(triple: Triple) {
    const LIB_NAME: &str = "jitterentropy_static";

    println!("Compiling jitterentropy...");
    let cargo_toml_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
    let jitterentropy_dir = format!("{cargo_toml_dir}/upstream/3rdparty/jitterentropy-library");

    let mut cc = cc::Build::new();
    cc.target(triple.to_triple())
        .warnings(false)
        .include(&jitterentropy_dir)
        .include(format!("{jitterentropy_dir}/src"));

    // Add the source files
    let src_files = std::fs::read_dir(format!("{jitterentropy_dir}/src"))
        .expect("Failed to read src directory")
        .filter_map(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("c") {
                Some(path)
            } else {
                None
            }
        });
    cc.files(src_files);

    // Set compiler flags. Warnings are commented out.
    cc.flag_if_supported("-fwrapv")
         .flag_if_supported("--param ssp-buffer-size=4")
         .flag_if_supported("-fvisibility=hidden")
         .flag_if_supported("-fPIE")
         //.flag_if_supported("-Wcast-align")
         //.flag_if_supported("-Wmissing-field-initializers")
         //.flag_if_supported("-Wshadow")
         //.flag_if_supported("-Wswitch-enum")
         //.flag_if_supported("-Wextra")
         //.flag_if_supported("-Wall")
         //.flag_if_supported("-pedantic")
         .flag_if_supported("-fPIC")
         .flag_if_supported("-O0")
         //.flag_if_supported("-Wconversion")
         ;

    if gcc_version_ge_490() {
        cc.flag_if_supported("-fstack-protector-strong");
    } else {
        cc.flag_if_supported("-fstack-protector-all");
    }

    cc.compile(LIB_NAME);
    println!("cargo:rustc-link-lib=static={LIB_NAME}");
}

fn gcc_version_ge_490() -> bool {
    if let Ok(output) = std::process::Command::new("gcc")
        .arg("-dumpversion")
        .output()
    {
        if let Ok(version) = String::from_utf8(output.stdout) {
            let parts: Vec<&str> = version.trim().split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    return major > 4 || (major == 4 && minor >= 9);
                }
            }
        }
    }
    false
}
