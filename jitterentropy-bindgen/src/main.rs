use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const SYS_CRATE_NAME: &str = "jitterentropy-sys2";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Wrong arguments: {:?}", args);
        eprintln!("Usage: {} <outfile> [triple]", args[0]);
        std::process::exit(1);
    }

    let bindings_file = &args[1];
    let triple = args.get(2);
    let root_dir = get_parent_n(Path::new(std::file!()), 3);

    println!("root_dir: {}", root_dir.display());
    let jitterentropy_sys_crate = root_dir.join(SYS_CRATE_NAME);
    let wrapper_header = jitterentropy_sys_crate.join("jitterentropy/jitterentropy.h");
    let rust_target = get_rust_version_from_cargo_metadata();

    println!("Rust version: {rust_target}");
    println!("Output file: {bindings_file}");

    if let Some(parent) = Path::new(bindings_file).parent() {
        std::fs::create_dir_all(parent).expect("Unable to create output directory");
    }

    let mut bindgen_builder = bindgen::builder();
    bindgen_builder = bindgen_builder
        .header(wrapper_header.display().to_string())
        .rust_target(bindgen::RustTarget::from_str(&rust_target).unwrap());

    // Clang arguments
    if let Some(triple) = triple {
        bindgen_builder = bindgen_builder.clang_args(["-target", triple]);
    }

    bindgen_builder = bindgen_builder
        .clang_arg("-v")
        .clang_arg("+A") // this fixes compilation
        .clang_arg(format!(
            "-I{}/jitterentropy",
            jitterentropy_sys_crate.display()
        ))
        .clang_arg(format!(
            "-I{}/jitterentropy/src",
            jitterentropy_sys_crate.display()
        ));

    // export list
    bindgen_builder = bindgen_builder
        .allowlist_var("JENT_MAJVERSION")
        .allowlist_var("JENT_MINVERSION")
        .allowlist_var("JENT_PATCHLEVEL")
        .allowlist_var("JENT_VERSION")
        .allowlist_function("jent_entropy_init")
        .allowlist_function("jent_entropy_collector_alloc")
        .allowlist_function("jent_entropy_collector_free")
        .allowlist_function("jent_read_entropy")
        .raw_line("use super::handwriten::*;")
        .ignore_methods()
        .blocklist_type("rand_data") // replaced with manually implemented type
        // other options
        .generate_comments(true)
        .derive_default(true);

    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(&bindings_file)
        .expect("Couldn't write bindings!");
}

fn get_parent_n(path: &Path, n: usize) -> PathBuf {
    let mut parent = path;
    for _ in 0..n {
        parent = parent.parent().unwrap();
    }
    parent.to_path_buf()
}

// Bindings have to be compatible with the Rust version specified for *-sys crate.
fn get_rust_version_from_cargo_metadata() -> String {
    let output: String = cmd_lib::run_fun!(cargo metadata --no-deps --format-version=1)
        .expect("failed to execute cargo metadata");

    let metadata: serde_json::Value =
        serde_json::from_slice(output.as_bytes()).expect("Failed to parse cargo metadata output");

    let packages = metadata["packages"].as_array().unwrap();
    let package = packages
        .iter()
        .find(|p| p["name"].as_str().unwrap() == SYS_CRATE_NAME)
        .expect("{SYS_CRATE_NAME} package not found");
    package["rust_version"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap()
}
