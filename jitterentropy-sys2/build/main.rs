pub mod cc;

fn main() {
    let cargo_toml_dir = env!("CARGO_MANIFEST_DIR");
    let jitterentropy_dir = format!("{cargo_toml_dir}/jitterentropy");

    cc::compile_and_link_jitterentropy(&jitterentropy_dir);

    println!("cargo:include={jitterentropy_dir}");
}
