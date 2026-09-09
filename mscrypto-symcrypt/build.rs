// Records how symcrypt-sys is linked so the provider can report it through
// BackendInfo::link_mode. There is no runtime way to learn this, so it is read
// from the same env vars symcrypt-sys uses and exposed as a cfg.
fn main() {
    // A target-prefixed variable takes precedence, mirroring symcrypt-sys.
    let target = std::env::var("TARGET").unwrap_or_default();
    let prefix = target.to_uppercase().replace('-', "_");
    println!("cargo::rerun-if-env-changed=SYMCRYPT_STATIC");
    println!("cargo::rerun-if-env-changed={prefix}_SYMCRYPT_STATIC");

    let read =
        |name: &str| std::env::var(format!("{prefix}_{name}")).or_else(|_| std::env::var(name));
    let is_static = read("SYMCRYPT_STATIC").map(|v| v != "0").unwrap_or(false);

    // v1 distinguishes dynamic vs prebuilt-static only. "from_source" is reserved
    // for a later linking change and is never emitted here.
    let mode = if is_static { "prebuilt" } else { "dynamic" };
    println!("cargo::rustc-cfg=mscrypto_link=\"{mode}\"");
    println!("cargo::rustc-check-cfg=cfg(mscrypto_link, values(\"dynamic\", \"prebuilt\", \"from_source\"))");
}
