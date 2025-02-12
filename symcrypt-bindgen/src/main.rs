use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Wrong arguments: {:?}", args);
        eprintln!("Usage: {} <triple> <outDir>", args[0]);
        std::process::exit(1);
    }

    let triple = &args[1];
    let out_dir = &args[2];

    if !SUPPORTED_TARGETS.contains(&triple.as_str()) {
        eprintln!(
            "Unsupported target: {}. Supported targets: {:?}",
            triple, SUPPORTED_TARGETS
        );
        std::process::exit(1);
    }

    let root_dir = get_parent_n(Path::new(std::file!()), 3);

    println!("root_dir: {}", root_dir.display());
    let symcrypt_sys_crate = root_dir.join("symcrypt-sys");
    let wrapper_header = symcrypt_sys_crate.join("inc/wrapper.h");
    let target_name = triple.replace("-", "_");
    let bindings_file = format!("{}/{}.rs", out_dir, target_name);
    let rust_target = get_rust_version_from_cargo_metadata();

    println!("Rust version: {rust_target}");
    println!("Output file: {bindings_file}");

    std::fs::create_dir_all(out_dir).expect("Unable to create output directory");

    let bindings = bindgen::builder()
        .header(wrapper_header.display().to_string())
        .rust_target(bindgen::RustTarget::from_str(&rust_target).unwrap())

        // Clang arguments
        .clang_arg("-v")
        .clang_args(["-target", triple])
        .clang_arg(format!("-I{}/inc", symcrypt_sys_crate.display()))
        .clang_arg(format!("-I{}/symcrypt/inc", symcrypt_sys_crate.display()))
        .clang_arg(format!("-I{}/symcrypt/lib", symcrypt_sys_crate.display()))

        // ALLOWLIST

        // INIT FUNCTIONS
        .allowlist_function("SymCryptModuleInit")
        .allowlist_var("^(SYMCRYPT_CODE_VERSION.*)$")
        // HASH FUNCTIONS
        .allowlist_function("^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)(?:Init|Append|Result|StateCopy)?$")
        .allowlist_var("^(SYMCRYPT_(SHA3_256|SHA3_384|SHA3_512|SHA256|SHA384|SHA512|SHA1|MD5)_RESULT_SIZE$)")
        .allowlist_var("^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)Algorithm$")
        // HMAC FUNCTIONS
        .allowlist_function("^SymCryptHmac(?:Sha(?:256|384|512|1)|Md5)(?:ExpandKey|Init|Append|Result|StateCopy)?$")
        .allowlist_var("^(SymCryptHmac(Sha256|Sha384|Sha512|Sha1|Md5)Algorithm)$")
        // GCM FUNCTIONS
        .allowlist_function("^(SymCryptGcm(?:ValidateParameters|ExpandKey|Encrypt|Decrypt|Init|StateCopy|AuthPart|DecryptPart|EncryptPart|EncryptFinal|DecryptFinal)?)$")
        .allowlist_function("SymCryptChaCha20Poly1305(Encrypt|Decrypt)")
        .allowlist_function("^SymCryptTlsPrf1_2(?:ExpandKey|Derive)?$")
        // CBC FUNCTIONS
        .allowlist_function("^SymCryptAesCbc(Encrypt|Decrypt)?$")
        // BLOCK CIPHERS
        .allowlist_var("SymCryptAesBlockCipher")
        .allowlist_function("^SymCryptAesExpandKey$")
        .allowlist_var("SYMCRYPT_AES_BLOCK_SIZE")
        // HKDF FUNCTIONS
        .allowlist_function("^(SymCryptHkdf.*)$") 
        // ECDH KEY AGREEMENT FUNCTIONS
        .allowlist_function("^SymCryptEcurve(Allocate|Free|SizeofFieldElement)$")
        .allowlist_var("^SymCryptEcurveParams(NistP256|NistP384|NistP521|Curve25519)$")
        .allowlist_function("^(SymCryptEckey(Allocate|Free|SizeofPublicKey|SizeofPrivateKey|GetValue|SetRandom|SetValue|SetRandom|))$")
        .allowlist_var("SYMCRYPT_FLAG_ECKEY_ECDH")
        .allowlist_var("SYMCRYPT_FLAG_ECKEY_ECDSA")
        .allowlist_function("SymCryptEcDhSecretAgreement")
        // RSA FUNCTIONS
        .allowlist_function("^SymCryptRsa.*") // Must allow ALL SymCryptRsakey* before blocking the functions that are not needed.
        .blocklist_function("SymCryptRsakeyCreate")
        .blocklist_function("SymCryptRsakeySizeofRsakeyFromParams")
        .blocklist_function("SymCryptRsakeyWipe")
        .blocklist_function("SymCryptRsaSelftest")
        .blocklist_function("^SymCryptRsaRaw.*$")
        .allowlist_var("SYMCRYPT_FLAG_RSAKEY_ENCRYPT")
        .allowlist_var("SYMCRYPT_FLAG_RSAKEY_SIGN")
        // ECDSA functions
        .allowlist_function("^(SymCryptEcDsa(Sign|Verify).*)")
        // RSA PKCS1 FUNCTIONS
        .allowlist_function("^(SymCryptRsaPkcs1(Sign|Verify|Encrypt|Decrypt).*)$")
        .allowlist_var("SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1")
        .allowlist_var("SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID")
        // RSA PSS FUNCTIONS
        .allowlist_function("^(SymCryptRsaPss(Sign|Verify).*)$")
        // OID LISTS
        .allowlist_var("^SymCrypt(Sha(1|256|384|512|3_(256|384|512))|Md5)OidList$")
        // UTILITY FUNCTIONS
        .allowlist_function("SymCryptWipe")
        .allowlist_function("SymCryptRandom")
        .allowlist_function("SymCryptLoadMsbFirstUint64")
        .allowlist_function("SymCryptStoreMsbFirstUint64")    

        .generate_comments(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(&bindings_file)
        .expect("Couldn't write bindings!");

    fix_bindings_for_windows(triple, &bindings_file);
}

fn get_parent_n(path: &Path, n: usize) -> PathBuf {
    let mut parent = path;
    for _ in 0..n {
        parent = parent.parent().unwrap();
    }
    parent.to_path_buf()
}

// Bindings have to be compatible with the Rust version specified for symcrypt-sys crate.
fn get_rust_version_from_cargo_metadata() -> String {
    let output: String = cmd_lib::run_fun!(cargo metadata --no-deps --format-version=1)
        .expect("failed to execute cargo metadata");

    let metadata: serde_json::Value =
        serde_json::from_slice(output.as_bytes()).expect("Failed to parse cargo metadata output");

    let packages = metadata["packages"].as_array().unwrap();
    let package = packages
        .iter()
        .find(|p| p["name"].as_str().unwrap() == "symcrypt-sys")
        .expect("symcrypt-sys package not found");
    package["rust_version"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap()
}

#[allow(clippy::collapsible_if)]
fn fix_bindings_for_windows(triple: &str, bindings_file: &str) {
    if triple.contains("windows") {
        println!("Fixing bindings for Windows");
        let link_str =
            r#"#[cfg_attr(feature = "dynamic", link(name = "symcrypt", kind = "dylib"))]"#;
        let regex_exp1 = regex::Regex::new(r"pub static \w+: \[SYMCRYPT_OID; \d+usize\];").unwrap();
        let regex_exp2 = regex::Regex::new(r"pub static \w+: PCSYMCRYPT_\w+;").unwrap();
        let bindings_content =
            std::fs::read_to_string(bindings_file).expect("Unable to read bindings file");

        let mut out_content = Vec::new();
        let lines: Vec<&str> = bindings_content.lines().collect();
        out_content.push(lines[0]);

        for i in 1..lines.len() {
            if lines[i - 1].contains("extern \"C\" {") {
                if regex_exp1.is_match(lines[i]) || regex_exp2.is_match(lines[i]) {
                    out_content.pop();
                    out_content.push(link_str);
                    out_content.push(lines[i - 1]);
                }
            }
            out_content.push(lines[i]);
        }

        out_content.push(""); // Add an empty line at the end
        std::fs::write(bindings_file, out_content.join("\n"))
            .expect("Unable to write bindings file");
    }
}
