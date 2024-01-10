extern crate bindgen;

use std::env;
use std::path::PathBuf;


/// This file is used to generate SymCrypt bindings. We have moved this over to a separate crate because it should only be 
/// used by developers of the symcrypt, and symcrypt-sys crates. Since bindings are maintained and directly checked into
/// symcrypt-sys crate there is no need to have the bindgen bulk included in the symcrypt-sys crate. 


fn main() {
    println!("cargo:libdir=../SymCrypt/inc"); // SymCrypt *.h files are needed for binding generation. If you are missing this,
    // try pulling SymCrypt as a git module 
    println!("cargo:rerun-if-changed=inc/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("inc/wrapper.h")
        .clang_arg("-v")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // ALLOWLIST

        // INIT FUNCTIONS
        .allowlist_function("SymCryptModuleInit")
        .allowlist_var("^(SYMCRYPT_CODE_VERSION.*)$")
        // HASH FUNCTIONS
        .allowlist_function("^(SymCryptSha(256|384)(?:Init|Append|Result|StateCopy)?)$")
        .allowlist_var("^(SYMCRYPT_(SHA256|SHA384)_RESULT_SIZE$)")
        // HMAC FUNCTIONS
        .allowlist_function("^(SymCryptHmacSha(256|384)(?:ExpandKey|Init|Append|Result|StateCopy)?)$")
        // GCM FUNCTIONS
        .allowlist_function("^(SymCryptGcm(?:ValidateParameters|ExpandKey|Encrypt|Decrypt|Init|StateCopy|AuthPart|DecryptPart|EncryptPart|EncryptFinal|DecryptFinal)?)$")
        .allowlist_function("SymCryptChaCha20Poly1305(Encrypt|Decrypt)")
        .allowlist_function("^SymCryptTlsPrf1_2(?:ExpandKey|Derive)?$")
        .allowlist_var("SymCryptAesBlockCipher")
        // HKDF FUNCTIONS
        .allowlist_function("^(SymCryptHkdf.*)$") // TODO: Tighten bindgen after implementation is complete.
        // ECDH KEY AGREEMENT FUNCTIONS
        .allowlist_function("^SymCryptEcurve(Allocate|Free|SizeofFieldElement)$")
        .allowlist_var("^SymCryptEcurveParams(NistP256|NistP384|Curve25519)$")
        .allowlist_function("^(SymCryptEckey(Allocate|Free|SizeofPublicKey|GetValue|SetRandom|SetValue|SetRandom|))$")
        .allowlist_var("SYMCRYPT_FLAG_ECKEY_ECDH")
        .allowlist_function("SymCryptEcDhSecretAgreement")
        // UTILITY FUNCTIONS
        .allowlist_function("SymCryptWipe")
        .allowlist_function("SymCryptRandom")
        
        .generate_comments(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("raw_generated_bindings.rs"))
        .expect("Couldn't write bindings!");
}
