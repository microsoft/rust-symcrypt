extern crate bindgen;

use std::env;
use std::path::PathBuf;


/// This file is used to generate SymCrypt bindings. We have moved this over to a separate crate because it should only be 
/// used by developers of the symcrypt, and symcrypt-sys crates. Since bindings are maintained and directly checked into
/// symcrypt-sys crate there is no need to have the bindgen bulk included in the symcrypt-sys crate. 


pub(crate) fn generate_bindings() {
    println!("cargo:libdir=SymCrypt/inc"); // SymCrypt *.h files are needed for binding generation. If you are missing this,
    // try pulling SymCrypt as a git module 
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_file = out_path.join("symcrypt_static_generated_bindings.rs");

    if bindings_file.exists() {
        println!("Bindings already generated, skipping bindgen.");
        return;
    }
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-v")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // ALLOWLIST

        // INIT FUNCTIONS
        .allowlist_function("SymCryptModuleInit")
        .allowlist_var("^(SYMCRYPT_CODE_VERSION.*)$")
        .allowlist_function("SymCryptInit")
        // HASH FUNCTIONS
        .allowlist_function("^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)(?:Init|Append|Result|StateCopy)?$")
        .allowlist_var("^(SYMCRYPT_(SHA3_256|SHA3_384|SHA3_512|SHA256|SHA384|SHA512|SHA1|MD5)_RESULT_SIZE$)")
        .allowlist_var("^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)Algorithm$")
        // HMAC FUNCTIONS
        .allowlist_function("^SymCryptHmac(?:Sha(?:256|384|512|1)|Md5)(?:ExpandKey|Init|Append|Result|StateCopy)?$")
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

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("symcrypt_static_generated_bindings.rs"))
        .expect("Couldn't write bindings!");
}
