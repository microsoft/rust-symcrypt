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
        .allowlist_function("^(SymCryptSha(256|384|512|1)(?:Init|Append|Result|StateCopy)?)$")
        .allowlist_var("^(SYMCRYPT_(SHA256|SHA384|SHA512|SHA1)_RESULT_SIZE$)")
        // HMAC FUNCTIONS
        .allowlist_function("^(SymCryptHmacSha(256|384|512)(?:ExpandKey|Init|Append|Result|StateCopy)?)$")
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
        // RSA FUNCTIONS
        .allowlist_function("^(SymCryptRsakey.*)$")
        .allowlist_function("^(SymCryptRsaRaw.*)$")
        // DSA FUNCTIONS
        .allowlist_function("^(SymCryptDsa(Sign|Verify).*)$")
        // RSA PKCS1 FUNCTIONS
        .allowlist_function("^(SymCryptRsaPkcs1(Sign|Verify|Encrypt|Decrypt).*)$")
        // RSA PSS FUNCTIONS
        .allowlist_function("^(SymCryptRsaPss(Sign|Verify).*)$")
        // UTILITY FUNCTIONS
        .allowlist_function("SymCryptWipe")
        .allowlist_function("SymCryptRandom")
        
        .generate_comments(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");
// SymCryptRsakeyAllocate
// SymCryptRsakeyGenerate
// SymCryptRsakeySetValue
// SymCryptRsakeyFree
// SymCryptSizeofRsakeyFromParams
// SymCryptRsakeyCreate
// SymCryptRsakeyWipe
// SymCryptRsakeyHasPrivateKey
// SymCryptRsakeySizeofModulus
// SymCryptRsakeyModulusBits
//SymCryptRsakeySizeofPublicExponent
// SymCryptRsakeySizeofPrime
// add sha1 for interop? 
// s
// SymCryptEcDsaVerify ! do not generate the self test 
// SymCryptDsaSign
// SymCryptDsaVerify
// SymCryptRsaPssSign
//SymCryptRsaPssVerify
// SymCryptRsaPkcs1Sign
// SymCryptRsaPkcs1Verify
// SymCryptRsaRaw*, includes SymCryptRsaRawEncrypt, SymCryptRsaRawDecrypt
// SymCryptRsaPkcs1Encrypt
// SymCryptRsaPkcs1Decrypt
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("raw_generated_bindings.rs"))
        .expect("Couldn't write bindings!");
}
