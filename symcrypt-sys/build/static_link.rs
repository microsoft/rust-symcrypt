use super::triple::Triple;

const LIB_NAME: &str = "symcrypt";

pub fn compile_and_link_symcrypt() -> std::io::Result<()> {
    // based on SymCrypt/lib/CMakeLists.txt

    let options = SymCryptOptions::new();
    println!("Build config: {:?}", options);

    // Required Windows bcrypt dependency for BCryptGenRandom
    const ADDITIONAL_DEPENDENCIES: &[&str] = &[
        #[cfg(windows)]
        "bcrypt",
    ];
    println!("cargo:rerun-if-changed=upstream");
    println!("Compiling SymCrypt...");

    compile_symcrypt_static(LIB_NAME, &options)?;
    println!("cargo:rustc-link-lib=static={LIB_NAME}");

    for dep in ADDITIONAL_DEPENDENCIES {
        println!("cargo:rustc-link-lib=dylib={dep}");
    }

    Ok(())
}

#[derive(Debug)]
struct SymCryptOptions {
    triple: Triple,
    symcrypt_use_asm: bool,
    //symcrypt_fips_build: bool,
}
impl SymCryptOptions {
    fn new() -> Self {
        Self {
            triple: Triple::get_target_triple(),
            symcrypt_use_asm: false,
            //symcrypt_fips_build: false,
        }
    }
    fn use_asm(&self) -> bool {
        self.symcrypt_use_asm
    }
    fn triple(&self) -> Triple {
        self.triple.clone()
    }

    fn preconfigure_cc(&self) -> cc::Build {
        let mut cc = cc::Build::new();
        cc.target(self.triple.to_triple())
            .include("inc")
            .include("symcrypt/inc")
            .include("symcrypt/lib")
            .warnings(false);

        if !self.symcrypt_use_asm {
            cc.define("SYMCRYPT_IGNORE_PLATFORM", None);
        }

        match self.triple {
            Triple::x86_64_pc_windows_msvc => {
                cc.asm_flag("/DSYMCRYPT_MASM");
            }
            Triple::aarch64_pc_windows_msvc => {
                cc.define("_ARM64_", None);
            }
            Triple::x86_64_unknown_linux_gnu => {
                cc.include("symcrypt/modules/linux/common");
                cc.flag("-mpclmul");
                cc.flag("-Wno-incompatible-pointer-types"); // Should we create parent Enum for Windows / Linux?
                                                            /*
                                                            cc.flag("-mpclmul")
                                                                .flag("-mssse3")
                                                                .flag("-mxsave")
                                                                .flag("-maes")
                                                                .flag("-msha")
                                                                .flag("-mrdrnd")
                                                                .flag("-mrdseed");
                                                            */
            }
            Triple::aarch64_unknown_linux_gnu => {
                cc.include("symcrypt/modules/linux/common");
                cc.flag("-Wno-incompatible-pointer-types");
            }
        }

        cc
    }
}

const SOURCE_DIR: &str = "symcrypt/lib";
const CMAKE_SOURCES_COMMON: &str = "
3des.c
a_dispatch.c
aes-asm.c
aes-c.c
aes-default-bc.c
aes-default.c
aes-key.c
aes-neon.c
aes-selftest.c
aes-xmm.c
aes-ymm.c
aescmac.c
aesCtrDrbg.c
aeskw.c
AesTables.c
blockciphermodes.c
ccm.c
chacha20_poly1305.c
chacha20.c
cpuid_notry.c
cpuid_um.c
cpuid.c
crt.c
DesTables.c
desx.c
dh.c
dl_internal_groups.c
dlgroup.c
dlkey.c
dsa.c
ec_dh.c
ec_dispatch.c
ec_dsa.c
ec_internal_curves.c
ec_montgomery.c
ec_mul.c
ec_short_weierstrass.c
ec_twisted_edwards.c
eckey.c
ecpoint.c
ecurve.c
equal.c
FatalIntercept.c
fdef_general.c
fdef_int.c
fdef_mod.c
fdef369_mod.c
fips_selftest.c
gcm.c
gen_int.c
ghash.c
hash.c
hkdf_selftest.c
hkdf.c
hmac.c
hmacmd5.c
hmacsha1.c
hmacsha224.c
hmacsha256.c
hmacsha384.c
hmacsha512.c
hmacsha512_224.c
hmacsha512_256.c
hmacsha3_224.c
hmacsha3_256.c
hmacsha3_384.c
hmacsha3_512.c
kmac.c
libmain.c
lms.c
marvin32.c
md2.c
md4.c
md5.c
mldsa.c
mldsa_primitives.c
mlkem.c
mlkem_primitives.c
modexp.c
paddingPkcs7.c
parhash.c
pbkdf2_hmacsha1.c
pbkdf2_hmacsha256.c
pbkdf2.c
poly1305.c
primes.c
rc2.c
rc4.c
rdrand.c
rdseed.c
recoding.c
rsa_enc.c
rsa_padding.c
rsakey.c
ScsTable.c
scsTools.c
selftest.c
service_indicator.c
session.c
sha1.c
sha256.c
sha256Par.c
sha256Par-ymm.c
sha256-xmm.c
sha256-ymm.c
sha512.c
sha512Par.c
sha512Par-ymm.c
sha512-ymm.c
sha3.c
sha3_224.c
sha3_256.c
sha3_384.c
sha3_512.c
shake.c
sp800_108_hmacsha1.c
sp800_108_hmacsha256.c
sp800_108_hmacsha512.c
sp800_108.c
srtp_kdf.c
srtp_kdf_selftest.c
ssh_kdf.c
ssh_kdf_sha256.c
ssh_kdf_sha512.c
sskdf.c
sskdf_selftest.c
tlsCbcVerify.c
tlsprf_selftest.c
tlsprf.c
xmss.c
xtsaes.c
";

// only for x86_64_unknown_linux_gnu
const SPECIAL_FLAGS: &str = r#"
set_source_files_properties(aes-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mvaes;-mvpclmulqdq")
set_source_files_properties(sha256Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
set_source_files_properties(sha512Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
set_source_files_properties(sha256-xmm.c PROPERTIES COMPILE_OPTIONS "-mssse3")
set_source_files_properties(sha256-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
set_source_files_properties(sha512-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
"#;

fn compile_symcrypt_static(lib_name: &str, options: &SymCryptOptions) -> std::io::Result<()> {
    let (already_compiled_files, intermediates) = compile_intermediates(&options);

    let mut base_files: Vec<&'static str> = CMAKE_SOURCES_COMMON
        .lines()
        .filter(|line| {
            let line = line.trim();
            !(line.is_empty() || line.starts_with("#") || already_compiled_files.contains(&line))
        })
        .collect();

    base_files.push("env_generic.c"); // symcrypt_generic

    let mut module_files = vec![];

    match options.triple() {
        Triple::x86_64_pc_windows_msvc | Triple::aarch64_pc_windows_msvc => {
            base_files.push("env_windowsUserModeWin8_1.c");
            base_files.push("IEEE802_11SaeCustom.c");
            //module_files.push("symcrypt/modules/windows/user/module.c");
            module_files.push("inc/static_WindowsDefault.c");
        }
        Triple::x86_64_unknown_linux_gnu => {
            base_files.push("linux/intrinsics.c");
            base_files.push("env_posixUserMode.c");
            module_files.push("inc/static_LinuxDefault.c");
        }
        Triple::aarch64_unknown_linux_gnu => {
            base_files.push("env_posixUserMode.c");
            module_files.push("inc/static_LinuxDefault.c");
        }
    }

    let asm_files = match options.triple() {
        Triple::x86_64_pc_windows_msvc => vec![
            "aesasm.asm",
            "fdef_asm.asm",
            "fdef_mulx.asm",
            "fdef369_asm.asm",
            "sha256xmm_asm.asm",
            "sha256ymm_asm.asm",
            "sha512ymm_asm.asm",
            "sha512ymm_avx512vl_asm.asm",
            "wipe.asm",
        ],
        Triple::aarch64_pc_windows_msvc => vec!["fdef_asm.asm", "fdef369_asm.asm", "wipe.asm"],
        Triple::x86_64_unknown_linux_gnu => vec![
            "aesasm-gas.asm",
            "fdef_asm-gas.asm",
            "fdef369_asm-gas.asm",
            "fdef_mulx-gas.asm",
            "wipe-gas.asm",
            "sha256xmm_asm-gas.asm",
            "sha256ymm_asm-gas.asm",
            "sha512ymm_asm-gas.asm",
            "sha512ymm_avx512vl_asm-gas.asm",
        ],
        Triple::aarch64_unknown_linux_gnu => {
            vec!["fdef_asm-gas.asm", "fdef369_asm-gas.asm", "wipe-gas.asm"]
        }
    };

    let mut cc = options.preconfigure_cc();
    cc.objects(intermediates);

    for file in base_files {
        cc.file(format!("{SOURCE_DIR}/{file}"));
    }

    if options.use_asm() {
        for file in asm_files {
            cc.file(format!(
                "{SOURCE_DIR}/asm/{}/{file}",
                options.triple.to_triple()
            ));
        }
    }
    cc.files(module_files);

    println!("Files to compile: {}", cc.get_files().count());
    cc.compile(lib_name);

    Ok(())
}

fn compile_intermediates(
    symcrypt_options: &SymCryptOptions,
) -> (Vec<&'static str>, Vec<std::path::PathBuf>) {
    let mut files = vec![];
    let mut intermediates = vec![];

    if symcrypt_options.triple() != Triple::x86_64_unknown_linux_gnu {
        return (files, intermediates);
    }

    for line in SPECIAL_FLAGS.lines() {
        if line.trim().is_empty() || line.trim().starts_with("#") {
            continue;
        }

        let line = line
            .strip_prefix("set_source_files_properties(")
            .unwrap()
            .strip_suffix(")")
            .unwrap();

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let file = parts[0];
        println!("Compiling {file} with custom options: {}", parts[3]);

        let options = parts[3]
            .trim_matches('"')
            .split(';')
            .filter(|s| !s.is_empty());

        let mut cc = symcrypt_options.preconfigure_cc();
        cc.file(format!("{SOURCE_DIR}/{file}"));
        for option in options {
            cc.flag(option);
        }
        let mut result = cc.compile_intermediates();

        files.push(file);
        intermediates.append(&mut result);
    }

    (files, intermediates)
}
