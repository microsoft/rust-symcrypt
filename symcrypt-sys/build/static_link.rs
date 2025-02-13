use super::triple::Triple;
use std::collections::HashSet;

const LIB_NAME: &str = "symcrypt";

/// Compiles and links the SymCrypt library statically.
/// This is the entery point for building SymCrypt statically.
///
/// - Determines the build configuration based on target architecture.
/// - Calls `compile_symcrypt_static()` to actually build SymCrypt.
/// - Outputs necessary metadata for Cargo (`cargo:rustc-link-lib=...`).
///
/// Based on SymCrypt's `CMakeLists.txt`, but adapted for Rust.
pub fn compile_and_link_symcrypt() -> std::io::Result<()> {
    let options = SymCryptOptions::new();
    println!("Build config: {:?}", options);

    // Required Windows bcrypt dependency for BCryptGenRandom
    const ADDITIONAL_DEPENDENCIES: &[&str] = &[
        #[cfg(windows)]
        "bcrypt",
    ];
    println!("cargo:rerun-if-changed=upstream");
    println!("Compiling SymCrypt...");

    // Compile and Build SymCrypt with provided SymCryptOptions
    compile_symcrypt_static(LIB_NAME, &options)?;
    println!("cargo:rustc-link-lib=static={LIB_NAME}");

    // Link additional dependencies
    for dep in ADDITIONAL_DEPENDENCIES {
        println!("cargo:rustc-link-lib=dylib={dep}");
    }

    Ok(())
}

// TODO: update -symcrypt_fips_build comment

/// Holds configuration options for compiling SymCrypt.
///
/// - `triple`: The target triple
/// - `symcrypt_use_asm`: Whether to enable assembly optimizations.
/// - `symcrypt_fips_build`: Whether to build in FIPS mode PLACEHOLDER
/// - `preconfiged_cc`: Returns a Pre-configured `cc` object for the target triple.
#[derive(Debug)]
struct SymCryptOptions {
    triple: Triple,
    symcrypt_use_asm: bool,
    //symcrypt_fips_build: bool, // TODO: Determine if we should expose FIPS build option?
}

impl SymCryptOptions {
    fn new() -> Self {
        Self {
            triple: Triple::get_target_triple(),
            symcrypt_use_asm: false, // FIXME: Turn this to true when we get ASM checked in
                                     //symcrypt_fips_build: false, // TODO: Determine if we should expose FIPS build option?
        }
    }
    fn use_asm(&self) -> bool {
        self.symcrypt_use_asm
    }
    fn triple(&self) -> Triple {
        self.triple.clone()
    }

    // Returns a cc object that has been preconfigured for the target triple
    fn preconfigure_cc(&self) -> cc::Build {
        let mut cc = cc::Build::new();
        cc.target(self.triple.to_triple())
            .include("inc")
            .include("symcrypt/inc")
            .include("symcrypt/lib")
            .warnings(false); // Ignore noisy warnings from SymCrypt

        if !self.symcrypt_use_asm {
            cc.define("SYMCRYPT_IGNORE_PLATFORM", None); // TODO: Fix when we get ASM
        }

        // Set min C version to C11.
        cc.flag("-std=c11");

        // Set specific flags for each target
        match self.triple {
            Triple::x86_64_pc_windows_msvc => {
                cc.define("_AMD64_", None);
                // cc.asm_flag("/DSYMCRYPT_MASM"); // MASM assembly TODO: enable for ASM
                cc.flag("/MP"); // Multi-threaded compilation
                cc.flag("/Zp8"); // Structure packing alignment
                cc.flag("/WX"); // Treat warnings as errors
                cc.flag("/guard:cf"); // Control Flow Guard
                cc.flag("/dynamicbase"); // Enable ASLR
                cc.flag("/EHsc"); // Exception handling
            }
            Triple::aarch64_pc_windows_msvc => {
                cc.define("_ARM64_", None);
            }
            Triple::x86_64_unknown_linux_gnu => {
                cc.flag("-mpclmul");
                cc.flag("-Wno-incompatible-pointer-types"); // Ignore noisy SymCrypt errors
                                                            // From SymCrypt-Platforms.cmake
                cc.flag("-mssse3");
                cc.flag("-mxsave");
                cc.flag("-maes");
                cc.flag("-msha");
                cc.flag("-mrdrnd");
                cc.flag("-mrdseed");
                cc.flag("-mbmi2");
                cc.flag("-fstack-protector-strong");
                cc.flag("-Wstack-protector");
                cc.flag("-fno-plt");
                cc.flag("-fno-builtin-bcmp");
                cc.flag("-fno-unroll-loops");
            }
            Triple::aarch64_unknown_linux_gnu => {
                cc.flag("-march=armv8-a+simd+crypto"); // Enable a baseline of features for the compiler to support everywhere.
                cc.flag("-flax-vector-conversions"); //  Setting -flax-vector-conversions to build Arm64 intrinsics code with GCC.
                cc.flag("-Wno-incompatible-pointer-types"); // Ignore noisy SymCrypt errors
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

fn compile_symcrypt_static(lib_name: &str, options: &SymCryptOptions) -> std::io::Result<()> {
    // Compile intermediates required this is currently only required for x86_64_unknown_linux_gnu
    let (already_compiled_files, intermediates) = compile_symcrypt_intermediates(&options);

    // Convert already compiled files to a HashSet for faster lookups
    let already_compiled_set: HashSet<&str> = already_compiled_files.iter().cloned().collect();

    // Prepares list of files to be compiled, excluding already compiled files for x86_64_unknown_linux_gnu
    let mut base_files: Vec<&'static str> = CMAKE_SOURCES_COMMON
        .lines()
        .map(str::trim) // Trim once instead of inside filter
        .filter(|line| {
            !line.is_empty() && !line.starts_with("#") && !already_compiled_set.contains(line)
        })
        .collect();

    base_files.push("env_generic.c"); // symcrypt_generic

    // Add module-specific files for each target
    let mut module_files = vec![];

    match options.triple() {
        Triple::x86_64_pc_windows_msvc | Triple::aarch64_pc_windows_msvc => {
            base_files.push("env_windowsUserModeWin8_1.c");
            base_files.push("IEEE802_11SaeCustom.c");
            module_files.push("inc/static_WindowsDefault.c");
        }
        Triple::x86_64_unknown_linux_gnu => {
            base_files.push("linux/intrinsics.c"); // Only needed for x86_64_unknown_linux_gnu
            base_files.push("env_posixUserMode.c");
            module_files.push("inc/static_LinuxDefault.c");
        }
        Triple::aarch64_unknown_linux_gnu => {
            base_files.push("env_posixUserMode.c");
            module_files.push("inc/static_LinuxDefault.c");
        }
    }

    // Add assembly pre generated ASM files to be compiled
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

    // Pre-Configure the cc compiler based on the target triple
    let mut cc = options.preconfigure_cc();

    // Add in the intermediates that were previously compiled, will be empty for most targets
    cc.objects(intermediates);

    // Add base files to be compiled
    for file in base_files {
        cc.file(format!("{SOURCE_DIR}/{file}"));
    }

    // Add assembly files to be compiled
    if options.use_asm() {
        for file in asm_files {
            cc.file(format!(
                "{SOURCE_DIR}/asm/{}/{file}", // TODO: replace with right file path when ASM checked in.
                options.triple.to_triple()
            ));
        }
    }

    // Add module-specific files to be compiled
    cc.files(module_files);

    println!("Files to compile: {}", cc.get_files().count());

    // Compiles all files and returns the compiled library
    cc.compile(lib_name);

    Ok(())
}

// Special compile files for x86_64_unknown_linux_gnu
const X86_64_LINUX_CUSTOM_COMPILE_FILES: &str = r#"
set_source_files_properties(aes-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mvaes;-mvpclmulqdq")
set_source_files_properties(sha256Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
set_source_files_properties(sha512Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
set_source_files_properties(sha256-xmm.c PROPERTIES COMPILE_OPTIONS "-mssse3")
set_source_files_properties(sha256-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
set_source_files_properties(sha512-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
"#;

/// Compiles the SymCrypt custom intermediates
///
/// Currently this is only required for x86_64_unknown_linux_gnu,
/// but can be modified to include other targets as needed.
///
/// If the target is not `x86_64_unknown_linux_gnu`, it returns empty vectors
fn compile_symcrypt_intermediates(
    symcrypt_options: &SymCryptOptions,
) -> (Vec<&'static str>, Vec<std::path::PathBuf>) {
    let mut files = vec![];
    let mut intermediates = vec![];

    // Only compile intermediates for x86_64_unknown_linux_gnu.
    // Can modify with additional targets as needed.
    if symcrypt_options.triple() != Triple::x86_64_unknown_linux_gnu {
        return (files, intermediates); // No intermediates to compile
    }

    // Fetch preconfigured cc based on the target triple.
    let mut cc = symcrypt_options.preconfigure_cc();

    for line in X86_64_LINUX_CUSTOM_COMPILE_FILES.lines() {
        if line.trim().is_empty() || line.trim().starts_with("#") {
            continue;
        }

        let line = line
            .strip_prefix("set_source_files_properties(")
            .expect("Malformed input: missing prefix")
            .strip_suffix(")")
            .expect("Malformed input: missing suffix");

        // Example of parts:
        // [aes-ymm.c, PROPERTIES, COMPILE_OPTIONS, "-mavx;-mavx2;-mvaes;-mvpclmulqdq"]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let file = parts[0];
        println!("Compiling {file} with custom options: {}", parts[3]);

        // Isolate the compile options
        let options = parts[3]
            .trim_matches('"')
            .split(';')
            .filter(|s| !s.is_empty());

        // Push intermediates to the cc object to be compiled
        cc.file(format!("{SOURCE_DIR}/{file}"));
        for option in options {
            cc.flag(option);
        }

        // Add the file to the list of files to be replaced by compiled intermediates.
        files.push(file);
    }

    // Use cc's compile_intermediates() to batch generate intermediate files without linking
    let mut result = cc.compile_intermediates();
    intermediates.append(&mut result);

    // Return files to be replaced by intermediates.
    (files, intermediates)
}
