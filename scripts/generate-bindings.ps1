# This script generates Rust bindings for the SymCrypt library using bindgen.
# It can be called directly from the command line or via generate-all-bindings.ps1.
#
# Prerequisites:
# - LLVM
# - bindgen

[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage="Current triple can be found by running 'clang -print-target-triple'")]
    [string]$triple,
    [Parameter(Mandatory, HelpMessage="Output directory for the generated bindings")]
    [string]$outDir
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $True

# Init variables
$SymCryptSysCrate = "$PSScriptRoot/../symcrypt-sys"
$SymCryptSysCrate = $SymCryptSysCrate.Replace("\", "/")
$wrapperHeader = "$SymCryptSysCrate/inc/wrapper.h"
$targetName = $triple.Replace("-", "_")
$bindingsFile = "$outDir/$targetName.rs"

$supportedTargets = @(
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu"
)

if ($supportedTargets -notcontains $triple) {
    Write-Error "Unsupported target: $triple. Supported targets: $supportedTargets"
    exit 1
}

$importRules = @(
# INIT FUNCTIONS
@("allowlist_function", "SymCryptModuleInit"),
@("allowlist_var", "^(SYMCRYPT_CODE_VERSION.*)$"),
# HASH FUNCTIONS
@("allowlist_function", "^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)(?:Init|Append|Result|StateCopy)?$"),
@("allowlist_var", "^(SYMCRYPT_(SHA3_256|SHA3_384|SHA3_512|SHA256|SHA384|SHA512|SHA1|MD5)_RESULT_SIZE$)"),
@("allowlist_var", "^SymCrypt(?:Sha3_(?:256|384|512)|Sha(?:256|384|512|1)|Md5)Algorithm$"),
# HMAC FUNCTIONS
@("allowlist_function", "^SymCryptHmac(?:Sha(?:256|384|512|1)|Md5)(?:ExpandKey|Init|Append|Result|StateCopy)?$"),
@("allowlist_var", "^(SymCryptHmac(Sha256|Sha384|Sha512|Sha1|Md5)Algorithm)$"),
# GCM FUNCTIONS
@("allowlist_function", "^(SymCryptGcm(?:ValidateParameters|ExpandKey|Encrypt|Decrypt|Init|StateCopy|AuthPart|DecryptPart|EncryptPart|EncryptFinal|DecryptFinal)?)$"),
@("allowlist_function", "SymCryptChaCha20Poly1305(Encrypt|Decrypt)"),
@("allowlist_function", "^SymCryptTlsPrf1_2(?:ExpandKey|Derive)?$"),
# CBC FUNCTIONS
@("allowlist_function", "^SymCryptAesCbc(Encrypt|Decrypt)?$"),
# BLOCK CIPHERS
@("allowlist_var", "SymCryptAesBlockCipher"),
@("allowlist_function", "^SymCryptAesExpandKey$"),
@("allowlist_var", "SYMCRYPT_AES_BLOCK_SIZE"),
# HKDF FUNCTIONS
@("allowlist_function", "^(SymCryptHkdf.*)$"), 
# ECDH KEY AGREEMENT FUNCTIONS
@("allowlist_function", "^SymCryptEcurve(Allocate|Free|SizeofFieldElement)$"),
@("allowlist_var", "^SymCryptEcurveParams(NistP256|NistP384|NistP521|Curve25519)$"),
@("allowlist_function", "^(SymCryptEckey(Allocate|Free|SizeofPublicKey|SizeofPrivateKey|GetValue|SetRandom|SetValue|SetRandom|))$"),
@("allowlist_var", "SYMCRYPT_FLAG_ECKEY_ECDH"),
@("allowlist_var", "SYMCRYPT_FLAG_ECKEY_ECDSA"),
@("allowlist_function", "SymCryptEcDhSecretAgreement"),
# RSA FUNCTIONS
@("allowlist_function", "^SymCryptRsa.*"), # Must allow ALL SymCryptRsakey* before blocking the functions that are not needed.
@("blocklist_function", "SymCryptRsakeyCreate"),
@("blocklist_function", "SymCryptRsakeySizeofRsakeyFromParams"),
@("blocklist_function", "SymCryptRsakeyWipe"),
@("blocklist_function", "SymCryptRsaSelftest"),
@("blocklist_function", "^SymCryptRsaRaw.*$"),
@("allowlist_var", "SYMCRYPT_FLAG_RSAKEY_ENCRYPT"),
@("allowlist_var", "SYMCRYPT_FLAG_RSAKEY_SIGN"),
# ECDSA functions
@("allowlist_function", "^(SymCryptEcDsa(Sign|Verify).*)"),
# RSA PKCS1 FUNCTIONS
@("allowlist_function", "^(SymCryptRsaPkcs1(Sign|Verify|Encrypt|Decrypt).*)$"),
@("allowlist_var", "SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1"),
@("allowlist_var", "SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID"),
# RSA PSS FUNCTIONS
@("allowlist_function", "^(SymCryptRsaPss(Sign|Verify).*)$"),
# OID LISTS
@("allowlist_var", "^SymCrypt(Sha(1|256|384|512|3_(256|384|512))|Md5)OidList$"),
# UTILITY FUNCTIONS
@("allowlist_function", "SymCryptWipe"),
@("allowlist_function", "SymCryptRandom"),
@("allowlist_function", "SymCryptLoadMsbFirstUint64"),
@("allowlist_function", "SymCryptStoreMsbFirstUint64")
)

$generateVarsParams = @()
$generateFunctionsParams = @()
foreach ($rule in $importRules) {
    $ruleType = $rule[0]
    $ruleValue = $rule[1]
    if ($ruleType -eq "allowlist_function") {
        $generateFunctionsParams += "--allowlist-function" 
        $generateFunctionsParams += $ruleValue
    } elseif ($ruleType -eq "blocklist_function") {
        $generateFunctionsParams += "--blocklist-function" 
        $generateFunctionsParams += $ruleValue
    } elseif ($ruleType -eq "allowlist_var") {
        $generateVarsParams += "--allowlist-var" 
        $generateVarsParams += $ruleValue
    }
}

$bindgenParams = @(
    #"--generate-block",
    #"--no-layout-tests",
    #"--with-derive-eq",
    "--with-derive-default"
    #"--with-derive-hash",
    #"--with-derive-ord",
    #"--use-array-pointers-in-arguments"
)
$clangParams = @(
    "-v",
    "-target", $triple,    
    "-I$SymCryptSysCrate/inc/lib",
    "-I$SymCryptSysCrate/symcrypt/inc",
    "-I$SymCryptSysCrate/symcrypt/lib"
)

# Generate bindings
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

bindgen `
    $wrapperHeader `
    @bindgenParams `
    @generateVarsParams `
    @generateFunctionsParams `
    -o $bindingsFile `
    -- @clangParams

if ($triple.Contains("windows")) {
    Write-Host "Fixing bindings for Windows"
    $linkStr = '#[link(name = "symcrypt", kind = "dylib")]'
    $regexExp1 = 'pub static \w+: \[SYMCRYPT_OID; \d+usize\];'
    $regexExp2 = 'pub static \w+: PCSYMCRYPT_\w+;'
    $bindingsContent = Get-Content $bindingsFile

    $outContent = @()
    $outContent += $bindingsContent[0]

    for ($i = 1; $i -lt $bindingsContent.Length; $i++) {
        if ($bindingsContent[$i-1].Contains('extern "C" {')) {
            if ($bindingsContent[$i] -match $regexExp1 -or $bindingsContent[$i] -match $regexExp2) {
                $outContent = $outContent[0..($outContent.Length - 2)]
                $outContent += $linkStr
                $outContent += $bindingsContent[$i-1]
            }
        }
        $outContent += $bindingsContent[$i]
    }
    
    $outContent | Set-Content $bindingsFile
}
