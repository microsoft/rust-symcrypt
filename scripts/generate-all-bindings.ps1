# This script generates Rust bindings for the SymCrypt library for all supported target triples.
# Prerequisites:
# - The script must be run on Windows with WSL installed.
# - LLVM and bindgen must be installed on both Windows and WSL.

# Installation instructions:
# Windows:
#    winget install LLVM.LLVM
#    cargo install bindgen-cli
# WSL Ubuntu:
#    sudo apt install pwsh clang libclang-dev
#    sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu # for cross-compilation
#    cargo install bindgen-cli

[CmdletBinding()]
param([string]$SymCryptRoot = "../SymCrypt")

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $True


cd "$PSScriptRoot/.." # Move to the root of the project
$SymCryptRoot = $SymCryptRoot.Replace("\", "/")

$header = "$SymCryptRoot/inc/wrapper.h"
$wrapperHeader = '
#ifdef __linux__
#include <stddef.h>
#endif

#include "symcrypt.h"
'
$wrapperHeader > $header

$bindingsDir = "$PSScriptRoot/../symcrypt-sys/src/bindings"
if (Test-Path $bindingsDir) {
    Remove-Item -Recurse -Force "$bindingsDir"
}

& "$PSScriptRoot/generate-bindings.ps1" $header "x86_64-pc-windows-msvc"
& "$PSScriptRoot/generate-bindings.ps1" $header "aarch64-pc-windows-msvc"

wsl --shutdown # force WSL to reload the environment
wsl exec bash "./scripts/generate-bindings.sh" $header "x86_64-unknown-linux-gnu"
wsl exec bash "./scripts/generate-bindings.sh" $header "aarch64-unknown-linux-gnu"

Remove-Item $header

cargo fmt -p symcrypt-sys