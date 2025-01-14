# This script generates Rust bindings for the SymCrypt library for all supported target triples.
# Prerequisites:
# - The script must be run on Windows with WSL installed.
# - LLVM and bindgen must be installed on both Windows and WSL.

# Installation instructions:
# Windows:
#    winget install LLVM.LLVM
#    cargo install bindgen-cli@0.71.1
# WSL Ubuntu:
#    sudo apt install pwsh clang libclang-dev
#    sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu # for cross-compilation
#    cargo install bindgen-cli@0.71.1

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $True

Push-Location "$PSScriptRoot/.." # Move to the root of the project

python3 "./symcrypt-sys/symcrypt/scripts/version.py" --build-info
mv -Force "./symcrypt-sys/symcrypt/inc/buildInfo.h" "./symcrypt-sys/inc/"

$bindingsDir = "./symcrypt-sys/src/bindings" # is relative to the project root
if (Test-Path $bindingsDir) {
    Remove-Item -Recurse -Force "$bindingsDir"
}

& "$PSScriptRoot/generate-bindings.ps1" "x86_64-pc-windows-msvc" $bindingsDir
& "$PSScriptRoot/generate-bindings.ps1" "aarch64-pc-windows-msvc" $bindingsDir

wsl --shutdown # force WSL to reload the environment
wsl exec bash "./scripts/generate-bindings.sh" "x86_64-unknown-linux-gnu" $bindingsDir
wsl exec bash "./scripts/generate-bindings.sh" "aarch64-unknown-linux-gnu" $bindingsDir

cargo fmt -p symcrypt-sys

Pop-Location
