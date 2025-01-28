# This script generates Rust bindings for the SymCrypt library for all supported target triples.
# Prerequisites:
# - The script must be run on Windows with WSL installed.
# - LLVM and bindgen must be installed on both Windows and WSL.

# Installation instructions:
# Setting up Windows:
#    winget install LLVM.LLVM
#
# Setting up WSL:
#  - It's better to install the most recent version of Ubuntu, rustup, etc.
#    wsl --install Ubuntu-24.04
#
#  - Enter the WSL shell and run the following commands:
#    sudo apt update && sudo apt upgrade
#    sudo apt install -y clang libclang-dev rustup
#    sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu # for cross-compilation
#    
#    rustup update 
#    rustup toolchain add stable
#    rustup target add x86_64-unknown-linux-gnu
#    rustup target add aarch64-unknown-linux-gnu

param (
    # Sets CARGO_TARGET_DIR environment variable for WSL builds.
    # This is necessary because if we try to build from Windows volume, WSL might fail to detect 
    # changes in the file system.
    [string]$wslTempDir = "~/rust-symcrypt/target"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $True

Push-Location "$PSScriptRoot/.." # Move to the root of the project

git submodule update --init

python3 "./symcrypt-sys/symcrypt/scripts/version.py" --build-info
mv -Force "./symcrypt-sys/symcrypt/inc/buildInfo.h" "./symcrypt-sys/inc/"

$bindingsDir = "./symcrypt-sys/src/bindings" # is relative to the project root
if (Test-Path $bindingsDir) {
    Remove-Item -Recurse -Force "$bindingsDir"
}

cargo run --locked --bin symcrypt-bindgen "x86_64-pc-windows-msvc" $bindingsDir
cargo run --locked --bin symcrypt-bindgen "aarch64-pc-windows-msvc" $bindingsDir

Write-Host "Restarting WSL..." && wsl --shutdown # force WSL to reload the environment
wsl exec bash "./scripts/run.sh" "export CARGO_TARGET_DIR=$wslTempDir && cargo build -p symcrypt-bindgen"
wsl exec bash "./scripts/run.sh" "export CARGO_TARGET_DIR=$wslTempDir && cargo run --locked --bin symcrypt-bindgen x86_64-unknown-linux-gnu $bindingsDir"
wsl exec bash "./scripts/run.sh" "export CARGO_TARGET_DIR=$wslTempDir && cargo run --locked --bin symcrypt-bindgen aarch64-unknown-linux-gnu $bindingsDir"

cargo fmt -p symcrypt-sys

Pop-Location
