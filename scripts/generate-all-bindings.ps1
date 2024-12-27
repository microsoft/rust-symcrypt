# This script generates all bindings for all four triples.
# Pre-requisites:
# - The script has to be run from on Windows with WSL installed
# - LLVM and bingen have to be installed on Windows and on WSL

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

Remove-Item -Recurse -Force "$PSScriptRoot/../symcrypt-sys/src/bindings"

& "$PSScriptRoot/generate-bindings.ps1" $header "x86_64-pc-windows-msvc"
& "$PSScriptRoot/generate-bindings.ps1" $header "aarch64-pc-windows-msvc"

wsl --shutdown # force WSL to reload the environment
wsl exec pwsh "scripts/generate-bindings.ps1" $header "x86_64-unknown-linux-gnu" "~/.cargo/bin/bindgen"
wsl exec pwsh "scripts/generate-bindings.ps1" $header "aarch64-unknown-linux-gnu" "~/.cargo/bin/bindgen"

Remove-Item $header

cargo fmt -p symcrypt-sys