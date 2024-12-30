#!/bin/bash
# Helper script called from generate-all-bindings.ps1, mainly to set the PATH to cargo binaries

export PATH=$PATH:~/.cargo/bin
pwsh ./scripts/generate-bindings.ps1 $1 $2
