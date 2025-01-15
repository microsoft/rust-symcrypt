#!/bin/bash
# Helper script called from generate-all-bindings.ps1, mainly to set the PATH to cargo binaries

export PATH=$PATH:~/.cargo/bin
echo "Running: $1"
eval "$1"