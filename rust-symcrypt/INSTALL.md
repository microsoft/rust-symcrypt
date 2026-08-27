# Detailed Build and Install

This page describes how to dynamically link `symcrypt` against SymCrypt on Windows and Linux.
Version 0.6.0 requires [SymCrypt v103.6.0](https://github.com/microsoft/SymCrypt/releases/tag/v103.6.0) or newer.
To build SymCrypt yourself, follow the upstream [build instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md).

## Windows

The Windows release archive contains both files required by an application:

- `symcrypt.lib` is the import library used by the linker during the build.
- `symcrypt.dll` is the dynamic library loaded when the application runs.

Set `SYMCRYPT_LIB_PATH` to the directory containing `symcrypt.lib`:

```powershell
$env:SYMCRYPT_LIB_PATH = "C:\path\to\SymCrypt\dll"
```

`SYMCRYPT_LIB_PATH` configures only the build-time linker search path. It does not change the
Windows DLL search path. At runtime, either place `symcrypt.dll` beside the application executable
or configure Windows so the directory containing the DLL is searched. See the Windows
[dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
for the complete rules.

## Linux

The Linux release archive contains `libsymcrypt.so*` under `lib/`.

Set `SYMCRYPT_LIB_PATH` to that directory for the build:

```bash
export SYMCRYPT_LIB_PATH="/path/to/SymCrypt/lib"
```

The runtime loader must also be able to find `libsymcrypt.so`. Configure this separately using the
appropriate mechanism for the distribution, such as `LD_LIBRARY_PATH`, `rpath`, or `ldconfig`.

## Target-specific environment variables

`SYMCRYPT_LIB_PATH` also accepts a target-prefixed form, which takes precedence over the unprefixed
variable. The prefix is the Rust target triple uppercased with `-` replaced by `_`.

Examples:

- `X86_64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `AARCH64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `X86_64_PC_WINDOWS_MSVC_SYMCRYPT_LIB_PATH`

This is useful when cross-compiling or when a host builds for multiple targets.
