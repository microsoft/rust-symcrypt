# Detailed Build and Install

The `symcrypt` crate dynamically links against the native SymCrypt library on Windows and Linux.
The native library must be available both while building the Rust application and when running it.

Version 0.6.0 requires
[SymCrypt v103.6.0](https://github.com/microsoft/SymCrypt/releases/tag/v103.6.0) or newer. The
recommended starting point is the matching archive from the official
[SymCrypt releases page](https://github.com/microsoft/SymCrypt/releases). To build SymCrypt
yourself, follow the upstream [build instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md).

## Windows installation

The Windows release archive contains two files used by Rust applications:

- `symcrypt.lib` is the import library used by the linker at build time.
- `symcrypt.dll` is the dynamic library loaded at runtime.

Both files are under the archive's `dll` directory:

```text
C:\path\to\SymCrypt\dll\
```

### Build-time configuration

Set `SYMCRYPT_LIB_PATH` to the directory containing `symcrypt.lib`:

```powershell
$env:SYMCRYPT_LIB_PATH = "C:\path\to\SymCrypt\dll"
```

This command configures the current PowerShell session. To persist the value for future terminals,
use:

```powershell
setx SYMCRYPT_LIB_PATH "C:\path\to\SymCrypt\dll"
```

Open a new terminal after using `setx`.

This sets only the `SYMCRYPT_LIB_PATH` variable. It does not modify the Windows `PATH` variable.

`SYMCRYPT_LIB_PATH` only tells the Rust linker where to find `symcrypt.lib`. It does not add the
directory to the Windows DLL search path and does not control which `symcrypt.dll` is loaded at
runtime.

### Runtime configuration

Windows searches several locations when loading a DLL. Relevant locations include:

1. The directory containing the application executable.
2. The Windows system directory.
3. The Windows directory.
4. The current working directory, depending on the active safe-search configuration.
5. Directories listed in the `PATH` environment variable.

The exact order depends on the application and Windows configuration. See Microsoft's
[dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
documentation for the complete rules.

The simplest deployment option is to place `symcrypt.dll` beside the final application executable.
For local development, another option is to add the SymCrypt `dll` directory to `PATH` before
running the application:

```powershell
$env:PATH = "C:\path\to\SymCrypt\dll;$env:PATH"
```

Setting `SYMCRYPT_LIB_PATH` and configuring runtime DLL discovery are separate steps.

## Linux installation

### Azure Linux 3

SymCrypt is normally preinstalled on Azure Linux 3. Install it if needed, apply available updates,
and verify the installed version:

```bash
sudo tdnf install symcrypt
sudo tdnf update symcrypt
tdnf info symcrypt
```

### Other supported distributions

Connect the system to [packages.microsoft.com](https://learn.microsoft.com/en-us/linux/packages),
then install the `symcrypt` package using the distribution's package manager.

For example, on Ubuntu 24.04:

```bash
curl -sSL -O https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y symcrypt
```

The package manager installs SymCrypt into the standard linker and runtime-loader paths. Do not set
`SYMCRYPT_LIB_PATH` or `LD_LIBRARY_PATH` when using this installation method.

If the package manager reports that no `symcrypt` package is available, use the
[manual archive installation](#manual-archive-installation) below.

### Manual archive installation

If a package is unavailable, download the matching Linux archive from the
[SymCrypt releases page](https://github.com/microsoft/SymCrypt/releases). The archive contains
`libsymcrypt.so*` under `lib/`.

For an extracted archive in a nonstandard location, configure the build-time linker:

```bash
export SYMCRYPT_LIB_PATH="/path/to/SymCrypt/lib"
```

The runtime loader must also be able to find `libsymcrypt.so`. For a local development session:

```bash
export LD_LIBRARY_PATH="/path/to/SymCrypt/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

For deployed applications, install the library in a standard system location, configure it through
`ldconfig`, or set an appropriate `rpath`.

## Target-specific environment variables

`SYMCRYPT_LIB_PATH` also accepts a target-prefixed form, which takes precedence over the unprefixed
variable. The prefix is the Rust target triple uppercased with `-` replaced by `_`.

Examples:

- `X86_64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `AARCH64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `X86_64_PC_WINDOWS_MSVC_SYMCRYPT_LIB_PATH`

This is useful when cross-compiling or when a host builds for multiple targets.
