# Detailed Build and Install

This page provides more detailed installation instructions for linking against `SymCrypt` on Windows and Linux.

The `symcrypt` crate is a wrapper on top of the `SymCrypt` library, and requires access to the `SymCrypt` library during the build and execution stage. For ease of use, the recommended way to configure your `SymCrypt` library dependancy is to obtain the required binaries from the official [SymCrypt Repo](https://github.com/microsoft/SymCrypt/releases/tag/v103.11.0).

However, If you wish to build your own version of the underlying `SymCrypt` library please follow the [Build Instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md) that are provided by SymCrypt to install SymCrypt for your target architecture.

By default, the crate links against SymCrypt dynamically. See [Static Linking](#static-linking) below for the experimental static-link option.

### Windows Install 

The `symcrypt.lib` can be found in the the following path after `SymCrypt` has been downloaded and unzipped.

`C:\Your-Path-To-SymCrypt-Release-Download\dll\`

The SymCrypt crate needs to link against the `SymCrypt` import library during build.

To do so you must set the `SYMCRYPT_LIB_PATH` environment variable. You can do this by using the following command:

`setx SYMCRYPT_LIB_PATH "<your-path-to-symcrypt-lib-folder>"`
The `symcrypt.dll` can be found in the the following path after SymCrypt has been downloaded and unzipped.
`C:\Your-Path-To-SymCrypt-Release-Download\dll\`
During runtime, Windows will handle finding all needed `dll`'s in order to run the intended program, this includes our `symcrypt.dll` file. The places Windows will look are:
1. The folder from which the application loaded.
2. The system folder. Use the `GetSystemDirectory` function to retrieve the path of this folder.
3. The Windows folder. Use the `GetWindowsDirectory` function to get the path of this folder.
4. The current folder.
5. The directories listed in the PATH environment variable.
For more info please see: [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
Here are 2 recommended options to ensure your `symcrypt.dll` is found by Windows during runtime.
1. Put the `symcrypt.dll` in the same folder as your output `.exe` file. If you are doing development (not release), the common path will be: `C:\your-project\target\debug\`.
2. Permanently add the `symcrypt.dll` path into your System PATH environment variable. Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypt.lib`

**NOTE:** By setting the `SYMCRYPT_LIB_PATH` via `setx SYMCRYPT_LIB_PATH "<your-path-to-symcrypt-lib-folder>"`; `symcrypt.dll` will already be on the `PATH` and you will not have to do any additional configuration for your program.

### Linux Install

Though the artifacts on the [SymCrypt Repo](https://github.com/microsoft/SymCrypt/releases/tag/v103.11.0). Have been built with `Ubuntu` in mind, the `SymCrypt` library has been built with very few standard library dependencies and should work on most Linux distributions. 

After installing and unzipping SymCrypt on a Linux distro, the required `libsymcrypt.so*` files can be found in the following path:
`~/Your-Path-To-SymCrypt-Release-Download/lib/`

The `symcrypt` crate needs to be able to link with these libs during build/run time. In order to mimic the installation path for other libraries, you must place the `libsymcrypt.so*` files into linker load path. The way that this is set will vary between distros. On most distros it set via the environment variable `$LD_LIBRARY_PATH`.

Alternatively, you can point the build at an arbitrary directory by setting `SYMCRYPT_LIB_PATH` to the folder containing `libsymcrypt.so*`. This adds that folder to the linker search path at build time but does not affect runtime library resolution — you still need the loader to find the `.so` at run time (e.g. via `LD_LIBRARY_PATH`, `rpath`, or `ldconfig`).

**Note:** While the `symcrypt` crate has only been tested on `Ubuntu`, working with other distros should be similar. The goal is to place the `libsymcrypt.so*` files in a location where the your Linux distro can find the required libs at build/run time. The path may be different depending on your flavour of Linux, and architecture.

---

## Target-Specific Environment Variables

All `SYMCRYPT_*` environment variables consumed by the build script (`SYMCRYPT_LIB_PATH`, `SYMCRYPT_STATIC`) also accept a target-prefixed form, which takes precedence when set. The prefix is the current Rust target triple, uppercased with `-` replaced by `_`.

Examples:
- `X86_64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `AARCH64_UNKNOWN_LINUX_GNU_SYMCRYPT_LIB_PATH`
- `X86_64_PC_WINDOWS_MSVC_SYMCRYPT_LIB_PATH`

This is useful when cross-compiling or when a single host needs different values for different targets.

---

## Static Linking

> **Experimental.** Static linking is a work-in-progress and not recommended for production use. The interface may change.

Static linking can be enabled by setting the environment veriable `SYMCRYPT_STATIC` to any non-zero value (e.g. `1`). When enabled, the build script will attempt to statically link SymCrypt into the final binary, instead of creating a dynamic link directive. Set `SYMCRYPT_LIB_PATH` to the directory containing the static `symcrypt` library. As SymCrypt's build system does not output a single static libsymcrypt library by default, acquiring such an object is left as an exercise to the reader.
