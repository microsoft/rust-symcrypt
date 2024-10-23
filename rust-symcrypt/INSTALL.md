# Detailed Build and Install

This page provides more detailed installation instructions

## Installation
For ease of use, the recommended usage is to obtain these binaries from the official SymCrypt [Repo](https://github.com/microsoft/SymCrypt/releases/tag/v103.4.2).

**Note:** If you wish to build your own version please follow the [Build Instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md) that are provided by SymCrypt to install SymCrypt for your target architecture.

Once SymCrypt is installed on your machine, we must configure your machine so that the SymCrypt crate's build script can easily find `symcrypt.dll` and `symcrypt.lib` which are needed on Windows, or the `libsymcrypt.so*` files which are needed for Linux. 

### Windows Install 

The `symcrypt.lib` can be found in the the following path after SymCrypt has been downloaded and unzipped.

`C:\Your-Path-To-SymCrypt-Release-Download\dll\`

The SymCrypt crate needs to link against the SymCrypt import library during build.

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

### Linux Install

After installing and unzipping SymCrypt on a Linux distro, the required `libsymcrypt.so*` files can be found in the following path:
`~/Your-Path-To-SymCrypt-Release-Download/lib/`

The symcrypt crate needs to be able to link with these libs during build/run time. In order to mimic the installation path for other libraries, you must place the `libsymcrypt.so*` files into linker load path. The way that this is set will vary between distros. On most distros it set via the environment variable `$LD_LIBRARY_PATH`.
