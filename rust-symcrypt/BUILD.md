# Detailed Build and Install

This page provides a more detailed build and installation instructions for users
who want to use their own `symcrypt*` files.

## Installation
To use the SymCrypt crate, you must have a local version of [SymCrypt](https://github.com/microsoft/SymCrypt) downloaded.

Please follow the [Build Instructions](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md) that is provided by SymCrypt to install SymCrypt for your target architecture.

Once SymCrypt is installed and built locally on your machine, we must configure your machine so that the SymCrypt crate's build script can easily find `symcrypttestmodule.dll` and `symcrypttestmodule.lib` which are needed on Windows, or the `libsymcrypt.so*` files which are needed for Linux. 

### Windows Install 

The `symcrypttestmodule.lib` can be found in the the following path after SymCrypt has been successfully downloaded and built. 

`C:\Your-Path-To-SymCrypt\SymCrypt\bin\lib`

The SymCrypt crate needs a static lib to link to during its build/link time. You must configure your system so that the SymCrypt crate's build script can easily find the needed `symcrypttestmodule.lib` file.

You can configure your system one of 3 ways.

1. Add the lib path as a one time cargo environment variable.
    ```powershell
    $env:RUSTFLAGS='-L C:\Your-Path-To-SymCrypt\SymCrypt\bin\lib'
    ```
    **Note:** This change will only persist within the current process, and you must re-set the PATH environment variable after closing the PowerShell window.

2. Manually copy the `symcrypttestmodule.lib` to `C:\Windows\System32`
    Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`

3. Permanently add the lib path into your system PATH environment variable. Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`

**Option 1 or Option 2 is what is recommended for ease of use.**

The `symcrypttestmodule.dll` can be found in the the following path after SymCrypt has been successfully downloaded and built. 

`C:\Your-Path-To-SymCrypt\SymCrypt\bin\exe`

During runtime, Windows will handle finding all needed `dll`'s in order to run the intended program, this includes our `symcrypttestmodule.dll` file. The places Windows will look are:

1. The folder from which the application loaded.
2. The system folder. Use the `GetSystemDirectory` function to retrieve the path of this folder.
3. The Windows folder. Use the `GetWindowsDirectory` function to get the path of this folder.
4. The current folder.
5. The directories listed in the PATH environment variable.

For more info please see: [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

Here are 4 recommended options to ensure your `symcrypttestmodule.dll` is found by Windows during runtime.

1. Put the symcrypttesmodule.dll in the same folder as your output `.exe` file. If you are doing development (not release), the common path will be: `C:\your-project\target\debug\`.
2. Add the symcrypttestmoudle.dll path as a one time environment variable. 
    ```powershell
    $env:PATH = "C:\Your-Path-To-SymCrypt\SymCrypt\bin\exe;$env:PATH"
    ```
    **Note:** This change will only persist within the current process, and you must re-set the PATH environment variable after closing the PowerShell window.

3. Manually copy `symcrypttestmodule.dll` into your `C:/Windows/System32/` 
    Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.dll`
4. Permanently add the `symcrypttestmodule.dll` path into your System PATH environment variable. Doing this will ensure that any project that uses the SymCrypt crate will be able to access `symcrypttestmodule.lib`

**Option 3 or Option 4 is what is recommended for ease of use.** 

### Linux Install

After building SymCrypt on linux, the required `libsymcrypt.so*` files can be found in the following path:
`~/Your-Path-To-SymCrypt/SymCrypt/bin/module/oe_full/`

The symcrypt crate needs to be able to link with these libs during build/run time. In order to mimic the installation path for other libraries, you must place the `libsymcrypt.so*` files into the `/usr/lib/x86_64-linux-gnu/` folder. This is where the linker will look for the `libsymcrypt.so*` files. 

**Note:** This process has been streamlined for `Mariner`, and there is no garuntee for combatibility on other Linux distros at the moment. 

