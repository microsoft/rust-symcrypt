# symcrypt-bindgen

This repository is intended for development purposes only. Users should not generate or use their
own raw bindings.

## Updating Bindings

Use the exact LLVM version specified by `LLVM_VERSION` in
[the Bindgen workflow](../.github/workflows/bindgen.yml). All four CI targets use this version.
Set `LIBCLANG_PATH` to that LLVM installation's `bin` directory on Windows or `lib` directory
on Linux, and put its `bin` directory first on `PATH`. Pinning the bindgen crate alone does
not pin the libclang library it loads.

To create new bindings, run the following command:

```powershell
cargo run --locked --bin symcrypt-bindgen <arch> <out dir>
```

For Windows users, there is a script available to update bindings for all four supported platforms:

```powershell
./scripts/generate_all_bindings.ps1
```

Alternatively, you can create a pull request with the `publish_new_bindings` label. In this case,
the bindings will be published as an artifact on GitHub.
