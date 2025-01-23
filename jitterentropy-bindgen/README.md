# jitterentropy-bindgen

This repository is intended for development purposes only. Users should not generate or use their
own raw bindings.

## Updating Bindings

To create new bindings, run the following command:

```powershell
cargo run --locked --bin jitterentropy-bindgen <out file> [triple]
```

For Windows users, there is a script available to update bindings for all four supported platforms:

```powershell
./scripts/generate_all_bindings.ps1
```

Alternatively, you can create a pull request with the `publish_new_bindings` label. In this case,
the bindings will be published as an artifact on GitHub.
