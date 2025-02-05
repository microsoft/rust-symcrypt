# Contributing

This document is intended to be read by the current developers of `rust-symcrypt`.

## Structure

This repo contains `rust-symcrypt` as well as `symcrypt-sys` with the former depending on the latter. We utilize the cargo workspaces feature to organize the cargo environment between both sub crates.

## How To Generate Bindings
Bindings can be generated 2 ways.
1. With the `generate-all-bindings.ps1` script.

Using this option will require you to have some build dependencies installed on your machine, more in depth installation instructions are provided in the `generate-all-bindings.ps1` file.

2. Via Github actions

Bindings can be created by creating a PR with the label `publish_new_bindings` attached to the PR. More info around labels can be found on the [Github documentation](https://docs.Github.com/en/issues/using-labels-and-milestones-to-track-work/managing-labels). This will create an artifact via Github actions that has the bindings for each supported triple. This Github action will not use the `SymCrypt` that is tied to the PR and instead will pull `SymCrypt` from the Github submodule. To update this please see the `Updating SymCrypt Submodule/SymCrypt Version` section.

**Note:** As part of the Github actions workflow, the CI will check the generated bindings in the Github actions against the new bindings that you are checking in. 

### Adding New APIs
To add safe wrappers for a new `symcrypt` API you must first generate the required bindings:

1. Ensure that you have the correct `SymCrypt` submodule. If you are updating the version of `SymCrypt` that `symcrypt-sys`, please see the `Updating SymCrypt Submodule/SymCrypt Version` section.
2. Add the new SymCrypt APIs to `symcrypt-bindgen/src/main`. Ensure to use regex semantics as to not include more that is needed for the API you are going to expose.
3. Generate new bindings with Github actions or the with `generate-all-bindings.ps1` script. 
4. Implement wrapper code in the `rust-symcrypt` layer. Ensure that you are properly documenting your changes and updating the API master list on `rust-symcrypt`'s README.md.
5. Once you are complete with your API additions, push and ensure that all CI checks pass. 
6. Depending on the type of change you are making you may or may not need to update the cargo version, for more info please see the `Cargo Publishing Guidelines` section.

### Updating SymCrypt Submodule/SymCrypt Version.
You may have to update the under-lying `SymCrypt` version from time to time, this will require you to update the `SymCrypt` submodule. Some examples of requiring to update the `SymCrypt` version include:
- Adding new bindings for APIs that have been released by `SymCrypt`.
- Applying a security patch provided by `SymCrypt`.
- When you update the static linking version.

`symcrypt-sys` depends on a `SymCrypt` via a Github submodule. The `SymCrypt` dependency is tied to a specific version of `SymCrypt`, and a specific commit from the `SymCrypt` Github repo. The specific commit that we depend on can be seen on VERSION.md. There is also a CI check that will ensure that your Github submodule matches the version specified in VERSION.md 

If you need to make an update to the `SymCrypt` submodule dependency, you can do so by:
1. First going to the `SymCrypt` submodule in `symcrypt-sys/symcrypt` and checking out the required commit. This should be tied to tagged release of `SymCrypt`.
2. Check in the change via `git add symcrypt-sys/symcrypt`.
3. Update `VERSION.md` in `symcrypt-sys` to include the new commit HASH that you have checked out in `Step 1`.
4. Update `README.md` with the new version of `SymCrypt` that `rust-symcrypt` depends on. 
5. Update the `build.yaml` file to ensure that you are downloading the correct SymCrypt dll and .so from the Github artifacts page. 
6. Push your changes and ensure that the CI check passes.


### Cargo Publishing Guidelines
1. Check out a branch and make your desired changes. ex: `user/<your-user>/bump_version_0.X.X`.
2. Update version number in the `Cargo.toml` of `rust-symcrypt`, or `symcrypt-sys` or both if required.
3. Update the `README.md` with the updated version of `rust-symcrypt` or `symcrypt-sys` or both if required.
4. Adhere to [semver](https://semver.org/) guidelines when bumping version numbers.
5. Test and validate your changes. As a minimum, manual `cargo test --all-features` must be ran on `Windows` and `WSL`. 
6. After your change is completed, create a PR against `main`, wait for review and ensure that all Github checks have passed. 
7. Once your PR is completed, check out `main` and prep `Cargo` release.
8. It is important to ensure that you have no dangling un-commited changes on your active branch. When publishing to `Crates.io`, these files will be published in as well.
9. You can verify which files will be published via `cargo package --list`.
10. Do a dry publish of the crate via `cargo publish --dry-run`.
11. If that was successful, publish the crate via `cargo publish`.
12. Update the release docs by assigning a new `tag` and detailing the changes associated with the new version. Make sure to highlight breaking changes. 
13. If the reason for bumping the version was a critical bug such as a danging pointer, or invalid memory reference, discuss doing a [cargo yank](https://doc.rust-lang.org/cargo/commands/cargo-yank.html) with the rest of the team.
