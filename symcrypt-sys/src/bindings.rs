// When SYMCRYPT_LIB_NAME is set, build.rs generates modified bindings in OUT_DIR
// and sets SYMCRYPT_BINDINGS_PATH to point to them.
#[cfg(all(target_os = "windows", custom_lib_name))]
include!(env!("SYMCRYPT_BINDINGS_PATH"));

#[cfg(all(target_os = "windows", target_arch = "x86_64", not(custom_lib_name)))]
mod x86_64_pc_windows_msvc;
#[cfg(all(target_os = "windows", target_arch = "x86_64", not(custom_lib_name)))]
pub use x86_64_pc_windows_msvc::*;

#[cfg(all(target_os = "windows", target_arch = "aarch64", not(custom_lib_name)))]
mod aarch64_pc_windows_msvc;
#[cfg(all(target_os = "windows", target_arch = "aarch64", not(custom_lib_name)))]
pub use aarch64_pc_windows_msvc::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod x86_64_unknown_linux_gnu;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use x86_64_unknown_linux_gnu::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod aarch64_unknown_linux_gnu;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use aarch64_unknown_linux_gnu::*;
