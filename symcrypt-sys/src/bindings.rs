#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) mod x86_64_pc_windows_msvc;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use x86_64_pc_windows_msvc::*;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub(crate) mod aarch64_pc_windows_msvc;
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub(crate) use aarch64_pc_windows_msvc::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod x86_64_unknown_linux_gnu;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) use x86_64_unknown_linux_gnu::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) mod aarch64_unknown_linux_gnu;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) use aarch64_unknown_linux_gnu::*;
