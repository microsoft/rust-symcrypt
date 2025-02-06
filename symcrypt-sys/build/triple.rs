#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Triple {
    x86_64_pc_windows_msvc,
    aarch64_pc_windows_msvc,
    x86_64_unknown_linux_gnu,
    aarch64_unknown_linux_gnu,
}

impl Triple {
    pub fn get_target_triple() -> Self {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

        match (target_os.as_str(), target_arch.as_str()) {
            ("windows", "x86_64") => Triple::x86_64_pc_windows_msvc,
            ("windows", "aarch64") => Triple::aarch64_pc_windows_msvc,
            ("linux", "x86_64") => Triple::x86_64_unknown_linux_gnu,
            ("linux", "aarch64") => Triple::aarch64_unknown_linux_gnu,
            _ => panic!("unsupported target. OS: {target_os}, Arch: {target_arch}"),
        }
    }
    pub fn to_triple(&self) -> &'static str {
        match self {
            Triple::x86_64_pc_windows_msvc => "x86_64-pc-windows-msvc",
            Triple::aarch64_pc_windows_msvc => "aarch64-pc-windows-msvc",
            Triple::x86_64_unknown_linux_gnu => "x86_64-unknown-linux-gnu",
            Triple::aarch64_unknown_linux_gnu => "aarch64-unknown-linux-gnu",
        }
    }
}
