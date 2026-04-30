#[cfg(windows)]
pub mod bcrypt;

#[cfg(not(windows))]
pub mod symcrypt;
