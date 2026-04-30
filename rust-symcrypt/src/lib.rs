#![doc = include_str!("../README.md")]

pub mod errors;
pub mod hash;
pub mod gcm;

mod backend;

// Modules not yet ported to the backend model — only available on Linux/SymCrypt
#[cfg(not(windows))]
pub mod chacha;
#[cfg(not(windows))]
pub mod cipher;
#[cfg(not(windows))]
pub mod ecc;
#[cfg(not(windows))]
pub mod hkdf;
#[cfg(not(windows))]
pub mod hmac;
#[cfg(not(windows))]
pub mod rsa;

#[cfg(not(windows))]
fn symcrypt_init() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    unsafe {
        INIT.call_once(|| {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        });
    }
}

/// Fills `buff` with cryptographically secure random bytes.
/// This function cannot fail under normal OS conditions.
pub fn symcrypt_random(buff: &mut [u8]) {
    #[cfg(not(windows))]
    {
        symcrypt_init();
        unsafe {
            symcrypt_sys::SymCryptRandom(buff.as_mut_ptr(), buff.len() as symcrypt_sys::SIZE_T);
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::*;
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buff.as_mut_ptr(),
                buff.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        assert!(
            status >= 0,
            "BCryptGenRandom failed: 0x{:08X}",
            status as u32
        );
    }
}

/// Byte order for numeric representations.
#[cfg(not(windows))]
pub enum NumberFormat {
    LSB,
    MSB,
}

#[cfg(not(windows))]
impl NumberFormat {
    fn to_symcrypt_format(&self) -> symcrypt_sys::SYMCRYPT_NUMBER_FORMAT {
        match self {
            NumberFormat::LSB => {
                symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_LSB_FIRST
            }
            NumberFormat::MSB => {
                symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_symcrypt_random() {
        let mut buff_1 = [0u8; 10];
        let mut buff_2 = [0u8; 10];

        symcrypt_random(&mut buff_1);
        symcrypt_random(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
