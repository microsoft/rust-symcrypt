#![doc = include_str!("../README.md")]
use std::sync::Once;

pub mod chacha;
pub mod cipher;
pub mod ecc;
pub mod errors;
pub mod gcm;
pub mod gcm2;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod rsa;

// symcrypt_init must be called before any other API can be called. All subsequent calls to symcrypt_init will be no-ops
fn symcrypt_init() {
    // Subsequent calls to `symcrypt_init()` after the first will not be invoked per .call_once docs https://doc.rust-lang.org/std/sync/struct.Once.html
    static INIT: Once = Once::new();
    unsafe {
        // SAFETY: FFI calls, blocking from being run again.
        INIT.call_once(|| {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        });
    }
}

/// Takes in a a buffer called `buff` and fills it with random bytes. This function cannot fail.
pub fn symcrypt_random(buff: &mut [u8]) {
    symcrypt_init();
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptRandom(buff.as_mut_ptr(), buff.len() as symcrypt_sys::SIZE_T);
    }
}

/// `NumberFormat` is an enum that contains a friendly representation of endianess
///
/// `LSB`: Bytes are ordered from the least significant to the most significant, commonly referred to as "little-endian".
///
/// `MSB`: Bytes are ordered from the most significant to the least significant, commonly referred to as "big-endian".
pub enum NumberFormat {
    LSB,
    MSB,
}

impl NumberFormat {
    /// Converts `NumberFormat` to the corresponding `SYMCRYPT_NUMBER_FORMAT`
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
