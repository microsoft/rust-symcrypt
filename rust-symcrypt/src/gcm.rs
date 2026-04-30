//! AES-GCM authenticated encryption.
//!
//! # Examples
//!
//! ## Encrypt in place
//! ```rust
//! use symcrypt::gcm::GcmExpandedKey;
//!
//! let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
//! let mut tag = [0u8; 16];
//! let mut nonce = [0u8; 12];
//! hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce).unwrap();
//! let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
//!
//! let mut buffer = [0u8; 60];
//! hex::decode_to_slice("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", &mut buffer).unwrap();
//!
//! let gcm_state = GcmExpandedKey::new(&p_key).unwrap();
//! gcm_state.encrypt_in_place(&nonce, &auth_data, &mut buffer, &mut tag);
//! ```

#[cfg(windows)]
use crate::backend::bcrypt::gcm as imp;
#[cfg(not(windows))]
use crate::backend::symcrypt::gcm as imp;

pub use imp::GcmExpandedKey;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gcm_encrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_ct = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", &mut buffer).unwrap();
        let mut tag = [0u8; 16];

        let gcm = GcmExpandedKey::new(&p_key).unwrap();
        gcm.encrypt_in_place(&nonce, &auth_data, &mut buffer, &mut tag);

        assert_eq!(hex::encode(buffer), expected_ct);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_gcm_decrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

        let mut tag = [0u8; 16];
        hex::decode_to_slice("5bc94fbc3221a5db94fae95ae7121a47", &mut tag).unwrap();

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", &mut buffer).unwrap();

        let gcm = GcmExpandedKey::new(&p_key).unwrap();
        gcm.decrypt_in_place(&nonce, &auth_data, &mut buffer, &tag).unwrap();
        assert_eq!(hex::encode(buffer), expected_pt);
    }

    #[test]
    fn test_gcm_decrypt_wrong_tag() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let mut tag = [0u8; 16];
        hex::decode_to_slice("5bc94fbc3221a5db94fae95ae7121aaa", &mut tag).unwrap();

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", &mut buffer).unwrap();

        let gcm = GcmExpandedKey::new(&p_key).unwrap();
        let result = gcm.decrypt_in_place(&nonce, &auth_data, &mut buffer, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_gcm_wrong_key_size() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308ad").unwrap();
        let result = GcmExpandedKey::new(&p_key);
        assert_eq!(result.unwrap_err(), crate::errors::SymCryptError::WrongKeySize);
    }

    #[test]
    fn test_gcm_key_len() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let gcm = GcmExpandedKey::new(&p_key).unwrap();
        assert_eq!(gcm.key_len(), 16);
    }
}
