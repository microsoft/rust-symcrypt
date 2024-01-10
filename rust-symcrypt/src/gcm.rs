//! Galois Counter Mode functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Encrypt in place
//!
//! ```
//! use symcrypt::block_ciphers::BlockCipherType;
//! use symcrypt::gcm::GcmExpandedKey;
//!
//! // Set up input
//! let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
//! let mut tag = [0u8; 16];
//!
//! let mut nonce_array = [0u8; 12];
//! hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
//!
//! let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
//! let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
//!
//! let mut buffer = [0u8; 60];
//! hex::decode_to_slice("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", &mut buffer).unwrap();
//!
//! let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
//! let cipher = BlockCipherType::AesBlock;
//!
//! // Perform encryption in place
//! let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
//! gcm_state.encrypt_in_place(&nonce_array, &auth_data, &mut buffer, &mut tag);
//!
//! assert_eq!(hex::encode(buffer), expected_result);
//! assert_eq!(hex::encode(tag), expected_tag);
//! ```
//!
//! ## Decrypt in place
//! ```
//! use symcrypt::block_ciphers::BlockCipherType;
//! use symcrypt::gcm::GcmExpandedKey;
//!
//! // Set up input
//! let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
//! let cipher = BlockCipherType::AesBlock;
//!
//! let mut nonce_array = [0u8; 12];
//! hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
//!
//! let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
//! let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

//! let mut tag = [0u8; 16];
//! hex::decode_to_slice("5bc94fbc3221a5db94fae95ae7121a47", &mut tag).unwrap();

//! let mut buffer = [0u8; 60];
//! hex::decode_to_slice("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", &mut buffer).unwrap();
//!
//! // Perform the decryption in place
//! let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
//! gcm_state
//!     .decrypt_in_place(&nonce_array, &auth_data, &mut buffer, &mut tag)
//!     .unwrap();
//! assert_eq!(hex::encode(buffer), expected_result);
//! ```
//!
use crate::block_ciphers::*;
use crate::errors::SymCryptError;
use std::pin::Pin;
use symcrypt_sys;

/// [`GcmExpandedKey`] is a struct that holds the Gcm expanded key from SymCrypt.
pub struct GcmExpandedKey {
    // expanded_key holds the key from SymCrypt which is Pin<Box<>>'d since the memory address for Self is moved around when
    // returning from GcmExpandedKey::new()

    // key_length holds the length of the expanded key. This value is normally 16 or 32 bytes.

    // SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.
    expanded_key: Pin<Box<symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY>>,
    key_length: usize,
}

/// `encrypt_in_place` and `decrypt_in_place` take in an allocated `buffer` as an in/out parameter for performance reasons.
/// This is for scenarios such as encrypting over a stream of data; allocating and copying data from a return will be costly performance wise.
impl GcmExpandedKey {
    /// `new` takes in a reference to a key and a [`BlockCipherType`] and returns an expanded key that is Pin<Box<>>'d.
    /// This function can fail and will propagate the error back to the caller. This call will fail if the wrong key size is provided.
    /// The only accepted Cipher for GCM is [`BlockCipherType::AesBlock`]
    pub fn new(key: &[u8], cipher: BlockCipherType) -> Result<Self, SymCryptError> {
        let mut expanded_key = Box::pin(symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default()); // boxing here so that the memory is not moved
        gcm_expand_key(key, &mut expanded_key, convert_cipher(cipher))?;
        let gcm_expanded_key = GcmExpandedKey {
            expanded_key: expanded_key,
            key_length: key.len(),
        };
        Ok(gcm_expanded_key)
    }

    /// `encrypt_in_place` takes in a `&mut buffer` that has the plain text data to be encrypted. After the encryption has been completed,
    /// the `buffer` will be over-written to contain the cipher text data. `encrypt_in_place` will also take in `tag` which is
    /// a `&mut buffer` where the resulting tag will be written to.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmEncrypt(
                &*self.expanded_key,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    /// `decrypt_in_place` takes in a `&mut buffer` that has the cipher text to be decrypted. After the decryption has been completed,
    /// the `buffer` will be over-written to contain the plain text data. `decrypt_in_place` will also take in a `tag` which will
    /// verify the cipher text has not been tampered with. `decrypt_in_place` can fail and you must check the result before using the
    /// value stored in `buffer`.
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptGcmDecrypt(
                &*self.expanded_key,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `key_len` returns a the length of the [`GcmExpandedKey`] as a `usize`.
    pub fn key_len(&self) -> usize {
        self.key_length
    }
}

unsafe impl Send for GcmExpandedKey {
    // TODO: Configure send/sync traits
}

unsafe impl Sync for GcmExpandedKey {
    // TODO: Configure send/sync traits
}

// Internal function to expand the SymCrypt Gcm Key.
fn gcm_expand_key(
    key: &[u8],
    expanded_key: &mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
    cipher: *const symcrypt_sys::SYMCRYPT_BLOCKCIPHER,
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptGcmExpandKey(
            expanded_key,
            cipher,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

/// [`validate_gcm_parameters`] is a utility function that validates the input parameters for a GCM call.
///
/// `cipher` will only accept [`BlockCipherType::AesBlock`]
/// `nonce` is a reference to a nonce array that must be 12 bytes.
/// `auth_data` is an optional parameter that can be provided, if you do not wish to provide
/// any auth data, input an empty array.
/// `data` is a reference to a data array to be encrypted
/// `tag` is a reference to your tag buffer, the size of the tag buffer will be checked.
pub fn validate_gcm_parameters(
    cipher: BlockCipherType,
    nonce: &[u8; 12], // GCM nonce length must be 12 bytes
    auth_data: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptGcmValidateParameters(
            convert_cipher(cipher),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data.len() as symcrypt_sys::UINT64,
            data.len() as symcrypt_sys::SIZE_T,
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::block_ciphers::BlockCipherType;

    #[test]
    fn test_gcm_expand_key_will_fail_wrong_key_size() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308ad").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let result = GcmExpandedKey::new(&p_key, cipher);

        match result {
            Ok(_) => {
                panic!("Test passed when it should fail");
            }
            Err(err) => {
                assert_eq!(err, SymCryptError::WrongKeySize);
            }
        }
    }

    #[test]
    fn test_gcm_encrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", &mut buffer).unwrap();

        let mut tag = [0u8; 16];

        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let cipher = BlockCipherType::AesBlock;

        let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        gcm_state.encrypt_in_place(&nonce_array, &auth_data, &mut buffer, &mut tag);

        assert_eq!(hex::encode(buffer), expected_result);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_gcm_decrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

        let mut tag = [0u8; 16];
        hex::decode_to_slice("5bc94fbc3221a5db94fae95ae7121a47", &mut tag).unwrap();

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", &mut buffer).unwrap();
        let cipher = BlockCipherType::AesBlock;

        let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        gcm_state
            .decrypt_in_place(&nonce_array, &auth_data, &mut buffer, &mut tag)
            .unwrap();
        assert_eq!(hex::encode(buffer), expected_result);
    }

    #[test]
    fn test_gcm_decrypt_will_fail_wrong_tag() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let mut tag = [0u8; 16];
        hex::decode_to_slice("5bc94fbc3221a5db94fae95ae7121aaa", &mut tag).unwrap();

        let mut buffer = [0u8; 60];
        hex::decode_to_slice("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", &mut buffer).unwrap();
        let cipher = BlockCipherType::AesBlock;

        let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        let result = gcm_state.decrypt_in_place(&nonce_array, &auth_data, &mut buffer, &mut tag);

        match result {
            Ok(_) => {
                panic!("Test passed when it should fail");
            }
            Err(err) => {
                assert_eq!(err, SymCryptError::AuthenticationFailure);
            }
        }
    }

    #[test]
    fn test_validate_parameters() {
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let cipher = BlockCipherType::AesBlock;

        validate_gcm_parameters(cipher, &nonce_array, &auth_data, &pt, &expected_tag).unwrap();
    }

    #[test]
    fn test_validate_parameters_fail() {
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3242121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let result = validate_gcm_parameters(cipher, &nonce_array, &auth_data, &pt, &expected_tag);
        assert_eq!(result.unwrap_err(), SymCryptError::WrongTagSize);
    }

    #[test]
    fn test_gcm_expanded_key_get_key_length() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let cipher = BlockCipherType::AesBlock;
        let gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        assert_eq!(gcm_state.key_len(), 16);
    }
}
