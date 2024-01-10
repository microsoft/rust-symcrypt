//! ChaChaPoly1305 Functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Encrypt in place
//!
//! ```
//! use hex::*;
//! use symcrypt::chacha::chacha20_poly1305_encrypt_in_place;
//!
//! // Set up inputs
//! let mut key_array = [0u8; 32];
//! hex::decode_to_slice( "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",&mut key_array,).unwrap();
//!
//! let mut nonce_array = [0u8; 12];
//! hex::decode_to_slice("070000004041424344454647", &mut nonce_array).unwrap();
//!
//! let mut auth_data = [0u8; 12];
//! hex::decode_to_slice("50515253c0c1c2c3c4c5c6c7", &mut auth_data).unwrap();
//!
//! let mut buffer = [0u8; 114];
//! hex::decode_to_slice("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", &mut buffer).unwrap();
//!
//! let expected_cipher = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
//! let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";
//! let mut tag = [0u8; 16];
//!
//! // Encrypt in place, must check this does not fail before checking the buffer or tag values.
//! chacha20_poly1305_encrypt_in_place(&key_array, &nonce_array, &auth_data, &mut buffer, &mut tag).unwrap();
//!
//! assert_eq!(hex::encode(buffer), expected_cipher);
//! assert_eq!(hex::encode(tag), expected_tag);
//!
//! ```
//!
//! ## Decrypt in place
//!
//! ```
//! use hex::*;
//! use symcrypt::chacha::chacha20_poly1305_decrypt_in_place;
//!
//! // Set up inputs
//! let mut key_array = [0u8; 32];
//! hex::decode_to_slice(
//!     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
//!     &mut key_array,
//! )
//! .unwrap();
//! let mut nonce_array = [0u8; 12];
//! hex::decode_to_slice("070000004041424344454647", &mut nonce_array).unwrap();
//!
//! let mut auth_data = [0u8; 12];
//! hex::decode_to_slice("50515253c0c1c2c3c4c5c6c7", &mut auth_data).unwrap();
//!
//! let mut buffer = [0u8; 114];
//! hex::decode_to_slice("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", &mut buffer).unwrap();
//!
//! let dst = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
//!
//! let mut tag_array = [0u8; 16];
//! hex::decode_to_slice("1ae10b594f09e26a7e902ecbd0600691", &mut tag_array).unwrap();
//!
//! // Decrypt in place, must check this does not fail before checking buffer values.
//! chacha20_poly1305_decrypt_in_place(
//!     &key_array,
//!     &nonce_array,
//!     &auth_data,
//!     &mut buffer,
//!     &tag_array,
//! )
//! .unwrap();
//!
//! assert_eq!(hex::encode(buffer), dst);
//! ```
//! }
//!
use crate::errors::SymCryptError;
use symcrypt_sys;

/// Stateless call to encrypt using ChaChaPoly1305.
///
/// You must check if this function fails before using the values stored in the buffer.
///
/// `key` must be 32 bytes
///
/// `nonce` must be 12 bytes
///
/// `auth_data` is an optional parameter that can be provided, if you do not wish to provide any auth data, input an empty array.
///
/// `buffer` is an out parameter that contains the plain text data to be encrypted. after the encryption is complete, the
/// resulting cipher text will be written to the `buffer` parameter.
///
/// `tag` must be 16 bytes and is an in/out parameter that the tag result will be written to.
///
/// There is no return value since `buffer` will be modified in place, if this function fails a `error::SymCryptError` will be returned.
/// If the function succeeds nothing will be returned and the `buffer` and `tag` parameters will be modified in place.
pub fn chacha20_poly1305_encrypt_in_place(
    key: &[u8; 32],   // ChaCha key length must be 32 bytes
    nonce: &[u8; 12], // ChaCha nonce length must be 12 bytes
    auth_data: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8; 16], // ChaCha tag must be 16 bytes
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptChaCha20Poly1305Encrypt(
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data.as_ptr(),
            auth_data.len() as symcrypt_sys::SIZE_T,
            buffer.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as symcrypt_sys::SIZE_T,
            tag.as_mut_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

/// Stateless call to decrypt using ChaChaPoly1305.
///
/// You must check if this function fails before using the values stored in the in/out parameters.
///
/// `key` must be 32 bytes
///
/// `nonce` must be 12 bytes
///
/// `auth_data` is an optional parameter that can be provided, if you do not wish to provide auth data, input an empty array.
///
/// `buffer` is an in/out parameter that contains the cipher text data to be decrypted. after the decryption is complete, the
/// resulting plain text will be written to the `buffer` parameter
///
/// `tag` must be 16 bytes and will be used to check if the decryption is successful.
///
/// There is no return value since `buffer` will be modified in place, if this function fails a `error::SymCryptError` will be returned.
/// If the function succeeds nothing will be returned and `buffer` will be modified in place.  
pub fn chacha20_poly1305_decrypt_in_place(
    key: &[u8; 32],   // ChaCha key length must be 32 bytes
    nonce: &[u8; 12], // ChaCha nonce length must be 12 bytes
    auth_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16], // ChaCha tag must be 16 bytes
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptChaCha20Poly1305Decrypt(
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chacha_encrypt() {
        let mut key_array = [0u8; 32];
        hex::decode_to_slice(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            &mut key_array,
        )
        .unwrap();

        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("070000004041424344454647", &mut nonce_array).unwrap();

        let mut auth_data = [0u8; 12];
        hex::decode_to_slice("50515253c0c1c2c3c4c5c6c7", &mut auth_data).unwrap();

        let mut buffer = [0u8; 114];
        hex::decode_to_slice("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", &mut buffer).unwrap();

        let expected_cipher = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

        let mut tag = [0u8; 16];
        chacha20_poly1305_encrypt_in_place(
            &key_array,
            &nonce_array,
            &auth_data,
            &mut buffer,
            &mut tag,
        )
        .unwrap();

        assert_eq!(hex::encode(buffer), expected_cipher);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_chacha_encrypt_no_auth_data() {
        let mut key_array = [0u8; 32];
        hex::decode_to_slice(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            &mut key_array,
        )
        .unwrap();

        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("070000004041424344454647", &mut nonce_array).unwrap();

        let mut buffer = [0u8; 114];
        hex::decode_to_slice("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", &mut buffer).unwrap();

        let expected_cipher = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";

        let mut tag = [0u8; 16];
        chacha20_poly1305_encrypt_in_place(&key_array, &nonce_array, &[], &mut buffer, &mut tag)
            .unwrap();

        assert_eq!(hex::encode(buffer), expected_cipher);
    }

    #[test]
    fn test_chacha_decrypt() {
        let mut key_array = [0u8; 32];
        hex::decode_to_slice(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            &mut key_array,
        )
        .unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("070000004041424344454647", &mut nonce_array).unwrap();

        let mut auth_data = [0u8; 12];
        hex::decode_to_slice("50515253c0c1c2c3c4c5c6c7", &mut auth_data).unwrap();

        let mut buffer = [0u8; 114];
        hex::decode_to_slice("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", &mut buffer).unwrap();

        let dst = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

        let mut tag_array = [0u8; 16];
        hex::decode_to_slice("1ae10b594f09e26a7e902ecbd0600691", &mut tag_array).unwrap();

        chacha20_poly1305_decrypt_in_place(
            &key_array,
            &nonce_array,
            &auth_data,
            &mut buffer,
            &tag_array,
        )
        .unwrap();

        assert_eq!(hex::encode(buffer), dst);
    }

    #[test]
    fn test_chacha_decrypt_failure() {
        let mut key_array = [0u8; 32];
        hex::decode_to_slice(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            &mut key_array,
        )
        .unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("000000000000000000000000", &mut nonce_array).unwrap();

        let mut auth_data = [0u8; 12];
        hex::decode_to_slice("50515253c0c1c2c3c4c5c6c7", &mut auth_data).unwrap();

        let mut buffer = [0u8; 114];
        hex::decode_to_slice("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", &mut buffer).unwrap();

        let mut tag_array = [0u8; 16];
        hex::decode_to_slice("1ae10b594f09e26a7e902ecbd0600691", &mut tag_array).unwrap();

        let result = chacha20_poly1305_decrypt_in_place(
            &key_array,
            &nonce_array,
            &auth_data,
            &mut buffer,
            &tag_array,
        );

        assert_eq!(result.unwrap_err(), SymCryptError::AuthenticationFailure);
    }
}
