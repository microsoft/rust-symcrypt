//! Galois Counter Mode functions. For further documentation please refer to symcrypt.h
//!
//! # Examples
//!
//! ## Encrypt in place
//!
//! ```rust
//! use symcrypt::cipher::BlockCipherType;
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
//! ```rust
//! use symcrypt::cipher::BlockCipherType;
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
use crate::cipher::{convert_cipher, BlockCipherType};
use crate::errors::SymCryptError;
use crate::symcrypt_init;
use std::mem;
use std::ptr;
use symcrypt_sys;

///
/// This type represents a common storage for SYMCRYPT_GCM_EXPANDED_KEY.
///
#[derive(Clone, Copy, Default)]
struct GcmExpandedKeyStorage(symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY);

impl GcmExpandedKeyStorage {
    //
    // `get_key_ptr` gets a constant pointer to the underlying SYMCRYPT_GCM_EXPANDED_KEY.
    //
    #[inline(always)]
    fn get_key_ptr(&self) -> *const symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY {
        ptr::addr_of!(self.0)
    }

    //
    // `get_key_ptr_mut` gets a mutable pointer to the underlying SYMCRYPT_GCM_EXPANDED_KEY.
    //
    #[inline(always)]
    fn get_key_ptr_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY {
        ptr::addr_of_mut!(self.0)
    }

    //
    // `zero_storage` zeroes the underlying SYMCRYPT_GCM_EXPANDED_KEY memory.
    //
    // This is unsafe as it uninitializes the storage that other unsafe code
    // may rely on being initialized.
    //
    #[inline(always)]
    unsafe fn zero_storage(&mut self) {
        symcrypt_sys::SymCryptWipe(
            self.get_key_ptr_mut() as *mut _,
            mem::size_of::<symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY>() as symcrypt_sys::SIZE_T,
        );
    }
}

///
/// This type represents an uninitialized GcmExpandedKeyStorage. It can be freely
/// copied, cloned, or moved as it does not contain any information.
///
#[derive(Clone, Copy, Default)]
pub struct GcmUninitializedKey(GcmExpandedKeyStorage);

impl GcmUninitializedKey {
    ///
    /// `expand_key` will initialize this SYMCRYPT_GCM_EXPANDED_KEY to using the probided
    /// cipher type and key.
    ///
    /// `cipher_type` is a `BlockCipherType` that determines the cipher to use for this key.
    /// The only supported cipher type is [`BlockCipherType::AesBlock`]
    ///
    /// `key_data` is a `&[u8]` that contains the key to initialize with.
    ///
    pub fn expand_key(
        &mut self,
        cipher_type: BlockCipherType,
        key_data: &[u8],
    ) -> Result<GcmExpandedKeyHandle, SymCryptError> {
        symcrypt_init();

        internal::gcm_expand_key(
            key_data,
            self.0.get_key_ptr_mut(),
            convert_cipher(cipher_type),
        )?;

        //
        // SAFETY: gcm_expand_key guarantees that the SYMCRYPT_GCM_EXPANDED_KEY storage is initialized on success.
        //

        unsafe { Ok(GcmExpandedKeyHandle::new(self)) }
    }
}

/// [`GcmExpandedKey`] is a struct that holds the Gcm expanded key from SymCrypt.
pub struct GcmExpandedKey {
    // expanded_key holds the key from SymCrypt which is Pin<Box<>>'d since the memory address for Self is moved around when
    // returning from GcmExpandedKey::new()

    // key_length holds the length of the expanded key. This value is normally 16 or 32 bytes.

    // SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
    // doing so would lead to use-after-free and inconsistent states.
    expanded_key: Box<GcmExpandedKeyStorage>,
    key_length: usize,
}

impl Drop for GcmExpandedKey {
    fn drop(&mut self) {
        //
        // SAFETY: Is is safe to uninitialize the underlying storage as this
        // if the only reference to it and we are being dropped.
        //

        unsafe {
            self.expanded_key.zero_storage();
        }
    }
}

/// `encrypt_in_place` and `decrypt_in_place` take in an allocated `buffer` as an in/out parameter for performance reasons.
/// This is for scenarios such as encrypting over a stream of data; allocating and copying data from a return will be costly performance wise.
impl GcmExpandedKey {
    /// `new` takes in a reference to a key and a [`BlockCipherType`] and returns an expanded key that is Pin<Box<>>'d.
    ///
    /// This function can fail and will propagate the error back to the caller. This call will fail if the wrong key size is provided.
    ///
    /// The only accepted Cipher for GCM is [`BlockCipherType::AesBlock`]
    pub fn new(key: &[u8], cipher: BlockCipherType) -> Result<Self, SymCryptError> {
        symcrypt_init();
        let mut expanded_key = Box::new(GcmExpandedKeyStorage::default()); // Get expanded_key that is already Pin<Box<T>>'d

        // Use as_mut() to get a Pin<&mut GcmInnerKey> and then call get_inner_mut to get *mut
        internal::gcm_expand_key(key, expanded_key.get_key_ptr_mut(), convert_cipher(cipher))?;
        let gcm_expanded_key = GcmExpandedKey {
            expanded_key,
            key_length: key.len(),
        };
        Ok(gcm_expanded_key)
    }

    ///
    /// Creates a borrowed reference to the underlying GcmExpandedKeyStorage.
    ///
    #[inline(always)]
    pub fn as_ref(&self) -> GcmExpandedKeyRef {
        self.into()
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    /// This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &mut [u8],
    ) {
        self.as_ref()
            .encrypt(nonce, auth_data, source, destination, tag);
    }

    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed. This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    #[inline(always)]
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        self.as_ref()
            .encrypt_in_place(nonce, auth_data, buffer, tag);
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    #[inline(always)]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        self.as_ref()
            .decrypt(nonce, auth_data, source, destination, tag)
    }

    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed. This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the cipher text data to be decrypted. After the decryption has been completed,
    /// `buffer` will be over-written to contain the plain text data.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    #[inline(always)]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        self.as_ref()
            .decrypt_in_place(nonce, auth_data, buffer, tag)
    }

    /// `key_len` returns a the length of the [`GcmExpandedKey`] as a `usize`.
    pub fn key_len(&self) -> usize {
        self.key_length
    }
}

// No custom Send / Sync impl. needed for GcmExpandedKey since the
// underlying data is a pointer to a SymCrypt struct that is not modified after it is created.
unsafe impl Send for GcmExpandedKey {}
unsafe impl Sync for GcmExpandedKey {}

///
/// This type represents a handle to an initialized GcmUnexpandedKey that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
/// 3. Zero the underlying storage when dropped.
///
pub struct GcmExpandedKeyHandle<'a>(&'a mut GcmExpandedKeyStorage);

impl<'a> GcmExpandedKeyHandle<'a> {
    //
    // # Safety:
    //
    // The caller must enture that the underlying storage has been correctly
    // initialized.
    //
    #[inline(always)]
    unsafe fn new(inner: &'a mut GcmUninitializedKey) -> Self {
        Self(&mut inner.0)
    }

    ///
    /// Creates a borrowed reference to the underlying GcmUnexpandedKey storage.
    ///
    #[inline(always)]
    pub fn as_ref(&self) -> GcmExpandedKeyRef {
        self.into()
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    #[inline(always)]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        self.as_ref()
            .decrypt(nonce, auth_data, source, destination, tag)
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed. This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the cipher text data to be decrypted. After the decryption has been completed,
    /// `buffer` will be over-written to contain the plain text data.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    #[inline(always)]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        self.as_ref()
            .decrypt_in_place(nonce, auth_data, buffer, tag)
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    /// This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &mut [u8],
    ) {
        self.as_ref()
            .encrypt(nonce, auth_data, source, destination, tag);
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed. This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    #[inline(always)]
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        self.as_ref()
            .encrypt_in_place(nonce, auth_data, buffer, tag);
    }
}

impl Drop for GcmExpandedKeyHandle<'_> {
    fn drop(&mut self) {
        //
        // SAFETY: Is is safe to uninitialize the underlying storage as this
        // if the only reference to it and we are being dropped.
        //

        unsafe {
            self.0.zero_storage();
        }
    }
}

///
/// This type represents a borrowed handle to an initialized SYMCRYPT_GCM_EXPANDED_KEY
/// that is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
///
/// This type does not zero the underlying storage when dropped.
///
pub struct GcmExpandedKeyRef<'a>(&'a GcmExpandedKeyStorage);

impl GcmExpandedKeyRef<'_> {
    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKeyHandle::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            let result = symcrypt_sys::SymCryptGcmDecrypt(
                self.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );

            match result {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed. This call can fail and the caller must check the result.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the decryption. It must match the nonce used during encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided. If you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the cipher text data to be decrypted. After the decryption has been completed,
    /// `buffer` will be over-written to contain the plain text data.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption. This is used to verify the integrity of the cipher text.
    ///
    /// If decryption succeeds, the function will return `Ok(())`, and `buffer` will contain the plain text. If it fails, an error of type `SymCryptError` will be returned.
    ///
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymCryptError> {
        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKeyHandle::new`.
        //

        unsafe {
            let result = symcrypt_sys::SymCryptGcmDecrypt(
                self.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );

            match result {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into()),
            }
        }
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    /// This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &mut [u8],
    ) {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKeyHandle::new` and we have asserted that both `source`
        // and `destination` are of the same length.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmEncrypt(
                self.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed. This call cannot fail.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce for the encryption.
    ///
    /// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide any auth data, input an empty array.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to. Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) {
        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKeyHandle::new`.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmEncrypt(
                self.0.get_key_ptr(),
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
}

impl<'a, 'b> From<&'a GcmExpandedKeyHandle<'b>> for GcmExpandedKeyRef<'a> {
    fn from(value: &'a GcmExpandedKeyHandle<'b>) -> Self {
        GcmExpandedKeyRef(value.0)
    }
}

impl<'a> From<&'a GcmExpandedKey> for GcmExpandedKeyRef<'a> {
    fn from(value: &'a GcmExpandedKey) -> Self {
        GcmExpandedKeyRef(&value.expanded_key)
    }
}

///
/// This type represents an uninitialized SYMCRYPT_GCM_STATE. It can be freely
/// copied, clones, or moved as it does not contain any information.
///
#[derive(Copy, Clone, Default)]
pub struct GcmStream(symcrypt_sys::SYMCRYPT_GCM_STATE);

impl GcmStream {
    //
    // `get_key_ptr_mut` gets a mutable pointer to the underlying SYMCRYPT_GCM_STATE.
    //
    #[inline(always)]
    fn get_state_ptr_mut(&mut self) -> *mut symcrypt_sys::SYMCRYPT_GCM_STATE {
        ptr::addr_of_mut!(self.0)
    }

    //
    // `initialize` initializes the underlying `SYMCRYPT_GCM_STATE`` with the provided key and nonce.
    //
    // `expanded_key` provides a borrowed reference to an initialized `SYMCRYPT_GCM_EXPANDED_KEY`
    //
    // `nonce` is a `&[u8; 12]` that is used as the nonce.
    //
    fn initialize<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> internal::GcmInitializedStream<'a> {
        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmInit(
                self.get_state_ptr_mut(),
                expanded_key.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
            );

            internal::GcmInitializedStream::new(self)
        }
    }

    ///
    /// Initializes this GcmStream as a GcmAuthStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_auth_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmAuthStream<'a> {
        GcmAuthStream(self.initialize(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmDecryptionStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_decryption_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmDecryptionStream<'a> {
        GcmDecryptionStream(self.initialize(expanded_key, nonce))
    }

    ///
    /// Initializes this GcmStream as a GcmEncryptionStream using the provided key, and nonce.
    ///
    /// `expanded_key` is a `GcmExpandedKeyRef` that provides a handle to the key to use
    /// for operations.
    ///
    /// `nonce` is a `&[u8; 12]` that is used as the nonce.
    ///
    #[inline(always)]
    pub fn as_encryption_stream<'a>(
        &'a mut self,
        expanded_key: GcmExpandedKeyRef<'a>,
        nonce: &[u8; 12],
    ) -> GcmEncryptionStream<'a> {
        GcmEncryptionStream(self.initialize(expanded_key, nonce))
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to autheticate,
/// but not encrypt or decrypt, data. It can later be converted to a GcmDecryptionStream or
/// GcmEncryptionStream.
///
pub struct GcmAuthStream<'a>(internal::GcmInitializedStream<'a>);

impl<'a> GcmAuthStream<'a> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut(&mut self) -> GcmAuthStreamRefMut {
        GcmAuthStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `authenticate` authenticates, but does not otherwise encrypt or decrypt, the provided data.
    ///
    /// `data` is a `&[u8]` that contains the data to authenticate.
    ///
    #[inline(always)]
    pub fn authenticate(&mut self, data: &[u8]) {
        self.as_ref_mut().authenticate(data);
    }

    ///
    /// `to_decryption_stream` converts this GcmAuthStream into a GcmDecryptionStream
    ///
    #[inline(always)]
    pub fn to_decryption_stream(self) -> GcmDecryptionStream<'a> {
        GcmDecryptionStream(self.0)
    }

    ///
    /// `to_encryption_stream` converts this GcmAuthStream into a GcmEncryptionStream
    ///
    #[inline(always)]
    pub fn to_encryption_stream(self) -> GcmEncryptionStream<'a> {
        GcmEncryptionStream(self.0)
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// autheticate, but not encrypt or decrypt, data.
///
pub struct GcmAuthStreamRefMut<'a>(internal::GcmInitializedStreamRefMut<'a>);

impl GcmAuthStreamRefMut<'_> {
    ///
    /// `authenticate` authenticates, but does not otherwise encrypt or decrypt, the provided data.
    ///
    /// `data` is a `&[u8]` that contains the data to authenticate.
    ///
    pub fn authenticate(&mut self, data: &[u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmAuthPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to decrypt data.
///
pub struct GcmDecryptionStream<'a>(internal::GcmInitializedStream<'a>);

impl GcmDecryptionStream<'_> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut(&mut self) -> GcmDecryptionStreamRefMut {
        GcmDecryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `complete` finishes this decryption stream and validates that the provided tag matches
    /// the generated tag.
    ///
    /// `tag` is a `&[u8]` that contains the authentication tag generated during encryption.
    /// This is used to verify the integrity of the cipher text.
    ///
    pub fn complete(mut self, tag: &[u8]) -> Result<(), SymCryptError> {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        let result = unsafe {
            symcrypt_sys::SymCryptGcmDecryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            )
        };

        self.0.drop_without_zero();
        match result {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            error => Err(error.into()),
        }
    }

    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        self.as_ref_mut().decrypt(source, destination);
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.as_ref_mut().decrypt_in_place(data);
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// decrypt data.
///
pub struct GcmDecryptionStreamRefMut<'a>(internal::GcmInitializedStreamRefMut<'a>);

impl GcmDecryptionStreamRefMut<'_> {
    ///
    /// `decrypt` performs a decryption of the data in `source` and writes the decrypted data to `destination`.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    pub fn decrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive and we've asserted that the source and destination buffers
        // are the same length.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    ///
    /// `decrypt_in_place` performs an in-place decryption on the `&mut buffer` that is passed.
    /// This is a partial decryption of the cipher text and the results of the plain text are not validated
    /// until `complete` is called.
    ///
    /// `source` is a `&[u8]` that contains the cipher text to be decrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the decrypted plain text.
    /// `destination` must be of the same length as `source`.
    ///
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }
}

///
/// This type represents a handle to an initialized GcmStream that can be used to
/// encrypt data.
///
pub struct GcmEncryptionStream<'a>(internal::GcmInitializedStream<'a>);

impl GcmEncryptionStream<'_> {
    ///
    /// `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
    ///
    #[inline(always)]
    pub fn as_ref_mut(&mut self) -> GcmEncryptionStreamRefMut {
        GcmEncryptionStreamRefMut(self.0.as_ref_mut())
    }

    ///
    /// `complete` finishes this encryption stream and returns the generated tag for validating
    /// decryption.
    ///
    /// `tag` is a `&mut [u8]` which is the buffer where the resulting tag will be written to.
    /// Tag size must be 12, 13, 14, 15, 16 per SP800-38D.
    /// Tag sizes of 4 and 8 are not supported.
    ///
    pub fn complete(mut self, tag: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmEncryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }

        self.0.drop_without_zero();
    }

    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    ///
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    #[inline(always)]
    pub fn encrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        self.as_ref_mut().encrypt(source, destination);
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    #[inline(always)]
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.as_ref_mut().encrypt_in_place(data);
    }
}

///
/// This type represents a borrowed mutable handle to an initialized GcmStream that can be used to
/// encrypt data.
///
pub struct GcmEncryptionStreamRefMut<'a>(internal::GcmInitializedStreamRefMut<'a>);

impl GcmEncryptionStreamRefMut<'_> {
    ///
    /// `encrypt` performs an encryption of the data in `source` and writes the encrypted data to `destination`.
    ///
    ///
    /// `source` is a `&[u8]` that contains the plain text to be encrypted.
    ///
    /// `destination` is a `&mut [u8]` that after decryption will contain the encrypted cipher text.
    /// `destination` must be of the same length as `source`.
    ///
    pub fn encrypt(&mut self, source: &[u8], destination: &mut [u8]) {
        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive and we've asserted that the source and destination buffers
        // are the same length.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    ///
    /// `encrypt_in_place` performs an in-place encryption on the `&mut buffer` that is passed.
    ///
    /// `buffer` is a `&mut [u8]` that contains the plain text data to be encrypted. After the encryption has been completed,
    /// `buffer` will be over-written to contain the cipher text data.
    ///
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        //
        // SAFETY: The internal stream is guaranteed to still be initialized while
        // self is alive.
        //

        unsafe {
            symcrypt_sys::SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }
}

/// [`validate_gcm_parameters`] is a utility function that validates the input parameters for a GCM call.
///
/// `cipher` will only accept [`BlockCipherType::AesBlock`]
///
/// `nonce` is a `&[u8; 12]`  that represents a nonce array.
///
/// `auth_data` is an optional `&[u8]` that can be provided, if you do not wish to provide
/// any auth data, input an empty array.
///
/// `data` is a `&[u8]` that represents the data array to be encrypted
///
/// `tag` is a `&[u8]` that represents the tag buffer, the size of the tag buffer will be checked and must be 12, 13, 14, 15, 16 per SP800-38D.
/// Tag sizes of 4 and 8 are not supported.
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
            data.len() as symcrypt_sys::UINT64,
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

mod internal {

    use std::{
        mem,
        ops::{Deref, DerefMut},
    };

    use symcrypt_sys::{SymCryptWipe, SYMCRYPT_GCM_STATE};

    use crate::errors::SymCryptError;

    use super::GcmStream;

    // Internal function to expand the SymCrypt Gcm Key.
    pub fn gcm_expand_key(
        key: &[u8],
        expanded_key: *mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
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

    ///
    /// This type represents a handle to an initialized GcmStream that
    /// is used to:
    /// 1. Provide a guarantee that the underlying storage is initialized.
    /// 2. Prevent the underlying storage from being moved or copied.
    /// 3. Zero the underlying storage when dropped.
    ///
    pub struct GcmInitializedStream<'a>(&'a mut GcmStream);

    impl<'a> GcmInitializedStream<'a> {
        //
        // `new` creates a new handle to an initialized GcmStream.
        //
        // # Safety:
        //
        // The caller must ensure that the underlying storage has been correctly
        // initialized.
        //
        pub unsafe fn new(inner: &'a mut GcmStream) -> Self {
            Self(inner)
        }

        //
        // `as_ref_mut` creates a new borrowed handle to the underlying GcmStream.
        //
        #[inline(always)]
        pub fn as_ref_mut(&mut self) -> GcmInitializedStreamRefMut {
            GcmInitializedStreamRefMut::new(self)
        }

        //
        // `drop_without_zero` will drop this handle to an GcmStream without
        // zeroing out the underlying storage. The caller should ensure that
        // the storage was (or will be) zeroed.
        //
        #[inline(always)]
        pub fn drop_without_zero(self) {
            mem::forget(self);
        }
    }

    impl Drop for GcmInitializedStream<'_> {
        fn drop(&mut self) {
            //
            // SAFETY: FFI calls to securly zero repr(C) structs
            //

            unsafe {
                SymCryptWipe(
                    self.0.get_state_ptr_mut() as *mut _,
                    mem::size_of::<SYMCRYPT_GCM_STATE>() as symcrypt_sys::SIZE_T,
                );
            }
        }
    }

    impl Deref for GcmInitializedStream<'_> {
        type Target = GcmStream;

        fn deref(&self) -> &Self::Target {
            self.0
        }
    }

    impl DerefMut for GcmInitializedStream<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0
        }
    }

    ///
    /// This type represents a borrowed handle to an initialized GcmStream that
    /// is used to:
    /// 1. Provide a guarantee that the underlying storage is initialized.
    /// 2. Prevent the underlying storage from being moved or copied.
    ///
    /// This type does not zero the underlying storage when dropped.
    ///
    pub struct GcmInitializedStreamRefMut<'a>(&'a mut GcmStream);

    impl<'a> GcmInitializedStreamRefMut<'a> {
        //
        // `new` creates a new borrowed mutable reference to an initialized GcmStream
        // from an existing owned reference.
        //
        #[inline(always)]
        pub fn new(inner: &'a mut GcmInitializedStream) -> Self {
            Self(inner.0)
        }
    }

    impl Deref for GcmInitializedStreamRefMut<'_> {
        type Target = GcmStream;

        fn deref(&self) -> &Self::Target {
            self.0
        }
    }

    impl DerefMut for GcmInitializedStreamRefMut<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cipher::BlockCipherType;

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
            .decrypt_in_place(&nonce_array, &auth_data, &mut buffer, &tag)
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
        let result = gcm_state.decrypt_in_place(&nonce_array, &auth_data, &mut buffer, &tag);

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

    #[test]
    fn test_invalid_aes_key() {
        let key_data = &[];

        let mut key_storage = GcmUninitializedKey::default();

        match key_storage.expand_key(BlockCipherType::AesBlock, key_data) {
            Err(SymCryptError::WrongKeySize) => {}
            Ok(_) => panic!("Incorrectly returned success when generating auth stream"),
            Err(error) => panic!("Invalid result when generating auth stream: {:?}", error),
        };
    }

    #[test]
    fn test_encrypt_decrypt_part() -> Result<(), SymCryptError> {
        let mut key = GcmUninitializedKey::default();
        let key = key.expand_key(
            BlockCipherType::AesBlock,
            &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap(),
        )?;

        let mut nonce = [0; 12];
        rand::fill(&mut nonce);

        let mut orig_data = [0; 1024];
        rand::fill(&mut orig_data);

        let (expected_encrypted, expected_tag) = {
            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];

            key.encrypt_in_place(&nonce, &[], &mut encrypted_data, &mut tag);
            (encrypted_data, tag)
        };

        let mut gcm_stream = GcmStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream = gcm_stream.as_encryption_stream(key.as_ref(), &nonce);

            let mut encrypted_data = [0; 1024];
            let mut tag = [0; 16];
            for (source, destination) in orig_data
                .chunks(chunk_size)
                .zip(encrypted_data.chunks_mut(chunk_size))
            {
                encryption_stream.encrypt(source, destination);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream = gcm_stream.as_decryption_stream(key.as_ref(), &nonce);

            let mut decrypted_data = [0; 1024];
            for (source, destination) in expected_encrypted
                .chunks(chunk_size)
                .zip(decrypted_data.chunks_mut(chunk_size))
            {
                decryption_stream.decrypt(source, destination);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_part_inplace() -> Result<(), SymCryptError> {
        let mut key = GcmUninitializedKey::default();
        let key = key.expand_key(
            BlockCipherType::AesBlock,
            &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap(),
        )?;

        let mut nonce = [0; 12];
        rand::fill(&mut nonce);

        let mut orig_data = [0; 1024];
        rand::fill(&mut orig_data);

        let (expected_encrypted, expected_tag) = {
            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            key.encrypt_in_place(&nonce, &[], &mut encrypted_data, &mut tag);
            (encrypted_data, tag)
        };

        let mut gcm_stream = GcmStream::default();
        for chunk_size in 1..orig_data.len() {
            let mut encryption_stream = gcm_stream.as_encryption_stream(key.as_ref(), &nonce);

            let mut encrypted_data = orig_data;
            let mut tag = [0; 16];
            for window in encrypted_data.chunks_mut(chunk_size) {
                encryption_stream.encrypt_in_place(window);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream = gcm_stream.as_decryption_stream(key.as_ref(), &nonce);

            let mut decrypted_data = expected_encrypted;
            for window in decrypted_data.chunks_mut(chunk_size) {
                decryption_stream.decrypt_in_place(window);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }
}
