use std::{mem, ptr::{addr_of, addr_of_mut}};

use internal::{GcmInitializedStream, GcmInitializedStreamRefMut};
use symcrypt_sys::{SymCryptGcmAuthPart, SymCryptGcmDecrypt, SymCryptGcmDecryptFinal, SymCryptGcmDecryptPart, SymCryptGcmEncrypt, SymCryptGcmEncryptFinal, SymCryptGcmEncryptPart, SymCryptGcmExpandKey, SymCryptGcmInit, SymCryptWipe, SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR, SYMCRYPT_GCM_EXPANDED_KEY, SYMCRYPT_GCM_STATE};

use crate::{cipher::{convert_cipher, BlockCipherType}, errors::SymCryptError, symcrypt_init};


///
/// This type represents an uninitialized GcmExpandedKey storage. It can be freely
/// copied, cloned, or moved as it does not contain any information.
/// 
#[derive(Clone, Copy, Default)]
pub struct GcmUnexpandedKey(SYMCRYPT_GCM_EXPANDED_KEY);

impl GcmUnexpandedKey {

    //
    // `get_key_ptr` gets a constant pointer to the underlying SYMCRYPT_GCM_EXPANDED_KEY.
    //
    #[inline(always)]
    fn get_key_ptr(&self) -> *const SYMCRYPT_GCM_EXPANDED_KEY {
        addr_of!(self.0)
    }

    //
    // `get_key_ptr_mut` gets a mutable pointer to the underlying SYMCRYPT_GCM_EXPANDED_KEY.
    //
    #[inline(always)]
    fn get_key_ptr_mut(&mut self) -> *mut SYMCRYPT_GCM_EXPANDED_KEY {
        addr_of_mut!(self.0)
    }

    ///
    /// `expand_key` will initialize this SYMCRYPT_GCM_EXPANDED_KEY to using the probided
    /// cipher type and key.
    /// 
    /// `cipher_type` is a `BlockCipherType` that determines the cipher to use for this key.
    /// The only supported cipher type is [`BlockCipherType::AesBlock`]
    /// 
    /// `key_data` is a `&[u8]` that contains the key to initialize with.
    /// 
    pub fn expand_key(&mut self, cipher_type: BlockCipherType, key_data: &[u8]) -> Result<GcmExpandedKey, SymCryptError> {
        symcrypt_init();
        let cipher = convert_cipher(cipher_type);

        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //
        
        unsafe {
            let result =
                SymCryptGcmExpandKey(
                    self.get_key_ptr_mut(),
                    cipher,
                    key_data.as_ptr(),
                    key_data.len() as symcrypt_sys::SIZE_T);

            if result != SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                return Err(result.into());
            }

            Ok(GcmExpandedKey::new(self))
        }
    }

}

///
/// This type represents a handle to an initialized GcmExpandedKey that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
/// 3. Zero the underlying storage when dropped.
/// 
pub struct GcmExpandedKey<'a>(&'a mut GcmUnexpandedKey);

impl<'a> GcmExpandedKey<'a> {

    //
    // # Safety:
    //
    // The caller must enture that the underlying storage has been correctly
    // initialized.
    //
    #[inline(always)]
    unsafe fn new(inner: &'a mut GcmUnexpandedKey) -> Self {
        Self(inner)
    }

    ///
    /// Creates a borrowed reference to the underlying GcmExpandedKey storage.
    /// 
    #[inline(always)]
    pub fn as_ref(&self) -> GcmExpandedKeyRef {
        GcmExpandedKeyRef::new(self)
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
        tag: &[u8]
        ) -> Result<(), SymCryptError>

    {

        self.as_ref().decrypt(nonce, auth_data, source, destination, tag)
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
        tag: &[u8]
        ) -> Result<(), SymCryptError>

    {

        self.as_ref().decrypt_in_place(nonce, auth_data, buffer, tag)
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
        tag: &mut [u8]
        )

    {

        self.as_ref().encrypt(nonce, auth_data, source, destination, tag);
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
        tag: &mut [u8]
        )

    {

        self.as_ref().encrypt_in_place(nonce, auth_data, buffer, tag);
    }

}

impl<'a> Drop for GcmExpandedKey<'a> {

    fn drop(&mut self) {
        
        //
        // SAFETY: FFI calls to securly zero repr(C) structs
        //

        unsafe {
            SymCryptWipe(
                self.0.get_key_ptr_mut() as *mut _,
                mem::size_of::<SYMCRYPT_GCM_EXPANDED_KEY>() as symcrypt_sys::SIZE_T);
        }
    }

}

///
/// This type represents a borrowed handle to an initialized GcmExpandedKey that
/// is used to:
/// 1. Provide a guarantee that the underlying storage is initialized.
/// 2. Prevent the underlying storage from being moved or copied.
/// 
/// This type does not zero the underlying storage when dropped.
/// 
pub struct GcmExpandedKeyRef<'a>(&'a GcmUnexpandedKey);

impl<'a> GcmExpandedKeyRef<'a> {

    ///
    /// `new` creates a new borrowed handle to an initialized GcmExpandedKey.
    /// 
    /// `expanded_key` is a `&GcmExpandedKey` that is the owning handle for the GcmExpandedKey to create a reference to.
    /// 
    #[inline(always)]
    pub fn new(expanded_key: &'a GcmExpandedKey) -> Self {
        Self(expanded_key.0)
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
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        source: &[u8],
        destination: &mut [u8],
        tag: &[u8]
        ) -> Result<(), SymCryptError>

    {

        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new` and we have asserted that both `source` and
        // `destination` are of the same length.
        //

        unsafe {
            let result = 
                SymCryptGcmDecrypt(
                    self.0.get_key_ptr(),
                    nonce.as_ptr(),
                    nonce.len() as symcrypt_sys::SIZE_T,
                    auth_data.as_ptr(),
                    auth_data.len() as symcrypt_sys::SIZE_T,
                    source.as_ptr(),
                    destination.as_mut_ptr(),
                    destination.len() as symcrypt_sys::SIZE_T,
                    tag.as_ptr(),
                    tag.len() as symcrypt_sys::SIZE_T);

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into())
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
        tag: &[u8]
        ) -> Result<(), SymCryptError>

    {

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new`.
        //

        unsafe {
            let result = 
                SymCryptGcmDecrypt(
                    self.0.get_key_ptr(),
                    nonce.as_ptr(),
                    nonce.len() as symcrypt_sys::SIZE_T,
                    auth_data.as_ptr(),
                    auth_data.len() as symcrypt_sys::SIZE_T,
                    buffer.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len() as symcrypt_sys::SIZE_T,
                    tag.as_ptr(),
                    tag.len() as symcrypt_sys::SIZE_T);

            match result {
                SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                error => Err(error.into())
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
        tag: &mut [u8]
        )

    {

        assert_eq!(source.len(), destination.len());

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new` and we have asserted that both `source` and
        // `destination` are of the same length.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T);
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
        tag: &mut [u8]
        )

    {

        //
        // SAFETY: The underlying SYMCRYPT_GCM_EXPANDED_KEY is guaranteed to be initialized
        // by the caller of `GcmExpandedKey::new`.
        //

        unsafe {
            SymCryptGcmEncrypt(
                self.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                buffer.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T);
        }
    }

}

///
/// This type represents an uninitialized SYMCRYPT_GCM_STATE. It can be freely
/// copied, clones, or moved as it does not contain any information.
/// 
#[derive(Copy, Clone, Default)]
pub struct GcmStream(SYMCRYPT_GCM_STATE);

impl GcmStream {

    //
    // `get_key_ptr_mut` gets a mutable pointer to the underlying SYMCRYPT_GCM_STATE.
    //
    #[inline(always)]
    fn get_state_ptr_mut(&mut self) -> *mut SYMCRYPT_GCM_STATE {
        addr_of_mut!(self.0)
    }

    //
    // `initialize` initializes the underlying `SYMCRYPT_GCM_STATE`` with the provided key and nonce.
    //
    // `expanded_key` provides a borrowed reference to an initialized `SYMCRYPT_GCM_EXPANDED_KEY`
    //
    // `nonce` is a `&[u8; 12]` that is used as the nonce.
    //
    fn initialize<'a>(&'a mut self, expanded_key: GcmExpandedKeyRef<'a>, nonce: &[u8; 12]) -> GcmInitializedStream<'a> {
        
        //
        // SAFETY: FFI call to initialize repr(C) struct.
        //
        
        unsafe {
            SymCryptGcmInit(
                self.get_state_ptr_mut(),
                expanded_key.0.get_key_ptr(),
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T);

            GcmInitializedStream::new(self)
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
        nonce: &[u8; 12]) -> GcmAuthStream<'a> {

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
        nonce: &[u8; 12]) -> GcmDecryptionStream<'a> {

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
        nonce: &[u8; 12]) -> GcmEncryptionStream<'a> {

        GcmEncryptionStream(self.initialize(expanded_key, nonce))
    }

}

///
/// This type represents a handle to an initialized GcmStream that can be used to autheticate,
/// but not encrypt or decrypt, data. It can later be converted to a GcmDecryptionStream or
/// GcmEncryptionStream.
/// 
pub struct GcmAuthStream<'a>(GcmInitializedStream<'a>);

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
pub struct GcmAuthStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl<'a> GcmAuthStreamRefMut<'a> {

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
            SymCryptGcmAuthPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T);
        }
    }

}

///
/// This type represents a handle to an initialized GcmStream that can be used to decrypt data.
/// 
pub struct GcmDecryptionStream<'a>(GcmInitializedStream<'a>);

impl<'a> GcmDecryptionStream<'a> {

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
            SymCryptGcmDecryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_ptr(),
                tag.len() as u64)
        };

        self.0.drop_without_zero();
        match result {
            SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            error => Err(error.into())
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
pub struct GcmDecryptionStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl<'a> GcmDecryptionStreamRefMut<'a> {

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
            SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as symcrypt_sys::SIZE_T);
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
            SymCryptGcmDecryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as symcrypt_sys::SIZE_T);
        }
    }

}

///
/// This type represents a handle to an initialized GcmStream that can be used to
/// encrypt data.
/// 
pub struct GcmEncryptionStream<'a>(GcmInitializedStream<'a>);

impl<'a> GcmEncryptionStream<'a> {

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
            SymCryptGcmEncryptFinal(
                self.0.get_state_ptr_mut(),
                tag.as_mut_ptr(),
                tag.len() as u64);
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
pub struct GcmEncryptionStreamRefMut<'a>(GcmInitializedStreamRefMut<'a>);

impl<'a> GcmEncryptionStreamRefMut<'a> {
    
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
            SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                destination.len() as u64);
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
            SymCryptGcmEncryptPart(
                self.0.get_state_ptr_mut(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as u64);
        }
    }
    
}

mod internal {

    use std::{mem, ops::{Deref, DerefMut}};

    use symcrypt_sys::{SymCryptWipe, SYMCRYPT_GCM_STATE};

    use super::GcmStream;

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

    impl<'a> Drop for GcmInitializedStream<'a> {

        fn drop(&mut self) {
        
            //
            // SAFETY: FFI calls to securly zero repr(C) structs
            //

            unsafe {
                SymCryptWipe(
                    self.0.get_state_ptr_mut() as *mut _,
                    mem::size_of::<SYMCRYPT_GCM_STATE>() as symcrypt_sys::SIZE_T);
            }
        }

    }

    impl<'a> Deref for GcmInitializedStream<'a> {

        type Target = GcmStream;
    
        fn deref(&self) -> &Self::Target {
            self.0
        }

    }

    impl<'a> DerefMut for GcmInitializedStream<'a> {

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

    impl<'a> Deref for GcmInitializedStreamRefMut<'a> {

        type Target = GcmStream;
    
        fn deref(&self) -> &Self::Target {
            self.0
        }

    }

    impl<'a> DerefMut for GcmInitializedStreamRefMut<'a> {

        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0
        }

    }

}

#[cfg(test)]
mod test {

    use crate::{cipher::BlockCipherType, errors::SymCryptError};

    use super::{GcmStream, GcmUnexpandedKey};

    #[test]
    fn test_invalid_aes_key() {
        let key_data = &[];

        let mut key_storage = GcmUnexpandedKey::default();

        match key_storage.expand_key(BlockCipherType::AesBlock, key_data) {
            Err(SymCryptError::WrongKeySize) => {},
            Ok(_) => panic!("Incorrectly returned success when generating auth stream"),
            Err(error) => panic!("Invalid result when generating auth stream: {:?}", error)
        };
    }

    #[test]
    fn test_encrypt_decrypt_part() -> Result<(), SymCryptError> {
        let mut key = GcmUnexpandedKey::default();
        let key =
            key.expand_key(
                BlockCipherType::AesBlock,
                &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap())?;

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
            let mut encryption_stream =
                gcm_stream.as_encryption_stream(
                    key.as_ref(),
                    &nonce);

            let mut encrypted_data = [0; 1024];
            let mut tag = [0; 16];
            for (source, destination) in
                orig_data.chunks(chunk_size)
                        .zip(encrypted_data.chunks_mut(chunk_size)) {

                encryption_stream.encrypt(source, destination);
            }

            encryption_stream.complete(&mut tag);
            assert_eq!(expected_encrypted, encrypted_data);
            assert_eq!(expected_tag, tag);
        }

        for chunk_size in 1..orig_data.len() {
            let mut decryption_stream =
                gcm_stream.as_decryption_stream(
                    key.as_ref(),
                    &nonce);

            let mut decrypted_data = [0; 1024];
            for (source, destination) in
                expected_encrypted.chunks(chunk_size)
                                .zip(decrypted_data.chunks_mut(chunk_size)) {

                decryption_stream.decrypt(source, destination);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_part_inplace() -> Result<(), SymCryptError> {
        let mut key = GcmUnexpandedKey::default();
        let key =
            key.expand_key(
                BlockCipherType::AesBlock,
                &hex::decode("feffe9928665731c6d6a8f9467308308").unwrap())?;

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
            let mut encryption_stream =
                gcm_stream.as_encryption_stream(
                    key.as_ref(),
                    &nonce);

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
            let mut decryption_stream =
                gcm_stream.as_decryption_stream(
                    key.as_ref(),
                    &nonce);

            let mut decrypted_data = expected_encrypted;
            for window in decrypted_data.chunks_mut(chunk_size) {
                decryption_stream.decrypt_in_place(window);
            }

            decryption_stream.complete(&expected_tag)?;
            assert_eq!(orig_data, decrypted_data);
        }

        Ok(())
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

        let mut key = GcmUnexpandedKey::default();
        let gcm_state = key.expand_key(cipher, &p_key).unwrap();
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

}
