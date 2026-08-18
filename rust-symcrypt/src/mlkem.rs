//! ML-KEM functions. For more info please refer to symcrypt.h
//!
//! ML-KEM establishes a shared secret between two parties. The receiver generates a key pair and
//! publishes the encapsulation key. The sender encapsulates using that public key and sends the
//! ciphertext to the receiver. The shared secret is never transmitted.
//!
//! ML-KEM does not authenticate either party. Use the shared secret according to the surrounding
//! protocol's KDF or key schedule rather than designing a protocol directly around these methods.
//!
//! # Examples
//!
//! ## Generate a key pair and complete a round trip
//! ```rust
//! use symcrypt::mlkem::{MlKemKey, MlKemParams};
//!
//! let receiver = MlKemKey::generate_key_pair(MlKemParams::MlKem768).unwrap();
//! let encapsulation_key = receiver.export_encapsulation_key().unwrap();
//!
//! let sender = MlKemKey::from_encapsulation_key(MlKemParams::MlKem768, &encapsulation_key).unwrap();
//! let encapsulation = sender.encapsulate().unwrap();
//!
//! let received = receiver.decapsulate(&encapsulation.ciphertext).unwrap();
//! assert_eq!(received.as_bytes(), encapsulation.shared_secret.as_bytes());
//! ```
//!
//! ## Store and restore a key pair from its private seed
//! ```rust
//! use symcrypt::mlkem::{MlKemKey, MlKemParams};
//!
//! let key = MlKemKey::generate_key_pair(MlKemParams::MlKem512).unwrap();
//!
//! let seed = key.export_private_seed().unwrap();
//! let restored = MlKemKey::from_private_seed(MlKemParams::MlKem512, &seed).unwrap();
//! assert_eq!(
//!     restored.export_encapsulation_key().unwrap(),
//!     key.export_encapsulation_key().unwrap()
//! );
//! ```
use crate::errors::SymCryptError;
use crate::symcrypt_init;
use std::ffi::c_void;
use std::fmt;

/// The size in bytes of the secret agreed by ML-KEM.
const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM parameter sets.
///
/// The parameter set is normally selected by the protocol using ML-KEM. Do not choose a different
/// set independently of the peer. ML-KEM-768 is the commonly deployed choice when a protocol does
/// not require another set.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MlKemParams {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl MlKemParams {
    /// Size in bytes of the `d || z` private seed.
    ///
    /// The seed does not identify its parameter set, so callers must store the parameter set
    /// alongside it.
    pub const PRIVATE_SEED_LEN: usize = 64;

    /// Returns the encapsulation key size in bytes.
    pub fn encapsulation_key_len(&self) -> usize {
        self.key_format_len(MlKemKeyFormat::EncapsulationKey)
    }

    /// Returns the decapsulation key size in bytes.
    pub fn decapsulation_key_len(&self) -> usize {
        self.key_format_len(MlKemKeyFormat::DecapsulationKey)
    }

    /// Returns the ciphertext size in bytes.
    pub fn ciphertext_len(&self) -> usize {
        symcrypt_init();
        let mut size: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call. `size` is a valid out-param for the duration of the call.
            match symcrypt_sys::SymCryptMlKemSizeofCiphertextFromParams(
                self.to_symcrypt_params(),
                &mut size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => size as usize,
                err => unreachable_size_error("SymCryptMlKemSizeofCiphertextFromParams", err),
            }
        }
    }

    /// Returns the key blob size for `format`.
    fn key_format_len(&self, format: MlKemKeyFormat) -> usize {
        symcrypt_init();
        let mut size: symcrypt_sys::SIZE_T = 0;
        unsafe {
            // SAFETY: FFI call. `size` is a valid out-param for the duration of the call.
            match symcrypt_sys::SymCryptMlKemSizeofKeyFormatFromParams(
                self.to_symcrypt_params(),
                format.to_symcrypt_format(),
                &mut size,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => size as usize,
                err => unreachable_size_error("SymCryptMlKemSizeofKeyFormatFromParams", err),
            }
        }
    }

    fn to_symcrypt_params(self) -> symcrypt_sys::SYMCRYPT_MLKEM_PARAMS {
        match self {
            MlKemParams::MlKem512 => {
                symcrypt_sys::_SYMCRYPT_MLKEM_PARAMS_SYMCRYPT_MLKEM_PARAMS_MLKEM512
            }
            MlKemParams::MlKem768 => {
                symcrypt_sys::_SYMCRYPT_MLKEM_PARAMS_SYMCRYPT_MLKEM_PARAMS_MLKEM768
            }
            MlKemParams::MlKem1024 => {
                symcrypt_sys::_SYMCRYPT_MLKEM_PARAMS_SYMCRYPT_MLKEM_PARAMS_MLKEM1024
            }
        }
    }
}

// Rust only exposes parameter and format values accepted by the size-query APIs.
fn unreachable_size_error(function: &str, err: symcrypt_sys::SYMCRYPT_ERROR) -> ! {
    panic!(
        "{} rejected a parameter set that this crate can represent: {}",
        function,
        SymCryptError::from(err)
    )
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum MlKemKeyFormat {
    PrivateSeed,
    DecapsulationKey,
    EncapsulationKey,
}

impl MlKemKeyFormat {
    fn to_symcrypt_format(self) -> symcrypt_sys::SYMCRYPT_MLKEMKEY_FORMAT {
        match self {
            MlKemKeyFormat::PrivateSeed => {
                symcrypt_sys::_SYMCRYPT_MLKEMKEY_FORMAT_SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED
            }
            MlKemKeyFormat::DecapsulationKey => {
                symcrypt_sys::_SYMCRYPT_MLKEMKEY_FORMAT_SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY
            }
            MlKemKeyFormat::EncapsulationKey => {
                symcrypt_sys::_SYMCRYPT_MLKEMKEY_FORMAT_SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY
            }
        }
    }
}

// Owns a SymCrypt ML-KEM key allocation.
#[derive(Debug)]
struct InnerMlKemKey(symcrypt_sys::PSYMCRYPT_MLKEMKEY);

impl Drop for InnerMlKemKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `self.0` is owned by this wrapper.
            if !self.0.is_null() {
                symcrypt_sys::SymCryptMlKemkeyFree(self.0);
            }
        }
    }
}

/// A 32-byte ML-KEM shared secret.
///
/// The bytes are wiped on drop and omitted from `Debug`.
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    /// Returns the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI call over a buffer this type owns.
            symcrypt_sys::SymCryptWipe(
                self.0.as_mut_ptr() as *mut c_void,
                SHARED_SECRET_LEN as symcrypt_sys::SIZE_T,
            );
        }
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([redacted])")
    }
}

/// The result of [`MlKemKey::encapsulate`].
#[derive(Debug)]
pub struct MlKemEncapsulation {
    /// The ciphertext to send to the peer.
    pub ciphertext: Vec<u8>,
    /// The shared secret.
    pub shared_secret: SharedSecret,
}

/// An ML-KEM key.
///
/// A key may contain a full key pair or only an encapsulation key.
#[derive(Debug)]
pub struct MlKemKey {
    inner_key: InnerMlKemKey,
    params: MlKemParams,
    has_private_key: bool,
    has_private_seed: bool,
}

impl MlKemKey {
    /// Generates a random ML-KEM key pair.
    pub fn generate_key_pair(params: MlKemParams) -> Result<Self, SymCryptError> {
        let inner_key = Self::allocate(params)?;
        unsafe {
            // SAFETY: `inner_key` is allocated and owned here. Flags request FIPS validation.
            match symcrypt_sys::SymCryptMlKemkeyGenerate(inner_key.0, 0) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(MlKemKey {
                    inner_key,
                    params,
                    // Generated keys contain both private representations.
                    has_private_key: true,
                    has_private_seed: true,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// Imports a full ML-KEM key from a `d || z` private seed.
    ///
    /// `seed` must be [`MlKemParams::PRIVATE_SEED_LEN`] bytes. Store the parameter set with the
    /// seed: importing the same seed under a different parameter set succeeds but creates an
    /// unrelated key.
    pub fn from_private_seed(params: MlKemParams, seed: &[u8]) -> Result<Self, SymCryptError> {
        Self::from_blob(params, seed, MlKemKeyFormat::PrivateSeed)
    }

    /// Imports an ML-KEM decapsulation key.
    ///
    /// `bytes` must be [`MlKemParams::decapsulation_key_len`] bytes. This format cannot be used to
    /// export the private seed.
    pub fn from_decapsulation_key(
        params: MlKemParams,
        bytes: &[u8],
    ) -> Result<Self, SymCryptError> {
        Self::from_blob(params, bytes, MlKemKeyFormat::DecapsulationKey)
    }

    /// Imports an ML-KEM encapsulation key.
    ///
    /// `bytes` must be [`MlKemParams::encapsulation_key_len`] bytes. The resulting key cannot
    /// decapsulate.
    pub fn from_encapsulation_key(
        params: MlKemParams,
        bytes: &[u8],
    ) -> Result<Self, SymCryptError> {
        Self::from_blob(params, bytes, MlKemKeyFormat::EncapsulationKey)
    }

    /// Exports the encapsulation key.
    pub fn export_encapsulation_key(&self) -> Result<Vec<u8>, SymCryptError> {
        self.export(MlKemKeyFormat::EncapsulationKey)
    }

    /// Exports the decapsulation key.
    ///
    /// Returns [`SymCryptError::IncompatibleFormat`] for a key imported from an encapsulation key.
    /// The returned bytes contain secret key material.
    /// The returned `Vec<u8>` is not wiped automatically; the caller must protect and erase it
    /// after use.
    pub fn export_decapsulation_key(&self) -> Result<Vec<u8>, SymCryptError> {
        // SymCrypt v103.6 returns INVALID_ARGUMENT here, while v103.7 and later return
        // INCOMPATIBLE_FORMAT. Normalize the transition across supported runtimes.
        if !self.has_private_key {
            return Err(SymCryptError::IncompatibleFormat);
        }
        self.export(MlKemKeyFormat::DecapsulationKey)
    }

    /// Exports the `d || z` private seed.
    ///
    /// Returns [`SymCryptError::IncompatibleFormat`] if the key does not contain the private seed.
    /// The returned bytes contain secret key material.
    /// The returned `Vec<u8>` is not wiped automatically; the caller must protect and erase it
    /// after use.
    pub fn export_private_seed(&self) -> Result<Vec<u8>, SymCryptError> {
        // Enforce the capability before allocating the output buffer.
        if !self.has_private_seed {
            return Err(SymCryptError::IncompatibleFormat);
        }
        self.export(MlKemKeyFormat::PrivateSeed)
    }

    /// Generates a shared secret and ciphertext.
    ///
    /// Send `ciphertext` to the peer holding the decapsulation key. Keep `shared_secret` private
    /// and use it only through the surrounding protocol's KDF or key schedule.
    pub fn encapsulate(&self) -> Result<MlKemEncapsulation, SymCryptError> {
        let mut ciphertext = vec![0u8; self.params.ciphertext_len()];
        let mut shared_secret = SharedSecret([0u8; SHARED_SECRET_LEN]);
        unsafe {
            // SAFETY: FFI call. Both output buffers are owned here and sized from SymCrypt's own
            // size queries.
            match symcrypt_sys::SymCryptMlKemEncapsulate(
                self.inner_key.0,
                shared_secret.0.as_mut_ptr(),
                SHARED_SECRET_LEN as symcrypt_sys::SIZE_T,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(MlKemEncapsulation {
                    ciphertext,
                    shared_secret,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// Decapsulates `ciphertext` into a shared secret.
    ///
    /// A correctly sized invalid ciphertext is implicitly rejected: this method returns `Ok` with
    /// a pseudo-random secret. A successful return therefore does not authenticate the ciphertext
    /// or peer. Authentication must be provided by the surrounding protocol.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, SymCryptError> {
        // Distinguish an incompatible key from an invalid ciphertext length.
        if !self.has_private_key {
            return Err(SymCryptError::IncompatibleFormat);
        }
        if ciphertext.len() != self.params.ciphertext_len() {
            return Err(SymCryptError::InvalidArgument);
        }

        let mut shared_secret = SharedSecret([0u8; SHARED_SECRET_LEN]);
        unsafe {
            // SAFETY: FFI call. The ciphertext length is checked above and the output buffer is
            // owned here.
            match symcrypt_sys::SymCryptMlKemDecapsulate(
                self.inner_key.0,
                ciphertext.as_ptr(),
                ciphertext.len() as symcrypt_sys::SIZE_T,
                shared_secret.0.as_mut_ptr(),
                SHARED_SECRET_LEN as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(shared_secret),
                err => Err(err.into()),
            }
        }
    }

    /// Returns the key's parameter set.
    pub fn params(&self) -> MlKemParams {
        self.params
    }

    /// Returns whether the key can decapsulate.
    pub fn can_decapsulate(&self) -> bool {
        self.has_private_key
    }

    /// Returns whether the private seed can be exported.
    pub fn has_private_seed(&self) -> bool {
        self.has_private_seed
    }

    fn allocate(params: MlKemParams) -> Result<InnerMlKemKey, SymCryptError> {
        symcrypt_init();
        unsafe {
            // SAFETY: FFI call. Wrapped immediately so the allocation is freed on any early return.
            let inner_key = InnerMlKemKey(symcrypt_sys::SymCryptMlKemkeyAllocate(
                params.to_symcrypt_params(),
            ));
            if inner_key.0.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }
            Ok(inner_key)
        }
    }

    fn from_blob(
        params: MlKemParams,
        blob: &[u8],
        format: MlKemKeyFormat,
    ) -> Result<Self, SymCryptError> {
        // Match the SymCrypt key format size requirement.
        if blob.len() != params.key_format_len(format) {
            return Err(SymCryptError::WrongKeySize);
        }

        let inner_key = Self::allocate(params)?;
        unsafe {
            // SAFETY: `blob` has the required length and `inner_key` is owned here.
            match symcrypt_sys::SymCryptMlKemkeySetValue(
                blob.as_ptr(),
                blob.len() as symcrypt_sys::SIZE_T,
                format.to_symcrypt_format(),
                0,
                inner_key.0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    // Match SymCrypt's capabilities for each imported format.
                    let (has_private_key, has_private_seed) = match format {
                        MlKemKeyFormat::PrivateSeed => (true, true),
                        MlKemKeyFormat::DecapsulationKey => (true, false),
                        MlKemKeyFormat::EncapsulationKey => (false, false),
                    };
                    Ok(MlKemKey {
                        inner_key,
                        params,
                        has_private_key,
                        has_private_seed,
                    })
                }
                err => Err(err.into()),
            }
        }
    }

    fn export(&self, format: MlKemKeyFormat) -> Result<Vec<u8>, SymCryptError> {
        let mut blob = vec![0u8; self.params.key_format_len(format)];
        unsafe {
            // SAFETY: `blob` is owned here and has the size required by SymCrypt.
            match symcrypt_sys::SymCryptMlKemkeyGetValue(
                self.inner_key.0,
                blob.as_mut_ptr(),
                blob.len() as symcrypt_sys::SIZE_T,
                format.to_symcrypt_format(),
                0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(blob),
                err => Err(err.into()),
            }
        }
    }
}

// SymCrypt permits concurrent read-only use of a key. Mutation is limited to construction.
unsafe impl Send for MlKemKey {}
unsafe impl Sync for MlKemKey {}

#[cfg(test)]
mod test {
    use super::*;

    const ALL_PARAMS: [MlKemParams; 3] = [
        MlKemParams::MlKem512,
        MlKemParams::MlKem768,
        MlKemParams::MlKem1024,
    ];

    #[test]
    fn test_mlkem_sizes_match_fips_203() {
        // Values from the SymCrypt ML-KEM size definitions.
        let expected = [
            (MlKemParams::MlKem512, 800, 1632, 768),
            (MlKemParams::MlKem768, 1184, 2400, 1088),
            (MlKemParams::MlKem1024, 1568, 3168, 1568),
        ];
        for (params, encaps, decaps, ciphertext) in expected {
            assert_eq!(params.encapsulation_key_len(), encaps);
            assert_eq!(params.decapsulation_key_len(), decaps);
            assert_eq!(params.ciphertext_len(), ciphertext);
            assert_eq!(
                params.key_format_len(MlKemKeyFormat::PrivateSeed),
                MlKemParams::PRIVATE_SEED_LEN
            );
        }
    }

    #[test]
    fn test_mlkem_round_trip() {
        for params in ALL_PARAMS {
            let receiver = MlKemKey::generate_key_pair(params).unwrap();
            assert!(receiver.can_decapsulate());
            assert!(receiver.has_private_seed());
            assert_eq!(receiver.params(), params);

            let encapsulation_key = receiver.export_encapsulation_key().unwrap();
            assert_eq!(encapsulation_key.len(), params.encapsulation_key_len());

            let sender = MlKemKey::from_encapsulation_key(params, &encapsulation_key).unwrap();
            assert!(!sender.can_decapsulate());
            assert!(!sender.has_private_seed());

            let encapsulation = sender.encapsulate().unwrap();
            assert_eq!(encapsulation.ciphertext.len(), params.ciphertext_len());

            let decapsulated = receiver.decapsulate(&encapsulation.ciphertext).unwrap();
            assert_eq!(
                decapsulated.as_bytes(),
                encapsulation.shared_secret.as_bytes()
            );
        }
    }

    #[test]
    fn test_mlkem_private_seed_round_trip() {
        for params in ALL_PARAMS {
            let key = MlKemKey::generate_key_pair(params).unwrap();
            let seed = key.export_private_seed().unwrap();
            assert_eq!(seed.len(), MlKemParams::PRIVATE_SEED_LEN);

            let restored = MlKemKey::from_private_seed(params, &seed).unwrap();
            assert!(restored.can_decapsulate());
            assert!(restored.has_private_seed());
            assert_eq!(
                restored.export_encapsulation_key().unwrap(),
                key.export_encapsulation_key().unwrap()
            );
            assert_eq!(
                restored.export_decapsulation_key().unwrap(),
                key.export_decapsulation_key().unwrap()
            );
        }
    }

    #[test]
    fn test_mlkem_decapsulation_key_round_trip() {
        for params in ALL_PARAMS {
            let key = MlKemKey::generate_key_pair(params).unwrap();
            let decapsulation_key = key.export_decapsulation_key().unwrap();
            assert_eq!(decapsulation_key.len(), params.decapsulation_key_len());

            let restored = MlKemKey::from_decapsulation_key(params, &decapsulation_key).unwrap();
            assert!(restored.can_decapsulate());
            assert!(!restored.has_private_seed());
            assert_eq!(
                restored.export_private_seed().unwrap_err(),
                SymCryptError::IncompatibleFormat
            );

            let encapsulation = key.encapsulate().unwrap();
            let decapsulated = restored.decapsulate(&encapsulation.ciphertext).unwrap();
            assert_eq!(
                decapsulated.as_bytes(),
                encapsulation.shared_secret.as_bytes()
            );
        }
    }

    #[test]
    fn test_mlkem_encapsulation_key_cannot_decapsulate() {
        for params in ALL_PARAMS {
            let key = MlKemKey::generate_key_pair(params).unwrap();
            let encapsulation = key.encapsulate().unwrap();

            let public_only =
                MlKemKey::from_encapsulation_key(params, &key.export_encapsulation_key().unwrap())
                    .unwrap();

            assert_eq!(
                public_only
                    .decapsulate(&encapsulation.ciphertext)
                    .unwrap_err(),
                SymCryptError::IncompatibleFormat
            );
            assert_eq!(
                public_only.export_decapsulation_key().unwrap_err(),
                SymCryptError::IncompatibleFormat
            );
            assert_eq!(
                public_only.export_private_seed().unwrap_err(),
                SymCryptError::IncompatibleFormat
            );
        }
    }

    #[test]
    fn test_mlkem_wrong_ciphertext_length() {
        let params = MlKemParams::MlKem768;
        let key = MlKemKey::generate_key_pair(params).unwrap();
        let too_short = vec![0u8; params.ciphertext_len() - 1];
        let too_long = vec![0u8; params.ciphertext_len() + 1];

        assert_eq!(
            key.decapsulate(&too_short).unwrap_err(),
            SymCryptError::InvalidArgument
        );
        assert_eq!(
            key.decapsulate(&too_long).unwrap_err(),
            SymCryptError::InvalidArgument
        );
    }

    #[test]
    fn test_mlkem_wrong_key_blob_length() {
        for params in ALL_PARAMS {
            assert_eq!(
                MlKemKey::from_private_seed(params, &[0u8; MlKemParams::PRIVATE_SEED_LEN - 1])
                    .unwrap_err(),
                SymCryptError::WrongKeySize
            );
            assert_eq!(
                MlKemKey::from_encapsulation_key(
                    params,
                    &vec![0u8; params.encapsulation_key_len() + 1]
                )
                .unwrap_err(),
                SymCryptError::WrongKeySize
            );
            assert_eq!(
                MlKemKey::from_decapsulation_key(
                    params,
                    &vec![0u8; params.decapsulation_key_len() - 1]
                )
                .unwrap_err(),
                SymCryptError::WrongKeySize
            );
        }
    }

    #[test]
    fn test_mlkem_tampered_ciphertext_is_implicitly_rejected() {
        // SymCrypt implicitly rejects correctly sized invalid ciphertexts.
        let params = MlKemParams::MlKem768;
        let key = MlKemKey::generate_key_pair(params).unwrap();
        let encapsulation = key.encapsulate().unwrap();

        let mut tampered = encapsulation.ciphertext.clone();
        tampered[0] ^= 0x01;

        let decapsulated = key.decapsulate(&tampered).unwrap();
        assert_ne!(
            decapsulated.as_bytes(),
            encapsulation.shared_secret.as_bytes()
        );
    }

    #[test]
    fn test_mlkem_shared_secret_debug_does_not_leak() {
        let key = MlKemKey::generate_key_pair(MlKemParams::MlKem512).unwrap();
        let encapsulation = key.encapsulate().unwrap();
        let rendered = format!("{:?}", encapsulation.shared_secret);

        assert_eq!(rendered, "SharedSecret([redacted])");

        let rendered = format!("{:?}", encapsulation);
        assert!(rendered.contains("SharedSecret([redacted])"));
        assert!(!rendered.contains(&hex::encode(encapsulation.shared_secret.as_bytes())));
    }

    // ML-KEM-768 vectors from `symcrypt-sys/symcrypt/unittest/kat_kem.dat`.

    // KAT_KEYGEN_D: 32 bytes, kat_kem.dat line 2787
    const KAT_KEYGEN_D: &str = "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc";

    // KAT_KEYGEN_Z: 32 bytes, kat_kem.dat line 2786
    const KAT_KEYGEN_Z: &str = "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd";

    // KAT_KEYGEN_EK: 1184 bytes, kat_kem.dat line 2788
    const KAT_KEYGEN_EK: &str = concat!(
        "6d14a071f7cc452558d5e71a7b087062ecb1386844588246126402b1fa1637733cd5f60cc84bcb646a7892614d7c51b1",
        "c7f1a2799132f13427dc482158da254470a59e00a4e49686fdc077559367270c2153f11007592c9c4310cf8a12c6a871",
        "3bd6bb51f3124f989ba0d54073cc242e0968780b875a869efb851586b9a868a384b9e6821b201b932c455369a739ec22",
        "569c977c212b381871813656af5b567ef893b584624c863a259000f17b254b98b185097c50ebb68b244342e05d4de520",
        "125b8e1033b1436093ace7ce8e71b458d525673363045a3b3eea9455428a398705a42327adb3774b7057f42b017ec073",
        "9a983f19e8214d09195fa24d2d571db73c19a6f8460e50830d415f627b88e94a7b153791a0c0c7e9484c74d53c714889",
        "f0e321b6660a532a5bc0e557fbca35e29bc611200ed3c633077a4d873c5cc67006b753bf6d6b7af6ca402ab618236c0a",
        "ffbc801f8222fbc36ce0984e2b18c944bbcbef03b1e1361c1f44b0d734afb1566cff8744da8b9943d6b45a3c09030702",
        "ca201ffe20cb7ec5b0d4149ee2c28e8b23374f471b57150d0ec9336261a2d5cb84a3acacc4289473a4c0abc617c9abc1",
        "78734434c82e1685588a5c2ea2678f6b3c2228733130c466e5b86ef491153e48662247b875d201020b566b81b64d839a",
        "b4633baa8ace202baab4496297f9807adbbb1e332c6f8022b2a18cfdd4a82530b6d3f007c3353898d966cc2c21cb4244",
        "bd00443f209870acc42bc33068c724ec17223619c1093cca6aeb29500664d1225036b4b81091906969481f1c723c140b",
        "9d6c168f5b64bea69c5fd6385df7364b8723bcc85e038c7e464a900d68a2127818994217aec8bdb39a970a9963de9368",
        "8e2ac82abcc22fb9277ba22009e878381a38163901c7d4c85019538d35caae9c41af8c929ee20bb08ca619e72c2f2262",
        "c1c9938572551ac02dc9268fbcc35d79011c3c090ad40a4f111c9be55c427eb796c1932d8673579af1b4c638b0944489",
        "012a2559a3b02481b01ac30ba8960f80c0c2b3947d36a12c080498bee448716c973416c8242804a3da099ee137b0ba90",
        "fe4a5c6a89200276a0cfb643ec2c56a2d708d7b4373e44c1502a763a600586e6cda6273897d44448287dc2e602dc3920",
        "0bf6166236559fd12a60892aeb153dd651bb469910b4b34669f91da8654d1eb72eb6e02800b3b0a7d0a48c836854d3a8",
        "3e65569cb7230bb44f3f143a6dec5f2c39ab90f274f2088bd3d6a6fca0070273bedc84777fb52e3c558b0ae06183d5a4",
        "8d452f68e15207f861627aca14279630f82ec3a0ca078633b600afa79743a600215be5637458ce2ce8aff5a08eb5017b",
        "2c766577479f8dc6bf9f5cc75089932161b96cea406620aedb630407f7687ebbb4814c7981637a48a90de68031e062a7",
        "af7612b4f5c7a6da86bd136529e64295a5613ea73bd3d4448cb81f243135c0a660beb9c17e651def469a7d90a15d3481",
        "090bcbf227012328941fa46f39c5006ad93d458aa6add655862b418c3094f551460df2153a5810a7da74f0614c2588be",
        "49dc6f5e88154642bd1d3762563326433507156a57c57694bdd26e7a246feb723aed67b04887c8e476b48cab59e5362f",
        "26a9ef50c2bc80ba146226216fe62968a60d04e8c170d741c7a2b0e1abdac968"
    );

    // KAT_KEYGEN_DK: 2400 bytes, kat_kem.dat line 2813
    const KAT_KEYGEN_DK: &str = concat!(
        "98a1b2da4a65cfb5845ea7311e6a06db731f1590c41ee74ba10782715b35a3102df637872be65bab37a1de2511d703c7",
        "0247b35ef27435485024d93fd9e77c43804f371749ba00b20a8c5c588bc9abe068aeaaa938517ebfe53b6b663282903d",
        "cd189736d7296816c733a1c77c6375e5397c0f189bbfe47643a61f58f8a3c6911be4611a8c7bc050021163d0a404dc14",
        "065748ff29be60d2b9fdcc8ffd98c587f38c67115786464bdb342b17e897d64617cbfb117973a5458977a7d7617a1b4d",
        "83ba03c611138a4673b1eb34b078033f97cffe80c146a26943f842b976327bf1cbc60119525bb9a3c03493349000dd8f",
        "51ba21a2e92361762324600e0c13aaa6cb69bfb24276483f6b02421259b7585263c1a028d682c508bbc2801a56e98b8f",
        "620b0483d79b5ad8585ac0a475bac77865194196338791b7985a05d109395cca8932722a91950d37e12b891420a52b62",
        "cbfa815df6174ce00e68bca75d4838ca280f713c7e6924afd95baa0d01ada637b158347034c0ab1a7183331a820acbcb",
        "83193a1a94c8f7e384aed0c35ed3cb3397bb638086e7a35a6408a3a4b90ce953707c19bc46c3b2da3b2ee32319c56b92",
        "8032b5ed1256d0753d341423e9db139de7714ff075caf58fd9f57d1a54019b5926406830dae29a875302a81256f4d6cf",
        "5e74034ea614bf70c2764b20c9589cdb5c25761a04e58292907c578a94a35836bee3112dc2c3ae2192c9deaa304b29c7",
        "fea1bdf47b3b6bcba2c0e55c9cdb6de7149e9cb17917718f12c8032de1ade0648d405519c70719becc701845cf9f4b91",
        "2fe71983ca34f9018c7ca7bb2f6c5d7f8c5b297359ec75209c2543ff11c4244977c5969524ec454d44c323fcca94acac",
        "273a0ec49b4a8a585bce7a5b305c04c3506422580357016a850c3f7ee17205a77b291c7731c9836c02aee5406f63c6a0",
        "7a214382aa15336c05d1045588107645ea7de6870fc0e55e1540974301c42ec14105518680f688abe4ce453738fe471b",
        "87fc31f5c68a39e68af51b0240b90e0364b04bac43d6fb68ab65ae028b62bd683b7d28ad38806bee725b5b2416a8d79c",
        "16ec2a99ea4a8d92a2f5052e67f97352289761c5c39fc5c742e9c0a740ca59fc0182f709d01b5187f00063daab397596",
        "eea4a31bdbcbd4c1bb0c55be7c6850fda9326b353e288c5013226c3c3923a791609e8002e73a5f7b6bb4a877b1fdf53b",
        "b2bab3dd424d31bbb448e609a66b0e343c286e8760312b6d37aa5201d21f53503d88389adca21c70fb6c0fc9c69d6616",
        "c9ea3780e35565c0c97c15179c95343ecc5e1c2a24de4699f6875ea2fa2dd3e357bc43914795207e026b850a2237950c",
        "108a512fc88c22488112607088185fb0e09c2c4197a83687266bab2e583e21c40f4cc008fe652804d8223f1520a90b0d",
        "5385c7553cc767c58d120ccd3ef5b5d1a6cd7bc00dff1321b2f2c432b64efb8a3f5d0064b3f34293026c851c2ded68b9",
        "dff4a28f6a8d225535e0477084430cffda0ac0552f9a212785b749913a06fa2274c0d15bad325458d323ef6bae13c001",
        "0d525c1d5269973ac29bda7c983746918ba0e002588e30375d78329e6b8ba8c4462a692fb6083842b8c8c92c60f25272",
        "6d14a071f7cc452558d5e71a7b087062ecb1386844588246126402b1fa1637733cd5f60cc84bcb646a7892614d7c51b1",
        "c7f1a2799132f13427dc482158da254470a59e00a4e49686fdc077559367270c2153f11007592c9c4310cf8a12c6a871",
        "3bd6bb51f3124f989ba0d54073cc242e0968780b875a869efb851586b9a868a384b9e6821b201b932c455369a739ec22",
        "569c977c212b381871813656af5b567ef893b584624c863a259000f17b254b98b185097c50ebb68b244342e05d4de520",
        "125b8e1033b1436093ace7ce8e71b458d525673363045a3b3eea9455428a398705a42327adb3774b7057f42b017ec073",
        "9a983f19e8214d09195fa24d2d571db73c19a6f8460e50830d415f627b88e94a7b153791a0c0c7e9484c74d53c714889",
        "f0e321b6660a532a5bc0e557fbca35e29bc611200ed3c633077a4d873c5cc67006b753bf6d6b7af6ca402ab618236c0a",
        "ffbc801f8222fbc36ce0984e2b18c944bbcbef03b1e1361c1f44b0d734afb1566cff8744da8b9943d6b45a3c09030702",
        "ca201ffe20cb7ec5b0d4149ee2c28e8b23374f471b57150d0ec9336261a2d5cb84a3acacc4289473a4c0abc617c9abc1",
        "78734434c82e1685588a5c2ea2678f6b3c2228733130c466e5b86ef491153e48662247b875d201020b566b81b64d839a",
        "b4633baa8ace202baab4496297f9807adbbb1e332c6f8022b2a18cfdd4a82530b6d3f007c3353898d966cc2c21cb4244",
        "bd00443f209870acc42bc33068c724ec17223619c1093cca6aeb29500664d1225036b4b81091906969481f1c723c140b",
        "9d6c168f5b64bea69c5fd6385df7364b8723bcc85e038c7e464a900d68a2127818994217aec8bdb39a970a9963de9368",
        "8e2ac82abcc22fb9277ba22009e878381a38163901c7d4c85019538d35caae9c41af8c929ee20bb08ca619e72c2f2262",
        "c1c9938572551ac02dc9268fbcc35d79011c3c090ad40a4f111c9be55c427eb796c1932d8673579af1b4c638b0944489",
        "012a2559a3b02481b01ac30ba8960f80c0c2b3947d36a12c080498bee448716c973416c8242804a3da099ee137b0ba90",
        "fe4a5c6a89200276a0cfb643ec2c56a2d708d7b4373e44c1502a763a600586e6cda6273897d44448287dc2e602dc3920",
        "0bf6166236559fd12a60892aeb153dd651bb469910b4b34669f91da8654d1eb72eb6e02800b3b0a7d0a48c836854d3a8",
        "3e65569cb7230bb44f3f143a6dec5f2c39ab90f274f2088bd3d6a6fca0070273bedc84777fb52e3c558b0ae06183d5a4",
        "8d452f68e15207f861627aca14279630f82ec3a0ca078633b600afa79743a600215be5637458ce2ce8aff5a08eb5017b",
        "2c766577479f8dc6bf9f5cc75089932161b96cea406620aedb630407f7687ebbb4814c7981637a48a90de68031e062a7",
        "af7612b4f5c7a6da86bd136529e64295a5613ea73bd3d4448cb81f243135c0a660beb9c17e651def469a7d90a15d3481",
        "090bcbf227012328941fa46f39c5006ad93d458aa6add655862b418c3094f551460df2153a5810a7da74f0614c2588be",
        "49dc6f5e88154642bd1d3762563326433507156a57c57694bdd26e7a246feb723aed67b04887c8e476b48cab59e5362f",
        "26a9ef50c2bc80ba146226216fe62968a60d04e8c170d741c7a2b0e1abdac968e29020839d052fa372585627f8b59ee3",
        "12ae414c979d825f06a6929a79625718a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd"
    );

    // KAT_DECAPS_DK: 2400 bytes, kat_kem.dat line 6011
    const KAT_DECAPS_DK: &str = concat!(
        "1e4ac87b1a692a529fdbbab93374c57d110b10f2b1ddebac0d196b7ba631b8e9293028a8f379888c422dc8d32bbf2260",
        "10c2c1ec73189080456b0564b258b0f23131bc79c8e8c11cef3938b243c5ce9c0edd37c8f9d29877dbbb615b9b5ac3c9",
        "48487e467196a9143efbc7cedb64b45d4acda2666cbc2804f2c8662e128f6a9969ec15bc0b9351f6f96346aa7abc743a",
        "14fa030e37a2e7597bddfc5a22f9cedaf8614832527210b26f024c7f6c0dcf551e97a4858764c321d1834ad51d75bb24",
        "6d277237b7bd41dc4362d063f4298292272d01011780b79856b296c4e946658b79603197c9b2a99ec66acb06ce2f69b5",
        "a5a61e9bd06ad443ceb0c74ed65345a903b614e81368aac2b3d2a79ca8ccaa1c3b88fb82a36632860b3f7950833fd021",
        "2ec96ede4ab6f5a0bda3ec6060a658f9457f6cc87c6b620c1a1451987486e496612a101d0e9c20577c571edb5282608b",
        "f4e1ac926c0db1c82a504a799d89885ca6252bd5b1c183af701392a407c05b848c2a3016c40613f02a449b3c7926da06",
        "7a533116506840097510460bbfd36073dcb0bfa009b36a9123eaa68f835f74a01b00d2097835964df521ce9210789c30",
        "b7f06e5844b444c53322396e4799baf6a88af7315860d0192d48c2c0da6b5ba64325543acdf5900e8bc477ab05820072",
        "d463affed097e062bd78c99d12b385131a241b708865b4190af69ea0a64db71448a60829369c7555198e438c9abc310b",
        "c70101913bb12faa5beef975841617c847cd6b336f877987753822020b92c4cc97055c9b1e0b128bf11f505005b6ab0e",
        "627795a20609efa991e598b80f37b1c6a1c3a1e9aee7028f77570ab2139128a00108c50eb305cdb8f9a603a6b078413f",
        "6f9b14c6d82b5199ce59d887902a281a027b717495fe12672a127bbf9b256c43720d7c160b281c12757da135b1933352",
        "be4ab67e40248afc318e2370c3b8208e695bdf337459b9acbfe5b487f76e9b4b4001d6cf90ca8c699a174d42972dc733",
        "f33389fdf59a1daba81d834955027334185ad02c76cf294846ca9294ba0ed66741ddec791cab34196ac5657c5a78321b",
        "56c33306b5102397a5c09c3508f76b48282459f81d0c72a43f737bc2f12f45422628b67db51ac1424276a6c08c3f7615",
        "665bbb8e928148a270f991bcf365a90f87c30687b68809c91f231813b866bea82e30374d80aa0c02973437498a53b14b",
        "f6b6ca1ed76ab8a20d54a083f4a26b7c038d81967640c20bf4431e71dacce8577b21240e494c31f2d877daf4924fd39d",
        "82d6167fbcc1f9c5a259f843e30987ccc4bce7493a2404b5e44387f707425781b743fb555685584e2557cc038b1a9b3f",
        "4043121f5472eb2b96e5941fec011ceea50791636c6abc26c1377ee3b5146fc7c85cb335b1e795eec2033ee44b9aa906",
        "85245ef7b4436c000e66bc8bcbf1cdb803ac1421b1fdb266d5291c8310373a8a3ce9562ab197953871ab99f382cc5aa9",
        "c0f273d1dca55d2712853871e1a83cb3b85450f76d3f3c42bab5505f7212fdb6b8b7f6029972a8f3751e4c94c1108b02",
        "d6ac79f8d938f05a1b2c229b14b42b31b01a364017e59578c6b033833774cb9b570f9086b722903b375446b495d8a29b",
        "f80751877a80fb724a0210c3e1692f397c2f1ddc2e6ba17af81b92acfabef5f7573cb493d184027b718238c89a3549b8",
        "905b28a83362867c082d3019d3ca70700731ceb73e8472c1a3a093361c5fea6a7d40955d07a41b64e50081a361b604cc",
        "518447c8e25765ab7d68b243275207af8ca6564a4cb1e94199dba1878c59bec809ab48b2f211badc6a1998d9c7227c13",
        "03f469d46a9c7e5303f98aba67569ae8227c16ba1fb3244466a25e7f823671810cc26206feb29c7e2a1a91959eeb03a9",
        "8252a4f7412674eb9a4b277e1f2595fca64033b41b40330812e9735b7c607501cd8183a22afc3392553744f33c4d2025",
        "26945c6d78a60e201a16987a6fa59d94464b56506556784824a07058f57320e76c825b9347f2936f4a0e5cdaa18cf883",
        "3945ae312a36b5f5a3810aac82381fdae4cb9c6831d8eb8abab850416443d739086b1c326fc2a3975704e396a59680c3",
        "b5f360f5480d2b62169cd94ca71b37bc5878ba2985e068ba050b2ce50726d4b4451b77aaa8676eae094982210192197b",
        "1e92a27f59868b78867887b9a70c32af84630aa908814379e6519150ba16439b5e2b0603d06aa6674557f5b0983e5cb6",
        "a97596069b01bb3128c416680657204fd07640392e16b19f337a99a304844e1aa474e9c799062971f672268960f5a82f",
        "950070bbe9c2a71950a3785bdf0b8440255ed63928d257845168b1eccc4191325aa76645719b28ebd89302dc6723c786",
        "df5217b243099ca78238e57e64692f206b177abc259660395cd7860fb35a16f6b2fe6548c85ab66330c517fa74cdf3cb",
        "49d26b1181901af775a1e180813b6a24c456829b5c38104ece43c76a437a6a33b6fc6c5e65c8a89466c1425485b29b9e",
        "1854368afca353e143d0a90a6c6c9e7fdb62a606856b5614f12b64b796020c3534c3605cfdc73b86714f411850228a28",
        "b8f4b49e663416c84f7e381f6af1071343bf9d39b45439240cc03897295fea080b14bb2d8119a880e164495c61bebc71",
        "39c11857c85e1750338d6343913706a507c9566464cd2837cf914d1a3c35e89b235c6ab7ed078bed234757c02ef6993d",
        "4a273cb8150528da4d76708177e9425546c83e147039766603b30da6268f4598a53194240a2832a3d67533b5056f9aaa",
        "c61b4b17b9a2693aa0d58891e6cc56cdd772410900c405af20b903797c64876915c37b8487a1449ce924cd345c29a36e",
        "08238f7a157cc7e516ab5ba73c8063f726bb5a0a0319e57127438c7fc601c99ccaae4c1a83726fdcb5045ed1a82a985e",
        "a995396d77272c66ce493289f6110910f37c2741ce47026a6f8261999c6482572b1693912ef12eebea7acf9234fb409f",
        "2a6090e6b0bfd895469d0b2a921bb723f87a33ea5465ab90f514b67698c0768b6ca498b022c512fa0875f054aa226586",
        "7e31c0e522651e024a07d60dd9f633166921f4126bc2b6aa01cc15a09b85bff8218c5aae95bc1ffb26ae5a137670f049",
        "10ca9d7241b6660c394c5455917746a26682fb71a432ea9530e839bdeb07433004f45a0ddaa0b24e3a566a540815f281",
        "e3fc259ac6cbc0acb8d62268b603bc676ab415c474bb94873e4487ae31a4e3845c79901550890ee8784eef904fee62ba",
        "8c5f952c68413052e0a7e3388bb8ff0ad602ae3ea14d9df6dd5e4cc6a381a41da5c137ecc49df587e178eaf47702ec62",
        "3780691a3233f69f12bd9c9b9637c51378ad71a831055277254cc63c5ad4cb76b4ab82e5fca135e8d26a6b3a89fa5b6f"
    );

    // KAT_DECAPS_C: 1088 bytes, kat_kem.dat line 6061
    const KAT_DECAPS_C: &str = concat!(
        "74a26c7d27146a22c7eab420134e973799cec1da2df61ae0fa7905a3a47485a063076bfa22d6e4fe5059de0a32e38f11",
        "abd63f990e91bd0e3a5bc6e710dfe5dc0f6d4a18147ebc2e2d9b179374d83692c53efbd45f28a2a928c2494f903576c4",
        "10eb1773895ebeadb119960eebda9c3c710795a6d9b781fc58b30d08107f4e20944a382afb079f31d21724f2c26e6a53",
        "412f0a908be7586f2b3d6d7c1dea0270e98aa209244bd88ed68aae01432342ba5f49e015cb476b5b78d15ea77a354cc9",
        "e9fd07137d8760be42fd4746c62c02028e7b405ddc95df3d021921cfeddb3d961b957eca302a263dab2dc117beb3e79e",
        "facfcf936dfc09fc0d19c358d724fa381ea06ca067c384e944302c3907ab15a1da4b41352692add59b061541f07eff25",
        "ec42f46e1a0e370cad06ff3fd997d4d2c5648af762231b382d0593401936cba21551a2ae30d8e8effcf43916b83138bb",
        "5e610364429879fa9cdd5b7d3cf2feabaa1dc8d50ce69402e21103e795df7074d1fcf65f8a4e18986d5417780602c63b",
        "e5a044863384bd3d8ffb685eac567ed8349dcf2ceb702b7375b145729998049d13e2cd466cf2231b9d3a20018ee908f8",
        "514a6c6a89df7232f91fcd84b81ebc8bc539e9a37a4324755564be1bf4fa1fb4571e0abbc9b52f9d090c33be599de6c8",
        "532c7cb7ec8b4e2d3c07505280e99923865903ffd18bc13b9c8164aa1eae84e38d3f57fdb8801785f105a6a8574bd2fe",
        "9bf305848e525330bc2d24f0257e47a4950f433a9233e8cdeba81dbae7d8c1a06d01f70de6ef663207d84952827bab3d",
        "451cbea0990007fbdb4240fe899a706f7c1563e05c70be9d575189ef83e0cf76195f6652491cce04f1ce2092170a92e0",
        "dd7301246a4c44fc0b4ee6aaa63fc7027840abd2ec25f654589738cd38b9e10b975cfb6c1d2eb4da97736998f84fdddd",
        "810d72da3c5ab13507420ddbfaa4f7750c1fae9c7dfb30f40a12aea689fc78da900020e3abb32a364d5c6b3c7544a1b5",
        "734a41e95c8314b448cd0b738d829af772a8f81c51adba2d85f326c8f5d6961cf12d44a9bedea00d1df5b48f429b1ce0",
        "c15ea5f5bc10b017247ba2c6be922b0563b8e9698677cb6c45ccf2081bf84219d2904c11ff92199f8aefad62d8608e20",
        "0802c5a07202cc820e9e520e31bf36a83002eca4018b0b3a398801562aa86c77ab0d50a8fbc3768b0a643b97e7f90721",
        "68de29b8175999c9aa48d301a3f0303172e9c7d4f16329d5ca9d42397c3982e10c9da42de88bd6c2ab91c1e71e778e58",
        "bb8f801f207a88a9b47f9c687afbba34eda6d2899e4fa0008aa2b539711753dc7c07f614e814f683d6c037562ae1fbbe",
        "6d7d5fa54b7a6d9451e11b01aaccc3bf2ed64742dd100e0eab2df6cccf937b6d5981eca0e01f3245cf26a72ad1adf066",
        "c8f5430d72f509963a657d85e554c14e26e8bec5d5f3ab998c9b29f16b04747d80749b30e51fd2a7f690c22f9986aaf6",
        "358d6fab8ded54971b32641de2b258590eeaa6bf1f32324a7c4c983f49466d86"
    );

    // KAT_DECAPS_K: 32 bytes, kat_kem.dat line 6084
    const KAT_DECAPS_K: &str = "3d23b10df232a180786f61261e85278251746580bebca6acbad60aef6952be69";

    #[test]
    fn test_mlkem_768_keygen_kat() {
        let mut seed = hex::decode(KAT_KEYGEN_D).unwrap();
        seed.extend_from_slice(&hex::decode(KAT_KEYGEN_Z).unwrap());
        assert_eq!(seed.len(), MlKemParams::PRIVATE_SEED_LEN);

        let key = MlKemKey::from_private_seed(MlKemParams::MlKem768, &seed).unwrap();

        assert_eq!(
            hex::encode(key.export_encapsulation_key().unwrap()),
            KAT_KEYGEN_EK
        );
        assert_eq!(
            hex::encode(key.export_decapsulation_key().unwrap()),
            KAT_KEYGEN_DK
        );
        assert_eq!(
            hex::encode(key.export_private_seed().unwrap()),
            hex::encode(&seed)
        );
    }

    #[test]
    fn test_mlkem_768_decaps_kat() {
        let key = MlKemKey::from_decapsulation_key(
            MlKemParams::MlKem768,
            &hex::decode(KAT_DECAPS_DK).unwrap(),
        )
        .unwrap();

        let shared_secret = key
            .decapsulate(&hex::decode(KAT_DECAPS_C).unwrap())
            .unwrap();

        assert_eq!(hex::encode(shared_secret.as_bytes()), KAT_DECAPS_K);
    }

    #[test]
    fn test_mlkem_key_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MlKemKey>();
    }
}
