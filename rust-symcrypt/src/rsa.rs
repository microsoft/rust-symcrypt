/// !REVIEW: I've tried to closely follow SymCrypts API calls and semantics making some simplifications, but I think we have a chance to simplify further if we choose to.
/// My questions / Suggestions:
/// 1. We've introduced the idea of the RsaKeyPair / RsaPublicKey state, which can hold a lot of data, and makes a lot of the calls to the underlying SymCrypt code redundant. most of the accessors no longer
/// needed to call SymCrypt since the same data is stored on the state or is assumed
/// 2. to keep this thread safe, I've combined the alloc / generate and alloc / set pattern to just one function
/// 3. This code is pretty raw, and would not be very usable, the idea would be to write a crate on top of this one, called something like symcrypt_rsa_parse, which will be a friendlier
/// interface on top of the RSA code we have right now it would have convenience functions like rsa_from_pkcs8, rsa_from_der, rsa_from_asn1 etc. ( this could be part of the intern project as well.)
/// 4. with how many steps / options there is for generating a key, we can maybe do a builder pattern, this would be similar to how it is on NCrypt / BCrypt where they have
/// RsaKey functions and the RsaKey.finalize() at the end.
/// ex:
///         builder = RsaKeyBuilder::new()
///             .key_mode(RsaKeyMode::KeyPair)
///             .key_usage(RsaKeyUsage::Sign)
///             .generate_key()
/// My thought is to leave it how it is right now as there are not that many parameters that we need to specify, but thought I would point out the pattern.
///
/// 5.
// !REVIEW: instead of using in/out buffers for the get functions, we can use Vec<> which will be slower but more robust, and will not require the user to know the len of the fields,
//  Or we could instead return a struct with the info
//       pub struct KeyReturnValue {
//          key_mode : RsaKeyMode,
//          modulus: u64,
//          p: &[u8],
//          q: &[u8],
//              ...
//        }

///
// Rsa functions. For further documentation please refer to symcrypt.h
// TODO rest of the documentation
use crate::errors::SymCryptError;
use crate::NumberFormat;
use std::ptr;

/// 2^16 + 1
const DEFAULT_PUBLIC_EXPONENT: u64 = 0x10001;

/// Rsa Public and Private Key State.
///
/// [`RsaKeyPair`] stores a private and public Rsa key.
pub struct RsaKeyPair {
    inner: symcrypt_sys::PSYMCRYPT_RSAKEY,
    key_usage: RsaKeyUsage,
}

/// Rsa Public Key State
///
/// [`RsaPublicKey`] stores an Rsa public key.
pub struct RsaPublicKey {
    inner: symcrypt_sys::PSYMCRYPT_RSAKEY,
    key_usage: RsaKeyUsage,
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// `RsaKeyUsage` will indicate if the [`RsaKeyPair`] or [`RsaPublicKey`] will be used for [`RsaKeyUsage::Sign`] or [`RsaKeyUsage::Encrypt`].
/// 
/// [`RsaKeyUsage::Encrypt`] will have both [`RsaKeyUsage::Sign`] and [`RsaKeyUsage::Encrypt`] flags set.
pub enum RsaKeyUsage {
    Sign,
    Encrypt,
}

// !Review: Should we add the no fips / minimal validation flags? The whole purpose is to eventually get to fips, adding these extra flags might not be needed?
// #define SYMCRYPT_FLAG_KEY_NO_FIPS               (0x100)
// #define SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION    (0x200)
// #define SYMCRYPT_FLAG_RSAKEY_SIGN       (0x1000) 
// #define SYMCRYPT_FLAG_RSAKEY_ENCRYPT    (0x2000)
impl RsaKeyUsage {
    pub fn to_flag(&self) -> symcrypt_sys::UINT32 {
        match self {
            RsaKeyUsage::Sign => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN,
            RsaKeyUsage::Encrypt => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT | symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN ,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RsaKeyPairBlob {
    modulus: Vec<u8>,
    pub_exp: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    d_p: Vec<u8>,
    d_q: Vec<u8>,
    crt_coefficient: Vec<u8>,
    private_exp: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RsaPublicKeyBlob {
    modulus: Vec<u8>,
    pub_exp: Vec<u8>,
}

impl RsaKeyPair {
    /// `generate_new()` generates a random Rsa key based on the provided parameters.
    ///
    /// `n_bits_mod` represents the desired bit length of the Rsa Key.
    ///
    /// `pub_exp` takes in an `Option<u64>` that is the public exponent. If `None` is provided, the default `2^16 +1` will be used.
    ///  
    /// `key_usage` will indicate if this key will be used for [`RsaKeyUsage::Sign`] or [`RsaKeyUsage::Encrypt`]
    pub fn generate_new(
        n_bits_mod: u32,
        pub_exp: Option<&[u8]>,
        key_usage: RsaKeyUsage,
    ) -> Result<Self, SymCryptError> {
        let rsa_key = allocate_rsa(2, n_bits_mod)?; // !Review: @Phil has mentioned that there is no scenario that we'd want to ONLY generate a public key, @Crypto folks is this the case?
        let u64_pub_exp = match pub_exp {
            Some(exp) => load_msb_first_u64(exp)?,
            None => DEFAULT_PUBLIC_EXPONENT, // If no public exponent is provided, use the default ( 2^16 + 1 )
        };
        unsafe {
            // SAFETY: FFI calls
            // No flags specified for SymCryptRsakeyAllocate
            match symcrypt_sys::SymCryptRsakeyGenerate(
                rsa_key,
                [u64_pub_exp].as_ptr(), // This array has a length of 1.
                1,
                key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaKeyPair {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `set_key_pair()` sets both the public and private key information onto [`RsaKeyPair`].
    ///
    /// `modulus_buffer` takes in a reference to a byte array that contains the modulus of the Rsa key.
    ///
    /// `pub_exp` takes in a `&[u8]` that is the public exponent represented by an array of bytes.
    ///
    /// `p` takes in reference to a byte array that contains the first prime.
    ///
    /// `q` takes in reference to a byte array that contains the second prime.
    pub fn set_key_pair(
        modulus_buffer: &[u8],
        pub_exp: &[u8],
        p: &[u8],
        q: &[u8],
        key_usage: RsaKeyUsage,
    ) -> Result<Self, SymCryptError> {
        let n_bits_mod = modulus_buffer.len() as u32;
        let rsa_key = allocate_rsa(2, n_bits_mod * 8)?;
        let u64_pub_exp = load_msb_first_u64(pub_exp)?;

        // Construct the primes_ptr and primes_len_ptr for SymCryptRsakeyValue consumption
        let primes_ptr = [p.as_ptr(), q.as_ptr()].as_mut_ptr();
        let primes_len_ptr = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ]
        .as_mut_ptr();
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [u64_pub_exp].as_ptr(), // This array has a length of 1.
                1 as symcrypt_sys::UINT32,
                primes_ptr,
                primes_len_ptr,
                2 as symcrypt_sys::UINT32,
                NumberFormat::MSB.to_num_format(),
                key_usage.to_flag(),
                rsa_key,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaKeyPair {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `size_of_primes()` returns a tuple containing the sizes, in bytes, of byte arrays large enough to store each of the two primes of the RSA key.
    pub fn size_of_primes(&self) -> (u32, u32) {
        unsafe {
            // SAFETY: FFI calls
            // Currently, only two prime RSA is supported, i.e. the only valid indexes are 0 and 1
            let prime_1 = symcrypt_sys::SymCryptRsakeySizeofPrime(self.inner, 0);
            let prime_2 = symcrypt_sys::SymCryptRsakeySizeofPrime(self.inner, 1);
            (prime_1, prime_2)
        }
    }

    /// `export_key_pair_blob()` returns a [`RsaKeyPairBlob`] value.
    pub fn export_key_pair_blob(&self) -> Result<RsaKeyPairBlob, SymCryptError> {
        // Get size of primes only once
        let (size_p, size_q) = self.size_of_primes();

        // Allocate buffers for filling RsaKeyPairBlob
        let mut modulus_buffer = vec![0u8; self.size_of_modulus() as usize];
        let mut pub_exp = vec![0u64; 1];
        let mut p = vec![0u8; size_p as usize];
        let mut q = vec![0u8; size_q as usize];

        let mut d_p = vec![0u8; size_p as usize];
        let mut d_q = vec![0u8; size_q as usize];

        let mut crt_coefficient = vec![0u8; size_p as usize];
        let mut private_exponent = vec![0u8; self.size_of_modulus() as usize];

        let mut primes_len = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ];
        let mut crt_lens = [
            d_p.len() as symcrypt_sys::SIZE_T,
            d_q.len() as symcrypt_sys::SIZE_T,
        ];

        unsafe {
            // SAFETY: FFI calls
            let result = symcrypt_sys::SymCryptRsakeyGetValue(
                self.inner,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                1 as symcrypt_sys::UINT32,
                [p.as_mut_ptr(), q.as_mut_ptr()].as_mut_ptr(),
                primes_len.as_mut_ptr(),
                2 as symcrypt_sys::UINT32,
                NumberFormat::MSB.to_num_format(),
                self.key_usage.to_flag(),
            );
            if result != symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                return Err(result.into());
            }

            let result = symcrypt_sys::SymCryptRsakeyGetCrtValue(
                self.inner,
                [d_p.as_mut_ptr(), d_q.as_mut_ptr()].as_mut_ptr(),
                crt_lens.as_mut_ptr(),
                2,
                crt_coefficient.as_mut_ptr(),
                crt_coefficient.len() as symcrypt_sys::SIZE_T,
                private_exponent.as_mut_ptr(),
                private_exponent.len() as symcrypt_sys::SIZE_T,
                NumberFormat::MSB.to_num_format(),
                self.key_usage.to_flag(),
            );
            if result != symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
                return Err(result.into());
            }
        }

        let pub_exp_bytes = store_msb_first_u64(pub_exp[0], self.size_of_public_exponent())?;

        Ok(RsaKeyPairBlob {
            modulus: modulus_buffer,
            pub_exp: pub_exp_bytes,
            p,
            q,
            d_p,
            d_q,
            crt_coefficient,
            private_exp: private_exponent,
        })
    }

    /// `export_public_key_blob()` will export a [`RsaPublicKey`].
    pub fn export_public_key_blob(&self) -> Result<RsaPublicKeyBlob, SymCryptError> {
        let mut modulus_buffer = vec![0u8; self.size_of_modulus() as usize];
        let mut pub_exp = vec![0u64; 1];
        unsafe {
            // SAFETY: FFI calls
            // When only getting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0.
            match symcrypt_sys::SymCryptRsakeyGetValue(
                self.inner,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                1 as symcrypt_sys::UINT32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                NumberFormat::MSB.to_num_format(),
                self.key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaPublicKeyBlob {
                    modulus: modulus_buffer,
                    pub_exp: store_msb_first_u64(pub_exp[0], self.size_of_public_exponent())?,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `size_of_modulus()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the modulus of the key.
    pub fn size_of_modulus(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeySizeofModulus(self.inner)
        }
    }

    /// `size_of_public_exponent()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the public exponent of the key.
    pub fn size_of_public_exponent(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Only one public exponent is supported, so the only valid index is 0.
            symcrypt_sys::SymCryptRsakeySizeofPublicExponent(self.inner, 0)
        }
    }

    /// `key_usage` returns the intended usage for the RSA key pair.
    pub fn key_usage(&self) -> RsaKeyUsage {
        self.key_usage
    }

    /// `key_usage` returns the intended usage for the RSA key pair.
    pub(crate) fn inner(&self) -> symcrypt_sys::PSYMCRYPT_RSAKEY  {
        self.inner
    }
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeyFree(self.inner);
        }
    }
}

impl RsaPublicKey {
    /// `set_public_key()` sets only the public key information onto the [`RsaPublicKey`].
    ///
    /// `modulus_buffer` takes in a reference to a byte array that contains the modulus of the Rsa key.
    ///
    /// `pub_exp` takes in a `&[u8]` that is an array of bytes representing the public exponent.
    pub fn set_public_key(
        modulus_buffer: &[u8],
        pub_exp: &[u8], 
        key_usage: RsaKeyUsage, // !Review should we let the caller deal with this? 
    ) -> Result<Self, SymCryptError> {
        let n_bits_mod = modulus_buffer.len() as u32;
        let rsa_key = allocate_rsa(0, n_bits_mod*8)?;
        let u64_pub_exp = load_msb_first_u64(pub_exp)?;
        unsafe {
            // SAFETY: FFI calls
            // When only setting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [u64_pub_exp].as_ptr(), // This array has a length of 1.
                1 as symcrypt_sys::UINT32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                NumberFormat::MSB.to_num_format(),
                key_usage.to_flag(), // !Review: can set this sign and encrypt
                rsa_key,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(RsaPublicKey {
                    inner: rsa_key,
                    key_usage: key_usage,
                }),
                err => Err(err.into()),
            }
        }
    }

    /// `size_of_modulus()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the modulus of the key.
    pub fn size_of_modulus(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeySizeofModulus(self.inner)
        }
    }

    /// `size_of_public_exponent()` returns a `u32` representing the (tight) size in bytes of a byte array big enough to store
    /// the public exponent of the key.
    pub fn size_of_public_exponent(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Only one public exponent is supported, so the only valid index is 0.
            symcrypt_sys::SymCryptRsakeySizeofPublicExponent(self.inner, 0)
        }
    }
    /// `key_usage` returns the intended usage for the RSA public key.
    pub fn key_usage(&self) -> RsaKeyUsage {
        self.key_usage
    }

    /// `key_usage` gives crate access to the 
    pub(crate) fn inner(&self) -> symcrypt_sys::PSYMCRYPT_RSAKEY  {
        self.inner
    }
}

impl Drop for RsaPublicKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeyFree(self.inner);
        }
    }
}

/// A trait for RSA signing.
pub trait RsaSign {
    /// Signs a message using the RSA private key.
    ///
    /// # Parameters
    ///
    /// - `message`: A byte slice representing the message to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(Vec<u8>)`: A vector of bytes containing the signature.
    /// - `Err(String)`: An error message if the signing operation fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// A trait for RSA signature verification.
pub trait RsaVerify {
    /// Verifies a message signature using the RSA public key.
    ///
    /// # Parameters
    ///
    /// - `message`: A byte slice representing the original message.
    /// - `signature`: A byte slice representing the signature to be verified.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(bool)`: A boolean indicating whether the signature is valid (`true`) or not (`false`).
    /// - `Err(String)`: An error message if the verification operation fails.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, String>;
}

/// A trait for RSA encryption.
pub trait RsaEncrypt {
    /// Encrypts a plaintext message using the RSA public key.
    ///
    /// # Parameters
    ///
    /// - `plaintext`: A byte slice representing the plaintext message to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(Vec<u8>)`: A vector of bytes containing the ciphertext.
    /// - `Err(String)`: An error message if the encryption operation fails.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;
}

/// A trait for RSA decryption.
pub trait RsaDecrypt {
    /// Decrypts a ciphertext message using the RSA private key.
    ///
    /// # Parameters
    ///
    /// - `ciphertext`: A byte slice representing the ciphertext message to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(Vec<u8>)`: A vector of bytes containing the decrypted plaintext.
    /// - `Err(String)`: An error message if the decryption operation fails.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

// Utility function to reduce common RSA allocation call
fn allocate_rsa(n_primes: u32, n_bits_mod: u32) -> Result<symcrypt_sys::PSYMCRYPT_RSAKEY, SymCryptError> {
    let rsa_params = symcrypt_sys::SYMCRYPT_RSA_PARAMS {
        version: 1 as symcrypt_sys::UINT32, // No other version aside from version 1 is specified
        nBitsOfModulus: n_bits_mod as symcrypt_sys::UINT32,
        nPrimes: n_primes as symcrypt_sys::UINT32, // To generate a only a public key, 0 must be passed.
        nPubExp: 1 as symcrypt_sys::UINT32,        // Value must be 1.
    };
    unsafe {
        // SAFETY: FFI calls
        let result = symcrypt_sys::SymCryptRsakeyAllocate(&rsa_params, 0);
        if result == ptr::null_mut() {
            return Err(SymCryptError::AuthenticationFailure)
        }
        Ok(result)
    }
}

/// Utility function to store a `u64` into a new byte vector in big-endian format.
fn store_msb_first_u64(value: u64, size_of_exp: u32) -> Result<Vec<u8>, SymCryptError> {
    let mut dst = vec![0u8; size_of_exp as usize]; // Allocate tight size in bytes for storing public exponent
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptStoreMsbFirstUint64(
            value,
            dst.as_mut_ptr(),
            size_of_exp as u64,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(SymCryptError::from(err)),
        }
    }
}

/// Load a `u64` from a byte slice assuming big-endian order.
fn load_msb_first_u64(src: &[u8]) -> Result<u64, SymCryptError> {
    let mut dst = 0u64;
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptLoadMsbFirstUint64(
            src.as_ptr(),
            src.len() as u64,
            &mut dst as *mut u64,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(SymCryptError::from(err)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::NumberFormat;

    #[test]
    fn test_generate_new_default_exponent() {
        let result = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.key_usage(), RsaKeyUsage::Sign);
    }

    #[test]
    fn test_generate_get_then_set() {
        let result = RsaKeyPair::generate_new(2048, None, RsaKeyUsage::Sign);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.key_usage(), RsaKeyUsage::Sign);

        let blob = key_pair.export_key_pair_blob().unwrap();
        let new_key_pair = RsaKeyPair::set_key_pair( &blob.modulus, &blob.pub_exp, &blob.p, &blob.q, key_pair.key_usage).unwrap();
        let blob_2 = new_key_pair.export_key_pair_blob().unwrap();
        assert_eq!(blob_2.crt_coefficient, blob.crt_coefficient);
    }

    #[test]
    fn test_set_and_get_key_pair() {
        let modulus = [
            215, 145, 16, 194, 78, 246, 213, 23, 173, 178, 123, 179, 152, 238, 67, 16, 25, 20, 102,
            36, 142, 210, 5, 164, 214, 122, 56, 206, 61, 65, 121, 44, 248, 241, 176, 72, 104, 251,
            188, 59, 107, 251, 214, 238, 237, 49, 27, 224, 96, 114, 82, 54, 116, 238, 151, 56, 73,
            216, 107, 88, 226, 27, 176, 247, 180, 48, 165, 127, 156, 133, 148, 69, 67, 191, 196,
            148, 115, 123, 86, 185, 169, 42, 111, 109, 121, 21, 9, 174, 183, 126, 219, 3, 32, 83,
            183, 63, 98, 253, 243, 108, 26, 9, 75, 68, 33, 248, 71, 223, 51, 231, 153, 194, 233,
            245, 53, 86, 243, 164, 94, 123, 146, 75, 161, 99, 5, 145, 85, 165, 187, 146, 243, 196,
            181, 223, 232, 32, 247, 253, 217, 211, 170, 187, 32, 23, 177, 11, 241, 133, 141, 8, 38,
            124, 133, 88, 81, 230, 110, 200, 219, 28, 149, 77, 25, 163, 18, 75, 183, 210, 68, 0,
            126, 3, 182, 196, 126, 207, 27, 92, 144, 174, 178, 203, 200, 146, 45, 180, 202, 3, 76,
            22, 202, 37, 87, 215, 183, 83, 159, 65, 144, 9, 172, 137, 75, 17, 51, 31, 176, 6, 168,
            197, 156, 195, 253, 36, 71, 64, 125, 253, 126, 155, 169, 79, 180, 233, 157, 193, 100,
            239, 237, 129, 4, 165, 38, 112, 247, 253, 174, 21, 245, 71, 236, 229, 56, 123, 134, 45,
            17, 124, 191, 60, 163, 218, 149, 209, 207, 181,
        ];

        let p = [
            243, 178, 90, 72, 143, 170, 126, 153, 156, 252, 2, 217, 218, 162, 40, 248, 110, 231,
            75, 107, 164, 216, 9, 203, 46, 234, 147, 154, 112, 197, 201, 4, 78, 28, 113, 170, 16,
            158, 111, 112, 209, 122, 73, 27, 228, 243, 16, 3, 87, 192, 183, 117, 30, 182, 231, 141,
            133, 103, 158, 180, 108, 186, 122, 14, 106, 15, 191, 28, 14, 239, 230, 122, 7, 121, 35,
            193, 127, 144, 25, 74, 185, 137, 60, 61, 181, 24, 55, 189, 45, 182, 96, 75, 53, 72,
            110, 249, 43, 175, 22, 130, 120, 144, 208, 121, 160, 92, 4, 86, 232, 74, 190, 228, 69,
            250, 240, 241, 19, 86, 223, 128, 164, 229, 4, 71, 19, 228, 152, 143,
        ];
        let q = [
            226, 115, 37, 192, 38, 148, 58, 223, 39, 192, 252, 148, 226, 240, 202, 224, 60, 234,
            242, 101, 85, 118, 66, 240, 20, 255, 38, 215, 219, 83, 181, 233, 147, 234, 237, 195,
            154, 94, 117, 100, 234, 9, 79, 200, 86, 157, 206, 186, 117, 146, 221, 20, 185, 202,
            129, 156, 81, 86, 171, 16, 66, 229, 67, 158, 157, 117, 226, 203, 148, 83, 191, 41, 100,
            55, 168, 76, 170, 43, 109, 76, 137, 167, 154, 154, 84, 251, 91, 91, 60, 217, 94, 142,
            236, 33, 136, 48, 146, 122, 8, 61, 231, 185, 247, 29, 165, 191, 167, 203, 177, 219, 74,
            208, 196, 13, 208, 32, 97, 145, 242, 21, 5, 81, 101, 118, 207, 14, 205, 123,
        ];

        let pub_exp: u64 = 65537;

        let result = RsaKeyPair::set_key_pair(
            &modulus,
            &pub_exp.to_be_bytes(),
            &p,
            &q,
            RsaKeyUsage::Sign,
        );
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!(key_pair.key_usage(), RsaKeyUsage::Sign);
        assert_eq!(key_pair.size_of_primes(), (128,128));
        assert_eq!(key_pair.size_of_modulus(), 256);
        assert_eq!(key_pair.size_of_public_exponent(), 3);
        let key_blob = key_pair.export_key_pair_blob().unwrap(); 
        assert_eq!(key_blob.modulus, modulus.to_vec());
        assert_eq!(key_blob.p, p);
        assert_eq!(key_blob.q, q);
    }

    #[test]
    fn test_set_and_get_public_key() { 
        let modulus = [
            215, 145, 16, 194, 78, 246, 213, 23, 173, 178, 123, 179, 152, 238, 67, 16, 25, 20, 102,
            36, 142, 210, 5, 164, 214, 122, 56, 206, 61, 65, 121, 44, 248, 241, 176, 72, 104, 251,
            188, 59, 107, 251, 214, 238, 237, 49, 27, 224, 96, 114, 82, 54, 116, 238, 151, 56, 73,
            216, 107, 88, 226, 27, 176, 247, 180, 48, 165, 127, 156, 133, 148, 69, 67, 191, 196,
            148, 115, 123, 86, 185, 169, 42, 111, 109, 121, 21, 9, 174, 183, 126, 219, 3, 32, 83,
            183, 63, 98, 253, 243, 108, 26, 9, 75, 68, 33, 248, 71, 223, 51, 231, 153, 194, 233,
            245, 53, 86, 243, 164, 94, 123, 146, 75, 161, 99, 5, 145, 85, 165, 187, 146, 243, 196,
            181, 223, 232, 32, 247, 253, 217, 211, 170, 187, 32, 23, 177, 11, 241, 133, 141, 8, 38,
            124, 133, 88, 81, 230, 110, 200, 219, 28, 149, 77, 25, 163, 18, 75, 183, 210, 68, 0,
            126, 3, 182, 196, 126, 207, 27, 92, 144, 174, 178, 203, 200, 146, 45, 180, 202, 3, 76,
            22, 202, 37, 87, 215, 183, 83, 159, 65, 144, 9, 172, 137, 75, 17, 51, 31, 176, 6, 168,
            197, 156, 195, 253, 36, 71, 64, 125, 253, 126, 155, 169, 79, 180, 233, 157, 193, 100,
            239, 237, 129, 4, 165, 38, 112, 247, 253, 174, 21, 245, 71, 236, 229, 56, 123, 134, 45,
            17, 124, 191, 60, 163, 218, 149, 209, 207, 181,
        ];
        let pub_exp: u64 = 65537;
        let result = RsaPublicKey::set_public_key(&modulus, &pub_exp.to_be_bytes(), RsaKeyUsage::Encrypt);

        assert!(result.is_ok());
        let pub_key = result.unwrap();

        assert_eq!(pub_key.key_usage(), RsaKeyUsage::Encrypt);
        assert_eq!(pub_key.size_of_modulus(), 256);
        assert_eq!(pub_key.size_of_public_exponent(), 3);
        assert_eq!(pub_key.number_of_pub_primes(), 0);
        let pub_key_blob = pub_key.export_public_key_blob().unwrap(); 
        assert_eq!(pub_key_blob.modulus, modulus.to_vec());
    }
}
