//! Rsa functions. For further documentation please refer to symcrypt.h
//! TODO rest of the documentation 
use crate::errors::SymCryptError;
use crate::NumberFormat;
use std::fmt;
use std::{pin::Pin, ptr};

const MAX_NUMBER_OF_PUBLIC_EXPONENTS: symcrypt_sys::UINT32 = 1;
const DEFAULT_PUBLIC_EXPONENT: u64 = 65537;

/// Key State for Rsa Keys.
///
/// [`RsaKeyPair`] can store either a public key only, or a private and public key. This information will be stored on the `key_mode` field and can be accessed by [`RsaKeyPair::get_key_mode()`].
pub struct RsaKeyPair {
    inner: Pin<Box<symcrypt_sys::PSYMCRYPT_RSAKEY>>, // Pin<box<>> to not move the underlying data.
    key_mode: RsaKeyMode, // Indicates if the key will contain a private/public keypair, or only a public key.
    key_usage: RsaKeyUsage,
    num_p_exp: u32, // !REVIEW this is not needed since the public exponent will always be one
}

impl fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKey")
            .field(
                "inner",
                &format_args!("{:p}", *self.inner.as_ref().get_ref()),
            )
            .field("key_mode", &self.key_mode)
            .field("key_usage", &self.key_usage)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// `RsaKeyMode` will indicate if this [`RsaKeyPair`] has [`RsaKeyMode::PublicOnly`] key or a [`RsaKeyMode::KeyPair`].
pub enum RsaKeyMode {
    PublicOnly,
    KeyPair,
}

impl RsaKeyMode {
    fn to_u32(&self) -> symcrypt_sys::UINT32 {
        match self {
            RsaKeyMode::PublicOnly => 0 as symcrypt_sys::UINT32,
            RsaKeyMode::KeyPair => 2 as symcrypt_sys::UINT32,
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// `RsaKeyUsage` will indicate if this [`RsaKeyPair`] will be used for [`RsaKeyUsage::Sign`] or [`RsaKeyUsage::Encrypt`].
pub enum RsaKeyUsage {
    Sign,
    Encrypt,
}

// !REVIEW: Based on the discussions i've had with Phil, and Sam offline, im not sure if we want to include the minimal validation or no fips flags as the purpose of this
// code will be to eventually be fips certified. We can include if the group thinks otherwise though. 

// #define SYMCRYPT_FLAG_KEY_NO_FIPS               (0x100)
// #define SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION    (0x200)
// #define SYMCRYPT_FLAG_RSAKEY_SIGN       (0x1000)
// #define SYMCRYPT_FLAG_RSAKEY_ENCRYPT    (0x2000)
impl RsaKeyUsage {
    pub fn to_flag(&self) -> symcrypt_sys::UINT32 {
        // making public so callers can access underlying flag
        match self {
            RsaKeyUsage::Sign => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_SIGN,
            RsaKeyUsage::Encrypt => symcrypt_sys::SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        }
    }
}

pub enum PrimeIndex {
    First,
    Second,
}

impl PrimeIndex {
    pub fn to_u32(self) -> u32 {
        match self {
            PrimeIndex::First => 0,
            PrimeIndex::Second => 1,
        }
    }
}

/// !REVIEW: I've tried to closely follow SymCrypts API calls and semantics making some simplifications, but I think we have the opperuntiy to simplify further if we chose.
/// My questions / Suggestions
/// 1. We've introduced the idea of the RsaKeyPair state, which can hold a lot of data, and makes a lot of the calls to the underlying SymCrypt code redundant. most of the accessors no longer
/// need to call SymCrypt since the same data is stored on the state.
/// 2. The idea of new() then generate_key() / generate_set_public_only() / set_key_pair() is a bit convoluted IMO, we can squash these together to something like: 
/// new_random(), and  new_set_public() and new_set_key_pair().
/// 3. Many of the functions ( get, set etc ) take in a NumberFormat that has to match the other specified arguments, is this something we want to store on the state?
/// 4. Another thought is to leave as is, and write a crate on top of this one, called something like symcrypt_rsa_parse, which will be a friendlier interface on top of the RSA code we have right now
/// It would have convenience functions like rsa_from_pkcs8, rsa_from_der, rsa_from_asn1 etc. ( this could be part of the intern project as well.)
/// 5. with how many steps / options there is for generating a key, we can maybe do a builder pattern, this would be similar to how it is on NCrypt / BCrypt where they have 
/// RsaKey functions and the RsaKey.finalize() at the end.
/// ex:
///         builder = RsaKeyBuilder::new()
///             .key_mode(RsaKeyMode::KeyPair)
///             .key_usage(RsaKeyUsage::Sign)
///             .generate_key()


/// Impl for the RsaKeyPair
impl RsaKeyPair {
    /// `new()` allocates a the space needed for an `RsaKeyPair`.
    /// To fill data, you must call one of [`RsaKeyPair::generate_key()`], [`RsaKeyPair::set_public_only()`] or [`RsaKeyPair::set_key_pair()`].
    /// 
    /// `n_bits_mod` represents the desired bit length of the Rsa Key.
    /// 
    /// `key_mode` will determine if this key will be allocated for a [`RsaKeyMode::PublicOnly`] or [`RsaKeyMode::KeyPair`] 
    /// 
    /// `key_usage` will indicate if this key will be used for [`RsaKeyUsage::Sign`] or [`RsaKeyUsage::Encrypt`]
    pub fn new(n_bits_mod: u32, key_mode: RsaKeyMode, key_usage: RsaKeyUsage) -> Self {
        let rsa_params = symcrypt_sys::SYMCRYPT_RSA_PARAMS {
            version: 1 as symcrypt_sys::UINT32, // No other version aside from version 1 is specified
            nBitsOfModulus: n_bits_mod as symcrypt_sys::UINT32,
            nPrimes: key_mode.to_u32(), //  Value must be 0 or 2, if only a public key is being generated, you can pass 0 for n_primes
            nPubExp: MAX_NUMBER_OF_PUBLIC_EXPONENTS, // Per SymCrypt documentation, only 1 is allowed
        };
        unsafe {
            // SAFETY: FFI calls
            // No flags specified for SymCryptRsakeyAllocate
            let rsa_key = Box::pin(symcrypt_sys::SymCryptRsakeyAllocate(&rsa_params, 0));
            RsaKeyPair {
                inner: rsa_key,
                key_mode: key_mode,
                key_usage: key_usage,
                num_p_exp: MAX_NUMBER_OF_PUBLIC_EXPONENTS,
            }
        }
    }

    /// `generate_key()` generates a random Rsa key based on the parameters passed into [`RsaKeyPair::new()`].
    /// 
    /// `generate_key()` can only be called after space for the key has been allocated through [`RsaKeyPair::new()`].
    /// 
    /// `pub_exp` takes in an `Option<u64>` that is the public exponent. If `None` is provided, the default `2^16 +1` will be used.
    pub fn generate_key(&mut self, pub_exp: Option<u64>) -> Result<(), SymCryptError> {
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsakeyGenerate(
                *self.inner,
                [pub_exp.unwrap_or(DEFAULT_PUBLIC_EXPONENT)].as_ptr(), // if no public exponent is provided, use the default ( 2^16 + 1 )
                self.num_p_exp,
                self.key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `set_public_only()` sets only the public key information onto the [`RsaKeyPair`]. 
    /// 
    /// `modulus_buffer` takes in a reference to a byte array that contains the modulus of the Rsa key.
    /// 
    /// `pub_exp` takes in a `u64` that is the public exponent.
    /// 
    /// `num_format` takes in a [`NumberFormat`] that specifies either [`NumberFormat::LSB`] or [`NumberFormat::MSB`] which must match ALL inputs.
    pub fn set_public_only(
        &mut self,
        modulus_buffer: &[u8],
        pub_exp: u64,
        num_format: NumberFormat,
    ) -> Result<(), SymCryptError> {
        unsafe {
            // SAFETY: FFI calls
            // When only setting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [pub_exp].as_ptr(),
                self.num_p_exp,
                ptr::null_mut(), 
                ptr::null_mut(),
                0,
                num_format.to_num_format(),
                self.key_usage.to_flag(),
                *self.inner,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `set_key_pair()` sets both the public and private key information onto [`RsaKeyPair`].
    /// 
    /// `modulus_buffer` takes in a reference to a byte array that contains the modulus of the Rsa key.
    /// 
    /// `pub_exp` takes in a `u64` that is the public exponent.
    /// 
    /// `p` takes in reference to a byte array that contains the first prime.
    /// 
    /// `q` takes in reference to a byte array that contains the second prime.
    /// 
    /// `num_format` takes in a [`NumberFormat`] that specifies either [`NumberFormat::LSB`] or [`NumberFormat::MSB`] which must match ALL inputs.
    pub fn set_key_pair(
        &mut self,
        modulus_buffer: &[u8],
        pub_exp: u64,         
        p: &[u8],              
        q: &[u8],            
        num_format: NumberFormat, 
    ) -> Result<(), SymCryptError> {

        // Construct the primes_ptr and primes_len_ptr for SymCryptRsakeyValue consumption
        let primes_ptr = [p.as_ptr(), q.as_ptr()].as_mut_ptr();
        let primes_len_ptr = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ]
        .as_mut_ptr();

        unsafe {
            // SAFETY: FFI calls
            // nPrimes must be 2, since this is a key pair.
            match symcrypt_sys::SymCryptRsakeySetValue(
                modulus_buffer.as_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                [pub_exp].as_ptr(),
                self.num_p_exp,
                primes_ptr,
                primes_len_ptr,            
                2 as symcrypt_sys::UINT32,
                num_format.to_num_format(),
                self.key_usage.to_flag(),
                *self.inner,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `has_private_key()` returns a `bool` indicating if there is a private key associated with the [`RsaKeyPair`].
    pub fn has_private_key(&self) -> bool {
        return self.key_mode == RsaKeyMode::KeyPair
        // ! REVIEW: can call 
        // SymCryptRsakeyHasPrivateKey(*self.inner) != 0 
        // There is no direct translation from BOOLEAN from C -> bool on Rust, we already have the state, we can save a call to SymCrypt
    }

    /// `size_of_modulus()` returns a `u32` indicating the size of the modulus on the [`RsaKeyPair`].
    pub fn size_of_modulus(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeySizeofModulus(*self.inner)
        }
    }

    /// `size_of_public_exponent()` returns a `u32` represents the size of the public exponent associated with the [`RsaKeyPair`].
    pub fn size_of_public_exponent(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Only one public exponent is supported, so the only valid index is 0.
            symcrypt_sys::SymCryptRsakeySizeofPublicExponent(*self.inner, 0)
        }
    }

    /// `size_of_prime()` returns the size in bytes of a byte array large enough to store the selected prime of the key.
    ///
    /// `index` takes in a [`PrimeIndex`] which represents either the [`PrimeIndex::First`] or [`PrimeIndex::Second`] index for the primes.   
    pub fn size_of_prime(&self, index: PrimeIndex) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            // Currently, only two prime RSA is supported, i.e. the only valid indexes are 0 and 1
            symcrypt_sys::SymCryptRsakeySizeofPrime(*self.inner, index.to_u32())
        }
    }

    /// `number_of_pub_exponents()` returns the number of public exponents associated with the [`RsaKeyPair`].
    pub fn number_of_pub_exponents(&self) -> u32 {

        // The only supported number of public exponents is 1
        MAX_NUMBER_OF_PUBLIC_EXPONENTS 

        // !REVIEW: from all documentation that I can see the number of public exponents can only be 1, and 0 is used to trigger a default option.
        // do we want to include this accessor? Instead of hard coding, we can call SymCryptRsakeyGetNumberOfPublicExponents, but it seems like a waste of a call to SymCrypt.
        // can we remove this entirely? based on offline convo, the number of exponents should always be 1
    }

    /// `number_of_pub_primes()` returns a `u32` representing the number of primes associated with the [`RsaKeyPair`]
    pub fn number_of_pub_primes(&self) -> u32 {
        self.key_mode.to_u32()
        // !REVIEW: Can call SymCryptRsakeyGetNumberOfPrimes() instead, but it's a wasteful call since we store the number on the state.
    }


    // !REVIEW: instead of using in/out buffers for the get functions, we can use Vec<> which will be slower but more robust, and will not require the user to know the len of the fields,
    //  Or we could instead return a struct with the info
//       pub struct KeyReturnValue {
//          key_mode : RsaKeyMode,
//          modulus: u64,
//          p: &[u8],
//          q: &[u8],
//        }
    


    /// `get_key_pair_value()` will take in and modify buffers for a [`RsaKeyPair`] that has a private and public key associated. 
    /// 
    /// `modulus_buffer` is a mutable buffer to a byte array that will be filled with the modulus of the Rsa key.
    /// 
    /// `pub_exp` is a mutable buffer to an array that will be filled with the public exponent of the Rsa key.
    /// 
    /// `p` is a mutable buffer to a byte array that will be filled with the first prime of the Rsa key.
    /// 
    /// `q` is a mutable buffer to a byte array that will be filled with the second prime of the Rsa key.
    /// 
    /// `num_format` takes in a [`NumberFormat`] that specifies either [`NumberFormat::LSB`] or [`NumberFormat::MSB`] which must match ALL inputs.
    pub fn get_key_pair_value(
        &mut self,
        modulus_buffer: &mut [u8],
        pub_exp: &mut [u64],
        p: &mut [u8],
        q: &mut [u8],
        num_format: NumberFormat,
    ) -> Result<(), SymCryptError> {
        let primes_prt = [p.as_mut_ptr(), q.as_mut_ptr()].as_mut_ptr();
        let primes_len = [
            p.len() as symcrypt_sys::SIZE_T,
            q.len() as symcrypt_sys::SIZE_T,
        ]
        .as_mut_ptr();
        unsafe {
            // SAFETY: FFI calls
            // nPrimes must be 2, since this is a key pair.
            match symcrypt_sys::SymCryptRsakeyGetValue(
                *self.inner,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                self.num_p_exp,
                primes_prt,
                primes_len,     
                2 as symcrypt_sys::UINT32, 
                num_format.to_num_format(),
                self.key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `get_public_key_value()` will take in and modify buffers for a [`RsaKeyPair`] that has only a public key assoicated
    /// 
    /// `modulus_buffer` is a mutable buffer to a byte array that will be filled with the modulus of the Rsa key
    /// 
    /// `pub_exp` is a mutable buffer to an array that will be filled with the public exponent of the Rsa key
    /// 
    /// `num_format` takes in a [`NumberFormat`] that specifies either [`NumberFormat::LSB`] or [`NumberFormat::MSB`] which must match ALL inputs.
    pub fn get_public_key_value(
        &mut self,
        modulus_buffer: &mut [u8],
        pub_exp: &mut [u64],
        num_format: NumberFormat,
    ) -> Result<(), SymCryptError> {
        unsafe {
            // SAFETY: FFI calls
            // When only getting the public key, ppPrimes, pcbPrimes and nPrimes can be NULL, NULL and 0.
            match symcrypt_sys::SymCryptRsakeyGetValue(
                *self.inner,
                modulus_buffer.as_mut_ptr(),
                modulus_buffer.len() as symcrypt_sys::SIZE_T,
                pub_exp.as_mut_ptr(),
                self.num_p_exp,
                ptr::null_mut(),
                ptr::null_mut(),
                0, 
                num_format.to_num_format(),
                self.key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `get_crt_value()` returns the crt values of the Crt key material from a [`RsaKeyPair`].
    /// 
    /// `crt` is a mutable slice of mutable slices, where each inner slice will be filled with a Crt exponent.
    ///  
    /// `crt_coefficent` is a mutable slice that will be filled with the Crt coefficient (`q^-1 mod p`).
    /// 
    /// `private_exponent` is a mutable slice that will be filled with the private exponent (`d`).
    /// 
    pub fn get_crt_value(
        &mut self,
        crt: &mut [&mut [u8]],
        crt_coefficent: &mut [u8],
        private_exponent: &mut [u8],
        num_format: NumberFormat,
    ) -> Result<(), SymCryptError> {
        let mut crt_pointers: Vec<*mut u8> = Vec::with_capacity(crt.len());
        let mut pcb_crt: Vec<symcrypt_sys::SIZE_T> = Vec::with_capacity(crt.len());

        for c in crt.iter_mut() {
            crt_pointers.push(c.as_mut_ptr()); // Collect mutable pointers
            pcb_crt.push(c.len() as symcrypt_sys::SIZE_T); // Collect lengths
        }

        let crt_pointers_prt = crt_pointers.as_mut_ptr();
        let pcb_crt_ptr = pcb_crt.as_mut_ptr();

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptRsakeyGetCrtValue(
                *self.inner,
                crt_pointers_prt,
                pcb_crt_ptr,
                crt.len().try_into().unwrap(),
                crt_coefficent.as_mut_ptr(),
                crt_coefficent.len() as symcrypt_sys::SIZE_T,
                private_exponent.as_mut_ptr(),
                private_exponent.len() as symcrypt_sys::SIZE_T,
                num_format.to_num_format(),
                self.key_usage.to_flag(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }

    /// `get_key_mode()` returns the [`RsaKeyMode`] associated with the [`RsaKeyPair`]
    pub fn get_key_mode(&self) -> RsaKeyMode {
        self.key_mode
    }

    /// `get_key_usage()` returns the [`RsaKeyUsage`] associated with the [`RsaKeyPair`]
    pub fn get_key_usage(&self) -> RsaKeyUsage {
        self.key_usage
    }
    
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptRsakeyFree(*self.inner);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rsa_key_generate_new_key_pass() {
        let mut my_key = RsaKeyPair::new(2048, RsaKeyMode::PublicOnly, RsaKeyUsage::Sign);
        let res = my_key.generate_key_in_place(&[65537]);
    }

    #[test]
    fn test_rsa_key_generate_new_key_fail() {
        let mut my_key = RsaKeyPair::new(2048, RsaKeyMode::PublicOnly, RsaKeyUsage::Sign);
        let res = my_key.generate_key_in_place(&[3]);
        assert!(res.is_err());
    }

    #[test]
    fn test_rsa_key_get_methods() {
        let mut my_key = RsaKeyPair::new(2048, RsaKeyMode::PublicOnly, RsaKeyUsage::Sign);
        let res = my_key.generate_key_in_place(&[65537]);

        assert_eq!(RsaKeyMode::PublicOnly, my_key.get_key_mode());
        assert_eq!(RsaKeyUsage::Sign, my_key.get_key_usage());
        assert!(!my_key.has_private_key()); // Assert only public key
        assert_eq!(my_key.number_of_pub_primes(), 1);
        assert!(my_key.size_of_public_exponent(), 1)
    }
}
