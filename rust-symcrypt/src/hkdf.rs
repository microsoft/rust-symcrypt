/// Code for HKDF functions, for more information please refer to symcrypt.h
/// 
/// 
/// 
/// 
use crate::errors::SymCryptError;
use symcrypt_sys;
use crate::hmac::HmacAlgorithm;


//SymCryptHmacSha1Algorithm, SymCryptHmacSha256Algorithm, or SymCryptHmacSha384Algorithm

pub fn hkdf(hmac_algorithm: HmacAlgorithm, key_material: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>, SymCryptError> {

    let mut hmac_res = vec![0u8; 42 as usize];

    unsafe {
        // UNSAFE: FFI calls
        match symcrypt_sys::SymCryptHkdf(
            hmac_algorithm.to_symcrypt_hmac_algorithm(),
            key_material.as_ptr(),
            key_material.len() as symcrypt_sys::SIZE_T,
            salt.as_ptr(),
            salt.len() as symcrypt_sys::SIZE_T,
            info.as_ptr(),
            info.len() as symcrypt_sys::SIZE_T,
            hmac_res.as_mut_ptr(),
            hmac_res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(hmac_res),
            err => return Err(SymCryptError::from(err)),
        }
    }
}

#[cfg(test)]
mod test { 
    use super::*;
    use hex;

    #[test]
    fn test_hkdf() {
        let key_material = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hmac_algorithm = HmacAlgorithm::HmacSha256;
    
        let expected = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        //let expected = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let res = hkdf(hmac_algorithm, &key_material, &salt, &info).unwrap();
        assert_eq!(res.len(), 42);
        assert_eq!(expected, hex::encode(res));
    }
}




// IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
// salt = 000102030405060708090a0b0c
// info = f0f1f2f3f4f5f6f7f8f9
// L    = 42
// PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
// OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865

// # IKM:  Input key material used as the HMAC message for the HKDF-Extract
// # salt: Salt value used as the HMAC key for the HKDF-Extract
// # info: Info values use as part of the HMAC message in the HKDF-Expand
// # L:    Output size in bytes (size of OKM)
// # PRK:  Pseudorandom key which is the output of HKDF-Extract
// # OKM:  Output key material; output of HKDF-Expand
// #
// # Note: L and PRK are not used in SymCrypt functional tests since L
// #       can be calculated from the OKM string and PRK is an intermediate
// #       result inside the HKDF expanded key.