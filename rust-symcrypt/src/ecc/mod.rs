//! Friendly rust types for CurveTypes. please see symcrypt.h for more info
//!
//! The [`CurveType`] enum provides an enumeration of supported curves that can be used in
//! elliptical curve operations. Currently the only supported curves are `NistP256`, `NistP384` and `Curve25519`
use crate::NumberFormat;
use crate::{errors::SymCryptError, symcrypt_init};
use lazy_static::lazy_static;
use std::ptr;

pub mod ecdsa;
pub mod ecdh;


/// review:   X25519 has one X component, NIST curves have X and Y components How do we ensure that we're doing the right sizes etc.
/// 
/// for EcDsa Symcrypt has a flag for "NO TRUNCATE" // Allowed flags:
//      SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION: If set then the hash value will
//      not be truncated.
/// do we want to enforce this? 
/// SymCrypt signature size is = privatekeysize*2 ? 
/// 
/// SYMCRYPT_FIPS_ASSERT will assert if the key usage is incorrect in SymCryptEcDsaSignEx which causes an AV. 
/// I've done a check in the rust code to return an error if the key usage is incorrect. Panic for something like this is not rust-like
/// 
/// 




/// [`CurveType`] provides an enum of the curve types that can be used when creating a key(s)
/// via `ecdh::EcDh::new()`. The current curve types supported is `NistP256`, `NistP384`, and `Curve25519`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum CurveType {
    NistP256,
    NistP384,
    Curve25519,
}


// EcKey is a wrapper around symcrypt_sys::PSYMCRYPT_ECKEY.
#[derive(Debug)]
pub(crate) struct InnerEcKey (symcrypt_sys::PSYMCRYPT_ECKEY);

unsafe impl Send for EcKey {
    // TODO: Discuss send/sync for rustls
}

unsafe impl Sync for EcKey {
    // TODO: Discuss send/sync for rustls
}

// Must drop the EcKey before the expanded EcCurve is dropped
// EcCurve has static lifetime so this will always be the case.
// No drop needed on InnerEcKey, drop is handled by EcKey::Drop();
impl Drop for EcKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEckeyFree(self.inner_key());
        }
    }
}

// InnerEcCurve is a wrapper around symcrypt_sys::PSYMCRYPT_ECURVE.
pub(crate) struct InnerEcCurve(pub(crate) symcrypt_sys::PSYMCRYPT_ECURVE);

unsafe impl Send for InnerEcCurve {
    // TODO: Discuss send/sync for rustls
}

unsafe impl Sync for InnerEcCurve {
    // TODO: Discuss send/sync for rustls
}

// Must drop EcCurve after EcKey is dropped, will always be the case since EcCurve is static.
impl Drop for InnerEcCurve {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEcurveFree(self.0)
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EcKeyUsage {
    EcDsa,

    EcDh,

    EcDhAndEcDsa,
}

impl EcKeyUsage {
    pub(crate) fn to_symcrypt_flag(&self) -> u32 {
        match self {
            EcKeyUsage::EcDsa => symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDSA,
            EcKeyUsage::EcDh => symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
            EcKeyUsage::EcDhAndEcDsa =>  { symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDSA | symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH },
        }
    }
}

#[derive(Debug)]
pub struct EcKey {
    inner_key: InnerEcKey,
    curve_type: CurveType,
    ec_key_usage: EcKeyUsage,
    has_private_key: bool
}

// EcKey is a generic key that can be used for elliptical curve operations.
impl EcKey {
    // new returns a new EcKey object that has the key and curve allocated.
    pub fn generate_key_pair(curve_type: CurveType, ec_key_usage: EcKeyUsage) -> Result<Self, SymCryptError> {
        let ec_curve = InnerEcCurve::new(curve_type); // Can fail here due to insufficient memory.
        unsafe {
            // SAFETY: FFI calls
            // Stack allocated since we will do SymCryptEckeyAllocate.
            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(ec_curve.0);
            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            match symcrypt_sys::SymCryptEckeySetRandom(
                ec_key_usage.to_symcrypt_flag(),
                key_ptr
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let key = EcKey {
                        inner_key: InnerEcKey(key_ptr),
                        curve_type: curve_type,
                        ec_key_usage,
                        has_private_key: true
                    };
                    Ok(key)
                }
                err => Err(err.into()),
            }
        }
    }

    pub fn set_key_pair(curve_type: CurveType, private_key: &[u8], public_key: Option<&[u8]>, ec_key_usage: EcKeyUsage) -> Result<Self, SymCryptError> {
        let ec_curve = InnerEcCurve::new(curve_type); // Can fail here due to insufficient memory.

        unsafe{ 
            //SAFETY: FFI calls
            // Stack allocated since we will do SymCryptEckeyAllocate.

            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(ec_curve.0);

            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            let (public_key_ptr, public_key_count) = match public_key {
                Some(key) => (key.as_ptr(), key.len() as symcrypt_sys::SIZE_T),
                None => (ptr::null(), 0),
            };

            match symcrypt_sys::SymCryptEckeySetValue(
                private_key.as_ptr(),
                private_key.len() as symcrypt_sys::SIZE_T,
                public_key_ptr,
                public_key_count,
                curve_to_num_format(curve_type),
                curve_to_ec_point_format(curve_type),
                ec_key_usage.to_symcrypt_flag(),
                key_ptr
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let key = EcKey {
                        inner_key: InnerEcKey(key_ptr),
                        curve_type: curve_type,
                        ec_key_usage,
                        has_private_key: true
                    };
                    Ok(key)
                }
                err => Err(err.into()),
            }
        }
    }

    pub fn set_public_key(curve_type: CurveType, public_key: &[u8], ec_key_usage: EcKeyUsage) -> Result<Self, SymCryptError> {
        let ec_curve = InnerEcCurve::new(curve_type); // Can fail here due to insufficient memory.
        unsafe {
            // SAFETY: FFI calls
            // Stack allocated since we will do SymCryptEckeyAllocate.

            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(ec_curve.0);
            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            match symcrypt_sys::SymCryptEckeySetValue(
                std::ptr::null(), // private key set to null since none is generated
                0,
                public_key.as_ptr(), // only a public key is attached
                public_key.len() as symcrypt_sys::SIZE_T,
                curve_to_num_format(curve_type),
                curve_to_ec_point_format(curve_type),
                ec_key_usage.to_symcrypt_flag(),
                key_ptr,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let key = EcKey {
                        inner_key: InnerEcKey(key_ptr),
                        curve_type: curve_type,
                        ec_key_usage,
                        has_private_key: false
                    };
                    Ok(key)
                }
                err => Err(err.into()),
            }
        }
    }

    pub fn export_public_key(&self) -> Result<Vec<u8>, SymCryptError> {
        let num_format = curve_to_num_format(self.get_curve_type());
        let ec_point_format = curve_to_ec_point_format(self.get_curve_type());

        unsafe {
            // SAFETY: FFI calls
            let pub_key_len =
                symcrypt_sys::SymCryptEckeySizeofPublicKey(self.inner_key(), ec_point_format);

            let mut pub_key_bytes = vec![0u8; pub_key_len as usize];
            match symcrypt_sys::SymCryptEckeyGetValue(
                self.inner_key(),
                std::ptr::null_mut(), // setting private key to null since we will only access public key
                0 as symcrypt_sys::SIZE_T,
                pub_key_bytes.as_mut_ptr(),
                pub_key_len as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                0, // No flags allowed
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(pub_key_bytes),
                err => Err(err.into()),
            }
        }
    }

    // Accessor to the inner key field.
    // Reference is not needed here since we are working with a raw SymCrypt pointer.
    pub(crate) fn inner_key(&self) -> symcrypt_sys::PSYMCRYPT_ECKEY {
        self.inner_key.0
    }

    // Accessor to the inner curve
    // Reference is used here since EcKey should still maintain ownership of the EcCurve.
    pub fn get_curve_type(&self) -> CurveType {
        self.curve_type
    }

    pub fn get_ec_curve_usage(&self) -> EcKeyUsage {
        self.ec_key_usage
    }

    pub fn has_private_key(&self) -> bool {
        self.has_private_key
    }

    pub fn get_curve_size(&self) -> u32 {
        unsafe {
            let ec_curve = InnerEcCurve::new(self.get_curve_type());
            let curve_size = symcrypt_sys::SymCryptEcurveSizeofFieldElement(ec_curve.0);
            curve_size
        }
    }

    pub fn get_size_of_private_key(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEckeySizeofPrivateKey(self.inner_key())
        }
    }

    pub fn get_size_of_public_key(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEckeySizeofPublicKey(self.inner_key(), curve_to_ec_point_format(self.get_curve_type()))
        }
    }
}

// Curves can be re-used across EcKey calls, creating static references to save on allocations and increase perf.
// unwraps used here since only way this could fail is via not enough memory.
lazy_static! {
    static ref NIST_P256: InnerEcCurve = internal_new(CurveType::NistP256).unwrap();
    static ref NIST_P384: InnerEcCurve = internal_new(CurveType::NistP384).unwrap();
    static ref CURVE_25519: InnerEcCurve = internal_new(CurveType::Curve25519).unwrap();
}

// SymCryptInit must be called before any EcDh operations are performed.
fn internal_new(curve: CurveType) -> Result<InnerEcCurve, SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        // Will only init once, subsequent calls to symcrypt_init() will be no-ops.
        // Calling here incase user did not call symcrypt_init() earlier on.
        symcrypt_init();

        // Stack allocated since SymCryptEcCurveAllocate is called.
        let curve_ptr = symcrypt_sys::SymCryptEcurveAllocate(to_symcrypt_curve(curve), 0);
        if curve_ptr.is_null() {
            return Err(SymCryptError::MemoryAllocationFailure);
        }
        // Curve needs to be wrapped to properly free the curve in the case there is an error in future initialization in EcDsa or EcDh.
        Ok(InnerEcCurve(curve_ptr))
    }
}

impl InnerEcCurve {
    // new() returns a EcCurve associated with the provided CurveType.
    pub(crate) fn new(curve: CurveType) -> &'static Self {
        let ec_curve: &'static InnerEcCurve = match curve {
            CurveType::NistP256 => &*NIST_P256,
            CurveType::NistP384 => &*NIST_P384,
            CurveType::Curve25519 => &*CURVE_25519,
        };

        ec_curve
    }
}

// to_symcrypt_curve() takes in the friendly CurveType enum and returns the symcrypt equivalent.
pub(crate) fn to_symcrypt_curve(curve: CurveType) -> symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS {
    match curve {
        CurveType::NistP256 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP256 }, // SAFETY: FFI calls
        CurveType::NistP384 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP384 }, // SAFETY: FFI calls
        CurveType::Curve25519 => unsafe { symcrypt_sys::SymCryptEcurveParamsCurve25519 }, // SAFETY: FFI calls
    }
}

// curve_to_num_format() returns the correct number format needed for TLS interop since 25519 spec defines the use of Little Endian.
pub(crate) fn curve_to_num_format(curve_type: CurveType) -> i32 {
    let num_format = match curve_type {
        CurveType::Curve25519 => NumberFormat::LSB.to_symcrypt_format(),
        CurveType::NistP256 | CurveType::NistP384 => NumberFormat::MSB.to_symcrypt_format(),
    };
    num_format
}

// curve_to_ec_point_format() returns the X or XY format needed for TLS interop.
pub(crate) fn curve_to_ec_point_format(curve_type: CurveType) -> i32 {
    // Curve25519 has only X coord, where as Nistp256 and NistP384 have X and Y coord
    let ec_point_format = match curve_type {
        CurveType::Curve25519 => symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_X,
        CurveType::NistP256 | CurveType::NistP384 => {
            symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY
        }
    };
    ec_point_format
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_eckey_generate_key_pair() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        assert_eq!(key.get_curve_type(), CurveType::NistP256);
        assert_eq!(key.has_private_key(), true);
    }

    #[test]
    fn test_eckey_generate_key_pair_same_curve() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let key2 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        assert_eq!(key.get_curve_type(), CurveType::NistP256);
        assert_eq!(key2.get_curve_type(), CurveType::NistP256);
        assert_eq!(key.has_private_key(), true);
        assert_eq!(key2.has_private_key(), true);
    }

    #[test]
    fn test_eckey_set_key_pair() {

        let private_key = hex::decode("b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906").unwrap();
        let public_key = hex::decode("51f99d2d52d4a6e734484a018b7ca2f895c2929b6754a3a03224d07ae61166ce4737da963c6ef7247fb88d19f9b0c667cac7fe12837fdab88c66f10d3c14cad1").unwrap();

        let key = EcKey::set_key_pair(CurveType::NistP256, &private_key, Some(&public_key), EcKeyUsage::EcDsa).unwrap();
        assert_eq!(key.get_curve_type(), CurveType::NistP256);
        assert_eq!(key.has_private_key(), true);

        let key2 = EcKey::set_key_pair(CurveType::NistP256, &private_key, None, EcKeyUsage::EcDsa).unwrap();

        assert_eq!(key2.export_public_key(), key.export_public_key());
    }

    #[test]
    fn test_eckey_set_key_wrong_curve_type() {
        // NistP256 Key
        let private_key = hex::decode("b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906").unwrap();

        let result = EcKey::set_key_pair(CurveType::NistP384, &private_key, None, EcKeyUsage::EcDsa).unwrap_err();

        assert_eq!(result, SymCryptError::InvalidArgument);

    }

    #[test]
    fn test_eckey_set_key_ecdh_and_ecdsa() {
        // NistP256 Key
        let private_key = hex::decode("b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906").unwrap();

        let key = EcKey::set_key_pair(CurveType::NistP256, &private_key, None, EcKeyUsage::EcDhAndEcDsa).unwrap();

        assert_eq!(key.get_ec_curve_usage(), EcKeyUsage::EcDhAndEcDsa);
    }

    #[test]
    fn test_eckey_set_key_pair_invalid_key_size() {
        let result = EcKey::set_key_pair(CurveType::NistP256, &[0u8; 3], Some(&[0u8; 99]), EcKeyUsage::EcDsa).unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_eckey_set_key_pair_invalid_public_key() {
        let private_key = hex::decode("b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906").unwrap();
        let result = EcKey::set_key_pair(CurveType::NistP256, &private_key, Some(&[0u8; 64]), EcKeyUsage::EcDsa).unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_eckey_generate_and_set_public_key() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let public_key = key.export_public_key().unwrap();
        let key2 = EcKey::set_public_key(CurveType::NistP256, &public_key, EcKeyUsage::EcDsa).unwrap();
        assert_eq!(key.get_curve_type(), CurveType::NistP256);
        assert_eq!(key2.get_curve_type(), CurveType::NistP256);
        assert_eq!(key.has_private_key(), true);
        assert_eq!(key2.has_private_key(), false);

        // ensure both have the same public key
        let public_key2 = key2.export_public_key().unwrap();
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_eckey_multiple_export_public_key() {
        let key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();
        let public_key = key.export_public_key().unwrap();
        let public_key2 = key.export_public_key().unwrap();
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_eckey_size_of_private_key() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let key_size = key.get_size_of_private_key();
        assert_eq!(key_size, 32);

        let key = EcKey::generate_key_pair(CurveType::NistP384, EcKeyUsage::EcDsa).unwrap();
        let key_size = key.get_size_of_private_key();
        assert_eq!(key_size, 48);

        let key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();
        let key_size = key.get_size_of_private_key();
        assert_eq!(key_size, 32);
    }
}
