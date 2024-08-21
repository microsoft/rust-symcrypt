//! EcDsa functions. For further documentation please refer to symcrypt.h
//!
//! # Example
//!
//! ## ECDSA Sign and Verify
//!
//! ```rust
//! use symcrypt::ecc::{EcKey, CurveType, EcKeyUsage};
//! use hex::*;
//!
//! // Set up input hash value
//! let hashed_message = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();
//!
//! // Generate a new ECDSA key pair
//! let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
//!
//! // Sign the hash value
//! let signature = key.ecdsa_sign(&hashed_message).unwrap();
//!
//! // Verify the signature
//! let result = key.ecdsa_verify(&signature, &hashed_message);
//!
//! // Assert the signature is valid
//! assert!(result.is_ok());
//!
//! ```
//!
use crate::ecc::{curve_to_num_format, CurveType, EcKey, EcKeyUsage};
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

impl EcKey {
    /// `ecdsa_sign()` returns a signature as a `Vec<u8>`, or a [`SymCryptError`] if the operation fails.
    ///
    /// `hashed_message` is a `&[u8]` that represents the hash value to sign.
    ///
    /// If the key usage is not [`EcKeyUsage::EcDsa`], or [`EcKeyUsage::EcDhAndEcDsa`] the function will
    /// fail with a [`SymCryptError`] with the value [`SymCryptError::InvalidArgument`].
    pub fn ecdsa_sign(&self, hash_value: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        // SymCrypt code AV's with SymCrypt Fatal Error.
        // Panic'ing is not normal here in Rust so we are handling the error instead and returning SymCryptError::InvalidArgument
        if self.get_ec_curve_usage() == EcKeyUsage::EcDh {
            return Err(SymCryptError::InvalidArgument);
        }
        // SymCrypt code AV's with SymCrypt Fatal Error for trying to sign with Curve25519 as it is not supported.
        // Panic'ing is not normal here in Rust so we are handling the error instead and returning SymCryptError::InvalidArgument
        if self.get_curve_type() == CurveType::Curve25519 {
            return Err(SymCryptError::InvalidArgument);
        }

        // Per SymCrypt docs, the size of the signature will be 2 x the size of the private key.
        let signature_size = self.get_size_of_private_key() * 2;
        let mut signature = vec![0u8; signature_size as usize]; // must be 2x size of private key SymCryptEckeySizeofPrivateKey
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEcDsaSign(
                self.inner_key(),
                hash_value.as_ptr(),
                hash_value.len() as symcrypt_sys::SIZE_T,
                curve_to_num_format(self.curve_type), // Derive number format from curve type
                0,
                signature.as_mut_ptr(),
                signature.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(signature),
                err => Err(err.into()),
            }
        }
    }

    /// `ecdsa_verify()` returns `Ok(())` if the signature is valid, or a [`SymCryptError`] if the operation fails.
    ///
    ///  Caller must check the return value to determine if the signature is valid before continuing.
    ///
    /// `signature` is a `&[u8]` that represents the signature to verify.
    ///
    /// `hashed_message` is a `&[u8]` that represents the hashed message to verify.
    ///
    /// if the key usage is not [`EcKeyUsage::EcDsa`], or [`EcKeyUsage::EcDhAndEcDsa`] the function will
    /// fail with a [`SymCryptError`] with the value [`SymCryptError::SignatureVerificationFailure`].
    pub fn ecdsa_verify(
        &self,
        signature: &[u8],
        hashed_message: &[u8],
    ) -> Result<(), SymCryptError> {
        // SymCrypt code does not support EcDsa operations with Curve25519.
        // SymCrypt does not panic here, but to remain consistent with ecdsa_sign, returning SymCryptError::InvalidArgument
        if self.get_curve_type() == CurveType::Curve25519 {
            return Err(SymCryptError::InvalidArgument);
        }
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEcDsaVerify(
                self.inner_key(),
                hashed_message.as_ptr(),
                hashed_message.len() as symcrypt_sys::SIZE_T,
                signature.as_ptr(),
                signature.len() as symcrypt_sys::SIZE_T,
                curve_to_num_format(self.curve_type), // Derive number format from curve type
                0,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::CurveType;
    use crate::ecc::EcKeyUsage;

    #[test]
    fn test_ecdsa_sign_and_verify_same_key() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();

        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let signature = key.ecdsa_sign(&hash_value).unwrap();

        let verify_result = key.ecdsa_verify(&signature, &hash_value);
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_ecsda_sign_with_25519_failure() {
        let key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let signature = key.ecdsa_sign(&hash_value).unwrap_err();
        assert!(signature == SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_ecsda_verify_with_25519_failure() {
        let key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDsa).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let key2 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let signature = key2.ecdsa_sign(&hash_value).unwrap();

        let result = key.ecdsa_verify(&signature, &hash_value).unwrap_err();
        assert!(result == SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_ecdsa_sign_and_verify_wrong_key_usage() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();
        let result = key.ecdsa_sign(&hash_value).unwrap_err();
        assert_eq!(result, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_ecdsa_verify_wrong_key_usage() {
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let signature = key.ecdsa_sign(&hash_value).unwrap();

        let key2 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDh).unwrap();
        let result = key2.ecdsa_verify(&signature, &hash_value).unwrap_err();
        assert_eq!(result, SymCryptError::SignatureVerificationFailure);
    }

    #[test]
    fn test_ecdsa_sign_and_verify_ecdsa_and_ecdh() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDhAndEcDsa).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();
        let verify_result = key.ecdsa_sign(&hash_value);
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_ecdsa_sign_and_verify_different_key() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();
        let signature = key.ecdsa_sign(&hash_value).unwrap();

        let key2 = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();

        let result = key2.ecdsa_verify(&signature, &hash_value).unwrap_err();
        assert_eq!(result, SymCryptError::SignatureVerificationFailure);
    }

    #[test]
    fn test_ecdsa_sign_without_private_key() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();
        let public_key_bytes = key.export_public_key().unwrap();
        let key = EcKey::set_public_key(CurveType::NistP256, &public_key_bytes, EcKeyUsage::EcDsa)
            .unwrap();
        let result = key.ecdsa_sign(&hash_value);
        assert_eq!(result, Err(SymCryptError::InvalidArgument));
    }

    #[test]
    fn test_ecdsa_sign_and_verify_different_curve_type() {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();

        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let _signature = key.ecdsa_sign(&hash_value).unwrap();

        let public_key_bytes = key.export_public_key().unwrap();

        let key2 =
            EcKey::set_public_key(CurveType::Curve25519, &public_key_bytes, EcKeyUsage::EcDsa)
                .unwrap_err();
        assert_eq!(key2, SymCryptError::InvalidArgument);
    }

    #[test]
    fn test_ecdsa_sign_with_imported_key() {
        let private_key =
            hex::decode("b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906")
                .unwrap();
        let key = EcKey::set_key_pair(CurveType::NistP256, &private_key, None, EcKeyUsage::EcDsa)
            .unwrap();

        let hash_value = hex::decode("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").unwrap();

        let signature = key.ecdsa_sign(&hash_value).unwrap();

        let verify_result = key.ecdsa_verify(&signature, &hash_value);
        assert!(verify_result.is_ok());
    }
}
