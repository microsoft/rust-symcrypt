//! Friendly rust errors for cryptographic operations.

use std::fmt;

/// `SymCryptError` enumerates all possible errors from the cryptographic backends.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum SymCryptError {
    NoError,
    Unused,
    WrongKeySize,
    WrongBlockSize,
    WrongDataSize,
    WrongNonceSize,
    WrongTagSize,
    WrongIterationCount,
    AuthenticationFailure,
    ExternalFailure,
    FipsFailure,
    HardwareFailure,
    NotImplemented,
    InvalidBlob,
    BufferTooSmall,
    InvalidArgument,
    MemoryAllocationFailure,
    SignatureVerificationFailure,
    IncompatibleFormat,
    ValueTooLarge,
    SessionReplayFailure,
    NotSupported,
    UnknownError(i32),
}

#[cfg(not(windows))]
impl From<symcrypt_sys::SYMCRYPT_ERROR> for SymCryptError {
    fn from(err: symcrypt_sys::SYMCRYPT_ERROR) -> Self {
        match err {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => SymCryptError::NoError,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_UNUSED => SymCryptError::Unused,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_KEY_SIZE => SymCryptError::WrongKeySize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_BLOCK_SIZE => SymCryptError::WrongBlockSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_DATA_SIZE => SymCryptError::WrongDataSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_NONCE_SIZE => SymCryptError::WrongNonceSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_TAG_SIZE => SymCryptError::WrongTagSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_ITERATION_COUNT => {
                SymCryptError::WrongIterationCount
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_AUTHENTICATION_FAILURE => {
                SymCryptError::AuthenticationFailure
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_EXTERNAL_FAILURE => {
                SymCryptError::ExternalFailure
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_FIPS_FAILURE => SymCryptError::FipsFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_HARDWARE_FAILURE => {
                SymCryptError::HardwareFailure
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NOT_IMPLEMENTED => SymCryptError::NotImplemented,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INVALID_BLOB => SymCryptError::InvalidBlob,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_BUFFER_TOO_SMALL => SymCryptError::BufferTooSmall,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INVALID_ARGUMENT => {
                SymCryptError::InvalidArgument
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_MEMORY_ALLOCATION_FAILURE => {
                SymCryptError::MemoryAllocationFailure
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE => {
                SymCryptError::SignatureVerificationFailure
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INCOMPATIBLE_FORMAT => {
                SymCryptError::IncompatibleFormat
            }
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_VALUE_TOO_LARGE => SymCryptError::ValueTooLarge,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_SESSION_REPLAY_FAILURE => {
                SymCryptError::SessionReplayFailure
            }
            _ => SymCryptError::UnknownError(err as i32),
        }
    }
}

/// Maps BCrypt NTSTATUS codes to SymCryptError.
#[cfg(windows)]
pub(crate) fn map_ntstatus(status: i32) -> SymCryptError {
    use windows_sys::Win32::Foundation::*;

    match status {
        STATUS_SUCCESS => SymCryptError::NoError,
        STATUS_INVALID_PARAMETER => SymCryptError::InvalidArgument,
        STATUS_BUFFER_TOO_SMALL => SymCryptError::BufferTooSmall,
        STATUS_NO_MEMORY => SymCryptError::MemoryAllocationFailure,
        STATUS_NOT_SUPPORTED => SymCryptError::NotSupported,
        STATUS_AUTH_TAG_MISMATCH => SymCryptError::AuthenticationFailure,
        STATUS_INVALID_SIGNATURE => SymCryptError::SignatureVerificationFailure,
        _ => SymCryptError::UnknownError(status),
    }
}

impl fmt::Display for SymCryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match *self {
            SymCryptError::NoError => "No error",
            SymCryptError::Unused => "Unused",
            SymCryptError::WrongKeySize => "Wrong key size",
            SymCryptError::WrongBlockSize => "Wrong block size",
            SymCryptError::WrongDataSize => "Wrong data size",
            SymCryptError::WrongNonceSize => "Wrong nonce size",
            SymCryptError::WrongTagSize => "Wrong tag size",
            SymCryptError::WrongIterationCount => "Wrong iteration count",
            SymCryptError::AuthenticationFailure => "Authentication failure",
            SymCryptError::ExternalFailure => "External failure",
            SymCryptError::FipsFailure => "FIPS failure",
            SymCryptError::HardwareFailure => "Hardware failure",
            SymCryptError::NotImplemented => "Not implemented",
            SymCryptError::InvalidBlob => "Invalid blob",
            SymCryptError::BufferTooSmall => "Buffer too small",
            SymCryptError::InvalidArgument => "Invalid argument",
            SymCryptError::MemoryAllocationFailure => "Memory allocation failure",
            SymCryptError::SignatureVerificationFailure => "Signature verification failure",
            SymCryptError::IncompatibleFormat => "Incompatible format",
            SymCryptError::ValueTooLarge => "Value too large",
            SymCryptError::SessionReplayFailure => "Session replay failure",
            SymCryptError::NotSupported => "Not supported",
            SymCryptError::UnknownError(code) => return write!(f, "Unknown error: {}", code),
        };
        write!(f, "{}", message)
    }
}
