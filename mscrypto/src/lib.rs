//! `mscrypto` is the backend-neutral cryptographic provider contract.
//!
//! It defines the traits, types, and errors shared by the SymCrypt and
//! BCrypt/CNG backends. This crate has zero native dependencies and implements
//! no cryptography itself; concrete providers live in separate crates
//! (`mscrypto-symcrypt`, `mscrypto-bcrypt`).

pub mod algorithm;
pub mod error;
pub mod hash;
pub mod mac;
pub mod provider;

#[cfg(feature = "sha3")]
pub mod sha3;
