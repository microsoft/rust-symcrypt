//! The provider surface: identity, capability queries, and backend metadata.
//!
//! Base hashing (`Hash`) is a supertrait, so every provider can hash.

use crate::algorithm::Algorithm;
use crate::hash::Hash;

pub trait CryptoProvider: Hash {
    fn info(&self) -> &BackendInfo;
    fn supports(&self, a: Algorithm) -> bool;
}

pub struct BackendInfo {
    pub name: &'static str,
    pub version: BackendVersion,
    pub link_mode: LinkMode,
    pub fips: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackendVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum LinkMode {
    DynamicSystem,
    PrebuiltStatic,
    BuildFromSourceStatic,
    NotApplicable,
}
