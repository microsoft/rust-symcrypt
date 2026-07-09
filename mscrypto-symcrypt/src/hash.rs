//! Hashing for the SymCrypt provider.

use mscrypto::algorithm::BaseHashAlgorithm;
use mscrypto::hash::provider::BuildDigest;
use mscrypto::hash::{Digest, Hash, HashOps};

use symcrypt::hash::{HashState, Sha256State, Sha384State, Sha512State};

use crate::SymCryptProvider;

/// Streaming SHA hasher. One concrete type covers every base algorithm, as the
/// contract's `Hash::Hasher` is a single associated type.
pub enum SymCryptHasher {
    Sha256(Sha256State),
    Sha384(Sha384State),
    Sha512(Sha512State),
}

impl HashOps for SymCryptHasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            SymCryptHasher::Sha256(state) => state.append(data),
            SymCryptHasher::Sha384(state) => state.append(data),
            SymCryptHasher::Sha512(state) => state.append(data),
        }
    }

    fn finalize(self) -> Digest {
        match self {
            SymCryptHasher::Sha256(mut state) => digest_from(state.result()),
            SymCryptHasher::Sha384(mut state) => digest_from(state.result()),
            SymCryptHasher::Sha512(mut state) => digest_from(state.result()),
        }
    }
}

/// Copies a fixed-size SymCrypt result into a `Digest`. SymCrypt's safe API hands
/// back an owned array, so the digest bytes are moved through a single stack copy
/// of at most `Digest::MAX_LEN` bytes.
fn digest_from<const N: usize>(out: [u8; N]) -> Digest {
    Digest::from_fn(N, |buf| buf.copy_from_slice(&out))
}

impl Hash for SymCryptProvider {
    type Hasher = SymCryptHasher;

    fn hash(&self, algorithm: BaseHashAlgorithm) -> SymCryptHasher {
        match algorithm {
            BaseHashAlgorithm::Sha256 => SymCryptHasher::Sha256(Sha256State::new()),
            BaseHashAlgorithm::Sha384 => SymCryptHasher::Sha384(Sha384State::new()),
            BaseHashAlgorithm::Sha512 => SymCryptHasher::Sha512(Sha512State::new()),
        }
    }

    fn digest(&self, algorithm: BaseHashAlgorithm, data: &[u8]) -> Digest {
        match algorithm {
            BaseHashAlgorithm::Sha256 => digest_from(symcrypt::hash::sha256(data)),
            BaseHashAlgorithm::Sha384 => digest_from(symcrypt::hash::sha384(data)),
            BaseHashAlgorithm::Sha512 => digest_from(symcrypt::hash::sha512(data)),
        }
    }
}

#[cfg(feature = "sha3")]
mod sha3_impl {
    use super::{digest_from, Digest, HashOps, SymCryptProvider};
    use mscrypto::algorithm::Sha3Algorithm;
    use mscrypto::error::Error;
    use mscrypto::sha3::Sha3;
    use symcrypt::hash::{HashState, Sha3_256State, Sha3_384State, Sha3_512State};

    /// Streaming SHA-3 hasher. One concrete type covers every SHA-3 algorithm.
    pub enum SymCryptSha3Hasher {
        Sha3_256(Sha3_256State),
        Sha3_384(Sha3_384State),
        Sha3_512(Sha3_512State),
    }

    impl HashOps for SymCryptSha3Hasher {
        fn update(&mut self, data: &[u8]) {
            match self {
                SymCryptSha3Hasher::Sha3_256(state) => state.append(data),
                SymCryptSha3Hasher::Sha3_384(state) => state.append(data),
                SymCryptSha3Hasher::Sha3_512(state) => state.append(data),
            }
        }

        fn finalize(self) -> Digest {
            match self {
                SymCryptSha3Hasher::Sha3_256(mut state) => digest_from(state.result()),
                SymCryptSha3Hasher::Sha3_384(mut state) => digest_from(state.result()),
                SymCryptSha3Hasher::Sha3_512(mut state) => digest_from(state.result()),
            }
        }
    }

    impl Sha3 for SymCryptProvider {
        type Sha3Hasher = SymCryptSha3Hasher;

        // SymCrypt always provides SHA-3, so construction never reports Unavailable.
        fn sha3(&self, algorithm: Sha3Algorithm) -> Result<SymCryptSha3Hasher, Error> {
            Ok(match algorithm {
                Sha3Algorithm::Sha3_256 => SymCryptSha3Hasher::Sha3_256(Sha3_256State::new()),
                Sha3Algorithm::Sha3_384 => SymCryptSha3Hasher::Sha3_384(Sha3_384State::new()),
                Sha3Algorithm::Sha3_512 => SymCryptSha3Hasher::Sha3_512(Sha3_512State::new()),
            })
        }

        fn sha3_digest(&self, algorithm: Sha3Algorithm, data: &[u8]) -> Result<Digest, Error> {
            Ok(match algorithm {
                Sha3Algorithm::Sha3_256 => digest_from(symcrypt::hash::sha3_256(data)),
                Sha3Algorithm::Sha3_384 => digest_from(symcrypt::hash::sha3_384(data)),
                Sha3Algorithm::Sha3_512 => digest_from(symcrypt::hash::sha3_512(data)),
            })
        }
    }
}

#[cfg(feature = "sha3")]
pub use sha3_impl::SymCryptSha3Hasher;

#[cfg(test)]
mod test {
    use crate::SymCryptProvider;
    use mscrypto::algorithm::BaseHashAlgorithm;
    use mscrypto::hash::{Digest, Hash, HashOps};

    #[cfg(feature = "sha3")]
    use mscrypto::algorithm::Sha3Algorithm;

    struct ShaVector {
        algorithm: BaseHashAlgorithm,
        msg: &'static str,
        md: &'static str,
    }

    const SHA2_VECTORS: &[ShaVector] = &[
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha256,
            msg: "",
            md: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha256,
            msg: "3ec009",
            md: "579badde3d29ecbdcbd56dacaf3f7fcfd40b1aac60dbc5b17e3902613864e470",
        },
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha384,
            msg: "",
            md: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        },
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha384,
            msg: "ac8a50",
            md: "1bdcb04240b4b43a110407baa08b404f042ea05c517ce2d9cc2be38cdfd916ce0db81615f869449e26416430cd5eb120",
        },
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha512,
            msg: "",
            md: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        },
        ShaVector {
            algorithm: BaseHashAlgorithm::Sha512,
            msg: "d4fc1f",
            md: "e668327148443a73d6ec4a9db28aac4280bd11e8a652175b1757de4fc03ebed5ea85e8945dae67b394be3065c84c15261f2f05bd071c13bc77fadeb6786911a1",
        },
    ];

    #[cfg(feature = "sha3")]
    struct Sha3Vector {
        algorithm: Sha3Algorithm,
        msg: &'static str,
        md: &'static str,
    }

    #[cfg(feature = "sha3")]
    const SHA3_VECTORS: &[Sha3Vector] = &[
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_256,
            msg: "",
            md: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        },
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_256,
            msg: "b053fa",
            md: "9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb",
        },
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_384,
            msg: "",
            md: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        },
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_384,
            msg: "6ab7d6",
            md: "ea12d6d32d69ad2154a57e0e1be481a45add739ee7dd6e2a27e544b6c8b5ad122654bbf95134d567987156295d5e57db",
        },
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_512,
            msg: "",
            md: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        },
        Sha3Vector {
            algorithm: Sha3Algorithm::Sha3_512,
            msg: "37d518",
            md: "4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3",
        },
    ];

    fn hex_of(digest: &Digest) -> String {
        hex::encode(digest.as_bytes())
    }

    #[test]
    fn sha2_matches_kat() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        for vector in SHA2_VECTORS {
            let input = hex::decode(vector.msg).expect("valid hex vector");
            let digest = provider.digest(vector.algorithm, &input);
            assert_eq!(hex_of(&digest), vector.md, "{:?}", vector.algorithm);
        }
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn sha3_matches_kat() {
        use mscrypto::sha3::Sha3;

        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        for vector in SHA3_VECTORS {
            let input = hex::decode(vector.msg).expect("valid hex vector");
            let digest = provider
                .sha3_digest(vector.algorithm, &input)
                .expect("SymCrypt always provides SHA-3");
            assert_eq!(hex_of(&digest), vector.md, "{:?}", vector.algorithm);
        }
    }

    #[test]
    fn streaming_matches_kat() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let mut hasher = provider.hash(BaseHashAlgorithm::Sha256);
        hasher.update(&[0x3e]);
        hasher.update(&[0xc0, 0x09]);
        assert_eq!(
            hex_of(&hasher.finalize()),
            "579badde3d29ecbdcbd56dacaf3f7fcfd40b1aac60dbc5b17e3902613864e470"
        );
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn sha3_streaming_matches_kat() {
        use mscrypto::sha3::Sha3;

        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let mut hasher = provider
            .sha3(Sha3Algorithm::Sha3_256)
            .expect("SymCrypt always provides SHA-3");
        hasher.update(&[0xb0]);
        hasher.update(&[0x53, 0xfa]);
        assert_eq!(
            hex_of(&hasher.finalize()),
            "9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb"
        );
    }
}
