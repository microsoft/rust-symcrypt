//! Hashing for the BCrypt provider

use std::ptr;

use mscrypto::algorithm::BaseHashAlgorithm;
#[cfg(feature = "sha3")]
use mscrypto::algorithm::Sha3Algorithm;
use mscrypto::hash::provider::BuildDigest;
use mscrypto::hash::{Digest, Hash, HashOps};

use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::Cryptography::*;

use crate::BcryptProvider;

const SHA256_LEN: usize = 32;
const SHA384_LEN: usize = 48;
const SHA512_LEN: usize = 64;

// windows-sys exposes the SHA-2 algorithm pseudo-handles but not the SHA-3 ones, so
// define them the same way it defines its own (a BCRYPT_ALG_HANDLE built from the value
// in the bcrypt pseudo-handle table). SHA-3 pseudo-handles exist on Windows 11 24H2 and later.
#[cfg(feature = "sha3")]
const BCRYPT_SHA3_256_ALG_HANDLE: BCRYPT_ALG_HANDLE = 0x0000_03B1_u32 as _;
#[cfg(feature = "sha3")]
const BCRYPT_SHA3_384_ALG_HANDLE: BCRYPT_ALG_HANDLE = 0x0000_03C1_u32 as _;
#[cfg(feature = "sha3")]
const BCRYPT_SHA3_512_ALG_HANDLE: BCRYPT_ALG_HANDLE = 0x0000_03D1_u32 as _;

// Mirrors the SDK's BCRYPT_SUCCESS / NT_SUCCESS macro: a nonnegative NTSTATUS is
// success; only negative values are failures.
fn bcrypt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Panics on a non-success `NTSTATUS`. Used on the infallible SHA-2 path (and once
/// SHA-3 is running), where a failure is catastrophic and cannot be reported.
fn expect_success(call: &str, status: NTSTATUS) {
    if !bcrypt_success(status) {
        panic!(
            "mscrypto-bcrypt: {} failed: NTSTATUS 0x{:08X}",
            call, status as u32
        );
    }
}

/// Owns a hash object handle, destroyed on drop.
struct HashHandle(BCRYPT_HASH_HANDLE);

unsafe impl Send for HashHandle {}

impl Drop for HashHandle {
    fn drop(&mut self) {
        // SAFETY: handle came from BCryptCreateHash and is destroyed once.
        unsafe { BCryptDestroyHash(self.0) };
    }
}

/// Streaming hasher shared by the SHA-2 and SHA-3 surfaces. Both run off process-global
/// algorithm pseudo-handles, so a hasher owns only its hash object.
pub struct BcryptHasher {
    hash: HashHandle,
    output_len: usize,
}

impl BcryptHasher {
    /// Builds a hasher from an algorithm pseudo-handle.
    fn new(alg: BCRYPT_ALG_HANDLE, output_len: usize) -> Self {
        BcryptHasher {
            hash: create_hash_handle(alg),
            output_len,
        }
    }
}

/// Creates a hash object from an algorithm pseudo-handle. Passing NULL/0 for the object
/// buffer allocates it and free it via BCryptDestroyHash. Panics on failure.
fn create_hash_handle(alg: BCRYPT_ALG_HANDLE) -> HashHandle {
    let mut handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
    // SAFETY: alg is a valid algorithm pseudo-handle; the hash object is bcrypt owned.
    let status =
        unsafe { BCryptCreateHash(alg, &mut handle, ptr::null_mut(), 0, ptr::null_mut(), 0, 0) };
    expect_success("BCryptCreateHash", status);
    HashHandle(handle)
}

impl HashOps for BcryptHasher {
    fn update(&mut self, data: &[u8]) {
        // BCryptHashData's length is a u32 (ULONG). On 64-bit a &[u8] can exceed
        // u32::MAX (for example a memory-mapped multi-GB file), and `len as u32` would
        // silently truncate it, so feed the input in chunks of at most u32::MAX bytes.
        // Successive calls hash the concatenation, so the digest covers the whole input.
        for chunk in data.chunks(u32::MAX as usize) {
            // SAFETY: hash handle is live; chunk is valid for its length.
            let status =
                unsafe { BCryptHashData(self.hash.0, chunk.as_ptr(), chunk.len() as u32, 0) };
            expect_success("BCryptHashData", status);
        }
    }

    fn finalize(self) -> Digest {
        let len = self.output_len;
        let handle = self.hash.0;
        Digest::from_fn(len, |buf| {
            // SAFETY: handle is live for the duration of this call (self is dropped only
            // after `from_fn` returns); buf holds exactly `len` bytes.
            let status = unsafe { BCryptFinishHash(handle, buf.as_mut_ptr(), len as u32, 0) };
            expect_success("BCryptFinishHash", status);
        })
    }
}

impl Hash for BcryptProvider {
    type Hasher = BcryptHasher;

    fn hash(&self, algorithm: BaseHashAlgorithm) -> BcryptHasher {
        let (alg, len) = match algorithm {
            BaseHashAlgorithm::Sha256 => (BCRYPT_SHA256_ALG_HANDLE, SHA256_LEN),
            BaseHashAlgorithm::Sha384 => (BCRYPT_SHA384_ALG_HANDLE, SHA384_LEN),
            BaseHashAlgorithm::Sha512 => (BCRYPT_SHA512_ALG_HANDLE, SHA512_LEN),
        };
        BcryptHasher::new(alg, len)
    }

    fn digest(&self, algorithm: BaseHashAlgorithm, data: &[u8]) -> Digest {
        let mut hasher = self.hash(algorithm);
        hasher.update(data);
        hasher.finalize()
    }
}

/// Maps a SHA-3 variant to its algorithm pseudo-handle.
#[cfg(feature = "sha3")]
fn sha3_alg_handle(algorithm: Sha3Algorithm) -> BCRYPT_ALG_HANDLE {
    match algorithm {
        Sha3Algorithm::Sha3_256 => BCRYPT_SHA3_256_ALG_HANDLE,
        Sha3Algorithm::Sha3_384 => BCRYPT_SHA3_384_ALG_HANDLE,
        Sha3Algorithm::Sha3_512 => BCRYPT_SHA3_512_ALG_HANDLE,
    }
}

/// Reports whether this Windows build implements a SHA-3 variant by trying to create a
/// throwaway hash from its pseudo-handle. SHA-3 landed in Windows 11 24H2, so the create
/// fails on older builds and the variant is reported as unavailable.
#[cfg(feature = "sha3")]
pub(crate) fn sha3_available(algorithm: Sha3Algorithm) -> bool {
    let mut handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
    // SAFETY: a throwaway availability probe; the object, if created, is destroyed on drop.
    let status = unsafe {
        BCryptCreateHash(
            sha3_alg_handle(algorithm),
            &mut handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            0,
        )
    };
    if bcrypt_success(status) {
        drop(HashHandle(handle));
        true
    } else {
        false
    }
}

#[cfg(feature = "sha3")]
mod sha3_impl {
    use super::{sha3_alg_handle, BcryptHasher, SHA256_LEN, SHA384_LEN, SHA512_LEN};
    use crate::BcryptProvider;
    use mscrypto::algorithm::Sha3Algorithm;
    use mscrypto::error::Error;
    use mscrypto::hash::{Digest, HashOps};
    use mscrypto::sha3::Sha3;

    impl Sha3 for BcryptProvider {
        type Sha3Hasher = BcryptHasher;

        fn sha3(&self, algorithm: Sha3Algorithm) -> Result<BcryptHasher, Error> {
            let (len, available) = match algorithm {
                Sha3Algorithm::Sha3_256 => (SHA256_LEN, self.sha3_256),
                Sha3Algorithm::Sha3_384 => (SHA384_LEN, self.sha3_384),
                Sha3Algorithm::Sha3_512 => (SHA512_LEN, self.sha3_512),
            };
            if !available {
                return Err(Error::Unavailable);
            }
            Ok(BcryptHasher::new(sha3_alg_handle(algorithm), len))
        }

        fn sha3_digest(&self, algorithm: Sha3Algorithm, data: &[u8]) -> Result<Digest, Error> {
            let mut hasher = self.sha3(algorithm)?;
            hasher.update(data);
            Ok(hasher.finalize())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::BcryptProvider;
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
        let provider = BcryptProvider::new().expect("SHA-2 providers open");
        for vector in SHA2_VECTORS {
            let input = hex::decode(vector.msg).expect("valid hex vector");
            let digest = provider.digest(vector.algorithm, &input);
            assert_eq!(hex_of(&digest), vector.md, "{:?}", vector.algorithm);
        }
    }

    #[test]
    fn streaming_matches_kat() {
        let provider = BcryptProvider::new().expect("SHA-2 providers open");
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
    fn sha3_matches_kat_when_available() {
        use mscrypto::algorithm::Algorithm;
        use mscrypto::error::Error;
        use mscrypto::provider::CryptoProvider;
        use mscrypto::sha3::Sha3;

        let provider = BcryptProvider::new().expect("SHA-2 providers open");
        for vector in SHA3_VECTORS {
            let input = hex::decode(vector.msg).expect("valid hex vector");
            match provider.sha3_digest(vector.algorithm, &input) {
                Ok(digest) => {
                    assert!(provider.supports(Algorithm::Sha3(vector.algorithm)));
                    assert_eq!(hex_of(&digest), vector.md, "{:?}", vector.algorithm);
                }
                Err(Error::Unavailable) => {
                    assert!(!provider.supports(Algorithm::Sha3(vector.algorithm)));
                }
                Err(other) => panic!("unexpected error for {:?}: {other:?}", vector.algorithm),
            }
        }
    }
}
