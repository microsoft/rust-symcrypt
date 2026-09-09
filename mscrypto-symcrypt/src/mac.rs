//! Keyed hashing (HMAC) for the SymCrypt provider.

use mscrypto::algorithm::{BaseHashAlgorithm, MacAlgorithm};
use mscrypto::hash::Digest;
use mscrypto::mac::{Mac, MacOps};

use symcrypt::errors::SymCryptError;
use symcrypt::hmac::{
    hmac_sha256, hmac_sha384, hmac_sha512, HmacSha256State, HmacSha384State, HmacSha512State,
    HmacState,
};

use crate::hash::digest_from;
use crate::SymCryptProvider;

/// Streaming HMAC state. One concrete type covers every supported algorithm, as the
/// contract's `Mac::MacState` is a single associated type.
pub enum SymCryptMac {
    HmacSha256(HmacSha256State),
    HmacSha384(HmacSha384State),
    HmacSha512(HmacSha512State),
}

impl MacOps for SymCryptMac {
    fn update(&mut self, data: &[u8]) {
        match self {
            SymCryptMac::HmacSha256(state) => state.append(data),
            SymCryptMac::HmacSha384(state) => state.append(data),
            SymCryptMac::HmacSha512(state) => state.append(data),
        }
    }

    fn finalize(self) -> Digest {
        match self {
            SymCryptMac::HmacSha256(state) => digest_from(state.result()),
            SymCryptMac::HmacSha384(state) => digest_from(state.result()),
            SymCryptMac::HmacSha512(state) => digest_from(state.result()),
        }
    }
}

impl Mac for SymCryptProvider {
    type MacState = SymCryptMac;

    fn mac(&self, algorithm: MacAlgorithm, key: &[u8]) -> SymCryptMac {
        match algorithm {
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256) => {
                SymCryptMac::HmacSha256(expect_key(HmacSha256State::new(key)))
            }
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha384) => {
                SymCryptMac::HmacSha384(expect_key(HmacSha384State::new(key)))
            }
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha512) => {
                SymCryptMac::HmacSha512(expect_key(HmacSha512State::new(key)))
            }
        }
    }

    fn mac_digest(&self, algorithm: MacAlgorithm, key: &[u8], data: &[u8]) -> Digest {
        match algorithm {
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256) => {
                digest_from(expect_key(hmac_sha256(key, data)))
            }
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha384) => {
                digest_from(expect_key(hmac_sha384(key, data)))
            }
            MacAlgorithm::Hmac(BaseHashAlgorithm::Sha512) => {
                digest_from(expect_key(hmac_sha512(key, data)))
            }
        }
    }
}

// HMAC accepts a key of any length, so SymCrypt's key expansion cannot fail here; the
// fallible signature exists only to share the generic MAC interface with algorithms
// whose key setup can fail (for example AES-CMAC, which rejects non-AES key sizes).
fn expect_key<T>(result: Result<T, SymCryptError>) -> T {
    result.unwrap_or_else(|error| {
        panic!("mscrypto-symcrypt: HMAC key expansion cannot fail: {error:?}")
    })
}

#[cfg(test)]
mod test {
    use crate::SymCryptProvider;
    use mscrypto::algorithm::{BaseHashAlgorithm, MacAlgorithm};
    use mscrypto::hash::Digest;
    use mscrypto::mac::{Mac, MacOps};

    struct MacVector {
        algorithm: MacAlgorithm,
        key: &'static str,
        msg: &'static str,
        tag: &'static str,
    }

    // RFC 4231 HMAC test cases 1 and 2.
    const HMAC_VECTORS: &[MacVector] = &[
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256),
            key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            msg: "4869205468657265",
            tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        },
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha384),
            key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            msg: "4869205468657265",
            tag: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        },
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha512),
            key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            msg: "4869205468657265",
            tag: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        },
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256),
            key: "4a656665",
            msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        },
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha384),
            key: "4a656665",
            msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            tag: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        },
        MacVector {
            algorithm: MacAlgorithm::Hmac(BaseHashAlgorithm::Sha512),
            key: "4a656665",
            msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            tag: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        },
    ];

    fn hex_of(digest: &Digest) -> String {
        hex::encode(digest.as_bytes())
    }

    #[test]
    fn hmac_matches_kat() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        for vector in HMAC_VECTORS {
            let key = hex::decode(vector.key).expect("valid hex key");
            let msg = hex::decode(vector.msg).expect("valid hex message");
            let tag = provider.mac_digest(vector.algorithm, &key, &msg);
            assert_eq!(hex_of(&tag), vector.tag, "{:?}", vector.algorithm);
        }
    }

    #[test]
    fn streaming_matches_kat() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("valid hex key");
        let mut mac = provider.mac(MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256), &key);
        mac.update(&hex::decode("4869").expect("valid hex"));
        mac.update(&hex::decode("205468657265").expect("valid hex"));
        assert_eq!(
            hex_of(&mac.finalize()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn verify_accepts_valid_tag() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let algorithm = MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256);
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("valid hex key");
        let msg = hex::decode("4869205468657265").expect("valid hex message");
        let tag = provider.mac_digest(algorithm, &key, &msg);
        provider
            .verify(algorithm, &key, &msg, tag.as_bytes())
            .expect("valid tag verifies");
    }

    #[test]
    fn verify_rejects_forged_tag() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let algorithm = MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256);
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("valid hex key");
        let msg = hex::decode("4869205468657265").expect("valid hex message");
        let mut tag = provider
            .mac_digest(algorithm, &key, &msg)
            .as_bytes()
            .to_vec();
        tag[0] ^= 0x01;
        assert!(provider.verify(algorithm, &key, &msg, &tag).is_err());
    }

    #[test]
    fn verify_rejects_wrong_length_tag() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let algorithm = MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256);
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("valid hex key");
        let msg = hex::decode("4869205468657265").expect("valid hex message");
        let tag = provider.mac_digest(algorithm, &key, &msg);
        assert!(provider
            .verify(algorithm, &key, &msg, &tag.as_bytes()[..16])
            .is_err());
    }

    #[test]
    fn streaming_verify_accepts_and_rejects() {
        let provider = SymCryptProvider::new().expect("SymCrypt module initializes");
        let algorithm = MacAlgorithm::Hmac(BaseHashAlgorithm::Sha256);
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("valid hex key");
        let msg = hex::decode("4869205468657265").expect("valid hex message");
        let tag = provider.mac_digest(algorithm, &key, &msg);

        let mut mac = provider.mac(algorithm, &key);
        mac.update(&msg);
        mac.verify(tag.as_bytes()).expect("valid tag verifies");

        let mut forged = tag.as_bytes().to_vec();
        forged[0] ^= 0x01;
        let mut mac = provider.mac(algorithm, &key);
        mac.update(&msg);
        assert!(mac.verify(&forged).is_err());
    }
}
