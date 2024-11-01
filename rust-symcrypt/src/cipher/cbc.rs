//! Functions for Cbc encryption and decryption. For more info please see symcrypt.h
//!
//!
//!
use crate::cipher::{validate_block_size, AesExpandedKey};
use crate::errors::SymCryptError;
use symcrypt_sys;

impl AesExpandedKey {
    /// `aes_cbc_encrypt()` encrypts the `plain_text` using the AES-CBC algorithm and writes to the `cipher_text` buffer provided.
    /// 
    /// This is a method on the `AesExpandedKey` struct, and you must initliaze an `AesExpandedKey` struct before calling this method.
    /// 
    /// `chaining_value` is a mutable reference to a buffer, that can represent the `IV` on the first call, and the `cipher_text` on subsequent calls.
    /// 
    /// `plain_text` is a slice of bytes that represents the data to be encrypted.
    /// 
    /// `cipher_text` is a mutable reference to a buffer that will be filled with the encrypted data. The length of this buffer must be equal to the length of the `plain_text` buffer.
    /// 
    /// This function will return an Error if the length of the `plain_text` and `cipher_text` buffers are not equal, or if they are not multiples of 16 bytes.
    fn aes_cbc_encrypt(
        &self,
        chaining_value: &mut [u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_block_size(plain_text, cipher_text)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcEncrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                plain_text.as_ptr(),
                cipher_text.as_mut_ptr(),
                plain_text.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }

    fn aes_cbc_decrypt(
        &self,
        chaining_value: &mut [u8],
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), SymCryptError> {
        validate_block_size(plain_text, cipher_text)?;
        unsafe {
            symcrypt_sys::SymCryptAesCbcDecrypt(
                self.expanded_key.get_inner(),
                chaining_value.as_mut_ptr(),
                cipher_text.as_ptr(),
                plain_text.as_mut_ptr(),
                plain_text.len() as symcrypt_sys::SIZE_T,
            );
        }
        Ok(())
    }
}


#[cfg(test)]
pub mod test{
    use super::*;
    use hex;

    #[test]
    fn test_aes_cbc_encrypt() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = hex::decode("00000000000000000000000000000000").unwrap();
        let plain_text = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
        let mut cipher_text = vec![0u8; plain_text.len()];

        aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text).unwrap();
        assert_eq!(hex::encode(cipher_text), "0336763e966d92595a567cc9ce537f5e");
    }

    #[test]
    fn test_aes_cbc_encrypt_multiple_blocks() {
        let key = hex::decode("5b219035dfc35ee9a6002e2434df384d1e2f62c71178607d").unwrap();
        let aes_cbc = AesExpandedKey::new(&key).unwrap();
        let mut chaining_value = hex::decode("24fab7b162e066c8f6dc847130d1ff34").unwrap();
        let plain_text = hex::decode("886e05184aa2441086c2a7df6d4d7f25").unwrap();
        let mut cipher_text = vec![0u8; plain_text.len()];
        aes_cbc.aes_cbc_encrypt(&mut chaining_value, &plain_text, &mut cipher_text).unwrap();
        assert_eq!(hex::encode(cipher_text), "b807ad5275628c309d243bcff8869593");

        assert_eq!(hex::encode(chaining_value), "1ff84d1cf5899f58eaf1da93b84cb674");

    }

//     COUNT = 0
// KEY = 5b219035dfc35ee9a6002e2434df384d1e2f62c71178607d
// IV = 24fab7b162e066c8f6dc847130d1ff34
// PLAINTEXT = 886e05184aa2441086c2a7df6d4d7f25
// CIPHERTEXT = b807ad5275628c309d243bcff8869593

// COUNT = 1
// KEY = e2c390cc5d4b4cdd9f688d8d6f937cb6530ede575d6c8c36
// IV = 1ff84d1cf5899f58eaf1da93b84cb674
// PLAINTEXT = bc1c85de86285f94da0e4d2b32ea4ac202f30166f9ad36e0846062d095c89d00
// CIPHERTEXT = 4382c804ec2bc4b71a64a37246d9d8b5ecf072c1fdb993aaee43f4b446a2e371

    fn test_aes_cbc_decrypt() {
        let key = hex::decode("").unwrap();
    }

    fn test_aes_cbc_decrypt_multiple_blocks() {
        let key = hex::decode("").unwrap();
    }

    fn test_aes_cbc_encrypt_decrypt_with_shared_keys() {

    }
    
    fn test_aes_cbc_wrong_block_size() {

    }

    fn test_aes_cbc_mismatch_text_length() {

    }

}
// COUNT = 0
// KEY = 9bceab233f4d2edc9220935664284525
// IV = db5063420e5f843d457f0a3118405fb2
// PLAINTEXT = 08d6fc05e8f7977fde2afc9508a6d55e
// CIPHERTEXT = 581506ac668b8f0b39d89d9a87a21c14

// COUNT = 1
// KEY = 5d98398b5e3b98d87e07ecf1332df4ac
// IV = db22065fb9302c4445151adc91310797
// PLAINTEXT = 4831f8d1a92cf167a444ccae8d90158dfc55c9a0742019e642116bbaa87aa205
// CIPHERTEXT = f03f86e1a6f1e23e70af3f3ab3b777fd43103f2e7a6fc245a3656799176a2611

// COUNT = 2
// KEY = 0fe59c00aec2179a01aa032c85b36ca5
// IV = f47a49295366a8e3daeb0836ce8bf548
// PLAINTEXT = 013f065cc6f510f41ae6bfade4e6df2d02f1cc744620926cbed653c1393ae9f206ebcda9ffef3748c7ec87c44f9ae4b6
// CIPHERTEXT = 30df62bd66848aa22e65ca2f5cc4be6b6c6d3806eece0d88caf944e46d476c4d9600e9414482308dbf98685c95d93233

// COUNT = 3
// KEY = 72d5c5de43b76667a4da64779dbd949d
// IV = 8afa034904220bf7eecb1ae607061245
// PLAINTEXT = 83f00bc4e745c9949dfb65c631fa78a3a0db82b41ba0d41d08a3ad2d4acda332c208449215f7fe17b0e43c\
//             8b0afad28529b49b8268956037771afc26a3edbe70
// CIPHERTEXT = 8478306b078ee5279862332b1f95de3bab28eb5ea5fc141d40efe3cc59fcf9c74d4034df16dec6e007a560\
//              fd5af9c0c3029254dffced41b5eb39f97932eb5ed1

// COUNT = 4
// KEY = 8ff68776fae95848f5e2ea56ba0958a2
// IV = 359387767486dd2887180936e0bf3e5e
// PLAINTEXT = 9517d3c89c73a4e3e2206a70df7d9374945e3403d60ffb60e996656550393025e44014d124fcaed8cc08bd\
//             52a9cf909fab4ebf4b3c1c1a35d0a7dff1bdc0306a4e5ac3cc128edca17ae3783aa3cdcb50
// CIPHERTEXT = 3f9d6390f481a4744c8b86db16f1abcf69df6e96aea7f8612cab97a05fc5f3c96524527b33d8c36c45b9de\
//              0692a8f415fa30d2f6594ea9ccc87a87b91a7f10982ff5d77db614169f51f8f8b1d4d7b6d8

// COUNT = 5
// KEY = 9e32ee00ecf0fa480de45f9bceb2fde7
// IV = e0d44304c1f8b937aee51bd6c11784e0
// PLAINTEXT = 01be902f7fb2a26abe6b58e5b49302c0d462471a8f14c4271b9bf68273915ac59f70d25835054b8620229d\
//             d6a094b2989254ebbef202bfed9e8ea6d45c3935bd1fbc8a6186c6ea01a6aca9b2095c4af9f694e897f351\
//             d5a6898980e5471c9c51
// CIPHERTEXT = db733c5a90df7eba4de02d45ab6d6583639a6f4a80e0bfca531a8f4a358f8fdd2e6d27946b1cb9c20b410a\
//              a9f4514bbb23c640f58860bc5966a87c0c3c08b9586c8188a1ddf1dae2e11636acfa6cde0d213f54d22d86\
//              c7f0c342679aa403124d

// COUNT = 6
// KEY = 95b82ca7648f16db2a56bc3770b92b62
// IV = 2b4374a536c931c413bafbcb15b64768
// PLAINTEXT = c1ee987500ecaf42a51a10997280ba4f754346663b11c08f41bfb5edab318d1c387b1b72764573843274fc\
//             ec3307c64a283e1d89de025e64b6810928571918bba0778fdde00055ae4a6f4270a3c0798f3e4ef8de2a38\
//             6d24aa084bd7e5971e27df2b1c3fa8e3fcc7d4550bad2a757c25
// CIPHERTEXT = 42e2146d8216682f2f502af4885abf2ae9fd387c60e2c033e4d1a2dc3402ee3e1661eebbece6df40ed9d0c\
//              4e02a3cae409d6638a04e0db06384e7b3ce0bc8c0cf5f4d75e4db01889df0185cb2706e7ec437c6c5c17e8\
//              a42f7d638d7db67e355618c66af295df8b3922bd8f7aca8d21a2

// COUNT = 7
// KEY = 0ba374e7c8aae92861069717f3771183
// IV = 4e9d84c4d6181c28713d1159e700998c
// PLAINTEXT = f0f27c1fa14e59f228f0095db814691834d9aed88c4453764a86554d6882a3e4658ad0cd98690cccc3a752\
//             3ceb08e3af6756f2d53860a19f98432ca3d5e864c360ce6009210a6fd60e8c503cfca3a6a8b5c4a6c44a87\
//             139babf26cff74fa64270a47929de7386a5832276c2493ee9b4b45a9316e6dbe91b4aa1b7d27edbf895a
// CIPHERTEXT = 3f6def3b4cfe2969c1920f89cdfaea391f3335e1fc848076b1665a37390d240ec6f9b3a78f9fc8d2fc9be6\
//              09d7218297228679993070370cbb41e5dc0e91a03e8d4b71aff1175dd39fe187833769c3e66c363d3b300e\
//              6cde52af217d4dd5b1603594dc753ee82a676cd12bd8f3d27fcfedc15f1da4f1fcffdea58ff3f9866a87

// COUNT = 8
// KEY = 62f8446755348cd578c7246218595d28
// IV = 9c1be5e442c16c282e1c4522f0082bb3
// PLAINTEXT = d717c90e22715001f62bbe2099871ee0f7cd6bdf8c9b98d2847dd3be21bd0b6c5e7db017d202ba67d653ec\
//             a3ea035a22554b29020c5c961dd5f23939ac2d8b7f669da72f949b4d91aae02c2f6150614159173b6903f7\
//             41a0bee0767040c2db65389f36be31e41267baf9072cc4173b274b5a297a3917a144876f10cda52402041c\
//             ace52c728410d24dc70402dcfff1ba
// CIPHERTEXT = 328a478ef22a6b8b9f7682e2161baeb7541f8610f182296ef1cb6d9c18469efda0ba8da765c0ba73d5d586\
//              f217652eb035de9bba79f87a63f27f1cbfedb0c58551f15624481006d9f675df2d9cbb0c7722d922921279\
//              3d5a32076ec95c502ed37b15f4fb4cffcf3e2982ee16d049e5326086ca13c2e16247fbec8d9eaa6c103223\
//              13bc97d5f9c32ea36e7a1be2556177

// COUNT = 9
// KEY = 963c57161af9868fd596883fe44b0243
// IV = bf09d9915fc415d104e7bee5d588dcc9
// PLAINTEXT = 4cea0f13644b350794d3934ce5b8966b4f660bcc2a223579e5ed1d23faab2a6a2184f159c58b4e30b49db4\
//             671a8cc1efb07d16bb318f657f0ebecbb8620661ec28cb0e33ac789ff63f6719f72f014d91f626ae42b2cf\
//             6066d5f191451ea50c50c8870ba8015b4de09df769040c5d62da89277b6795284db5a45016d416d0541f68\
//             7f93c0ac7c837736154d9799e82751d2482734c2e354f5e2a1036c32cf61e0
// CIPHERTEXT = e6b06677589519fec0a5063099ebb694390eb002a134c3d4102fb5d7b1d09503bc6031a470d010a666d8ea\
//              d1bebc87c14ccb770b4fe6432aaff4d13399df19529670b4524a8401dcdb57811e6f5cfbe05dd15f3b0043\
//              d4c392e80c73543e3e5a2afbdf3256354884b097155dff870900e74a84ca8e9102a74af067da041f413ca7\
//              593adb677c0d0d259ceed3083224fdc07fe88b2e1d64fd828fa0eeb5c3a1d9