//! Functions for Cbc encryption and decryption. For more info please see symcrypt.h
//! 
//! 
//! 
use crate::errors::SymCryptError;
use crate::cipher::{BlockCipherType, convert_cipher, AesExpandedKey};
use symcrypt_sys;



pub fn cbc_aes_encrypt() { 

}

pub fn cbc_aes_decrypt() { 

}



// SYMCRYPT_ERROR
// SYMCRYPT_CALL
// SymCryptAesExpandKey(
//     _Out_               PSYMCRYPT_AES_EXPANDED_KEY  pExpandedKey,
//     _In_reads_(cbKey)   PCBYTE                      pbKey,
//                         SIZE_T                      cbKey );
// SYMCRYPT_ERROR
// SYMCRYPT_CALL
// SymCryptAesExpandKey(
//     _Out_               PSYMCRYPT_AES_EXPANDED_KEY  pExpandedKey,
//     _In_reads_(cbKey)   PCBYTE                      pbKey,
//                         SIZE_T                      cbKey );


// SYMCRYPT_CALL
// SymCryptXxxCbcEncrypt(
//      _In_                                        PCSYMCRYPT_XXX_EXPANDED_KEY pExpandedKey,
//      _Inout_updates_( SYMCRYPT_XXX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
//      _In_reads_( cbData )                        PCBYTE                      pbSrc,
//      _Out_writes_( cbData )                      PBYTE                       pbDst,
//                                                  SIZE_T                      cbData );
//
//      Encrypt data using the CBC chaining mode.
//      On entry the pbChainingValue is the IV which is xorred into the first plaintext block of the CBC encryption.
//      On exit the pbChainingValue is updated to the last ciphertext block of the result.
//      This allows a longer CBC encryption to be done incrementally.
//
//      cbData must be a multiple of the block size. For efficiency reasons this routine does not return an error
//      if cbData is not a proper multiple; instead the result is undefined. The routine might hang,
//      round cbData down to a multiple of the block size, or return random data that cannot be decrypted.
//
//      The pbSrc and pbDst buffers may be the same, or they may be non-overlapping. However, they may
//      not be partially overlapping.
//
//
// VOID
// SYMCRYPT_CALL
// SymCryptXxxCbcDecrypt(
//      _In_                                        PCSYMCRYPT_XXX_EXPANDED_KEY pExpandedKey,
//      _Inout_updates_( SYMCRYPT_XXX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
//      _In_reads_( cbData )                        PCBYTE                      pbSrc,
//      _Out_writes_( cbData )                      PBYTE                       pbDst,
//                                                  SIZE_T                      cbData );
//
//      Decrypt data using the CBC chaining mode.
//      On entry the pbChainingValue is the IV to be xorred into the first plaintext block of the CBC decryption.
//      On exit the pbChainingValue is updated to the last ciphertext block of the input.
//      This allows a longer CBC decryption to be done incrementally.
//
//      cbData must be a multiple of the block size. For efficiency reasons this routine does not return an error
//      if cbData is not a proper multiple; instead the result is undefined. The routine might hang,
//      round cbData down to a multiple of the block size, or return random data.
//
//      The pbSrc and pbDst buffers may be the same, or they may be non-overlapping. However, they may
//      not be partially overlapping.
//
//

// VOID
// SYMCRYPT_CALL
// SymCryptAesCbcEncrypt(
//     _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
//     _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
//     _In_reads_( cbData )                        PCBYTE                      pbSrc,
//     _Out_writes_( cbData )                      PBYTE                       pbDst,
//                                                 SIZE_T                      cbData );

// VOID
// SYMCRYPT_CALL
// SymCryptAesCbcDecrypt(
//     _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
//     _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
//     _In_reads_( cbData )                        PCBYTE                      pbSrc,
//     _Out_writes_( cbData )                      PBYTE                       pbDst,
//                                                 SIZE_T                      cbData );



// # files CBCGFSbox*
// COUNT = 0
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
// CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

// COUNT = 1
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = 9798c4640bad75c7c3227db910174e72
// CIPHERTEXT = a9a1631bf4996954ebc093957b234589

// COUNT = 2
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = 96ab5c2ff612d9dfaae8c31f30c42168
// CIPHERTEXT = ff4f8391a6a40ca5b25d23bedd44a597

// COUNT = 3
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = 6a118a874519e64e9963798a503f1d35
// CIPHERTEXT = dc43be40be0e53712f7e2bf5ca707209

// COUNT = 4
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = cb9fceec81286ca3e989bd979b0cb284
// CIPHERTEXT = 92beedab1895a94faa69b632e5cc47ce

// COUNT = 5
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = b26aeb1874e47ca8358ff22378f09144
// CIPHERTEXT = 459264f4798f6a78bacb89c15ed3d601

// COUNT = 6
// KEY = 00000000000000000000000000000000
// IV = 00000000000000000000000000000000
// PLAINTEXT = 58c8e00b2631686d54eab84b91f0aca1
// CIPHERTEXT = 08a4e2efec8a8e3312ca7460b9040bbf