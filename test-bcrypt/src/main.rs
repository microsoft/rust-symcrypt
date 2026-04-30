use sha2::{Sha256, Digest};
use symcrypt::gcm::GcmExpandedKey;
use symcrypt::hash::{sha256, sha3_256, HashState, Sha256State};

fn main() {
    let input = b"hello world";

    // SHA-256 one-shot via BCrypt backend
    let our_digest = sha256(input);
    println!("SHA-256 (symcrypt): {}", hex::encode(&our_digest));

    // SHA-256 via sha2 crate for check
    let ref_digest = Sha256::digest(input);
    println!("SHA-256 (sha2):     {}", hex::encode(&ref_digest));
    assert_eq!(our_digest.as_slice(), ref_digest.as_slice(), "SHA-256 mismatch!");
    println!("SHA-256 match:      OK");

    // SHA-256 stateful via BCrypt backend
    let mut state = Sha256State::new();
    state.append(input);
    let stateful_digest = state.result();
    assert_eq!(our_digest, stateful_digest, "Stateful SHA-256 mismatch!");
    println!("SHA-256 stateful:   OK");

    // SHA-3 via BCrypt works on my machine, want to try on an older one.
    // notice result return, have to check error.
    match sha3_256(input) {
        Ok(digest) => println!("SHA3-256:           {}", hex::encode(&digest)),
        Err(e) => println!("SHA3-256:           ERR: {:?}", e),
    }

    // AES-GCM encrypt then decrypt
    let key = [0x42u8; 16];
    let nonce = [0u8; 12];
    let aad = b"additional data";
    let plaintext = b"secret message!!";

    let gcm = GcmExpandedKey::new(&key).unwrap();

    let mut buf = plaintext.to_vec();
    let mut tag = [0u8; 16];
    gcm.encrypt_in_place(&nonce, aad, &mut buf, &mut tag);
    println!("AES-GCM ciphertext: {}", hex::encode(&buf));
    println!("AES-GCM tag:        {}", hex::encode(&tag));

    gcm.decrypt_in_place(&nonce, aad, &mut buf, &tag).unwrap();
    println!("AES-GCM decrypted:  {}", String::from_utf8_lossy(&buf));

    // Tampered tag — should fail
    let mut bad_tag = tag;
    bad_tag[0] ^= 0xFF;
    match gcm.decrypt_in_place(&nonce, aad, &mut buf, &bad_tag) {
        Ok(_) => println!("AES-GCM bad tag:    ERR: should have failed"),
        Err(e) => println!("AES-GCM bad tag:    ERR: {:?}", e),
    }
}
