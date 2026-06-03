//! Integration tests for the public hash API.
//!
//! Every test here hits `loader_poc::hash::*`, which forces the
//! lazy loader to: extract symcrypt.dll → LoadLibraryExW → resolve four
//! function pointers via GetProcAddress → call them.  If any link in the
//! pipeline is broken, these tests fail with a clear error.

use loader_poc::hash::{sha256, Sha256State};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---- One-shot vectors ----

#[test]
fn one_shot_empty() {
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn one_shot_abc() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn one_shot_hello_world() {
    assert_eq!(
        hex(&sha256(b"hello world")),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

/// 1 MiB of zeros — exercises SymCrypt's multi-block streaming code path.
/// If `include_bytes!` truncated the DLL or extraction corrupted it, single-
/// block tests can still pass but this one will diverge.
#[test]
fn one_shot_1mib_zeros() {
    let input = vec![0u8; 1024 * 1024];
    assert_eq!(
        hex(&sha256(&input)),
        "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
    );
}

// ---- Streaming API ----

#[test]
fn streaming_matches_one_shot() {
    let one = sha256(b"hello world");
    let mut s = Sha256State::new();
    s.append(b"hello world");
    let streamed = s.result();
    assert_eq!(one, streamed);
}

#[test]
fn streaming_multi_append() {
    let mut s = Sha256State::new();
    s.append(b"hello");
    s.append(b" ");
    s.append(b"world");
    assert_eq!(s.result(), sha256(b"hello world"));
}

#[test]
fn streaming_empty_then_finish() {
    let s = Sha256State::new();
    assert_eq!(s.result(), sha256(b""));
}

/// Concurrent use of independent states must not interfere.  Proves the
/// per-instance state isolation and that the loaded DLL handles concurrent
/// calls from multiple threads.
#[test]
fn streaming_two_threads_independent_states() {
    let h1 = std::thread::spawn(|| {
        let mut s = Sha256State::new();
        for _ in 0..1000 {
            s.append(b"abc");
        }
        s.result()
    });
    let h2 = std::thread::spawn(|| {
        let mut s = Sha256State::new();
        for _ in 0..1000 {
            s.append(b"abc");
        }
        s.result()
    });
    let a = h1.join().unwrap();
    let b = h2.join().unwrap();
    assert_eq!(a, b, "two threads hashing the same input got different digests");
}
