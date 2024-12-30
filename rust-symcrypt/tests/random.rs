#[test]
fn test_random() {
    const N : usize = 256;
    let mut buf = [0u8; N];
    symcrypt::symcrypt_random(&mut buf);
    assert_ne!(buf, [0u8; N]);
}