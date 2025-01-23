use jitterentropy_sys2::*;

#[test]
fn basic_test() {
    let result = unsafe { jent_entropy_init() };
    assert_eq!(
        result, 0,
        "jent_entropy_init failed with result: {}",
        result
    );

    let collector = unsafe { jent_entropy_collector_alloc(0, 0) };
    assert!(
        !collector.is_null(),
        "jent_entropy_collector_alloc returned null"
    );

    let mut buffer = vec![0 as ::std::os::raw::c_char; 16];
    let result = unsafe { jent_read_entropy(collector, buffer.as_mut_ptr(), buffer.len()) };
    assert!(
        result > 0,
        "jent_read_entropy failed with result: {}",
        result
    );

    unsafe { jent_entropy_collector_free(collector) };
}
