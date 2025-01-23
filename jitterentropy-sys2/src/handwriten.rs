#![allow(non_camel_case_types)]

/// The entropy pool
// https://stackoverflow.com/a/38315613
#[repr(C)]
pub struct rand_data {
    _data: [u8; 0],
    _marker:
        core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}
