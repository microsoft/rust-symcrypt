#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

// Output the raw, un-modified bindings.
include!(concat!(env!("OUT_DIR"), "/raw_generated_bindings.rs"));
