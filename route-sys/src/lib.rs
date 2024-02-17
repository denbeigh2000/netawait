#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// #![allow(non_upper_case_globals)]
// #![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
// #![allow(dead_code)]
// pub use bindings::*;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// mod bindings;
// pub use bindings::*;
