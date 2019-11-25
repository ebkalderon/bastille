use std::io::Error;
use std::process::Command;

use libc::{c_char, c_int};

use crate::process::Child;
use crate::Sandbox;

const SANDBOX_STRING: u64 = 0;

pub fn create_sandbox(config: &Sandbox, command: &mut Command) -> Result<Child, Error> {
    unimplemented!()
}

#[link(name = "c")]
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}
