use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{env, ptr};

use libc::{c_char, c_int};
use log::debug;

use crate::process::Child;
use crate::{util, Sandbox};

const PROFILE_HEADER: &'static str = "(version 1)\n(deny default)\n(allow process-fork)\n";

pub fn create_sandbox(config: &Sandbox, command: &mut Command) -> Result<Child, Error> {
    let pid = util::catch_io_error(unsafe { libc::fork() })?;
    if pid == 0 {
        let old_cwd = env::current_dir()?;
        env::set_current_dir("/")?;
        env::set_var("PWD", "/");

        let mut profile = Profile::new();
        profile.push("(allow file-read* (subpath \"/\"))\n");
        profile.push("(allow process-exec (subpath \"/\"))\n");

        if config.allow_devices {
            profile.push("(allow file-ioctl (subpath \"/\"))\n");
        }

        let mut error_buf = ptr::null_mut();
        let c_str = profile.to_cstring();
        if unsafe { sandbox_init(c_str.as_ptr(), 0, &mut error_buf) } == -1 {
            let raw_error = unsafe { CStr::from_ptr(error_buf) };
            let error = Error::new(ErrorKind::Other, raw_error.to_string_lossy());
            unsafe { sandbox_free_error(error_buf) };
            Err(error)
        } else {
            if old_cwd.exists() {
                env::set_current_dir(&old_cwd)?;
                env::set_var("PWD", old_cwd);
            } else if let Ok(home) = env::var("HOME") {
                if env::set_current_dir(&home).is_ok() {
                    env::set_var("PWD", home);
                }
            }

            Err(command.exec())
        }
    } else {
        Ok(Child::from_parts(None, None, None, pid))
    }
}

#[derive(Debug)]
pub struct Profile<'a>(Cow<'a, str>);

impl<'a> Profile<'a> {
    pub fn new() -> Self {
        Profile(PROFILE_HEADER.into())
    }

    pub fn push(&mut self, lines: &'a str) {
        self.0 += lines
    }

    pub fn to_cstring(&self) -> CString {
        debug!("generated sandbox profile: {}", self.0.replace("\n", "\\n"));
        CString::new(self.0.as_bytes()).expect("string contained invalid bytes")
    }
}

#[link(name = "c")]
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}
