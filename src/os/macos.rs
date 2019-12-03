// TODO: Huge hack just to get example to work.

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::thread::JoinHandleExt;
use std::process::Command;
use std::time::Duration;
use std::{env, fs, process, ptr, thread};

use libc::{c_char, c_int};
use log::debug;
use sandboxfs::Mapping;
use time::Timespec;

use crate::process::Child;
use crate::{util, Sandbox};

const PROFILE_HEADER: &str = "(version 1)\n(deny default)\n(allow process-fork)\n";

pub fn create_sandbox(config: &Sandbox, command: &mut Command) -> Result<Child, Error> {
    let temp_dir = tempfile::tempdir().unwrap();
    let mount_point = temp_dir.path().join("mnt");

    let sandbox_pid = util::catch_io_error(unsafe { libc::fork() })?;
    if sandbox_pid == 0 {
        temp_dir.into_path();

        while !mount_point.join("bin").exists() {
            thread::sleep(Duration::from_millis(10));
        }

        let old_cwd = env::current_dir()?;
        let chroot_dir = CString::new(mount_point.as_os_str().as_bytes()).unwrap();
        util::catch_io_error(unsafe { libc::chroot(chroot_dir.as_ptr()) })?;
        env::set_current_dir("/")?;
        env::set_var("PWD", "/");

        let mut profile = Profile::new();
        profile.push("(allow file-read* (subpath \"/\"))\n");
        profile.push("(allow file-write* (subpath \"/\"))\n");
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
        let fs_pid = util::catch_io_error(unsafe { libc::fork() })?;
        if fs_pid == 0 {
            fs::create_dir_all(&mount_point)?;

            let (read, write) = os_pipe::pipe()?;
            let read = unsafe { File::from_raw_fd(read.into_raw_fd()) };
            let write = unsafe { File::from_raw_fd(write.into_raw_fd()) };

            let handle = thread::spawn(move || {
                sandboxfs::mount(
                    &mount_point,
                    &["-o", "fs=sandboxfs"],
                    &[
                        Mapping::from_parts("/bin".into(), "/bin".into(), false).unwrap(),
                        Mapping::from_parts("/usr".into(), "/usr".into(), false).unwrap(),
                    ],
                    Timespec::new(60, 0),
                    read,
                    write,
                )
                .expect_err("sandboxfs should not exit success")
            });

            while util::catch_io_error(unsafe { libc::kill(sandbox_pid, 0) }).unwrap_or(1) == 0 {
                thread::sleep(Duration::from_millis(10));
            }

            let thread = handle.as_pthread_t();
            if unsafe { libc::pthread_kill(thread, libc::SIGHUP) } != 0 {
                eprintln!("failed to send SIGHUP to sandboxfs thread");
            }

            handle.join().expect("failed to join on sandboxfs thread");
            drop(temp_dir);
            process::exit(0)
        } else {
            temp_dir.into_path();
            Ok(Child::from_parts(None, None, None, sandbox_pid))
        }
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
