// TODO: Huge hack just to get example to work.

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;
use std::{env, ptr, thread};

use libc::{c_char, c_int};
use log::{debug, trace};

use self::sandboxfs::Sandboxfs;
use crate::process::Child;
#[cfg(feature = "piped")]
use crate::process::ChildStderr;
#[cfg(any(feature = "piped", feature = "piped-merged"))]
use crate::process::{ChildStdin, ChildStdout};
use crate::{util, Sandbox};

mod sandboxfs;

const PROFILE_HEADER: &str = "(version 1)\n(deny default)\n(allow process*)\n";

pub fn create_sandbox(config: &Sandbox, command: &mut Command) -> Result<Child, Error> {
    let temp_dir = {
        let temp_dir = tempfile::tempdir()?;

        let uid = config.uid.unwrap_or_else(|| unsafe { libc::getuid() });
        let gid = config.gid.unwrap_or_else(|| unsafe { libc::getgid() });
        trace!("setting temp directory owner to uid({}), gid({})", uid, gid);
        let root = CString::new(temp_dir.path().as_os_str().as_bytes()).unwrap();
        util::catch_io_error(unsafe { libc::chown(root.as_ptr(), uid, gid) })?;

        temp_dir
    };

    let (mut tx, mut rx) = UnixStream::pair()?;
    #[cfg(any(feature = "piped", feature = "piped-merged"))]
    let (stdin_r, stdin_w) = os_pipe::pipe()?;
    #[cfg(any(feature = "piped", feature = "piped-merged"))]
    let (stdout_r, stdout_w) = os_pipe::pipe()?;
    #[cfg(feature = "piped")]
    let (stderr_r, stderr_w) = os_pipe::pipe()?;

    let sandbox_pid = util::catch_io_error(unsafe { libc::fork() })?;
    if sandbox_pid == 0 {
        drop(tx);
        #[cfg(any(feature = "piped", feature = "piped-merged"))]
        drop(stdin_w);
        #[cfg(any(feature = "piped", feature = "piped-merged"))]
        drop(stdout_r);
        #[cfg(feature = "piped")]
        drop(stderr_r);

        let mount_point = temp_dir.into_path().join("mnt");

        let mut buf = [0u8; 1];
        rx.read(&mut buf)?;
        rx.shutdown(Shutdown::Both)?;
        drop(rx);

        let real_uid = unsafe { libc::getuid() };
        util::catch_io_error(unsafe { libc::seteuid(0) })?;

        let old_cwd = env::current_dir()?;
        let chroot_dir = CString::new(mount_point.as_os_str().as_bytes()).unwrap();
        util::catch_io_error(unsafe { libc::chroot(chroot_dir.as_ptr()) })?;
        env::set_current_dir("/")?;
        env::set_var("PWD", "/");

        util::catch_io_error(unsafe { libc::seteuid(real_uid) })?;

        if let Some(gid) = config.gid {
            debug!("setting sandbox gid to {}", gid);
            util::catch_io_error(unsafe { libc::setgid(gid) })?;
        }

        if let Some(uid) = config.uid {
            debug!("setting sandbox uid to {}", uid);
            util::catch_io_error(unsafe { libc::setuid(uid) })?;
        }

        let mut profile = Profile::new();
        profile.push("(allow file-read* (subpath \"/\"))\n");
        profile.push("(allow file-write* (subpath \"/\"))\n");
        profile.push("(allow network-bind (local ip \"localhost:*\"))\n");
        profile.push("(allow network-inbound (local ip \"localhost:*\"))\n");
        profile.push("(allow sysctl-read)\n");

        // FIXME: Doesn't have much of an effect, since sandboxfs does not support device files.
        // Once that underlying limitation is resolved, this should be tested more vigorously.
        if config.allow_devices {
            profile.push("(allow file-ioctl (subpath \"/\"))\n");
        }

        if config.allow_network {
            profile.push("(allow network* (local ip) (local tcp) (local udp))\n");
            profile.push("(allow network* (remote ip) (remote tcp) (remote udp))\n");
            profile.push("(allow network* (remote unix-socket))\n");
            profile.push("(allow system-socket)\n");
        }

        // FIXME: Need to fix `ps` command here. Note that even when disabling the sandbox
        // completely, the command still doesn't seem to work inside of a chroot.
        if config.allow_sysctl {
            profile.push("(allow sysctl-write)\n");
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

            // FIXME: Commands are currently statically forced to run in either inherit or piped
            // mode until the `std::command::Command` builder offers some way to extract its fields
            // and inspect them at run-time.
            #[cfg(feature = "piped")]
            let error = command
                .stdin(stdin_r)
                .stdout(stdout_w)
                .stderr(stderr_w)
                .exec();
            #[cfg(feature = "piped-merged")]
            let error = command
                .stdin(stdin_r)
                .stdout(stdout_w.try_clone()?)
                .stderr(stdout_w)
                .exec();
            #[cfg(not(any(feature = "piped", feature = "piped-merged")))]
            let error = command.exec();

            Err(error)
        }
    } else {
        let fs_pid = util::catch_io_error(unsafe { libc::fork() })?;
        if fs_pid == 0 {
            #[cfg(any(feature = "piped", feature = "piped-merged"))]
            drop(stdin_w);
            #[cfg(any(feature = "piped", feature = "piped-merged"))]
            drop(stdout_r);
            #[cfg(feature = "piped")]
            drop(stderr_r);

            let mut sandboxfs = Sandboxfs::new(temp_dir)?;
            let mounts = sandboxfs.mount(&config)?;
            tx.write(&[0])?;

            loop {
                match util::catch_io_error(unsafe { libc::kill(sandbox_pid, 0) }) {
                    Ok(_) => thread::sleep(Duration::from_millis(10)),
                    Err(err) => match err.raw_os_error() {
                        Some(libc::EPERM) => thread::sleep(Duration::from_millis(10)),
                        Some(libc::ESRCH) => break,
                        _ => return Err(err),
                    },
                }
            }

            sandboxfs.unmount(mounts)?;
            drop(sandboxfs);

            std::process::exit(0)
        } else {
            temp_dir.into_path();

            #[cfg(any(feature = "piped", feature = "piped-merged"))]
            let stdin = ChildStdin(stdin_w);
            #[cfg(feature = "piped")]
            let stdout = ChildStdout(stdout_r);
            #[cfg(feature = "piped-merged")]
            let stdout = ChildStdout(stdout_r);
            #[cfg(feature = "piped")]
            let stderr = ChildStderr(stderr_r);
            #[cfg(feature = "piped-merged")]
            let stderr = None;
            #[cfg(not(any(feature = "piped", feature = "piped-merged")))]
            let (stdin, stdout, stderr) = (None, None, None);

            Ok(Child::from_parts(stdin, stdout, stderr, sandbox_pid))
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
