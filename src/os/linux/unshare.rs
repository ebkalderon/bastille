use std::io::{Error, ErrorKind};
use std::{fs, ptr};

use libc::{c_int, c_ulong, c_void, pid_t};

use crate::{util, Sandbox};

pub unsafe fn clone_process(config: &Sandbox) -> Result<pid_t, Error> {
    fs::metadata("/proc/self/ns/user")
        .map_err(|_| Error::new(ErrorKind::Other, "User namespaces are unsupported"))?;

    if let Ok(max) = fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        let max_user_ns: i32 = max
            .trim()
            .parse()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        if max_user_ns == 0 {
            let msg = "Max user namespaces is set to 0";
            return Err(Error::new(ErrorKind::Other, msg));
        }
    }

    let mut unshare_flags = libc::SIGCHLD | libc::CLONE_NEWNS | libc::CLONE_NEWUSER;
    if !config.enable_sysctl {
        unshare_flags |= libc::CLONE_NEWPID;
    }
    if !config.enable_network {
        unshare_flags |= libc::CLONE_NEWNET;
    }

    util::catch_io_error(raw_clone(unshare_flags, ptr::null_mut()))
        .map_err(|_| Error::new(ErrorKind::Other, "Unable to call raw_clone()"))
}

unsafe fn raw_clone(flags: c_int, child_stack: *mut c_void) -> c_int {
    libc::syscall(libc::SYS_clone, flags as c_ulong, child_stack) as c_int
}
