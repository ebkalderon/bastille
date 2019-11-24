use std::fs;
use std::io::{Error, ErrorKind, Write};

use libc::{c_uint, gid_t, pid_t, uid_t};

use super::{IS_PRIVILEGED, OVERFLOW_GID, OVERFLOW_UID, PROC_DIR};
use crate::util;

pub unsafe fn read_overflow_ids() -> Result<(), Error> {
    let buf = fs::read_to_string("/proc/sys/kernel/overflowuid")?;
    OVERFLOW_UID = buf
        .trim()
        .parse()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    let buf = fs::read_to_string("/proc/sys/kernel/overflowgid")?;
    OVERFLOW_GID = buf
        .trim()
        .parse()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    Ok(())
}

pub unsafe fn write_uid_gid_map(
    sandbox_uid: uid_t,
    sandbox_gid: gid_t,
    parent_uid: uid_t,
    parent_gid: gid_t,
    pid: Option<pid_t>,
    deny_groups: bool,
    map_root: bool,
) -> Result<(), Error> {
    let ns_dir = {
        let pid = pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "self".to_string());

        let proc = PROC_DIR
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Expected /proc to be open"))?;

        proc.read_link(pid).and_then(|path| proc.sub_dir(&path))?
    };

    let uid_map = if map_root && parent_uid != 0 && sandbox_uid != 0 {
        format!("0 {} 1\n{} {} 1\n", OVERFLOW_UID, sandbox_uid, parent_uid)
    } else {
        format!("{} {} 1\n", sandbox_uid, parent_uid)
    };

    let gid_map = if map_root && parent_gid != 0 && sandbox_gid != 0 {
        format!("0 {} 1\n{} {} 1\n", OVERFLOW_GID, sandbox_gid, parent_gid)
    } else {
        format!("{} {} 1\n", sandbox_gid, parent_gid)
    };

    // We have to be root to be allowed to write to the uid map for setuid apps, so temporary set
    // fsuid to 0.
    let old_fsuid = if IS_PRIVILEGED {
        Some(util::catch_io_error(libc::setfsuid(0))? as c_uint)
    } else {
        None
    };

    ns_dir
        .update_file("uid_map", 0)
        .and_then(|mut file| file.write_all(uid_map.as_bytes()))
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to set up uid map"))?;

    if deny_groups {
        let setgroups = ns_dir.update_file("setgroups", 0);
        if let Err(err) = setgroups.and_then(|mut file| file.write_all(b"deny\n")) {
            // If /proc/[pid]/setgroups does not exist, assume we are
            // running a linux kernel < 3.19, i.e. we live with the
            // vulnerability known as CVE-2014-8989 in older kernels
            // where setgroups does not exist.
            match err.kind() {
                ErrorKind::NotFound => {}
                _ => return Err(Error::new(ErrorKind::Other, "Error writing to setgroups")),
            }
        }
    }

    ns_dir
        .update_file("gid_map", 0)
        .and_then(|mut file| file.write_all(gid_map.as_bytes()))
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to set up gid map"))?;

    if let Some(old) = old_fsuid {
        util::catch_io_error(libc::setfsuid(old))?;
    }

    Ok(())
}
