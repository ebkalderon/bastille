use std::fs;
use std::io::{Error, ErrorKind, Write};

use libc::{c_uint, gid_t, pid_t, uid_t};

use super::{IS_PRIVILEGED, OVERFLOW_GID, OVERFLOW_UID, PROC_DIR};
use crate::catch_io_error;

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
        PROC_DIR
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Expected /proc descriptor to be open"))
            .and_then(|proc| proc.sub_dir(format!("{}/ns", pid)))?
    };

    let uid_map = if map_root && parent_uid != 0 && sandbox_uid != 0 {
        format!("0 {} 1\n{} {} 1", OVERFLOW_UID, sandbox_uid, parent_uid)
    } else {
        format!("{} {} 1", sandbox_uid, parent_uid)
    };

    let gid_map = if map_root && parent_gid != 0 && sandbox_gid != 0 {
        format!("0 {} 1\n{} {} 1", OVERFLOW_GID, sandbox_gid, parent_gid)
    } else {
        format!("{} {} 1", sandbox_gid, parent_gid)
    };

    // We have to be root to be allowed to write to the uid map for setuid apps, so temporary set
    // fsuid to 0.
    let old_fsuid = if IS_PRIVILEGED {
        Some(catch_io_error(libc::setfsuid(0))? as c_uint)
    } else {
        None
    };

    ns_dir
        .write_file("uid_map", 0)
        .and_then(|mut f| writeln!(f, "{}", uid_map))?;

    if deny_groups {
        let setgroups = ns_dir.write_file("setgroups", 0);
        if let Err(err) = setgroups.and_then(|mut f| writeln!(f, "deny")) {
            // If /proc/[pid]/setgroups does not exist, assume we are
            // running a linux kernel < 3.19, i.e. we live with the
            // vulnerability known as CVE-2014-8989 in older kernels
            // where setgroups does not exist.
            match err.kind() {
                ErrorKind::NotFound => {}
                _ => return Err(err),
            }
        }
    }

    ns_dir
        .write_file("gid_map", 0)
        .and_then(|mut f| writeln!(f, "{}", gid_map))?;

    if let Some(old) = old_fsuid {
        catch_io_error(libc::setfsuid(old))?;
    }

    Ok(())
}
