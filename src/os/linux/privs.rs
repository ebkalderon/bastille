use std::io::{Error, ErrorKind};

use caps::{CapSet, Capability, CapsHashSet};
use libc::uid_t;

use super::{IS_PRIVILEGED, REAL_UID, REQUESTED_CAPS, SANDBOX_UID};
use crate::util;

// This acquires the privileges that Bastille will need to work. If this binary is not setuid, then
// this does nothing, and it relies on unprivileged user namespaces to be used. This case is
// `IS_PRIVILEGED = FALSE`.
pub unsafe fn try_acquire_privs() -> Result<(), Error> {
    let effective_uid = libc::geteuid();
    let is_setuid = REAL_UID != effective_uid;

    if is_setuid {
        if effective_uid != 0 {
            let msg = format!("Unexpected setuid user {}, should be 0", effective_uid);
            return Err(Error::new(ErrorKind::Other, msg));
        }

        IS_PRIVILEGED = true;

        // We want to keep running as euid=0 until at the clone() operation because doing so will
        // make the user namespace be owned by root, which makes it not ptrace:able by the user as
        // it otherwise would be. After that we will run fully as the user, which is necessary
        // e.g. to be able to read from a fuse mount from the user.
        //
        // However, we don't want to accidentally mis-use euid=0 for escalated filesystem access
        // before the clone(), so we set fsuid to the uid.
        if libc::setfsuid(REAL_UID) < 0 {
            return Err(Error::new(ErrorKind::Other, "Unable to set fsuid"));
        }

        // setfsuid can't properly report errors, check that it worked (as per manpage).
        let new_fsuid = libc::setfsuid(-1i32 as uid_t) as uid_t;
        if new_fsuid != REAL_UID {
            let msg = format!("Unable to set fsuid (was {})", new_fsuid);
            return Err(Error::new(ErrorKind::Other, msg));
        }

        // We never need capabilities after execve(), so lets drop everything from the bounding
        // set.
        drop_cap_bounding_set(true)?;
        // Keep only the required capabilities for setup.
        set_required_caps()?;
    } else if REAL_UID != 0 && has_caps()? {
        // We have some capabilities in the non-setuid case, which should not happen. Probably
        // caused by the binary being setcap instead of setuid which we don't support anymore.
        let msg = "Unexpected capabilities but not setuid, maybe old file caps config?";
        return Err(Error::new(ErrorKind::Other, msg));
    } else {
        if REAL_UID == 0 {
            // If our uid is 0, default to inheriting all caps.
            let effective = caps::read(None, CapSet::Effective)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            REQUESTED_CAPS = effective.into_iter().collect();
        } else {
            // No worries, we will try unprivileged user namespaces later on.
        }
    }

    // Never gain any more privileges during exec.
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        let msg = "Failed to enable PR_SET_NO_NEW_PRIVS";
        return Err(Error::new(ErrorKind::Other, msg));
    }

    Ok(())
}

// This is called once we're inside the namespace.
pub unsafe fn switch_to_user_with_privs() -> Result<(), Error> {
    // If we're in a new user namespace, we got back the bounding set, clear it again.
    drop_cap_bounding_set(false)?;
    if !IS_PRIVILEGED {
        return Ok(());
    }

    // Tell kernel not clear capabilities when later dropping root uid.
    util::catch_io_error(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0))?;
    util::catch_io_error(libc::setuid(SANDBOX_UID))?;

    // Regain effective required capabilities from permitted.
    set_required_caps()?;

    Ok(())
}

unsafe fn drop_cap_bounding_set(drop_all: bool) -> Result<(), Error> {
    if drop_all {
        prctl_caps(&[], true, false)
    } else {
        prctl_caps(REQUESTED_CAPS.as_slice(), true, false)
    }
}

unsafe fn set_required_caps() -> Result<(), Error> {
    let mut required = CapsHashSet::new();
    required.insert(Capability::CAP_NET_ADMIN);
    required.insert(Capability::CAP_SETGID);
    required.insert(Capability::CAP_SETUID);
    required.insert(Capability::CAP_SYS_ADMIN);
    required.insert(Capability::CAP_SYS_CHROOT);
    required.insert(Capability::CAP_SYS_PTRACE);
    caps::set(None, CapSet::Effective, required.clone())
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    caps::set(None, CapSet::Permitted, required)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    caps::set(None, CapSet::Inheritable, CapsHashSet::new())
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    Ok(())
}

unsafe fn has_caps() -> Result<bool, Error> {
    caps::read(None, CapSet::Permitted)
        .map(|c| !c.is_empty())
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}

unsafe fn prctl_caps(
    caps: &[Capability],
    do_bounding_set: bool,
    do_ambient_set: bool,
) -> Result<(), Error> {
    for cap in &caps::all() {
        let should_keep = caps.contains(cap);

        let is_ambient_supported = caps::runtime::ambient_set_supported().is_ok();
        if should_keep && do_ambient_set && is_ambient_supported {
            if caps::raise(None, CapSet::Ambient, *cap).is_err() {
                let error = Error::last_os_error();
                match error.kind() {
                    ErrorKind::InvalidInput | ErrorKind::PermissionDenied => {}
                    _ => return Err(error),
                }
            }
            // println!("raising ambient capability {}", cap);
        }

        if !should_keep && do_bounding_set {
            if caps::drop(None, CapSet::Bounding, *cap).is_err() {
                let error = Error::last_os_error();
                match error.kind() {
                    ErrorKind::InvalidInput | ErrorKind::PermissionDenied => {}
                    _ => return Err(error),
                }
            }
            // println!("dropping bounding capability {}", cap);
        }
    }

    Ok(())
}
