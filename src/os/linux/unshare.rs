use std::ffi::CString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Error, ErrorKind, Read};
use std::os::unix;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::{env, ptr};

use libc::{c_char, c_int, c_ulong, c_void, pid_t};
use libmount::mountinfo;
use log::debug;
use openat::Dir;

use super::{IS_PRIVILEGED, PROC_DIR};
use crate::{util, Mapping, Sandbox};

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
    if !config.allow_sysctl {
        unshare_flags |= libc::CLONE_NEWPID;
    }
    if !config.allow_network {
        unshare_flags |= libc::CLONE_NEWNET;
    }

    util::catch_io_error(raw_clone(unshare_flags, ptr::null_mut()))
        .map_err(|_| Error::new(ErrorKind::Other, "Unable to clone() process"))
}

unsafe fn raw_clone(flags: c_int, child_stack: *mut c_void) -> c_int {
    libc::syscall(libc::SYS_clone, flags as c_ulong, child_stack) as c_int
}

pub unsafe fn setup_environment(config: &Sandbox) -> Result<(), Error> {
    // Need to do this before the chroot, but after we're the real uid.
    let mappings = config.mappings.resolve_symlinks()?;

    // Mark everything as slave, so that we still receive mounts from the real root, but don't
    // propagate mounts to the real root.
    let root = CString::new("/".as_bytes())?;
    util::catch_io_error(libc::mount(
        ptr::null(),
        root.as_ptr(),
        ptr::null(),
        libc::MS_SLAVE | libc::MS_REC,
        ptr::null(),
    ))?;

    // Create a tmpfs which we will use as / in the namespace.
    let base_path = CString::new("/tmp".as_bytes())?;
    let tmpfs = CString::new("tmpfs".as_bytes())?;
    util::catch_io_error(libc::mount(
        tmpfs.as_ptr(),
        base_path.as_ptr(),
        tmpfs.as_ptr(),
        libc::MS_NODEV | libc::MS_NOSUID,
        ptr::null(),
    ))?;

    // Chdir to the new root tmpfs mount. This will be the CWD during the entire setup. Access old
    // or new root via "old_root" and "new_root".
    let old_cwd = env::current_dir()?;
    env::set_current_dir("/tmp")?;

    // We create a subdir "$base_path/new_root" for the new root, that way we can `pivot_root()` to
    // `base_path`, and put the old root at "$base_path/old_root". This avoids problems accessing
    // the `old_root` dir if the user requested to bind mount something over `/` (or over `/tmp`,
    // now that we use that for `base_path`).

    let new_root = "new_root";
    DirBuilder::new().mode(0o0755).create(&new_root)?;

    let new_root = CString::new(new_root)?;
    util::catch_io_error(libc::mount(
        new_root.as_ptr(),
        new_root.as_ptr(),
        ptr::null(),
        libc::MS_MGC_VAL | libc::MS_BIND | libc::MS_REC,
        ptr::null(),
    ))?;

    let old_root = "old_root";
    DirBuilder::new().mode(0o0755).create(&old_root)?;

    // NB: This is our first pivot to `old_root`!
    let old_root = CString::new(old_root)?;
    util::catch_io_error(pivot_root(base_path.as_ptr(), old_root.as_ptr()))?;
    env::set_current_dir("/")?;

    if IS_PRIVILEGED {
        // TODO: Need to fork process and run the code below using an unprivileged socket.
        setup_new_root(&config, mappings.as_slice())?;
    } else {
        setup_new_root(&config, mappings.as_slice())?;
    }

    // The old root better be rprivate or we will send unmount events to the parent namespace.
    util::catch_io_error(libc::mount(
        old_root.as_ptr(),
        old_root.as_ptr(),
        ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        ptr::null(),
    ))?;

    // Detach the old root.
    util::catch_io_error(libc::umount2(old_root.as_ptr(), libc::MNT_DETACH))?;

    // NB: This is our second pivot!
    //
    // We're aiming to make `/new_root` the real root, and get rid of `/old_root`. To do this, we
    // need a temporary place to store it before we can unmount it.
    let old_root_dir = Dir::open("/")?;
    env::set_current_dir("/new_root")?;

    // While the documentation claims that put_old must be underneath
    // new_root, it is perfectly fine to use the same directory as the
    // kernel checks only if old_root is accessible from new_root.

    // Both runc and LXC are using this "alternative" method for
    // setting up the root of the container:

    // https://github.com/opencontainers/runc/blob/master/libcontainer/rootfs_linux.go#L671
    // https://github.com/lxc/lxc/blob/master/src/lxc/conf.c#L1121
    let dot = CString::new(".".as_bytes())?;
    util::catch_io_error(pivot_root(dot.as_ptr(), dot.as_ptr()))?;
    util::catch_io_error(libc::fchdir(old_root_dir.as_raw_fd()))?;
    util::catch_io_error(libc::umount2(dot.as_ptr(), libc::MNT_DETACH))?;
    env::set_current_dir("/")?;
    env::set_var("PWD", "/");

    debug!("environment created successfully!");

    // FIXME: This is a hack need to call this after the umask is reset to the old value.
    if old_cwd.exists() {
        env::set_current_dir(&old_cwd)?;
        env::set_var("PWD", old_cwd);
    } else if let Ok(home) = env::var("HOME") {
        if env::set_current_dir(&home).is_ok() {
            env::set_var("PWD", home);
        }
    }

    Ok(())
}

unsafe fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    libc::syscall(libc::SYS_pivot_root, new_root, put_old) as c_int
}

unsafe fn setup_new_root(config: &Sandbox, mappings: &[Mapping]) -> Result<(), Error> {
    for mapping in mappings {
        let source = mapping
            .host
            .strip_prefix("/")
            .map(|p| Path::new("/old_root").join(p))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let dest = mapping
            .sandbox
            .strip_prefix("/")
            .map(|p| Path::new("/new_root").join(p))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        if source.is_dir() {
            DirBuilder::new()
                .mode(0o755)
                .recursive(true)
                .create(&dest)?;
        } else {
            if let Some(parent) = dest.parent() {
                DirBuilder::new()
                    .mode(0o755)
                    .recursive(true)
                    .create(&parent)?;
            }

            OpenOptions::new()
                .mode(0o666)
                .write(true)
                .create(true)
                .open(&dest)?;
        }

        bind_mount(
            &source,
            &dest,
            mapping.writable,
            config.allow_dev_read,
            config.allow_sysctl,
        )?;
    }

    for (source, dest) in &config.soft_links {
        let dest = dest
            .strip_prefix("/")
            .map(|p| Path::new("/new_root").join(p))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        if let Some(parent) = dest.parent() {
            DirBuilder::new()
                .mode(0o755)
                .recursive(true)
                .create(&parent)?;
        }

        debug!("symlinking {:?} -> {:?}", source, dest);
        unix::fs::symlink(&source, &dest)?;
    }

    for dir in &config.directories {
        let dir = dir
            .strip_prefix("/")
            .map(|p| Path::new("/new_root").join(p))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        debug!("creating new directory {:?}", dir);
        DirBuilder::new().mode(0o755).recursive(true).create(dir)?;
    }

    Ok(())
}

fn bind_mount(
    source: &Path,
    dest: &Path,
    writable: bool,
    allow_dev: bool,
    allow_proc: bool,
) -> Result<(), Error> {
    debug!("mounting {:?} -> {:?}", source, dest);

    util::catch_io_error(unsafe {
        libc::mount(
            CString::new(source.as_os_str().as_bytes())?.as_ptr() as *const c_char,
            CString::new(dest.as_os_str().as_bytes())?.as_ptr() as *const c_char,
            ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            ptr::null(),
        )
    })?;

    let mount_info = unsafe {
        let proc = PROC_DIR
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Other, "Expected /proc to be open"))?;
        let proc_self = proc.read_link("self")?;
        let mut mount_info = proc.open_file(&proc_self.join("mountinfo"))?;

        let mut buf = Vec::new();
        mount_info.read_to_end(&mut buf)?;
        buf
    };

    let mut mount_points: Vec<_> = mountinfo::Parser::new(mount_info.as_slice())
        .map(|mount| mount.map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string())))
        .collect::<Result<_, _>>()?;

    mount_points.retain(|mount| Path::new(&mount.mount_point).starts_with(&dest));

    let root_mount_point = mount_points.remove(0);
    if root_mount_point.fstype.to_string_lossy() == "proc" && !allow_proc {
        let msg = "Mounting procfs is not permitted";
        return Err(Error::new(ErrorKind::PermissionDenied, msg));
    }

    let current_flags = root_mount_point.get_flags();
    let mut flags = current_flags | libc::MS_NOSUID;
    if !allow_dev {
        flags |= libc::MS_NODEV;
    }
    if !writable {
        flags |= libc::MS_RDONLY;
    }

    if flags != current_flags {
        let none = CString::new("none".as_bytes())?;
        let dest = CString::new(dest.as_os_str().as_bytes())?;
        util::catch_io_error(unsafe {
            libc::mount(
                none.as_ptr(),
                dest.as_ptr(),
                ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | flags,
                ptr::null(),
            )
        })?;
    }

    // We need to work around the fact that a bind mount does not apply the flags, so we need to
    // manually apply the flags to all submounts in the recursive case. Note: This does not apply
    // the flags to mounts which are later propagated into this namespace.
    for mount in mount_points {
        let current_flags = root_mount_point.get_flags();
        let mut flags = current_flags | libc::MS_NOSUID;
        if !allow_dev {
            flags |= libc::MS_NODEV;
        }
        if !writable {
            flags |= libc::MS_RDONLY;
        }

        if flags != current_flags {
            let none = CString::new("none".as_bytes())?;
            let dest = CString::new(mount.mount_point.as_bytes())?;
            util::catch_io_error(unsafe {
                libc::mount(
                    none.as_ptr(),
                    dest.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | flags,
                    ptr::null(),
                )
            })?;
        }
    }

    Ok(())
}
