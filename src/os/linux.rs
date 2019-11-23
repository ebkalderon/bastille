//! FIXME: Need to refactor this to be safer. Currently we are following the design of Bubblewrap
//! very closely until feature parity, but refactoring to a safer Rust API will follow.

use std::io::{Error, ErrorKind};
use std::os::unix::process::CommandExt;
use std::process::Command;

use caps::Capability;
use ipc_channel::ipc;
use libc::{gid_t, uid_t};
use openat::Dir;

use crate::process::Child;
#[cfg(feature = "piped")]
use crate::process::{ChildStderr, ChildStdin, ChildStdout};
use crate::Sandbox;

mod creds;
mod net;
mod privs;
mod unshare;

// Used by `privs::try_acquire_privs()`.
static mut REAL_UID: uid_t = 0;
static mut REAL_GID: gid_t = 0;
static mut OVERFLOW_UID: uid_t = 0;
static mut OVERFLOW_GID: gid_t = 0;
static mut IS_PRIVILEGED: bool = false;
static mut REQUESTED_CAPS: Vec<Capability> = Vec::new();

static mut SANDBOX_UID: uid_t = -1i32 as uid_t;
static mut SANDBOX_GID: gid_t = -1i32 as gid_t;
static mut PROC_DIR: Option<Dir> = None;

pub fn create_sandbox(config: &Sandbox, command: &mut Command) -> Result<Child, Error> {
    unsafe {
        REAL_UID = libc::getuid();
        REAL_GID = libc::getgid();

        // Note that `setfsuid` and `capset` are per-thread rather than per-process, so acquiring
        // privileges should be safe in multithreaded scenarios with multiple sandboxes spawning! 🎉
        privs::try_acquire_privs()?;
        creds::read_overflow_ids()?;
        open_proc_dir()?;

        SANDBOX_UID = config.uid.map(|uid| uid as uid_t).unwrap_or(REAL_UID);
        SANDBOX_GID = config.gid.map(|gid| gid as gid_t).unwrap_or(REAL_GID);

        let (tx, rx) = ipc::channel()?;
        #[cfg(feature = "piped")]
        let (stdin_r, stdin_w) = os_pipe::pipe()?;
        #[cfg(feature = "piped")]
        let (stdout_r, stdout_w) = os_pipe::pipe()?;
        #[cfg(feature = "piped")]
        let (stderr_r, stderr_w) = os_pipe::pipe()?;

        let pid = unshare::clone_process(&config)?;
        if pid == 0 {
            // Child, in sandbox, privileged in the parent or in the user namespace (if
            // --unshare-user).
            //
            // Note that for user namespaces we run as euid 0 during clone(), so the child user
            // namespace is owned by euid 0. This means that the regular user namespace parent
            // (with uid != 0) doesn't have any capabilities in it, which is nice as we can't
            // exploit those. In particular the parent user namespace doesn't have CAP_PTRACE which
            // would otherwise allow the parent to hijack of the child after this point.
            //
            // Unfortunately this also means you can't ptrace the final sandboxed process from
            // outside the sandbox either.

            drop(tx);
            #[cfg(feature = "piped")]
            drop(stdin_w);
            #[cfg(feature = "piped")]
            drop(stdout_r);
            #[cfg(feature = "piped")]
            drop(stderr_r);

            // Wait for the parent to init uid/gid maps and drop caps.
            rx.recv().expect("Failed to communicate with parent");

            // At this point we can completely drop root uid, but retain the
            // required permitted caps. This allow us to do full setup as
            // the user uid, which makes e.g. fuse access work.
            privs::switch_to_user_with_privs()?;
            if !config.enable_network {
                net::setup_loopback_device()?;
            }

            if !IS_PRIVILEGED {
                // In the unprivileged case we have to write the uid/gid maps in the child, because
                // we have no caps in the parent.

                // TODO: Like with `bwrap`, we might have to first map the `SANDBOX_UID` and
                // `SANDBOX_GID` to 0, otherwise we can't mount the devpts filesystem because root
                // is not mapped. Later, we will create another child user namespace and map back
                // to the real uid. But before we write this code, we should investigate whether
                // this hack should even be necessary to perform conditionally, or perhaps we could
                // just allow device access all the time.

                creds::write_uid_gid_map(
                    SANDBOX_UID,
                    SANDBOX_GID,
                    REAL_UID,
                    REAL_GID,
                    None,
                    true,
                    false,
                )?;
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
            #[cfg(not(feature = "piped"))]
            let error = command.exec();

            Err(error)
        } else {
            // Parent, outside sandbox, privileged (initially). Discover namespace ids before we
            // drop privileges.

            // creds::read_namespace_ids(pid)?;
            if IS_PRIVILEGED {
                // We're running as euid 0, but the uid we want to map is not 0. This means we're
                // not allowed to write this from the child user namespace, so we do it from the
                // parent.
                //
                // Also, we map uid/gid 0 in the namespace (to overflowuid) if opt_needs_devpts is
                // true, because otherwise the mount of devpts fails due to root not being mapped.
                creds::write_uid_gid_map(
                    SANDBOX_UID,
                    SANDBOX_GID,
                    REAL_UID,
                    REAL_GID,
                    Some(pid),
                    true,
                    true, // TODO: Decide whether to always allow /dev access in sandbox.
                )?;
            }

            // Notify child process that the uid/gid map has been written and to begin setup.
            let _ = tx.send(());

            // TODO: monitor child process and report exit code from child.

            #[cfg(feature = "piped")]
            let stdin = ChildStdin(stdin_w);
            #[cfg(feature = "piped")]
            let stdout = ChildStdout(stdout_r);
            #[cfg(feature = "piped")]
            let stderr = ChildStderr(stderr_r);
            #[cfg(not(feature = "piped"))]
            let (stdin, stdout, stderr) = (None, None, None);

            Ok(Child::from_parts(stdin, stdout, stderr, pid))
        }
    }
}

unsafe fn open_proc_dir() -> Result<(), Error> {
    PROC_DIR = Dir::open("/proc")
        .map(Some)
        .map_err(|_| Error::new(ErrorKind::Other, "Unable to open /proc dir"))?;
    Ok(())
}
