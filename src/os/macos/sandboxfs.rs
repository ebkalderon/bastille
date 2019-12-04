use std::fs::{self, File};
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::thread::JoinHandleExt;
use std::path::{Path, PathBuf};
use std::str;
use std::thread::{self, JoinHandle};

use log::{debug, error};
use os_pipe::{PipeReader, PipeWriter};
use tempfile::TempDir;
use time::Timespec;

use crate::{Mappings, Sandbox};

const MOUNT_OPTIONS: &[&'static str] = &["-o", "fsname=sandboxfs", "-o", "allow_root"];
const TTL_SECONDS: i64 = 60;

#[derive(Debug)]
pub struct Sandboxfs {
    input: PipeWriter,
    output: BufReader<PipeReader>,
    handle: Option<JoinHandle<()>>,
    mount_point: TempDir,
}

impl Sandboxfs {
    pub fn new(mount_point: TempDir) -> Result<Self, Error> {
        let (input_read, input_write) = os_pipe::pipe()?;
        let (output_read, output_write) = os_pipe::pipe()?;

        let path = mount_point.path().join("mnt");
        fs::create_dir_all(&path)?;
        let handle = thread::spawn(move || {
            let ttl = Timespec::new(TTL_SECONDS, 0);
            let input = unsafe { File::from_raw_fd(input_read.into_raw_fd()) };
            let output = unsafe { File::from_raw_fd(output_write.into_raw_fd()) };
            match sandboxfs::mount(&path, MOUNT_OPTIONS, &[], ttl, input, output) {
                Ok(_) => error!("sandboxfs is not supposed to exit with Ok()"),
                Err(msg) => debug!("sandboxfs exited with message: {}", msg),
            }
        });

        Ok(Sandboxfs {
            input: input_write,
            output: BufReader::new(output_read),
            handle: Some(handle),
            mount_point,
        })
    }

    pub fn mount(&mut self, config: &Sandbox) -> Result<Mounts, Error> {
        let (mount_msg, unmount_msg) = to_sandboxfs_messages(&config.mappings)?;
        writeln!(&mut self.input, "{}", mount_msg)?;

        let mut message = String::new();
        self.output.read_line(&mut message)?;

        if message != "Done\n" {
            return Err(Error::new(ErrorKind::Other, message));
        }

        let root_dir = self.mount_point.path().join("mnt");
        Ok(Mounts::new(root_dir, unmount_msg))
    }

    pub fn unmount(&mut self, mounts: Mounts) -> Result<(), Error> {
        writeln!(&mut self.input, "{}", mounts.unmount_message)?;

        let mut message = String::new();
        self.output.read_line(&mut message)?;

        if message != "Done\n" {
            return Err(Error::new(ErrorKind::Other, message));
        }

        Ok(())
    }
}

impl Drop for Sandboxfs {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            debug!("shutting down sandboxfs thread");

            let thread = handle.as_pthread_t();
            if unsafe { libc::pthread_kill(thread, libc::SIGHUP) } != 0 {
                error!("failed to send SIGHUP to sandboxfs thread");
            }

            handle.join().expect("failed to join on sandboxfs thread");
        }
    }
}

#[derive(Debug)]
pub struct Mounts {
    root_dir: PathBuf,
    unmount_message: String,
}

impl Mounts {
    fn new(root_dir: PathBuf, unmount_message: String) -> Self {
        Mounts {
            root_dir,
            unmount_message,
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }
}

fn to_sandboxfs_messages(mappings: &Mappings) -> Result<(String, String), Error> {
    let mappings = mappings.resolve_symlinks()?;

    let mut mount_messages = Vec::with_capacity(mappings.len());
    let mut unmount_messages = Vec::with_capacity(mappings.len());

    for mapping in mappings {
        mount_messages.push(format!(
            r#"{{"Map": {{"Mapping": {:?}, "Target": {:?}, "Writable": {}}}}}"#,
            mapping.sandbox_path(),
            mapping.host_path(),
            mapping.is_writable()
        ));

        unmount_messages.push(format!(r#"{{"Unmap": {:?}}}"#, mapping.sandbox_path()));
    }

    let mount_msg = format!("[{}]\n", mount_messages.join(","));
    let unmount_msg = format!("[{}]\n", unmount_messages.join(","));
    debug!("mount message: {}", mount_msg.replace("\n", "\\n"));
    debug!("unmount message: {}", unmount_msg.replace("\n", "\\n"));

    Ok((mount_msg, unmount_msg))
}
