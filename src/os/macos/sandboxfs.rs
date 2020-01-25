use std::fs::{self, File};
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::thread::JoinHandleExt;
use std::str;
use std::thread::{self, JoinHandle};

use libc::{c_int, gid_t, uid_t};
use log::{debug, error};
use os_pipe::PipeWriter;
use sandboxfs::Mapping;
use tempfile::TempDir;
use time::Timespec;

use crate::{util, Mappings, Sandbox};

const MOUNT_OPTIONS: &[&str] = &["-o", "fsname=sandboxfs", "-o", "allow_other"];
const TTL_SECONDS: i64 = 60;

#[derive(Debug)]
pub struct Sandboxfs {
    input: PipeWriter,
    handle: Option<JoinHandle<()>>,
    mount_point: TempDir,
}

impl Sandboxfs {
    pub fn new(mount_point: TempDir, config: &Sandbox) -> Result<Self, Error> {
        let (input_read, input_write) = os_pipe::pipe()?;
        let (output_read, output_write) = os_pipe::pipe()?;
        let mappings = to_sandboxfs_mappings(&config.mappings)?;

        let path = mount_point.path().join("mnt");
        fs::create_dir_all(&path)?;
        let handle = thread::Builder::new()
            .name("sandboxfs".into())
            .spawn(move || {
                let gid = unsafe { libc::getgid() };
                util::catch_io_error(unsafe { pthread_setugid_np(0, gid) }).unwrap();

                let ttl = Timespec::new(TTL_SECONDS, 0);
                let input = unsafe { File::from_raw_fd(input_read.into_raw_fd()) };
                let output = unsafe { File::from_raw_fd(output_write.into_raw_fd()) };
                match sandboxfs::mount(&path, MOUNT_OPTIONS, &mappings[..], ttl, input, output) {
                    Ok(_) => error!("sandboxfs is not supposed to exit with Ok()"),
                    Err(msg) => debug!("sandboxfs exited with message: {}", msg),
                }
            })?;

        let mut input = input_write;
        block_until_mounted(&mut input, BufReader::new(output_read))?;

        Ok(Sandboxfs {
            input,
            handle: Some(handle),
            mount_point,
        })
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

fn to_sandboxfs_mappings(mappings: &Mappings) -> Result<Vec<Mapping>, Error> {
    let mappings = mappings.resolve_symlinks()?;
    mappings
        .into_iter()
        .map(|m| {
            let sandbox_path = m.sandbox_path().to_owned();
            let host_path = m.host_path().to_owned();
            Mapping::from_parts(sandbox_path, host_path, m.is_writable())
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
        })
        .collect()
}

fn block_until_mounted<I, O>(mut input: I, mut output: O) -> Result<(), Error>
where
    I: Write,
    O: BufRead,
{
    input.write_all(b"[]\n\n")?;
    input.flush()?;

    let mut message = String::new();
    output.read_line(&mut message)?;

    if message != "Done\n" {
        let error = format!("Received invalid sandboxfs response: {:?}", message);
        return Err(Error::new(ErrorKind::Other, error));
    }

    Ok(())
}

#[link(name = "c")]
extern "C" {
    fn pthread_setugid_np(uid: uid_t, gid: gid_t) -> c_int;
}
