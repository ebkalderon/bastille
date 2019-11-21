// TODO: There should be an async version of this module when tokio 0.2 introduces a [blocking API]
// where long-running IO calls can be passed to a threadpool and converted into a `Future`.
//
// [blocking API]: https://github.com/tokio-rs/tokio/issues/588

use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use libc::{c_int, pid_t};
use os_pipe::{PipeReader, PipeWriter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{catch_io_error, catch_io_error_repeat};

#[derive(Debug, Deserialize, Serialize)]
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pid: pid_t,
    #[serde(skip)]
    status: Option<ExitStatus>,
}

impl Child {
    pub(crate) fn from_parts<I, O, E>(stdin: I, stdout: O, stderr: E, pid: pid_t) -> Self
    where
        I: Into<Option<ChildStdin>>,
        O: Into<Option<ChildStdout>>,
        E: Into<Option<ChildStderr>>,
    {
        Child {
            stdin: stdin.into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            pid,
            status: None,
        }
    }
}

impl Child {
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn wait(&mut self) -> Result<ExitStatus, Error> {
        drop(self.stdin.take());

        if let Some(status) = self.status {
            return Ok(status);
        }

        let mut status = 0 as c_int;
        catch_io_error_repeat(|| unsafe { libc::waitpid(self.pid, &mut status, 0) })?;

        self.status = Some(ExitStatus::from_raw(status));
        Ok(ExitStatus::from_raw(status))
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }

        let mut status = 0 as c_int;
        let pid = catch_io_error_repeat(|| unsafe {
            libc::waitpid(self.pid, &mut status, libc::WNOHANG)
        })?;

        if pid == 0 {
            Ok(None)
        } else {
            self.status = Some(ExitStatus::from_raw(status));
            Ok(Some(ExitStatus::from_raw(status)))
        }
    }

    pub fn kill(&mut self) -> Result<(), Error> {
        if self.status.is_some() {
            let msg = "invalid argument: can't kill an exited process";
            Err(Error::new(ErrorKind::InvalidInput, msg))
        } else {
            catch_io_error(unsafe { libc::kill(self.pid, libc::SIGKILL) }).map(|_| ())
        }
    }
}

#[derive(Debug)]
pub struct ChildStdin(pub(crate) PipeWriter);

impl Write for ChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl FromRawFd for ChildStdin {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        ChildStdin(PipeWriter::from_raw_fd(fd))
    }
}

#[doc(hidden)]
impl<'de> Deserialize<'de> for ChildStdin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawFd::deserialize(deserializer)
            .map(|fd| unsafe { PipeWriter::from_raw_fd(fd) })
            .map(ChildStdin)
    }
}

#[doc(hidden)]
impl Serialize for ChildStdin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::os::unix::io::AsRawFd;
        RawFd::serialize(&self.0.as_raw_fd(), serializer)
    }
}

#[derive(Debug)]
pub struct ChildStdout(pub(crate) PipeReader);

impl Read for ChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl FromRawFd for ChildStdout {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        ChildStdout(PipeReader::from_raw_fd(fd))
    }
}

#[doc(hidden)]
impl<'de> Deserialize<'de> for ChildStdout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawFd::deserialize(deserializer)
            .map(|fd| unsafe { PipeReader::from_raw_fd(fd) })
            .map(ChildStdout)
    }
}

#[doc(hidden)]
impl Serialize for ChildStdout {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::os::unix::io::AsRawFd;
        RawFd::serialize(&self.0.as_raw_fd(), serializer)
    }
}

#[derive(Debug)]
pub struct ChildStderr(pub(crate) PipeReader);

impl Read for ChildStderr {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl FromRawFd for ChildStderr {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        ChildStderr(PipeReader::from_raw_fd(fd))
    }
}

#[doc(hidden)]
impl<'de> Deserialize<'de> for ChildStderr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawFd::deserialize(deserializer)
            .map(|fd| unsafe { PipeReader::from_raw_fd(fd) })
            .map(ChildStderr)
    }
}

#[doc(hidden)]
impl Serialize for ChildStderr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::os::unix::io::AsRawFd;
        RawFd::serialize(&self.0.as_raw_fd(), serializer)
    }
}
