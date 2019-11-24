// TODO: There should be an async version of this module when tokio 0.2 introduces a [blocking API]
// where long-running IO calls can be passed to a threadpool and converted into a `Future`.
//
// [blocking API]: https://github.com/tokio-rs/tokio/issues/588

use std::io::{self, Error, ErrorKind, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

use libc::{c_int, pid_t};
use os_pipe::{PipeReader, PipeWriter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::util;

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
        util::catch_io_error_repeat(|| unsafe { libc::waitpid(self.pid, &mut status, 0) })?;

        self.status = Some(ExitStatus::from_raw(status));
        Ok(ExitStatus::from_raw(status))
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }

        let mut status = 0 as c_int;
        let pid = util::catch_io_error_repeat(|| unsafe {
            libc::waitpid(self.pid, &mut status, libc::WNOHANG)
        })?;

        if pid == 0 {
            Ok(None)
        } else {
            self.status = Some(ExitStatus::from_raw(status));
            Ok(Some(ExitStatus::from_raw(status)))
        }
    }

    pub fn wait_with_output(&mut self) -> Result<Output, Error> {
        drop(self.stdin.take());

        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        match (self.stdout.take(), self.stderr.take()) {
            (None, None) => {}
            (Some(mut out), None) => {
                let res = out.read_to_end(&mut stdout);
                res.unwrap();
            }
            (None, Some(mut err)) => {
                let res = err.read_to_end(&mut stderr);
                res.unwrap();
            }
            (Some(mut out), Some(mut err)) => {
                let res = out.read_to_end(&mut stdout);
                res.unwrap();
                let res = err.read_to_end(&mut stderr);
                res.unwrap();
                // FIXME: Should implement some kind of simultaneous non-blocking read of both
                // pipes to ensure they don't block on each other. This seems to work for the short
                // term, though. See this source file for more details:
                // https://github.com/rust-lang/rust/blob/fae75cd216c481de048e4951697c8f8525669c65/src/libstd/sys/unix/pipe.rs#L80-L129
            }
        }

        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    pub fn kill(&mut self) -> Result<(), Error> {
        if self.status.is_some() {
            let msg = "invalid argument: can't kill an exited process";
            Err(Error::new(ErrorKind::InvalidInput, msg))
        } else {
            util::catch_io_error(unsafe { libc::kill(self.pid, libc::SIGKILL) }).map(|_| ())
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
