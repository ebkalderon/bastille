use std::io::{Error, ErrorKind};

use libc::c_int;

pub fn catch_io_error_repeat<F>(mut f: F) -> Result<c_int, Error>
where
    F: FnMut() -> c_int,
{
    loop {
        match catch_io_error(f()) {
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

pub fn catch_io_error(status: c_int) -> Result<c_int, Error> {
    if status == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(status)
    }
}
