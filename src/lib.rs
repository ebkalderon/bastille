use std::collections::HashSet;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use self::process::Child;

pub mod process;

mod os;
mod util;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Mapping {
    sandbox: PathBuf,
    host: PathBuf,
    writable: bool,
}

impl Mapping {
    pub fn from_parts<P, Q>(sandbox: P, host: Q, writable: bool) -> Result<Self, MappingError>
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        let sandbox_path = sandbox.into();
        if !sandbox_path.is_absolute() {
            return Err(MappingError(ErrorKind::NotAbsolute(sandbox_path)));
        }

        let is_normalized = {
            let mut components = sandbox_path.components();
            assert_eq!(
                components.next(),
                Some(Component::RootDir),
                "Path expected to be absolute"
            );
            let is_normal: fn(&Component) -> bool = |c| match c {
                Component::CurDir => panic!("Dot components ought to have been skipped"),
                Component::Normal(_) => true,
                Component::ParentDir | Component::Prefix(_) => false,
                Component::RootDir => panic!("Root directory should have already been handled"),
            };
            components.skip_while(is_normal).next().is_none()
        };

        if !is_normalized {
            return Err(MappingError(ErrorKind::NotNormalized(sandbox_path)));
        }

        Ok(Mapping {
            sandbox: sandbox_path,
            host: host.into(),
            writable,
        })
    }

    pub fn sandbox_path(&self) -> &Path {
        &self.sandbox
    }

    pub fn host_path(&self) -> &Path {
        &self.host
    }

    pub fn is_writable(&self) -> bool {
        self.writable
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MappingError(ErrorKind);

impl Display for MappingError {
    fn fmt(&self, fmt: &mut Formatter) -> FmtResult {
        write!(fmt, "{}", self.0)
    }
}

impl std::error::Error for MappingError {}

#[derive(Clone, Debug, PartialEq)]
enum ErrorKind {
    NotAbsolute(PathBuf),
    NotNormalized(PathBuf),
}

impl Display for ErrorKind {
    fn fmt(&self, fmt: &mut Formatter) -> FmtResult {
        match *self {
            ErrorKind::NotAbsolute(ref path) => write!(
                fmt,
                "mount path `{}` is not absolute",
                path.to_string_lossy()
            ),
            ErrorKind::NotNormalized(ref path) => write!(
                fmt,
                "host path `{}` is not normalized",
                path.to_string_lossy(),
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Mappings(Vec<Mapping>);

impl Mappings {
    pub fn push(&mut self, item: Mapping) {
        self.0.push(item);
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn resolve_symlinks(&self) -> Result<Vec<Mapping>, Error> {
        self.0
            .clone()
            .into_iter()
            .try_fold(Vec::new(), |mut acc, mut mapping| {
                let real = mapping.host.canonicalize()?;
                std::mem::replace(&mut mapping.host, real);
                acc.push(mapping);
                Ok(acc)
            })
    }
}

impl Extend<Mapping> for Mappings {
    fn extend<I: IntoIterator<Item = Mapping>>(&mut self, iter: I) {
        self.0.extend(iter)
    }
}

#[derive(Clone, Debug)]
pub struct Sandbox {
    mappings: Mappings,
    soft_links: Vec<(PathBuf, PathBuf)>,
    directories: HashSet<PathBuf>,
    allow_devices: bool,
    allow_local_sockets: bool,
    allow_network: bool,
    allow_sysctl: bool,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl Sandbox {
    pub fn new() -> Self {
        Sandbox {
            mappings: Mappings::default(),
            soft_links: Vec::new(),
            directories: HashSet::new(),
            uid: None,
            gid: None,
            allow_devices: false,
            allow_local_sockets: false,
            allow_network: false,
            allow_sysctl: false,
        }
    }

    pub fn mount(&mut self, mapping: Mapping) -> &mut Self {
        self.mappings.push(mapping);
        self
    }

    pub fn mounts<I>(&mut self, mappings: I) -> &mut Self
    where
        I: IntoIterator<Item = Mapping>,
    {
        self.mappings.extend(mappings);
        self
    }

    pub fn mounts_clear(&mut self) -> &mut Self {
        self.mappings.clear();
        self
    }

    pub fn soft_link<P, Q>(&mut self, src: P, dest: Q) -> &mut Self
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        self.soft_links.push((src.into(), dest.into()));
        self
    }

    pub fn soft_links<I, P, Q>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = (P, Q)>,
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        let links = entries.into_iter().map(|(p, q)| (p.into(), q.into()));
        self.soft_links.extend(links);
        self
    }

    pub fn directory<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        self.directories.insert(path.into());
        self
    }

    pub fn directories<I, P>(&mut self, paths: I) -> &mut Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.directories.extend(paths.into_iter().map(Into::into));
        self
    }

    pub fn uid(&mut self, value: u32) -> &mut Self {
        self.uid = Some(value);
        self
    }

    pub fn gid(&mut self, value: u32) -> &mut Self {
        self.gid = Some(value);
        self
    }

    pub fn allow_devices(&mut self, enabled: bool) -> &mut Self {
        self.allow_devices = enabled;
        self
    }

    pub fn allow_local_sockets(&mut self, enabled: bool) -> &mut Self {
        self.allow_local_sockets = enabled;
        self
    }

    pub fn allow_network(&mut self, enabled: bool) -> &mut Self {
        self.allow_network = enabled;
        self
    }

    pub fn allow_sysctl(&mut self, enabled: bool) -> &mut Self {
        self.allow_sysctl = enabled;
        self
    }

    pub fn spawn(&self, command: &mut Command) -> Result<Child, Error> {
        os::create_sandbox(self, command)
    }
}
