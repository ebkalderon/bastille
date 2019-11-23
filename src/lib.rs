use std::collections::HashSet;
use std::io::Error;
use std::path::{Component, PathBuf};
use std::process::Command;

use self::process::Child;

pub mod process;

mod os;
mod util;

#[derive(Clone, Debug)]
pub struct Mapping {
    sandbox: PathBuf,
    host: PathBuf,
    writable: bool,
}

impl Mapping {
    pub fn from_parts<P, Q>(sandbox: P, host: Q, writable: bool) -> Result<Self, ()>
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        let sandbox_path = sandbox.into();
        if !sandbox_path.is_absolute() {
            return Err(());
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
            return Err(());
        }

        Ok(Mapping {
            sandbox: sandbox_path,
            host: host.into(),
            writable,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Sandbox {
    mappings: Vec<Mapping>,
    soft_links: Vec<(PathBuf, PathBuf)>,
    directories: HashSet<PathBuf>,
    enable_network: bool,
    enable_domain_sockets: bool,
    enable_sysctl: bool,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl Sandbox {
    pub fn new() -> Self {
        Sandbox {
            mappings: Vec::new(),
            soft_links: Vec::new(),
            directories: HashSet::new(),
            uid: None,
            gid: None,
            enable_network: false,
            enable_domain_sockets: false,
            enable_sysctl: false,
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

    pub fn soft_link<P, Q>(&mut self, src: P, dest: P) -> &mut Self
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

    pub fn enable_network(&mut self, enabled: bool) -> &mut Self {
        self.enable_network = enabled;
        self
    }

    pub fn enable_domain_sockets(&mut self, enabled: bool) -> &mut Self {
        self.enable_domain_sockets = enabled;
        self
    }

    pub fn enable_sysctl(&mut self, enabled: bool) -> &mut Self {
        self.enable_sysctl = enabled;
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

    pub fn spawn(&self, command: &mut Command) -> Result<Child, Error> {
        os::create_sandbox(self, command)
    }
}
