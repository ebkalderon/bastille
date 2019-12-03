use std::process::Command;

use bastille::{Mapping, Sandbox};

#[cfg(target_os = "linux")]
fn main() {
    Sandbox::new()
        .mount(Mapping::from_parts("/usr", "/usr", false).unwrap())
        .mount(Mapping::from_parts("/dev", "/dev", true).unwrap())
        .soft_link("usr/lib64", "/lib64")
        .allow_devices(true)
        .allow_network(false)
        .allow_sysctl(false)
        .spawn(&mut Command::new("bash").env_clear())
        .expect("Failed to spawn process in sandbox")
        .wait()
        .expect("Failed to wait on spawned process");
}

#[cfg(target_os = "macos")]
fn main() {
    Sandbox::new()
        .mount(Mapping::from_parts("/bin", "/bin", false).unwrap())
        .mount(Mapping::from_parts("/usr", "/usr", false).unwrap())
        .mount(Mapping::from_parts("/dev", "/dev", true).unwrap())
        .allow_devices(true)
        .allow_network(false)
        .allow_sysctl(false)
        .spawn(&mut Command::new("bash").env_clear())
        .expect("Failed to spawn process in sandbox")
        .wait()
        .expect("Failed to wait on spawned process");
}
