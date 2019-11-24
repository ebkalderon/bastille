use std::process::Command;

use bastille::{Mapping, Sandbox};

fn main() {
    Sandbox::new()
        .mount(Mapping::from_parts("/usr", "/usr", false).unwrap())
        .mount(Mapping::from_parts("/dev/foo", "/dev/null", true).unwrap())
        .soft_link("usr/lib64", "/lib64")
        .allow_dev_read(false)
        .allow_network(true)
        .allow_sysctl(true)
        .spawn(&mut Command::new("bash").env_clear())
        .expect("Failed to spawn process in sandbox")
        .wait()
        .expect("Failed to wait on spawned process");
}
