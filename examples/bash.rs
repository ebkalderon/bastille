use std::process::Command;

use bastille::{Mapping, Sandbox};

fn main() {
    Sandbox::new()
        .mount(Mapping::from_parts("/usr", "/usr", false).unwrap())
        .mount(Mapping::from_parts("/dev", "/dev", true).unwrap())
        .soft_link("usr/lib64", "/lib64")
        .enable_network(true)
        .enable_sysctl(true)
        .spawn(&mut Command::new("bash").env_clear())
        .expect("Failed to spawn process in sandbox")
        .wait()
        .expect("Failed to wait on spawned process");
}