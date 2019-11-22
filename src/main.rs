use std::process::Command;

use bastille::Sandbox;

fn main() {
    Sandbox::new()
        .enable_network(false)
        .enable_sysctl(true)
        .spawn(&mut Command::new("/bin/bash").env_clear())
        .expect("Failed to spawn process in sandbox")
        .wait()
        .expect("Failed to wait on spawned process");
}
