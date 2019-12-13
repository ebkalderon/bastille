fn main() {
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-lib=sandbox");
    }
}
