#[cfg(target_os = "linux")]
pub use self::linux::create_sandbox;
#[cfg(target_os = "macos")]
pub use self::macos::create_sandbox;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
