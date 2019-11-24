# Bastille

A process sandboxing library written in Rust.

Please note that this sandboxing library is a work in progress and has not yet
been reviewed for correctness and overall security, so use at your own risk.

## Motivation

At the time of writing, Arch Linux [chose to enable unprivileged namespace
support][arch] with kernel version +5.1.8, meaning that [gaol] now finally works
on Arch Linux. However, it relies on a `chroot` jail which is rather easy to
escape, and the API is also incompatible with `std::command::Command`.
[rusty-sandbox] works as expected on macOS using more secure methods, but Linux
is unsupported and it does not allow for filesystem mapping and mounting nor
fine-grained access control.

[gaol]: https://crates.io/crates/gaol
[arch]: https://bbs.archlinux.org/viewtopic.php?id=247016
[rusty-sandbox]: https://crates.io/crates/rusty-sandbox

## Work in progress

- [x] Spawn commands under a cloned process in a new namespace.
- [x] Environment variables, arguments, and current working directory can be
      configured via the standard `std::process::Command` builder.
- [ ] Command stdio can be configured via the standard `std::process::Command`
      builder (this is currently unsupported until rust-lang/rust#44434 is
      resolved).
- [x] Multiple sandboxes can be spawned in multi-threaded programs without
      interfering with each other (this is possible because `clone(2)` ensures
      process isolation between parent and sandbox).
- [x] Sandbox spawned in one thread doesn't elevate user privileges for all
      other threads in the parent process, meaning other threads in Rust code
      aren't inadvertently granted Super Cow Powers (this is possible because
      `setfsuid` and `capset` are per-thread rather than per-process, and any
      times that Bastille does call `setuid`, we are in a separate child
      process).
- [x] Unshare the user namespace (always on; will add the option to toggle
      off if requested, should Bastille detect the process is `setuid`).
- [x] Unshare the network namespace (WIP, successfully unshares and creates a
      local loopback device, but the interface has some configuration issues).
- [x] Unshare the PID namespace.
- [ ] Unshare the IPC namespace.
- [ ] Unshare the UTS (Unix socket) namespace.
- [x] Set up filesystem sandbox:
  * Canonicalize all paths in mappings (eliminating symlinks), create a new
    `tmpfs` mount point for the new root in `$base_path`, create a dir
    `$base_path/new_root`, `pivot_root()` to `$base_path`, put the old root in
    `$base_path/old_root`. Next, set up `new_root` with all the mounts,
    directories, symlinks, etc. and `pivot_root()` again to `/new_root`,
    unmount `/old_root`, and unshare mount permissions.
- [ ] Add macOS backend using `sandboxd`.
- [ ] Add FreeBSD backend using `capsicum` (don't have a box to test with ATM).
- [ ] Add OpenBSD backend using `pledge` (don't have a box to test with ATM).

## Credit

Design for the Linux backend implementation is loosely inspired by [Bubblewrap].

[Bubblewrap]: https://github.com/containers/bubblewrap

## License

Bastille is free and open source software distributed under the terms of the
[MIT](./LICENSE-MIT) and the [Apache 2.0](./LICENSE-APACHE) licenses.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
