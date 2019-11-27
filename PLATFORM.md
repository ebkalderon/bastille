# Platform-specific notes

## Linux

Linux is the only platform in the WIP list above with any notion of user
namespaces. This means that it is likely the only version of this library which
can run without `sudo` and/or `setuid`. It is also the most fully featured
backend at the moment, currently a rough re-implementation of [Bubblewrap] in
Rust, with some architectural differences, and exposed as an in-process library.

[Bubblewrap]: https://github.com/containers/bubblewrap

## macOS

macOS supports unprivileged sandboxing through [Seatbelt/sandboxd][sandboxd] via
a nicely declarative format, but it does not have UID/GID and PID namespaces and
does not include the ability to remap the filesystem in an arbitrary manner.
Additionally, macOS does not have bind mounts nor `tmpfs`, meaning that these
features may have to be emulated with `chroot(2)`. Additionally, newer versions
of macOS disallow hard-linking of directories, except for Apple's Time Machine,
meaning we might need to depend on [sandboxfs], which would require users to
install [osxfuse] before running Bastille.

Another annoyance is that `chroot(2)` is also considered a privileged operation,
and there appears to be no kernel API for temporarily requesting specific
`chroot` capabilities on macOS like on Linux, meaning you would need to use
`sudo` and/or install Bastille as `setuid`. `xhyve` and `Hypervisor.framework`
are not exactly viable alternatives since they perform full hardware
virtualization and would require booting a full macOS guest in order to work.
This is definitely a degraded experience, and unless Apple introduces a
hypothetical `Container.framework` to newer versions of macOS, it will likely
remain a second-class citizen.

[sandboxd]: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
[sandboxfs]: https://github.com/bazelbuild/sandboxfs
[osxfuse]: https://osxfuse.github.io/

## FreeBSD

FreeBSD also supports a declarative unprivileged sandboxing API via [capsicum],
but this also does not include the necessary features above. It might be
possible to hook into `libjail` instead, which can do 99% of what we want. Jails
have separate UID/GID namespaces, permit host filesystem remapping and mounting,
and can restrict network access declaratively. Also, FreeBSD includes `nullfs`
(which is functionally similar to `bind` mounts on Linux) and also has native
`tmpfs` support. Unfortunately, calling into `libjail` is a privileged
operation, meaning this will also require the user to use `sudo` and/or install
as `setuid`.

[capsicum]: https://wiki.freebsd.org/Capsicum

## Approach to elevated permissions

It should be noted that out of all of the platforms described above, only Linux
does not require elevated privileges to create a fully-featured jail. Even then,
user namespaces are not enabled by default in all Linux distributions, so in
reality, unprivileged sandboxes seem to be the exception rather than the norm.

The continued development of Bastille should not be deterred by other platforms
unfortunately requiring `sudo` or `setuid` access, because having a unified
cross-platform API for spawning jailed processes across platforms is still
massively useful. Perhaps we could offer an optional feature flag which enables
or disables the filesystem remapping API, allowing Bastille to be used in
unprivileged contexts on all platforms where the user doesn't need `pivot_root`
or `chroot` functionality.
