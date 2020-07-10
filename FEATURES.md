# Sandboxing feature matrix

<table>
  <thead>
    <tr>
      <th rowspan="2">Feature</th>
      <th colspan="4">Support level</th>
    </tr>
    <tr>
      <th>Platform</th>
      <th>Supported?</th>
      <th>Mechanism</th>
      <th>Caveats</th>
    </tr>
  </thead>
  <tbody>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (mapping paths read/write)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>bind</tt> mounts, <tt>pivot_root</tt></td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✔️ </td>
      <td>
        <ul>
          <li><tt>sandboxfs</tt> and <tt>chroot</tt></li>
          <li><tt>file-read*</tt></li>
          <li><tt>file-read-data</tt></li>
          <li><tt>file-write*</tt></li>
          <li><tt>file-write-data</tt></li>
          <li><tt>file-write-mount</tt></li>
          <li><tt>file-write-unmount</tt></li>
        </ul>
      </td>
      <td>
        <ul>
          <li>Requires OSXFUSE to be installed separately.</li>
          <li>
            Directory tree is visible outside the sandbox because there is no
            equivalent to <tt>pivot_root</tt> in macOS.
          </li>
          <li>
            Device files are not properly supported on <tt>sandboxfs</tt>. See
            <a href="https://github.com/bazelbuild/sandboxfs/issues/87">
            bazelbuild/sandboxfs#87</a>.
          </li>
        </ul>
      </td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (metadata read/write, e.g. <tt>ls</tt>)</td>
      <td>Linux</td>
      <td>TODO: RESEARCH</td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✅</td>
      <td>
        <ul>
          <li><tt>file-read-metadata</tt></li>
          <li><tt>file-write-owner</tt></li>
          <li><tt>file-write-setugid</tt></li>
          <li><tt>file-write-times</tt></li>
        </ul>
      </td>
      <td></td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (extended attributes read/write)</td>
      <td>Linux</td>
      <td>✅</td>
      <td>TODO: RESEARCH</td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✅</td>
      <td>
        <ul>
          <li><tt>file-read-xattr</tt>, <tt>file-write-xattr</tt></li>
          <li><tt>sandboxfs</tt> 2.0 supports extended attrributes</li>
        </ul>
      </td>
      <td></td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (allow/deny <tt>chroot</tt>)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>seccomp</tt></td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✅</td>
      <td><tt>file-chroot</tt></td>
      <td></td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (<tt>procfs</tt>)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>procfs</tt> mounts</td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>❌</td>
      <td></td>
      <td><tt>procfs</tt> does not exist on macOS, so it's not applicable.</td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Filesystem (<tt>tmpfs</tt>)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>tmpfs</tt> mounts</td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✔️ </td>
      <td>Ramdisks, real directories</td>
      <td>
        <ul>
          <li>No <tt>tmpfs</tt> implementation for OSXFUSE, sadly.
          <li>HFS+ ramdisks are available, but they cannot swap to disk.</li>
          <li>
            Can be emulated with a global temp dir for the current session and
            using <tt>sandboxfs</tt> to map subdirectories to each location
            where a <tt>tmpfs</tt> is requested. This has noticeable performance
            overhead, though, unlike real <tt>tmpfs</tt>, and the dirtree is
            visible outside the sandbox.
          </li>
          <li>
            You can set the global temp dir location in the sandbox like this:
            <pre><code>(define TMPDIR (literal "/path/to/tmpdir"))</code></pre>
          </li>
        </ul>
      </td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Network (destination, protocol, port filtering)</td>
      <td>Linux</td>
      <td>✔️ </td>
      <td><tt>CLONE_NEWNET</tt>, <tt>netlink</tt></td>
      <td>
        <ul>
          <li>Trivial to set up block-all, local-only, and allow-all.</li>
          <li>
            Harder to do fine-tuned protocol and port filtering.
            See <a href="https://github.com/flatpak/flatpak/issues/1202">
            flatpak/flatpak#1202</a>.
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✅</td>
      <td>
        <ul>
          <li><tt>network*</tt></li>
          <li><tt>network-bind</tt></li>
          <li><tt>network-inbound</tt></li>
          <li><tt>network-outbound</tt></li>
          <li><tt>system-socket</tt>
        </ul>
      </td>
      <td>No IP filtering; only accepts <tt>localhost</tt> or <tt>*</tt>.</td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">Network (hiding host interfaces)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>CLONE_NEWNET</tt>, <tt>netlink</tt>, <tt>seccomp</tt></td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>❌</td>
      <td></td>
      <td>
        No way to hide host network interfaces on macOS because lack of
        namespacing. Inherits network configuration from host.
      </td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">IPC (allow/deny UNIX sockets)</td>
      <td>Linux</td>
      <td>✔️ </td>
      <td><tt>CLONE_NEWNET</tt>, <tt>netlink</tt></td>
      <td>
        No way to differentiate between TCP and UNIX sockets. You can only block
        all or allow all access to existing sockets or creation of new sockets.
      </td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✔️ </td>
      <td>
        <ul>
          <li><tt>system-socket</tt></li>
          <li><tt>network* (remote unix (path-literal PATH))</tt></li>
        </ul>
      </td>
      <td>
        No way to differentiate between TCP and UNIX sockets. You can only block
        all or allow all creation of new sockets. We <i>can</i> whitelist access
        to external UNIX sockets by path, though.
      </td>
    </tr>
    <!-- ROW BEGIN -->
    <tr>
      <td rowspan="2">IPC (allow/deny SysV IPC, semaphores, Mach ports, etc.)</td>
      <td>Linux</td>
      <td>✅</td>
      <td><tt>CLONE_NEWIPC</tt>, <tt>seccomp</tt></td>
      <td></td>
    </tr>
    <tr>
      <td>macOS (<tt>sandboxd</tt>)</td>
      <td>✔️ </td>
      <td>
        <ul>
          <li><tt>ipc*</tt></li>
          <li><tt>ipc-posix*</tt></li>
          <li><tt>ipc-posix-sem</tt></li>
          <li><tt>ipc-posix-shm</tt></li>
          <li><tt>ipc-sysv*</tt></li>
          <li><tt>ipc-sysv-msg</tt></li>
          <li><tt>ipc-sysv-sem</tt></li>
          <li><tt>ipc-sysv-shm</tt></li>
          <li><tt>mach-bootstrap</tt> (?)</li>
          <li><tt>mach-lookup</tt></li>
        </ul>
      </td>
      <td>
        No way to restrict IPC only to processes inside the sandbox due to lack
        of namespacing. If enabled, IPC endpoints outside the sandbox are
        visible.
      </td>
    </tr>
  </tbody>
</table>
