# PetaLinux compatibility review

## Conclusion

The library is source-compatible with the reviewed PetaLinux v15 environment
and Linux 5.10-class AArch64 targets. The full source and consumers compile for
`aarch64-linux-gnu`. Final runtime qualification on the actual PetaLinux image
is still required because the daemon plugins, kernel configuration, libc ABI,
permissions and root filesystem are target-specific.

The generic verification shared object targets AArch64 and records
`GLIBC_2.17` as its maximum glibc symbol baseline. A glibc-based target at or
above that baseline is ABI-compatible at this layer. A musl-based or otherwise
custom PetaLinux image must rebuild with its own SDK sysroot.

## Reference findings

The separately supplied `ipsec_app_project_v15_petalinux` tree establishes the
following target baseline:

- AArch64 PetaLinux SDK build
- strongSwan 5.8.4 compatibility
- `charon` with the VICI and kernel-netlink plugins
- VICI sockets under `/run` or `/var/run`
- C11 and POSIX.1-2008 source support

That test application invokes `ipsec`, `swanctl` and other commands. The
Native library does not reuse those command paths. It connects directly to the
VICI Unix socket and uses Linux Netlink and `/proc/net/xfrm_stat` for status.

## Target requirements

- Linux kernel with `CONFIG_XFRM`, `NETLINK_XFRM` and `NETLINK_ROUTE`
- mounted `/proc` for XFRM statistics
- strongSwan `charon` started by the operating system
- strongSwan VICI and kernel-netlink plugins enabled
- access permission to the VICI socket
- sufficient privilege, normally `CAP_NET_ADMIN`, for XFRM dumps if required
  by the target security policy
- POSIX threads and standard Linux socket APIs in the target libc

The source uses APIs available well before Linux 5.10, including Unix sockets,
`SOCK_CLOEXEC`, `MSG_NOSIGNAL`, `clock_gettime`, POSIX mutexes and the stable
XFRM/rtnetlink UAPI. It does not contain architecture-specific assembly,
hard-coded pointer sizes or host-endian packet serialization.

## Ubuntu native build

Only GNU Make and the normal C build tools are required:

```sh
sudo apt-get install build-essential
make clean
make -j"$(nproc)"
```

Outputs:

```text
lib/libipsec_native.a
lib/libipsec_native.so
```

The equivalent helper is:

```sh
./scripts/build_ubuntu.sh
```

## Generic AArch64 cross build

```sh
sudo apt-get install gcc-aarch64-linux-gnu
make clean
make -j"$(nproc)" CROSS_COMPILE=aarch64-linux-gnu-
```

or:

```sh
./scripts/build_aarch64.sh
```

## PetaLinux sysroot build

A generic Ubuntu AArch64 compiler is sufficient for compile verification, but
the shared library should be linked against the actual PetaLinux SDK sysroot
for deployment:

```sh
export SYSROOT=/opt/petalinux-sdk/sysroots/aarch64-xilinx-linux
make clean
make -j"$(nproc)" \
    CROSS_COMPILE=aarch64-linux-gnu- \
    SYSROOT="${SYSROOT}"
```

If the PetaLinux SDK environment exports a complete `CC`, `AR` and `RANLIB`,
they may be passed directly on the Make command line instead. Do not mix host
headers with a target sysroot.

For CMake:

```sh
SYSROOT=/opt/petalinux-sdk/sysroots/aarch64-xilinx-linux \
    ./scripts/build_cmake_aarch64.sh
```

## Target verification

```sh
readelf -h libipsec_native.so
readelf -d libipsec_native.so
./ipsec_native_app --config endpoint.conf check
./ipsec_native_app --config endpoint.conf status all
```

The live validation must cover VICI connection/load, PSK initiate, IKE/CHILD
state, XFRM state/policy, route dumps, rekey, termination and the lifecycle
loop. Runtime verification has not been claimed until these commands execute
against the actual PetaLinux peer and image.
