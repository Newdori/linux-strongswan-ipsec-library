# linux-strongswan-ipsec-library

Native C11 control/status library for strongSwan IKEv2/IPsec on Linux.

The library communicates with an already running `charon` daemon through
VICI and reads kernel status through NETLINK_XFRM, `/proc/net/xfrm_stat`, and
NETLINK_ROUTE. It never launches `swanctl`, `ip`, `systemctl`, `tcpdump`,
`iptables`, or another shell command.

The product source is under `libipsec`. This repository is licensed
under the Apache License 2.0. See [LICENSE](LICENSE),
[NOTICE](libipsec/NOTICE), and
[THIRD_PARTY_NOTICES.md](libipsec/THIRD_PARTY_NOTICES.md).

## Supported scope

- strongSwan 5.8.4 or newer VICI baseline
- IKEv2 connection load, unload, and list
- PSK load and VICI credential clear
- IKE/CHILD initiate, terminate, rekey, and wait
- IKE/CHILD/algorithm/daemon structured status
- read-only XFRM state, policy, and statistics
- read-only interface, address, and route status
- IPv4 and IPv6 status decoding
- x86_64 and AArch64 Linux builds

`charon` must be installed, configured with the VICI and kernel-netlink
plugins, and started by the operating system. The library does not manage the
daemon or firewall.

## Build

Run build commands from the library directory:

```sh
cd libipsec
```

CMake is the primary build system. One script supports host and ZynqMP builds:

```sh
./build.sh
./build.sh zynqmp
./build.sh clean
```

Host and ZynqMP outputs are isolated under `build/host` and `build/zynqmp`.
The host build runs registered unit tests by default. Set `RUN_TESTS=OFF` to
build without executing them, or `BUILD_TESTING=OFF` to omit test targets.

GNU Make follows separate host and ZynqMP targets:

```sh
make -C ipsec host
make -C ipsec zynqmp
make -C ipsec
```

`make -C ipsec host` uses `ipsec/Makefile.host`; `make -C ipsec zynqmp` uses
`ipsec/Makefile.zynqmp`; and plain `make -C ipsec` builds both. Outputs are
kept separate:

```text
lib/x86_64/libipsec.a
lib/x86_64/libipsec.so
lib/zynqmp/libipsec.a
lib/zynqmp/libipsec.so
```

GNU Make library objects are generated under `ipsec/obj/x86_64` or
`ipsec/obj/zynqmp`.

The application has separate host and ZynqMP targets:

```sh
make -C apps host
make -C apps zynqmp
```

Application objects are generated under `apps/obj/x86_64` or
`apps/obj/zynqmp`. Executables are generated under the matching `apps/bin`
directory.

The default ZynqMP tool prefix is `aarch64-linux-gnu-`:

```sh
make -C ipsec zynqmp CROSS_COMPILE=aarch64-linux-gnu-
```

When using a PetaLinux SDK, source its environment first. If the compiler does
not already carry its sysroot flags, pass the target sysroot explicitly:

```sh
make -C ipsec zynqmp \
  CC="$CC" AR="$AR" RANLIB="$RANLIB" \
  SYSROOT="$SDKTARGETSYSROOT"
```

See [PetaLinux compatibility](libipsec/docs/petalinux_compatibility.md)
for target requirements and SDK sysroot builds.

Live peer integration tests are opt-in:

```sh
IPSEC_NATIVE_BUILD_INTEGRATION_TESTS=ON RUN_TESTS=OFF ./build.sh
```

Read the [integration test instructions](libipsec/tests/integration/README.md)
before running them on a dedicated daemon.

## Usage

See:

- [Native CLI application](libipsec/apps/README.md)
- [Public API](libipsec/docs/public_api.md)

The `ipsec_app` target reuses product-relevant settings from v15
endpoint configuration files and provides `load`, `up`, `down`, IKE/CHILD
rekey, structured `status`, and live `loop` verification commands. It does not
carry over v15 packet capture, traffic generation, firewall, matrix, barrier,
or report behavior.

When `pcViciSocketPath` is `NULL`, `InitializeIpsec()` attempts
`/run/charon.vici` and then `/var/run/charon.vici`.

Every `Get*()` list must be released by its matching `Free*List()` function.
Input strings and PSK bytes are borrowed only for the duration of the call.
PSK data is not retained in the context or written to logs.

## Thread model

- Different contexts are independent.
- Calls using the same context may originate from different threads, but VICI
  transactions are serialized internally.
- There is no background event thread in the first implementation.
- Logger callbacks execute on the calling thread and must not re-enter the
  same context.
- The caller must ensure no API call is active while `DeinitializeIpsec()`
  runs.

See [Native architecture](libipsec/docs/native_architecture.md) for
details.

## Runtime permissions

The process needs access to the configured VICI Unix socket. XFRM dump
availability depends on the kernel and security policy. Permission errors are
returned as `IPSEC_ERR_PERMISSION`; the library does not require root
unconditionally.

## Dependency verification

After building on Linux:

```sh
readelf -d build/libipsec.so
ldd build/libipsec.so
nm -D build/libipsec.so
```

Expected dynamic dependencies are libc and pthread support as provided by the
target toolchain. There must be no `libstrongswan`, `libcharon`, or `libvici`
dependency.

The shared object uses `ipsec/libipsec.map` to export only the documented
public API. Internal VICI and Netlink parser symbols remain local.

## Validation status

Unit tests cover v15 endpoint configuration conversion, VICI encode/decode
boundaries, version-tolerant `/proc/net/xfrm_stat` parsing, XFRM state/policy
Netlink decoding, and interface/address/route Netlink decoding. Malformed and
truncated inputs are included.

The complete source, static/shared libraries, Native CLI, unit-test binaries,
and live integration-test binary compile with C11, `-Wall`, `-Wextra`,
`-Wpedantic`, and `-Werror` for x86_64 and AArch64 Linux. A real `charon`, peer,
and kernel XFRM runtime are still required for target-host qualification.

See [v15 analysis](libipsec/docs/v15_analysis.md),
[build verification](libipsec/docs/build_verification.md), and
[phase status](libipsec/docs/phase_status.md) for the detailed records.
