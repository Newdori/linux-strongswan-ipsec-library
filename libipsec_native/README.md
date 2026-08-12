# libipsec_native

Native C11 control/status library for strongSwan IKEv2/IPsec on Linux.

Licensed under the Apache License 2.0. See `../LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md`.

The library communicates with an already running charon daemon through VICI and reads kernel status through NETLINK_XFRM, /proc/net/xfrm_stat, and NETLINK_ROUTE. It never launches swanctl, ip, systemctl, tcpdump, iptables, or another shell command.

## Supported scope

- strongSwan 5.8.4 or newer VICI baseline
- IKEv2 connection load/unload/list
- PSK load and VICI credential clear
- IKE/CHILD initiate, terminate, rekey, and wait
- IKE/CHILD/algorithm/daemon structured status
- read-only XFRM state/policy/statistics
- read-only interface/address/route status
- IPv4 and IPv6 status decoding
- x86_64 and aarch64 Linux builds

charon must be installed, configured with the VICI and kernel-netlink plugins, and started by the operating system. The library does not manage the daemon or firewall.

## Build

CMake is the primary build system.

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

GNU Make is also supported.

    make

For the v15-style host/cross build, `Makefile.host` follows the
`CROSS_COMPILE`, `CC`, `AR`, and `RANLIB` convention. It places the static
archive in the `lib` directory:

    make -f Makefile.host clean all
    make -f Makefile.host app

The outputs are `./lib/libipsec_native.a` and `./ipsec_native_app`. For
aarch64:

    make -f Makefile.host clean all app \
      CROSS_COMPILE=aarch64-linux-gnu-

Outputs:

    lib/libipsec_native.a
    lib/libipsec_native.so

An aarch64 CMake toolchain may set:

    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)

or use GNU Make directly:

    make clean
    make CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)"

Helper scripts are provided for reproducible host and cross builds:

    ./scripts/build_ubuntu.sh
    ./scripts/build_aarch64.sh
    ./scripts/build_cmake_aarch64.sh

For deployment on PetaLinux, pass its SDK sysroot instead of linking the
shared library against a generic Ubuntu cross sysroot. See
`docs/petalinux_compatibility.md`.

The CMake examples are enabled by default. Live peer integration tests are
opt-in:

    cmake -S . -B build-live \
      -DIPSEC_NATIVE_BUILD_INTEGRATION_TESTS=ON
    cmake --build build-live --target test_live_ipsec

See tests/integration/README.md before running it on a dedicated daemon.

## Usage

See:

- examples/simple_psk.c
- examples/show_status.c
- apps/ipsec_native_app/README.md
- docs/public_api.md

The `ipsec_native_app` target reuses the product-relevant settings in the v15
endpoint configuration files and provides `load`, `up`, `down`, IKE/CHILD
rekey, structured `status`, and live `loop` verification commands. It does not
carry over v15 packet capture, traffic generation, firewall, matrix, barrier,
or report behavior.

When pcViciSocketPath is NULL, InitializeIpsec() attempts /run/charon.vici and then /var/run/charon.vici.

Every Get*() list must be released by its matching Free*List() function. Input strings and PSK bytes are borrowed only for the duration of the call. PSK data is not retained in the context or written to logs.

## Thread model

- Different contexts are independent.
- Calls using the same context may originate from different threads, but VICI transactions are serialized internally.
- There is no background event thread in the first implementation.
- Logger callbacks execute on the calling thread and must not re-enter the same context.
- The caller must ensure no API call is active while DeinitializeIpsec() runs.

See docs/native_architecture.md for details.

## Runtime permissions

The process needs access to the configured VICI Unix socket. XFRM dump availability depends on the kernel and security policy. Permission errors are returned as IPSEC_ERR_PERMISSION; the library does not require root unconditionally.

## Dependency verification

After building on Linux:

    readelf -d build/libipsec_native.so
    ldd build/libipsec_native.so
    nm -D build/libipsec_native.so

Expected dynamic dependencies are libc and pthread support as provided by the target toolchain. There must be no libstrongswan, libcharon, or libvici dependency.

The shared object uses `src/libipsec_native.map` to export only the documented
public API. Internal VICI and Netlink parser symbols remain local.

Verify forbidden command execution APIs and command names:

    grep -R -n -E '\b(system|popen|fork|exec[a-z]*)[[:space:]]*\(' src include
    grep -R -n -E '"(swanctl|ipsec|ip|systemctl|tcpdump|iptables|nft|ss)"' src include

## Validation status

Unit tests cover the v15 endpoint configuration conversion, VICI
encode/decode boundaries, version-tolerant
/proc/net/xfrm_stat parsing, XFRM state/policy Netlink decoding, and
interface/address/route Netlink decoding. Malformed and truncated inputs are
included.

The full source, static/shared libraries, examples, the Native CLI, six
unit-test binaries, and the live integration-test binary have been
cross-compiled with C11,
-Wall, -Wextra, -Wpedantic, and -Werror for x86_64 Linux and aarch64 Linux.
The parser-only VICI and xfrm_stat tests also pass by execution on the
development host. A real charon/peer and kernel XFRM runtime are not available
on that host, so the live integration workflow remains a required target-host
verification step.

See docs/v15_analysis.md for the source-program analysis,
docs/native_architecture.md for the Native replacement design, and
docs/petalinux_compatibility.md for target requirements and cross builds.
