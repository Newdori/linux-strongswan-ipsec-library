# Build and verification record

Date: 2026-08-12

## Strict cross compilation

The complete product source was compiled as position-independent C11 code for
both targets with:

    -std=c11
    -D_POSIX_C_SOURCE=200809L
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -fPIC

Results:

| Target | All source objects | Static library | Shared library |
|---|---:|---:|---:|
| x86_64-linux-gnu | PASS | PASS | PASS |
| aarch64-linux-gnu | PASS | PASS | PASS |

The following consumers also compile and link for both targets:
- `tests/unit/test_vici_packet.c`
- `tests/unit/test_xfrm_stats.c`
- `tests/unit/test_xfrm_netlink.c`
- `tests/unit/test_route_netlink.c`
- `tests/unit/test_app_config.c`
- `tests/unit/test_app_command.c`
- `tests/unit/test_app_loop.c`
- `tests/integration/test_live_ipsec.c`
- `app/`
- public headers included from a C++17 translation unit

## CMake verification

The primary CMake build was configured with a Linux x86_64 cross target and
successfully built:

- `ipsec_native_static`
- `ipsec_native_shared`
- all seven unit-test targets
- `ipsec_app`
- opt-in `test_live_ipsec`

`cmake --install` successfully installed the static library, versioned shared
library symlink set, and three public headers.

## Executed host tests

The development host is Windows and has no Linux kernel XFRM or charon daemon.
The platform-independent parser cores were therefore executed through
test-only compatibility headers:

| Test | Result |
|---|---:|
| VICI packet encode/decode and malformed boundaries | PASS |
| `/proc/net/xfrm_stat` key/value and malformed input | PASS |
| v15 endpoint configuration parse/convert (fixture and two actual configs) | PASS |
| interactive CLI command tokenizer and number validation | PASS |
| application lifecycle mock loop, 25 iterations | PASS |

The compatibility headers under `tests/host/` are not part of product targets.
Linux Netlink unit binaries are compiled but require a Linux runner to execute.

## ELF and ABI checks

`readelf -d` on both shared objects shows no strongSwan library dependency.
The x86_64 object requires libc and pthread; the aarch64 object additionally
records its target runtime loader. The version script exports exactly the 35
documented public API symbols under `IPSEC_NATIVE_0.1`; internal VICI/Netlink
symbols are local.

## Prohibited behavior scans

Source-only scans of `ipsec/` and `include/` report:

| Check | Matches |
|---|---:|
| `system`, `popen`, `fork`, `exec*` calls | 0 |
| forbidden command execution strings | 0 |
| `sprintf` calls | 0 |
| strongSwan/charon/libvici dynamic symbols | 0 |

The v15 application configuration parser was executed against the repository
fixture and the actual v15 `pc_a_initiator.conf` and `pc_b_responder.conf`;
all three parsed and converted successfully. The `Makefile.host` dependency
graph was also checked with the `aarch64-linux-gnu-` prefix. Its archive target
is `./lib/zynqmp/libipsec.a`.

## Public repository and PetaLinux build update

- The product directory was renamed to `libipsec`; library implementation and
  build entry points now reside under `libipsec/ipsec`.
- GNU Make host and ZynqMP library builds, both application builds, and the
  complete CMake target graph compile successfully from the relocated paths.
- CMake registers all seven unit tests. The Windows verification host cannot
  execute the generated Linux ELF test binaries; execution remains covered by
  the Ubuntu CI job and target-host validation.
- GNU Make produced both `lib/x86_64/libipsec.a` and
  `lib/x86_64/libipsec.so` for x86_64 Linux.
- The same Make dependency graph produced AArch64 ELF archives and shared
  objects with strict C11 warnings enabled.
- The AArch64 ELF headers report `EM_AARCH64`.
- The application Makefile produced x86_64 and AArch64 executables through
  its `host` and `zynqmp` targets.
- The interactive application sources, including the session dispatcher and
  quoted command parser, compile and link for both architectures with strict
  warnings enabled.
- GNU Make library object and dependency files are isolated under the
  target-specific `ipsec/obj/x86_64` and `ipsec/obj/zynqmp` directories;
  application objects use the same layout below `app/obj`.
- CMake found POSIX Threads through `Threads::Threads` and the complete
  static/shared/application/test build passed.
- The Ubuntu CI invokes the GNU Make and CMake entry points directly.
- The supplied PetaLinux v15 tree was reviewed for its AArch64, strongSwan
  5.8.4, VICI socket and rootfs expectations. See
  `docs/petalinux_compatibility.md`.

The AArch64 compile result proves source/toolchain compatibility, not runtime
qualification on the final PetaLinux image. Target runtime validation remains
required.

## Target-host verification still required

- strongSwan 5.8.4 and newer live VICI interoperability
- actual PSK peer establishment and IKE/CHILD rekey/termination
- PFS, ESN, NAT-T, tunnel and transport configurations used by the product
- live XFRM state/policy/statistics and route dump comparison
- Ubuntu native GCC build and PetaLinux aarch64 toolchain build
- concurrency, reconnect, long-duration and malformed-daemon stress tests

Use `tests/integration/README.md` and run these checks on isolated test daemons;
the integration cleanup clears credentials loaded over VICI.
