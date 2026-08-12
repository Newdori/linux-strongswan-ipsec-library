#!/usr/bin/env bash

set -euo pipefail

pcScriptDirectory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pcProjectDirectory=$(CDPATH= cd -- "${pcScriptDirectory}/.." && pwd)
pcCrossCompile=${CROSS_COMPILE:-aarch64-linux-gnu-}
uiJobCount=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
acMakeArguments=(
    -C "${pcProjectDirectory}/ipsec"
    -j"${uiJobCount}"
    zynqmp
    "CROSS_COMPILE=${pcCrossCompile}"
)

if ! command -v "${pcCrossCompile}gcc" >/dev/null 2>&1; then
    printf 'Compiler not found: %sgcc\n' "${pcCrossCompile}" >&2
    exit 1
else
    # Continue with the selected AArch64 toolchain.
    :
fi

if [[ -n "${SYSROOT:-}" ]]; then
    acMakeArguments+=("SYSROOT=${SYSROOT}")
else
    # A generic Ubuntu cross sysroot will be used.
    :
fi

make -C "${pcProjectDirectory}/ipsec" clean_zynqmp
make "${acMakeArguments[@]}"

"${pcCrossCompile}readelf" -h \
    "${pcProjectDirectory}/lib/zynqmp/libipsec.so" | grep -q 'AArch64'

printf 'Created AArch64 libraries:\n'
printf '  %s\n' "${pcProjectDirectory}/lib/zynqmp/libipsec.a"
printf '  %s\n' "${pcProjectDirectory}/lib/zynqmp/libipsec.so"
