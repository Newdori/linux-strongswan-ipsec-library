#!/usr/bin/env bash

set -euo pipefail

pcScriptDirectory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pcProjectDirectory=$(CDPATH= cd -- "${pcScriptDirectory}/.." && pwd)
pcBuildDirectory=${BUILD_DIRECTORY:-"${pcProjectDirectory}/build/aarch64"}
uiJobCount=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
acCmakeArguments=(
    -S "${pcProjectDirectory}/ipsec"
    -B "${pcBuildDirectory}"
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_TOOLCHAIN_FILE="${pcProjectDirectory}/ipsec/cmake/toolchains/aarch64-linux-gnu.cmake"
    -DIPSEC_NATIVE_BUILD_INTEGRATION_TESTS=OFF
)

if [[ -n "${SYSROOT:-}" ]]; then
    acCmakeArguments+=("-DCMAKE_SYSROOT=${SYSROOT}")
else
    # A generic Ubuntu cross sysroot will be used.
    :
fi

cmake "${acCmakeArguments[@]}"
cmake --build "${pcBuildDirectory}" --parallel "${uiJobCount}"
