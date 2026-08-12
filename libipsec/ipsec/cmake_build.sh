#!/usr/bin/env bash

set -euo pipefail

PrintUsage()
{
    printf 'Usage: %s [host|zynqmp|clean]\n' "${0##*/}"
}

pcSourceDirectory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pcProjectDirectory=$(CDPATH= cd -- "${pcSourceDirectory}/.." && pwd)
pcTarget=${1:-host}
pcBuildType=${BUILD_TYPE:-Release}
pcCrossCompile=${CROSS_COMPILE:-aarch64-linux-gnu-}
pcSysroot=${SYSROOT:-${PETALINUX_SYSROOT:-}}
uiJobCount=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
bBuildTesting=${BUILD_TESTING:-ON}
bBuildApplication=${IPSEC_NATIVE_BUILD_APPLICATION:-ON}
bBuildIntegrationTests=${IPSEC_NATIVE_BUILD_INTEGRATION_TESTS:-OFF}
bRunTests=${RUN_TESTS:-ON}
acCmakeArguments=()

if [[ 1 -lt $# ]]; then
    PrintUsage >&2
    exit 2
else
    # Continue with the selected target.
    :
fi

if command -v cmake >/dev/null 2>&1; then
    # CMake is available.
    :
else
    printf 'CMake was not found in PATH.\n' >&2
    exit 1
fi

case "${pcTarget}" in
host)
    pcBuildDirectory="${pcProjectDirectory}/build/host"
    ;;
zynqmp)
    pcBuildDirectory="${pcProjectDirectory}/build/zynqmp"
    pcCompiler=${CC:-${pcCrossCompile}gcc}
    pcArchiver=${AR:-${pcCrossCompile}ar}
    pcRanlib=${RANLIB:-${pcCrossCompile}ranlib}

    if command -v "${pcCompiler}" >/dev/null 2>&1 ||
       [[ -f "${pcCompiler}" ]]; then
        # The selected cross compiler is available.
        :
    else
        printf 'Cross compiler was not found: %s\n' "${pcCompiler}" >&2
        exit 1
    fi

    acCmakeArguments+=(
        -DCMAKE_SYSTEM_NAME=Linux
        -DCMAKE_SYSTEM_PROCESSOR=aarch64
        "-DCMAKE_C_COMPILER=${pcCompiler}"
        "-DCMAKE_AR=${pcArchiver}"
        "-DCMAKE_RANLIB=${pcRanlib}"
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
    )

    if [[ -n "${pcSysroot}" ]]; then
        acCmakeArguments+=("-DCMAKE_SYSROOT=${pcSysroot}")
    else
        # Use the cross compiler's default sysroot.
        :
    fi
    ;;
clean)
    cmake -E remove_directory "${pcProjectDirectory}/build/host"
    cmake -E remove_directory "${pcProjectDirectory}/build/zynqmp"
    printf 'Removed CMake host and ZynqMP build directories.\n'
    exit 0
    ;;
*)
    PrintUsage >&2
    exit 2
    ;;
esac

acCmakeArguments+=(
    -S "${pcSourceDirectory}"
    -B "${pcBuildDirectory}"
    "-DCMAKE_BUILD_TYPE=${pcBuildType}"
    "-DBUILD_TESTING=${bBuildTesting}"
    -DCMAKE_LINK_DEPENDS_USE_LINKER=FALSE
    "-DIPSEC_NATIVE_BUILD_APPLICATION=${bBuildApplication}"
    "-DIPSEC_NATIVE_BUILD_INTEGRATION_TESTS=${bBuildIntegrationTests}"
)

cmake "${acCmakeArguments[@]}"
cmake --build "${pcBuildDirectory}" --parallel "${uiJobCount}"

if [[ "host" == "${pcTarget}" && "ON" == "${bBuildTesting}" &&
      "ON" == "${bRunTests}" ]]; then
    ctest --test-dir "${pcBuildDirectory}" --output-on-failure
else
    # Cross-compiled tests are built but not executed on the build host.
    :
fi

printf 'CMake %s build completed: %s\n' "${pcTarget}" "${pcBuildDirectory}"
