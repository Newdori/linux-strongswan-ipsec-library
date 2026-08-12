#!/usr/bin/env bash

set -euo pipefail

PrintUsage()
{
    printf 'Usage: %s [host|zynqmp|clean]\n' "${0##*/}"
}

ResolveBuildTool()
{
    local pcTool=$1
    local pcResolved
    local pcDirectory

    if pcResolved=$(command -v "${pcTool}" 2>/dev/null); then
        printf '%s\n' "${pcResolved}"
    elif [[ -f "${pcTool}" ]]; then
        pcDirectory=$(CDPATH= cd -- "$(dirname -- "${pcTool}")" && pwd)
        printf '%s/%s\n' "${pcDirectory}" "$(basename -- "${pcTool}")"
    else
        return 1
    fi
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

    if pcCompiler=$(ResolveBuildTool "${pcCompiler}"); then
        # The selected cross compiler was resolved to an absolute path.
        :
    else
        printf 'Cross compiler was not found: %s\n' "${pcCompiler}" >&2
        exit 1
    fi
    if pcArchiver=$(ResolveBuildTool "${pcArchiver}"); then
        # The selected archiver was resolved to an absolute path.
        :
    else
        printf 'Cross archiver was not found: %s\n' "${pcArchiver}" >&2
        exit 1
    fi
    if pcRanlib=$(ResolveBuildTool "${pcRanlib}"); then
        # The selected ranlib was resolved to an absolute path.
        :
    else
        printf 'Cross ranlib was not found: %s\n' "${pcRanlib}" >&2
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
