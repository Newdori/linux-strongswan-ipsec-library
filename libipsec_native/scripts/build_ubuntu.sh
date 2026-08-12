#!/usr/bin/env bash

set -euo pipefail

pcScriptDirectory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pcProjectDirectory=$(CDPATH= cd -- "${pcScriptDirectory}/.." && pwd)
uiJobCount=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}

make -C "${pcProjectDirectory}" clean
make -C "${pcProjectDirectory}" -j"${uiJobCount}" all

printf 'Created:\n'
printf '  %s\n' "${pcProjectDirectory}/lib/libipsec_native.a"
printf '  %s\n' "${pcProjectDirectory}/lib/libipsec_native.so"
