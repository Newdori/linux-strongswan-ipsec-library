#!/usr/bin/env bash

set -euo pipefail

pcScriptDirectory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pcProjectDirectory=$(CDPATH= cd -- "${pcScriptDirectory}/.." && pwd)
uiJobCount=${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}

make -C "${pcProjectDirectory}/ipsec" clean_host
make -C "${pcProjectDirectory}/ipsec" -j"${uiJobCount}" host

printf 'Created:\n'
printf '  %s\n' "${pcProjectDirectory}/lib/x86_64/libipsec.a"
printf '  %s\n' "${pcProjectDirectory}/lib/x86_64/libipsec.so"
