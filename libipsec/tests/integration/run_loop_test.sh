#!/bin/sh

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 CONFIG [COUNT] [DELAY_MS]" >&2
    exit 2
fi

pcConfig=$1
uiCount=${2:-100}
uiDelayMs=${3:-500}
pcApplication=${IPSEC_APP:-./apps/bin/x86_64/ipsec_app}

exec "$pcApplication" --config "$pcConfig" test loop \
    --count "$uiCount" --delay-ms "$uiDelayMs"
