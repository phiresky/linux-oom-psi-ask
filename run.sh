#!/bin/sh
# Launch psi-ask insulated from the memory pressure it is watching.
# It must run inside your Wayland session, so this uses the *user* manager:
#   MemoryMin/MemoryLow=  kernel avoids reclaiming our pages under pressure
#   MemorySwapMax=0       never swapped
# oom_score_adj=-1000, signaling any process, and unlimited mlockall need
# capabilities instead of root on Wayland: run ./install-caps.sh once
# (the user manager cannot raise LimitMEMLOCK, so capabilities it is).
set -eu
cd "$(dirname "$0")"
[ -x target/release/psi-ask ] || cargo build --release
exec systemd-run --user -t --same-dir --collect \
    --unit=psi-ask \
    -p MemoryMin=128M \
    -p MemoryLow=128M \
    -p MemorySwapMax=0 \
    ./target/release/psi-ask "$@"
