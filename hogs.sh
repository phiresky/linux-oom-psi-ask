#!/bin/sh
# Start (or stop) a pack of memory hogs to demo psi-ask, safely fenced in a
# cgroup: MemoryHigh throttling makes them thrash in reclaim, which raises
# real PSI memory pressure without endangering the rest of the system.
#
#   ./hogs.sh            start 4 hogs, 512M high / 1G max
#   ./hogs.sh 8          start 8 hogs
#   ./hogs.sh 8 2G 4G    8 hogs, MemoryHigh=2G, MemoryMax=4G
#   ./hogs.sh stop       stop them
set -eu
UNIT=psi-demo-hogs

if [ "${1:-}" = "stop" ]; then
    systemctl --user stop "$UNIT.scope" 2>/dev/null && echo "hogs stopped" \
        || echo "no hogs running"
    exit 0
fi

COUNT=${1:-4}
HIGH=${2:-512M}
MAX=${3:-1G}

HOG=$(mktemp /tmp/psi-demo-hog-XXXX.py)
cat > "$HOG" <<'EOF'
import time
# grow to ~700M and keep re-touching pages so reclaim never wins
bufs = []
while True:
    if len(bufs) < 88:
        bufs.append(bytearray(8 * 1024 * 1024))
    for b in bufs[::4]:
        b[::4096] = b'\x01' * len(b[::4096])
    time.sleep(0.01)
EOF

systemd-run --user --scope --collect --unit="$UNIT" \
    -p MemoryHigh="$HIGH" -p MemoryMax="$MAX" -p MemorySwapMax=0 \
    sh -c "for i in \$(seq $COUNT); do python3 '$HOG' & done; wait" &

echo "$COUNT hogs started (MemoryHigh=$HIGH MemoryMax=$MAX)."
echo "watch:  cat /proc/pressure/memory"
echo "stop:   ./hogs.sh stop"
