#!/bin/sh
# Give the psi-ask binary the capabilities it needs for full protection
# without running the GUI as root (which doesn't mix with a user Wayland
# session):
#   cap_ipc_lock      unlimited mlockall (never swapped/reclaimed)
#   cap_sys_resource  set /proc/self/oom_score_adj = -1000
#   cap_sys_nice      nice -20 so it stays responsive while thrashing
#   cap_kill          SIGSTOP/SIGCONT/SIGTERM/SIGKILL any process
# Re-run after every rebuild (the file is replaced, caps are per-inode).
set -eu
cd "$(dirname "$0")"
[ -x target/release/psi-ask ] || cargo build --release
sudo setcap cap_ipc_lock,cap_sys_resource,cap_sys_nice,cap_kill+ep target/release/psi-ask
getcap target/release/psi-ask
