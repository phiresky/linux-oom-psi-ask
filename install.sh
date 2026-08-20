#!/bin/sh
# Build and install psi-ask as a systemd user service:
#   ~/.local/bin/psi-ask            capability-blessed binary
#   ~/.config/systemd/user/psi-ask.service
set -eu
cd "$(dirname "$0")"

cargo build --release
install -Dm755 target/release/psi-ask "$HOME/.local/bin/psi-ask"
sudo setcap cap_ipc_lock,cap_sys_resource,cap_sys_nice,cap_kill+ep \
    "$HOME/.local/bin/psi-ask"
install -Dm644 psi-ask.service \
    "$HOME/.config/systemd/user/psi-ask.service"

# The GUI needs the session's Wayland socket in the user manager's env.
if ! systemctl --user show-environment | grep -q '^WAYLAND_DISPLAY='; then
    echo "note: importing WAYLAND_DISPLAY into the systemd user environment"
    systemctl --user import-environment WAYLAND_DISPLAY XDG_CURRENT_DESKTOP 2>/dev/null || true
fi
systemctl --user daemon-reload
systemctl --user enable --now psi-ask.service
systemctl --user --no-pager status psi-ask.service | head -5
echo
echo "logs:    journalctl --user -u psi-ask -f"
echo "disable: systemctl --user disable --now psi-ask"
