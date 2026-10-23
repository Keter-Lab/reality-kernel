#!/bin/sh
# deb: $1 = remove | purge | upgrade | failed-upgrade | abort-install | ...
# rpm: $1 = 0 on erase, 1 on upgrade (this script is the old package's).
set -e
systemd_running() { [ -d /run/systemd/system ]; }

case "$1" in
    purge | 0)
        # The private audit key and the engine state go; the audit logs and
        # the public key stay: they are evidence (docs/audit.md).
        rm -f /var/lib/rk/audit.key /var/lib/rk/engine-state.json
        ;;
esac

case "$1" in
    1)
        # rpm upgrade: start the new binary.
        if systemd_running; then
            systemctl try-restart rk-sensor.service
        fi
        ;;
    remove | purge | 0)
        if systemd_running; then
            systemctl daemon-reload
        fi
        ;;
esac
exit 0
