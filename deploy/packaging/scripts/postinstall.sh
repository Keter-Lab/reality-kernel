#!/bin/sh
# deb: $1 = configure, $2 = previously configured version (empty on install).
# rpm: $1 = 1 on install, 2 on upgrade.
set -e
systemd_running() { [ -d /run/systemd/system ]; }

case "$1" in
    configure)
        if systemd_running; then
            systemctl daemon-reload
            if [ -z "${2:-}" ]; then
                systemctl enable --now rk-sensor.service
            else
                # Upgrade: the new sensor adopts the pins, or replaces a
                # different object without a gap (docs/design/phase-10.md §3).
                systemctl try-restart rk-sensor.service
            fi
        fi
        ;;
    1)
        if systemd_running; then
            systemctl daemon-reload
            systemctl enable --now rk-sensor.service
        fi
        ;;
    2)
        # The old package's %postun restarts the service.
        if systemd_running; then
            systemctl daemon-reload
        fi
        ;;
esac
exit 0
