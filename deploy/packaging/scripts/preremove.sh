#!/bin/sh
# deb: $1 = remove | upgrade | deconfigure | failed-upgrade.
# rpm: $1 = 0 on erase, 1 on upgrade.
set -e

case "$1" in
    remove | deconfigure | 0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now rk-sensor.service
        fi
        # Stopping keeps the pinned programs enforcing, and once the
        # heartbeat is stale they deny every governed ENFORCE action.
        # Removal must end protection explicitly (docs/design/phase-10.md §5).
        /usr/bin/rk-sensor --uninstall
        ;;
esac
exit 0
