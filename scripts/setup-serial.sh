#!/usr/bin/env bash
# Installs the Meshtastic serial udev rule. Run with sudo.
set -euo pipefail

RULE=99-melodi-serial.rules
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$RULE"
DEST="/etc/udev/rules.d/$RULE"

if [[ ${EUID} -ne 0 ]]; then
    echo "error: needs root — run: sudo $0" >&2
    exit 1
fi

if [[ ! -f "$SRC" ]]; then
    echo "error: rule not found at $SRC" >&2
    exit 1
fi

install -m 0644 -o root -g root "$SRC" "$DEST"
udevadm control --reload-rules
udevadm trigger --subsystem-match=tty --action=change
udevadm settle

echo "installed $DEST"

shopt -s nullglob
found=0
for link in /dev/ttyMEL*; do
    dev="$(readlink -f "$link")"
    printf '  %-28s -> %-14s %s\n' "$link" "$dev" "$(stat -c '%U:%G %a' "$dev")"
    found=1
done

if [[ $found -eq 0 ]]; then
    echo "  no Meshtastic radio detected"
fi
