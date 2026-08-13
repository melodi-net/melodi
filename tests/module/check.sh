#!/bin/sh
set -eu

directory=$1

for module in melodi_core melodi_loop melodi_usb melodi_usb_emulator; do
    test -f "$directory/$module.ko" || {
        printf '%s\n' "missing module: $module.ko" >&2
        exit 1
    }
    test "$(modinfo -F name "$directory/$module.ko")" = "$module"
    test "$(modinfo -F license "$directory/$module.ko")" = GPL
done

test "$(modinfo -F depends "$directory/melodi_core.ko")" = libcurve25519
test "$(modinfo -F depends "$directory/melodi_loop.ko")" = melodi_core
test "$(modinfo -F depends "$directory/melodi_usb.ko")" = melodi_core
test "$(modinfo -F depends "$directory/melodi_usb_emulator.ko")" = \
    libcomposite,udc-core
test "$(modinfo -F alias "$directory/melodi_usb.ko")" = \
    'tty-ldisc-29
usb:v1D6BpF00Dd0100dc*dsc*dp*icFFisc4Dip01in00*'

if nm -u "$directory/melodi_core.ko" "$directory/melodi_loop.ko" \
    "$directory/melodi_usb.ko" "$directory/melodi_usb_emulator.ko" |
    grep -E '(^|[[:space:]])(can_|ip6?_|inet6?_|tcp_|udp_)'; then
    printf '%s\n' 'forbidden stack dependency found' >&2
    exit 1
fi
