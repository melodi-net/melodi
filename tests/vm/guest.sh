#!/bin/sh
set -eu

root=$1

test "$(id -u)" -eq 0 || {
    printf '%s\n' 'the VM test user must be root' >&2
    exit 2
}
test -d "/lib/modules/$(uname -r)/build" || {
    printf '%s\n' 'the VM image needs matching packaged kernel headers' >&2
    exit 2
}

make -C "$root" verify
make -C "$root" module-install-smoke
make -C "$root" install-smoke
make -C "$root" uninstall-smoke
make -C "$root" loop-smoke
make -C "$root" namespace-smoke
make -C "$root" language-smoke
test -z "$(pgrep -x melodid 2>/dev/null || true)"
