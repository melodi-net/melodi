#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

allowed='^(build|src|tests|\.git|\.agents|\.codex|\.direnv)$'
bad_dirs=$(find . -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | grep -Ev "$allowed" || true)
if test -n "$bad_dirs"; then
    printf '%s\n' "forbidden project directories:" "$bad_dirs" >&2
    exit 1
fi

scan_files=$(find src tests -type f ! -path 'tests/architecture/check.sh' ! -path 'tests/architecture/comments.sh' ! -path 'tests/architecture/comments.awk' -print 2>/dev/null || true)
scan_files=$(printf '%s\n%s\n' 'Makefile' 'flake.nix' "$scan_files" | sed '/^$/d')
runtime_scan_files=$(printf '%s\n' "$scan_files" | grep -v '^tests/vm/run.sh$')
if printf '%s\n' "$scan_files" | xargs grep -nE \
    '(AF|PF|SOL)_MELODI|AF_INET6?|PF_CAN|ARPHRD_CAN|struct[[:space:]]+can_frame|/dev/(net/)?tun|TUNSETIFF|AF_PACKET'; then
    printf '%s\n' 'forbidden application architecture found' >&2
    exit 1
fi

if printf '%s\n' "$runtime_scan_files" | xargs grep -niE \
    '(^|[^[:alnum:]_])(daemon|libusb)([^[:alnum:]_]|$)|tty(USB|ACM)|serial (helper|path|forward)|bzImage|initramfs|grub-install|reboot|AF_UNIX|AF_LOCAL'; then
    printf '%s\n' 'forbidden runtime or kernel workflow found' >&2
    exit 1
fi

tty_paths=$(printf '%s\n' "$runtime_scan_files" | xargs grep -nE \
    '/dev/tty[^[:space:]]*' 2>/dev/null || true)
if printf '%s\n' "$tty_paths" | grep -vE \
    '/dev/ttyMEL([[:digit:]]+|N)([^[:alnum:]_]|$)' | grep -q .; then
    printf '%s\n' "$tty_paths" >&2
    printf '%s\n' 'forbidden tty device name found' >&2
    exit 1
fi

if printf '%s\n' "$scan_files" | xargs grep -niE \
    '(git[[:space:]]+clone|curl|wget).*(linux|kernel)|linux-(stable|next)\.git|make[[:space:]].*(bzImage|modules_install)|install-kernel|kernel-build|kernel-patch'; then
    printf '%s\n' 'forbidden kernel acquisition or build workflow found' >&2
    exit 1
fi

if grep -RInE 'MELODI_A_DEST_(NODE_?NUM(BER)?|LOCATOR)' src tests; then
    printf '%s\n' 'NodeNum destination UAPI is forbidden' >&2
    exit 1
fi

if grep -RInE 'node_number|NODE_NUMBER' \
    src/kernel/core src/proto/mapping.c src/proto/mapping.h \
    src/proto/wire.c src/proto/wire.h; then
    printf '%s\n' 'native locator is mislabeled as a NodeNum' >&2
    exit 1
fi

send_handler=$(sed -n '/^static int melodi_send(/,/^}/p' \
    src/kernel/core/netlink.c)
printf '%s\n' "$send_handler" | grep -q \
    'melodi_binding_by_socket(net, info->snd_portid)' || {
    printf '%s\n' 'send handler does not require a socket binding' >&2
    exit 1
}
printf '%s\n' "$send_handler" | grep -q \
    'dev_hold(dev)' || {
    printf '%s\n' 'send handler does not use the bound interface' >&2
    exit 1
}
printf '%s\n' "$send_handler" | grep -q \
    'melodi_data_admit' || {
    printf '%s\n' 'send handler does not reserve the complete message' >&2
    exit 1
}
printf '%s\n' "$send_handler" | grep -q \
    'dev_queue_xmit(message)' || {
    printf '%s\n' 'send handler bypasses the netdevice transmit path' >&2
    exit 1
}

start_xmit=$(sed -n '/^static netdev_tx_t melodi_start_xmit(/,/^}/p' \
    src/kernel/core/main.c)
printf '%s\n' "$start_xmit" | grep -q \
    'logical_tx_queue' || {
    printf '%s\n' 'netdevice transmit does not accept logical messages' >&2
    exit 1
}

queue_entry=$(sed -n '/^struct melodi_tx_queue_entry {/,/^};/p' \
    src/kernel/core/internal.h)
printf '%s\n' "$queue_entry" | grep -q \
    'struct melodi_node_id destination;' || {
    printf '%s\n' 'queued data does not retain the destination NodeId' >&2
    exit 1
}
printf '%s\n' "$queue_entry" | grep -q \
    'u16 destination_service;' || {
    printf '%s\n' 'queued data does not retain destination service policy' >&2
    exit 1
}
grep -q '^void melodi_queue_state_changed(struct net_device \*dev)' \
    src/kernel/core/queue.c || {
    printf '%s\n' 'queued data cannot be invalidated by state changes' >&2
    exit 1
}
grep -q 'melodi_data_queue_valid_locked' src/kernel/core/queue.c || {
    printf '%s\n' 'queued data is not revalidated before transport' >&2
    exit 1
}
if grep -q 'melodi->policy_mode = mode' src/kernel/core/netlink.c; then
    printf '%s\n' 'Netlink bypasses policy-state invalidation' >&2
    exit 1
fi
grep -q 'melodi_policy_set_mode(dev, mode)' src/kernel/core/netlink.c || {
    printf '%s\n' 'policy mode does not use the state-aware setter' >&2
    exit 1
}

mapping_definitions=$(grep -RIl \
    '^int melodi_map_native_locator(' src --include='*.c' | wc -l)
test "$mapping_definitions" -eq 1 || {
    printf '%s\n' 'NodeId mapping must have one implementation' >&2
    exit 1
}

if grep -RInE 'MELODI_MESH_RADIO_CONFIG|MELODI_MESH_.*CAPABILIT|melodi_mesh_radio_config' \
    src tests/unit tests/usb; then
    printf '%s\n' 'custom Meshtastic readiness extension is forbidden' >&2
    exit 1
fi

grep -q '^#define MELODI_MESH_PRIVATE_PORT 256$' \
    src/proto/meshtastic.h || {
    printf '%s\n' 'stock PRIVATE_APP PortNum is required' >&2
    exit 1
}
grep -q 'MELODI_MESH_EVENT_MY_INFO' src/kernel/usb/main.c || {
    printf '%s\n' 'stock MyNodeInfo readiness is required' >&2
    exit 1
}
grep -q 'melodi_link_ready(device->netdev, true, local_locator)' \
    src/kernel/usb/main.c || {
    printf '%s\n' 'stock NodeNum must be reported as the link locator' >&2
    exit 1
}

if grep -niE 'meshtastic|protobuf|portnum|phoneapi|usb_(ep|descriptor)' \
    src/kernel/include/melodi/core.h; then
    printf '%s\n' 'backend-specific type leaked into the core ABI' >&2
    exit 1
fi

if grep -RIn 'EXPORT_SYMBOL(' src/kernel; then
    printf '%s\n' 'kernel exports must use EXPORT_SYMBOL_GPL' >&2
    exit 1
fi

for path in patches docs daemon vendor packaging; do
    test ! -e "$path" || { printf '%s\n' "forbidden root path: $path" >&2; exit 1; }
done

test ! -n "$(find . -type f \( -name '*.patch' -o -name '*.diff' \) ! -path './.git/*' -print -quit)" || {
    printf '%s\n' 'Linux patch artifacts are forbidden' >&2
    exit 1
}

executable=$(find src tests -type f -perm /111 -print -quit 2>/dev/null || true)
test -z "$executable" || { printf '%s\n' "executable source is forbidden: $executable" >&2; exit 1; }

exit 0
