#!/bin/sh
set -eu

root=$1
build=$2
image=${VM_IMAGE:-}
format=${VM_IMAGE_FORMAT:-qcow2}
key=${VM_SSH_KEY:-}
user=${VM_SSH_USER:-root}
port=${VM_SSH_PORT:-22222}
memory=${VM_MEMORY:-2048}
stage="$build/vm"
archive="$stage/source.tar.gz"
log="$stage/console.log"
known_hosts="$stage/known-hosts"
pid=

test -n "$image" || {
    printf '%s\n' 'set VM_IMAGE to a provisioned stock-distribution image' >&2
    exit 2
}
test -r "$image" || {
    printf '%s\n' "VM image is not readable: $image" >&2
    exit 2
}
test -n "$key" && test -r "$key" || {
    printf '%s\n' 'set VM_SSH_KEY to the image root login key' >&2
    exit 2
}
case "$port" in
    ''|*[!0-9]*) exit 2 ;;
esac
case "$memory" in
    ''|*[!0-9]*) exit 2 ;;
esac
command -v qemu-system-x86_64 >/dev/null 2>&1
command -v ssh >/dev/null 2>&1
command -v scp >/dev/null 2>&1

cleanup()
{
    if test -n "$pid" && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

rm -rf "$stage"
mkdir -p "$stage"
tar -C "$root" --exclude build --exclude .git -czf "$archive" \
    Makefile LICENSE src tests

qemu-system-x86_64 \
    -machine accel=kvm:tcg -cpu max -smp 2 -m "$memory" \
    -display none -serial "file:$log" -snapshot \
    -drive "file=$image,format=$format,if=virtio" \
    -netdev "user,id=melodi_net,hostfwd=tcp:127.0.0.1:$port-:22" \
    -device virtio-net-pci,netdev=melodi_net &
pid=$!

ssh_run()
{
    ssh -i "$key" -p "$port" -o BatchMode=yes -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile="$known_hosts" "$@"
}
attempt=0
while test "$attempt" -lt 120; do
    if ssh_run "$user@127.0.0.1" true 2>/dev/null; then
        break
    fi
    kill -0 "$pid" 2>/dev/null || {
        cat "$log" >&2
        exit 1
    }
    sleep 1
    attempt=$((attempt + 1))
done
test "$attempt" -lt 120 || {
    cat "$log" >&2
    exit 1
}

scp -i "$key" -P "$port" -o BatchMode=yes -o ConnectTimeout=2 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile="$known_hosts" \
    "$archive" "$user@127.0.0.1:/tmp/melodi-source.tar.gz"
ssh_run "$user@127.0.0.1" \
    'rm -rf /tmp/melodi-vm && mkdir /tmp/melodi-vm && tar -C /tmp/melodi-vm -xzf /tmp/melodi-source.tar.gz && sh /tmp/melodi-vm/tests/vm/guest.sh /tmp/melodi-vm'
