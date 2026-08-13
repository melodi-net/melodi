#!/bin/sh
set -eu

build=$1
module_dir=$build/kernel
identity_dir=
emulator_loaded=0
receiver_pid=
received=
received_meta=

cleanup()
{
    test -z "$receiver_pid" || kill "$receiver_pid" 2>/dev/null || true
    if test "$emulator_loaded" = 1; then
        rmmod melodi_usb_emulator 2>/dev/null || true
    fi
    rmmod melodi_usb 2>/dev/null || true
    rmmod melodi_core 2>/dev/null || true
    rmmod libcomposite 2>/dev/null || true
    rmmod dummy_hcd 2>/dev/null || true
    if test -n "$identity_dir"; then
        rm -rf "$identity_dir"
    fi
}

wait_status()
{
    interface=$1
    expected=$2
    count=0
    while test "$count" -lt 100; do
        if "$build/bin/melodi" status -i "$interface" 2>/dev/null |
            grep -q "$interface: $expected"; then
            return 0
        fi
        sleep 0.1
        count=$((count + 1))
    done
    "$build/bin/melodi" status -i "$interface" >&2 || true
    return 1
}

reset_radio()
{
    serial=$1
    for path in /sys/bus/usb/devices/*/serial; do
        test -f "$path" || continue
        test "$(cat "$path")" = "$serial" || continue
        device=${path%/serial}
        bus=$(printf '%03d' "$(cat "$device/busnum")")
        number=$(printf '%03d' "$(cat "$device/devnum")")
        usbreset "/dev/bus/usb/$bus/$number"
        return
    done
    printf '%s\n' "USB radio not found: $serial" >&2
    return 1
}

radio_device()
{
    serial=$1
    for path in /sys/bus/usb/devices/*/serial; do
        test -f "$path" || continue
        test "$(cat "$path")" = "$serial" || continue
        printf '%s\n' "${path%/serial}"
        return
    done
    return 1
}

wait_power()
{
    device=$1
    expected=$2
    count=0
    while test "$count" -lt 100; do
        test "$(cat "$device/power/runtime_status")" = "$expected" && return
        sleep 0.1
        count=$((count + 1))
    done
    return 1
}

test "$(id -u)" = 0 || {
    printf '%s\n' 'usb-emulation requires root' >&2
    exit 2
}
modinfo dummy_hcd >/dev/null 2>&1 || {
    printf '%s\n' 'usb-emulation requires the stock-kernel dummy_hcd module' >&2
    exit 2
}
command -v usbreset >/dev/null 2>&1 || {
    printf '%s\n' 'usb-emulation requires usbreset' >&2
    exit 2
}
test ! -d /sys/class/net/mel0 || {
    printf '%s\n' 'usb-emulation requires no loaded Melodi modules' >&2
    exit 2
}
for module in melodi_core melodi_usb melodi_usb_emulator; do
    test -f "$module_dir/$module.ko" || {
        printf '%s\n' "missing module: $module_dir/$module.ko" >&2
        exit 2
    }
done

trap cleanup EXIT HUP INT TERM
modprobe dummy_hcd num=2
modprobe libcomposite
insmod "$module_dir/melodi_core.ko" interfaces=3 \
    radios=melodi-emulator-2,melodi-emulator-1,unassigned-radio
"$build/bin/melodi" status -i mel0 | grep -q \
    'mel0: disconnected radio=melodi-emulator-2'
"$build/bin/melodi" status -i mel1 | grep -q \
    'mel1: disconnected radio=melodi-emulator-1'
"$build/bin/melodi" status -i mel2 | grep -q \
    'mel2: disconnected radio=unassigned-radio'
if "$build/bin/melodi" link set -i mel1 \
    --usb-serial melodi-emulator-2 2>/dev/null; then
    printf '%s\n' 'duplicate radio selector was accepted' >&2
    exit 1
fi
insmod "$module_dir/melodi_usb.ko" allow_test_device=1
test "$(cat /sys/class/net/mel0/type)" = 65534
ip link set dev mel0 up
ip link set dev mel1 up
ip link set dev mel2 up
test "$(cat /sys/class/net/mel0/carrier)" = 0
test "$(cat /sys/class/net/mel1/carrier)" = 0
test "$(cat /sys/class/net/mel2/carrier)" = 0
ip -details link show dev mel0 | grep -q 'link/none'
test -z "$(ip -o -4 addr show dev mel0)"
test -z "$(ip -o -6 addr show dev mel0)"

insmod "$module_dir/melodi_usb_emulator.ko" near_miss=1
emulator_loaded=1
sleep 1
wait_status mel0 disconnected
wait_status mel1 disconnected
rmmod melodi_usb_emulator
emulator_loaded=0

identity_dir=$(mktemp -d "${TMPDIR:-/tmp}/melodi-usb.XXXXXX")
received="$identity_dir/received"
received_meta="$identity_dir/received.meta"
"$build/bin/melodi" identity generate "$identity_dir/identity0"
"$build/bin/melodi" identity generate "$identity_dir/identity1"
"$build/bin/melodi" identity load -i mel0 --generation 1 \
    "$identity_dir/identity0"
"$build/bin/melodi" identity load -i mel1 --generation 1 \
    "$identity_dir/identity1"
node0=$("$build/bin/melodi" id -i mel0)
node1=$("$build/bin/melodi" id -i mel1)
ifindex0=$(cat /sys/class/net/mel0/ifindex)
ifindex1=$(cat /sys/class/net/mel1/ifindex)

insmod "$module_dir/melodi_usb_emulator.ko" firmware_refusal=1
emulator_loaded=1
wait_status mel0 failed
wait_status mel1 failed
"$build/bin/melodi" status -i mel0 | grep -F 'failed: firmware:'
"$build/bin/melodi" status -i mel1 | grep -F 'failed: firmware:'
rmmod melodi_usb_emulator
emulator_loaded=0
wait_status mel0 disconnected
wait_status mel1 disconnected

insmod "$module_dir/melodi_usb_emulator.ko" unsafe_configuration=1
emulator_loaded=1
wait_status mel0 failed
wait_status mel1 failed
"$build/bin/melodi" status -i mel0 | grep -F 'failed: radio-tx:'
"$build/bin/melodi" status -i mel1 | grep -F 'failed: radio-tx:'
rmmod melodi_usb_emulator
emulator_loaded=0
wait_status mel0 disconnected
wait_status mel1 disconnected

insmod "$module_dir/melodi_usb_emulator.ko" malformed_protobuf=1
emulator_loaded=1
wait_status mel0 failed
wait_status mel1 failed
"$build/bin/melodi" status -i mel0 | grep -F 'failed: protobuf:'
"$build/bin/melodi" status -i mel1 | grep -F 'failed: protobuf:'
rmmod melodi_usb_emulator
emulator_loaded=0
wait_status mel0 disconnected
wait_status mel1 disconnected

insmod "$module_dir/melodi_usb_emulator.ko" pause_handshake=1
emulator_loaded=1
wait_status mel0 configuring
wait_status mel1 configuring
rmmod melodi_usb_emulator
emulator_loaded=0
wait_status mel0 disconnected
wait_status mel1 disconnected

insmod "$module_dir/melodi_usb_emulator.ko"
emulator_loaded=1
wait_status mel0 ready
wait_status mel1 ready
wait_status mel2 disconnected
test "$(cat /sys/class/net/mel0/carrier)" = 1
test "$(cat /sys/class/net/mel1/carrier)" = 1
ip link show dev mel0 | grep -q 'LOWER_UP'
ip link show dev mel1 | grep -q 'LOWER_UP'
"$build/bin/melodi" status -i mel0 | grep -F \
    'mel0: ready radio=melodi-emulator-2 bus='
"$build/bin/melodi" status -i mel1 | grep -F \
    'mel1: ready radio=melodi-emulator-1 bus='
ethtool -i mel0 | grep -Fx 'firmware-version: melodi-usb-test-1'
ethtool -i mel1 | grep -Fx 'firmware-version: melodi-usb-test-1'
bus0=$(ethtool -i mel0 | sed -n 's/^bus-info: //p')
bus1=$(ethtool -i mel1 | sed -n 's/^bus-info: //p')
test -n "$bus0"
test -n "$bus1"
test "$bus0" != "$bus1"

"$build/bin/melodi" discover -i mel0
"$build/bin/melodi" discover -i mel1
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '
"$build/bin/melrecv" -i mel1 12345 >"$received" \
    2>"$received_meta" &
receiver_pid=$!
sleep 1
payload=$(awk 'BEGIN { for (i = 0; i < 700; i++) printf "%c", 97 + i % 26 }')
"$build/bin/melsend" --reliable -i mel0 "$node1" 12345 "$payload"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$payload" "$received"
grep -Fx "$node0 49152" "$received_meta"

"$build/bin/melrecv" -i mel1 12345 >"$received" \
    2>"$received_meta" &
receiver_pid=$!
sleep 1
"$build/bin/melsend" --broadcast -i mel0 12345 \
    'bridged USB broadcast'
wait "$receiver_pid"
receiver_pid=
grep -Fx 'bridged USB broadcast' "$received"
grep -Fx "$node0 49152" "$received_meta"

device0=$(radio_device melodi-emulator-1)
device1=$(radio_device melodi-emulator-2)
printf '%s\n' 0 >"$device0/power/autosuspend_delay_ms"
printf '%s\n' 0 >"$device1/power/autosuspend_delay_ms"
printf '%s\n' auto >"$device0/power/control"
printf '%s\n' auto >"$device1/power/control"
wait_power "$device0" suspended
wait_power "$device1" suspended
test "$(cat /sys/class/net/mel0/carrier)" = 0
test "$(cat /sys/class/net/mel1/carrier)" = 0
printf '%s\n' on >"$device0/power/control"
printf '%s\n' on >"$device1/power/control"
wait_power "$device0" active
wait_power "$device1" active
wait_status mel0 ready
wait_status mel1 ready
"$build/bin/melodi" discover -i mel0
"$build/bin/melodi" discover -i mel1
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '

reset_radio melodi-emulator-1
reset_radio melodi-emulator-2
wait_status mel0 ready
wait_status mel1 ready
test "$(cat /sys/class/net/mel0/ifindex)" = "$ifindex0"
test "$(cat /sys/class/net/mel1/ifindex)" = "$ifindex1"
test "$("$build/bin/melodi" id -i mel0)" = "$node0"
test "$("$build/bin/melodi" id -i mel1)" = "$node1"

rmmod melodi_usb_emulator
emulator_loaded=0
wait_status mel0 disconnected
wait_status mel1 disconnected
test "$(cat /sys/class/net/mel0/carrier)" = 0
test "$(cat /sys/class/net/mel1/carrier)" = 0
test "$(cat /sys/class/net/mel0/ifindex)" = "$ifindex0"
test "$(cat /sys/class/net/mel1/ifindex)" = "$ifindex1"
test "$("$build/bin/melodi" id -i mel0)" = "$node0"
test "$("$build/bin/melodi" id -i mel1)" = "$node1"

insmod "$module_dir/melodi_usb_emulator.ko"
emulator_loaded=1
wait_status mel0 ready
wait_status mel1 ready
test "$(cat /sys/class/net/mel0/carrier)" = 1
test "$(cat /sys/class/net/mel1/carrier)" = 1
test "$(cat /sys/class/net/mel0/ifindex)" = "$ifindex0"
test "$(cat /sys/class/net/mel1/ifindex)" = "$ifindex1"
test "$("$build/bin/melodi" id -i mel0)" = "$node0"
test "$("$build/bin/melodi" id -i mel1)" = "$node1"
"$build/bin/melodi" discover -i mel0
"$build/bin/melodi" discover -i mel1
"$build/bin/melping" -i mel1 "$node0" | grep -F 'reply from '
