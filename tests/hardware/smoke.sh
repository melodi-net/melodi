#!/bin/sh
set -eu

build=$1
serials=${HARDWARE_SERIALS:-}
firmwares=${HARDWARE_FIRMWARES:-}
core="$build/kernel/melodi_core.ko"
usb="$build/kernel/melodi_usb.ko"
tool="$build/bin/melodi"
send="$build/bin/melsend"
receive="$build/bin/melrecv"
identity0="$build/hardware-identity0.key"
identity1="$build/hardware-identity1.key"
payload="$build/hardware-payload.txt"
metadata="$build/hardware-payload.meta"
tty0=/dev/ttyMEL0
tty1=/dev/ttyMEL1
receiver_pid=

test "$(id -u)" -eq 0 || {
    printf '%s\n' 'hardware-smoke requires root' >&2
    exit 2
}
test -n "$serials" || {
    printf '%s\n' 'set HARDWARE_SERIALS to exactly two comma-separated USB serials' >&2
    exit 2
}
old_ifs=$IFS
IFS=,
set -- $serials
IFS=$old_ifs
test "$#" -eq 2 && test -n "$1" && test -n "$2" && test "$1" != "$2" || {
    printf '%s\n' 'HARDWARE_SERIALS must contain two distinct values' >&2
    exit 2
}
serial0=$1
serial1=$2
firmware0=
firmware1=
if test -n "$firmwares"; then
    IFS=,
    set -- $firmwares
    IFS=$old_ifs
    test "$#" -eq 2 && test -n "$1" && test -n "$2" || {
        printf '%s\n' 'HARDWARE_FIRMWARES must contain two values' >&2
        exit 2
    }
    firmware0=$1
    firmware1=$2
fi

for expected in "$serial0" "$serial1"; do
    matches=0
    for file in /sys/bus/usb/devices/*/serial; do
        test -r "$file" || continue
        test "$(cat "$file")" = "$expected" && matches=$((matches + 1))
    done
    test "$matches" -eq 1 || {
        printf '%s\n' "USB serial $expected matched $matches devices" >&2
        exit 2
    }
done
test ! -d /sys/module/melodi_core || {
    printf '%s\n' 'Melodi modules are already loaded' >&2
    exit 2
}

cleanup()
{
    test -z "$receiver_pid" || kill "$receiver_pid" 2>/dev/null || true
    test ! -d /sys/module/melodi_usb || "$tool" tty release 2>/dev/null || true
    rmmod melodi_usb 2>/dev/null || true
    rmmod melodi_core 2>/dev/null || true
    rm -f "$tty0" "$tty1"
    rm -f "$identity0" "$identity1" "$payload" "$metadata"
}
trap cleanup EXIT INT TERM

insmod "$core" interfaces=2 "radios=$serial0,$serial1"
insmod "$usb"
"$tool" tty scan
test -c "$tty0"
test -c "$tty1"
ip link set dev mel0 up
ip link set dev mel1 up
"$tool" identity generate "$identity0"
"$tool" identity generate "$identity1"
"$tool" identity load -i mel0 --generation 1 "$identity0"
"$tool" identity load -i mel1 --generation 1 "$identity1"

wait_ready()
{
    interface=$1
    count=0
    while test "$count" -lt 300; do
        if "$tool" status -i "$interface" 2>/dev/null | grep -q ': ready'; then
            return 0
        fi
        sleep 0.1
        count=$((count + 1))
    done
    "$tool" status -i "$interface" >&2 || true
    return 1
}
wait_ready mel0
wait_ready mel1

node0=$("$tool" id -i mel0)
node1=$("$tool" id -i mel1)
test "$(cat /sys/class/net/mel0/type)" = 65534
test "$(cat /sys/class/net/mel1/type)" = 65534
test -z "$(ip -o -4 addr show dev mel0)"
test -z "$(ip -o -6 addr show dev mel0)"
test -z "$(ip -o -4 addr show dev mel1)"
test -z "$(ip -o -6 addr show dev mel1)"
detected0=$(ethtool -i mel0 | sed -n 's/^firmware-version: //p')
detected1=$(ethtool -i mel1 | sed -n 's/^firmware-version: //p')
case "$detected0" in 2.7.*|2.8.*) ;; *) exit 1; esac
case "$detected1" in 2.7.*|2.8.*) ;; *) exit 1; esac
test -z "$firmware0" || test "$detected0" = "$firmware0"
test -z "$firmware1" || test "$detected1" = "$firmware1"
printf '%s\n' "mel0 firmware=$detected0" "mel1 firmware=$detected1"
"$tool" status -i mel0 | grep -F "radio=$serial0"
"$tool" status -i mel1 | grep -F "radio=$serial1"

fragmented=$(awk 'BEGIN { for (i = 0; i < 700; i++) printf "%c", 65 + i % 26 }')
"$receive" -i mel1 12345 >"$payload" 2>"$metadata" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel0 "$node1" 12345 "$fragmented"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$fragmented" "$payload"
grep -Fx "$node0 49152" "$metadata"
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '

"$receive" -i mel0 12346 >"$payload" 2>"$metadata" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel1 "$node0" 12346 reverse
wait "$receiver_pid"
receiver_pid=
grep -Fx reverse "$payload"
grep -Fx "$node1 49152" "$metadata"

"$receive" -i mel1 12347 >"$payload" 2>"$metadata" &
receiver_pid=$!
sleep 1
"$send" --broadcast -i mel0 12347 broadcast
wait "$receiver_pid"
receiver_pid=
grep -Fx broadcast "$payload"
grep -Fx "$node0 49152" "$metadata"

test -z "$(pgrep -x melodid 2>/dev/null || true)"
"$tool" tty release
rmmod melodi_usb
rmmod melodi_core
trap - EXIT INT TERM
rm -f "$tty0" "$tty1" "$identity0" "$identity1" "$payload" "$metadata"
