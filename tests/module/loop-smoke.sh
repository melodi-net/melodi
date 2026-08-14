#!/bin/sh
set -eu

build=$1
core="$build/kernel/melodi_core.ko"
loop="$build/kernel/melodi_loop.ko"
tool="$build/bin/melodi"
send="$build/bin/melsend"
receive="$build/bin/melrecv"
collision_fixture="$build/unit/test_collision_fixture"
identity0="$build/loop-identity0.key"
identity1="$build/loop-identity1.key"
identity2="$build/loop-identity2.key"
received="$build/loop-received.txt"
received_meta="$build/loop-received.meta"
monitored="$build/loop-monitored.txt"
receiver_pid=
monitor_pid=

wait_peer()
{
    interface=$1
    node=$2
    locator=$3
    round=$4
    generation=$5
    attempts=0

    while ! "$tool" peers -i "$interface" |
        grep -F "$node state=authenticated locator=$locator round=$round generation=$generation " >/dev/null
    do
        attempts=$((attempts + 1))
        test "$attempts" -lt 100 || return 1
        sleep 0.1
    done
}

test "$(id -u)" -eq 0 || {
    printf '%s\n' 'loop-smoke requires root' >&2
    exit 2
}
test ! -d /sys/module/melodi_core || {
    printf '%s\n' 'melodi_core is already loaded' >&2
    exit 2
}

cleanup()
{
    test -z "$receiver_pid" || kill "$receiver_pid" 2>/dev/null || true
    test -z "$monitor_pid" || kill "$monitor_pid" 2>/dev/null || true
    rmmod melodi_loop 2>/dev/null || true
    rmmod melodi_core 2>/dev/null || true
    rm -f "$identity0" "$identity1" "$identity2" "$received" \
        "$received_meta" "$monitored"
}
trap cleanup EXIT INT TERM

insmod "$core"
test -d /sys/class/net/mel0
test "$(cat /sys/class/net/mel0/operstate)" = down
"$tool" status -i mel0 | grep -Fx 'mel0: disconnected'
ip link set dev mel0 up
test "$(cat /sys/class/net/mel0/carrier)" -eq 0
ip -details link show dev mel0 | grep -F 'NO-CARRIER'

insmod "$loop"
test -d /sys/class/net/mel1
"$tool" status -i mel0 | grep -E '^mel0: configuring( |$)'
ip link set dev mel1 up
parameters=/sys/module/melodi_loop/parameters
printf '%s\n' 1 >"$parameters/fault_reset"
printf '%s\n' 1 >"$parameters/drop_every"
rm -f "$identity0" "$identity1" "$identity2"
"$collision_fixture" "$identity0" "$identity1"
"$tool" identity load -i mel0 --generation 1 "$identity0"
"$tool" identity load -i mel1 --generation 1 "$identity1"
if "$tool" identity load -i mel0 --generation 1 "$identity0"; then
    exit 1
fi
"$tool" identity load -i mel0 --generation 2 "$identity0"
"$tool" status -i mel0 | grep -E '^mel0: ready( |$)'
"$tool" status -i mel1 | grep -E '^mel1: ready( |$)'
tc qdisc replace dev mel0 root handle 1: mq
tc qdisc replace dev mel0 parent 1:1 handle 10: pfifo limit 128
node0=$("$tool" id -i mel0)
node1=$("$tool" id -i mel1)
printf '%s\n' "$node0" | grep -E '^m[ybndrfg8ejkmcpqxot1uwisza345h769]{53}$'
printf '%s\n' "$node1" | grep -E '^m[ybndrfg8ejkmcpqxot1uwisza345h769]{53}$'
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
printf '%s\n' 0 >"$parameters/drop_every"
printf '%s\n' 1 >"$parameters/fault_reset"
"$send" -i mel0 "$node1" 12345 'queued discovery message'
wait "$receiver_pid"
receiver_pid=
grep -Fx 'queued discovery message' "$received"
grep -Fx "$node0 49152" "$received_meta"
wait_peer mel0 "$node1" a03bace6 1 1
wait_peer mel1 "$node0" 7ef81479 0 2
test "$(cat /sys/class/net/mel0/carrier)" -eq 1
test "$(cat /sys/class/net/mel1/carrier)" -eq 1
ip -details link show dev mel0 | grep -F 'LOWER_UP'
ip -details link show dev mel1 | grep -F 'LOWER_UP'
ethtool -i mel0 | grep -Fx 'driver: melodi_core'
ethtool -i mel0 | grep -Fx 'version: 0.1.0/loop-0.1.0'
ethtool -i mel0 | grep -Fx 'firmware-version: virtual'
ethtool -i mel0 | grep -Fx 'bus-info: melodi-loop'
ethtool -S mel0 | grep -F 'authenticated_peers:'
"$tool" stats -i mel0 | grep -E '^authenticated_peers=[1-9][0-9]*$'
"$tool" peers -i mel0 | grep -F "$node1"
"$tool" policy -i mel0 | grep -Fx 'authenticated'
"$tool" policy -i mel0 trusted
"$tool" policy -i mel0 | grep -Fx 'trusted'
"$tool" trust -i mel0 "$node1"
"$tool" policy -i mel0 authenticated
"$tool" policy -i mel0 service 12345 deny
if "$send" -i mel0 "$node1" 12345 denied >/dev/null 2>&1; then
    exit 1
fi
"$tool" policy -i mel0 service 12345 allow
"$tool" policy -i mel0 service 12345 clear
"$tool" policy -i mel0 broadcast deny
if "$send" --broadcast -i mel0 12345 denied >/dev/null 2>&1; then
    exit 1
fi
"$tool" policy -i mel0 broadcast allow
"$tool" policy -i mel0 trusted
"$tool" policy -i mel0 service 12345 deny
"$tool" policy -i mel0 broadcast deny
"$tool" policy -i mel0 reset
"$tool" policy -i mel0 | grep -Fx 'authenticated'
"$tool" monitor -i mel1 >"$monitored" &
monitor_pid=$!
sleep 1
"$tool" discover -i mel0
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '

"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" -i mel0 "$node1" 12345 'native melodi message'
wait "$receiver_pid"
receiver_pid=
grep -Fx 'native melodi message' "$received"
grep -Fx "$node0 49152" "$received_meta"
tc -s qdisc show dev mel0 | grep -E 'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt'
sleep 1
kill "$monitor_pid"
wait "$monitor_pid" 2>/dev/null || true
monitor_pid=
grep -E '^rx 0107' "$monitored"
grep -E '^rx [0-9a-f]+$' "$monitored"

"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --broadcast -i mel0 12345 'authenticated broadcast'
wait "$receiver_pid"
receiver_pid=
grep -Fx 'authenticated broadcast' "$received"
grep -Fx "$node0 49152" "$received_meta"

printf '%s\n' 160 >/sys/module/melodi_loop/parameters/frame_mtu
fragmented=$(awk 'BEGIN { for (i = 0; i < 400; i++) printf "%c", 97 + i % 26 }')
broadcasted=$(awk 'BEGIN { for (i = 0; i < 300; i++) printf "%c", 48 + i % 10 }')
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --broadcast -i mel0 12345 "$broadcasted"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$broadcasted" "$received"
grep -Fx "$node0 49152" "$received_meta"

"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel0 "$node1" 12345 "$fragmented"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$fragmented" "$received"
grep -Fx "$node0 49152" "$received_meta"

faulted=$(awk 'BEGIN { for (i = 0; i < 700; i++) printf "%c", 65 + i % 26 }')
damaged=$(awk 'BEGIN { for (i = 0; i < 100; i++) printf "%c", 48 + i % 10 }')
printf '%s\n' 1 >"$parameters/fault_reset"
printf '%s\n' 2 >"$parameters/drop_every"
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel0 "$node1" 12345 "$faulted"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$faulted" "$received"
grep -Fx "$node0 49152" "$received_meta"

printf '%s\n' 0 >"$parameters/drop_every"
printf '%s\n' 1 >"$parameters/fault_reset"
printf '%s\n' 2 >"$parameters/duplicate_every"
printf '%s\n' 2 >"$parameters/reorder_every"
printf '%s\n' 5 >"$parameters/latency_ms"
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --ordered -i mel0 "$node1" 12345 "$fragmented"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$fragmented" "$received"

printf '%s\n' 0 >"$parameters/duplicate_every"
printf '%s\n' 0 >"$parameters/reorder_every"
printf '%s\n' 0 >"$parameters/latency_ms"
printf '%s\n' 1 >"$parameters/fault_reset"
printf '%s\n' 2 >"$parameters/corrupt_every"
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel0 "$node1" 12345 "$damaged"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$damaged" "$received"

printf '%s\n' 0 >"$parameters/corrupt_every"
printf '%s\n' 1 >"$parameters/fault_reset"
printf '%s\n' 2 >"$parameters/locator_mismatch_every"
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" --reliable -i mel0 "$node1" 12345 "$damaged"
wait "$receiver_pid"
receiver_pid=
grep -Fx "$damaged" "$received"

printf '%s\n' 0 >"$parameters/locator_mismatch_every"
printf '%s\n' 0 >"$parameters/queue_limit"
"$receive" -i mel1 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
"$send" -i mel0 "$node1" 12345 'backpressure retained'
sleep 1
kill -0 "$receiver_pid"
printf '%s\n' 128 >"$parameters/queue_limit"
wait "$receiver_pid"
receiver_pid=
grep -Fx 'backpressure retained' "$received"

"$tool" identity generate "$identity2"
"$tool" identity load -i mel0 --generation 1 "$identity2"
node2=$("$tool" id -i mel0)
test "$node2" != "$node0"
"$tool" policy -i mel0 trusted
"$tool" discover -i mel0
sleep 1
"$tool" peers -i mel0 | grep -F "$node1" | grep -F 'state=authenticated'
if "$build/bin/melping" -i mel0 "$node1" >/dev/null 2>&1; then
    exit 1
fi
"$tool" trust -i mel0 "$node1"
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '
"$tool" identity load -i mel0 --generation 3 \
    --migrate-policy-from "$node2" --confirm-node-id "$node0" "$identity0"
test "$("$tool" id -i mel0)" = "$node0"
"$tool" discover -i mel0
sleep 1
"$build/bin/melping" -i mel0 "$node1" | grep -F 'reply from '
if "$tool" identity load -i mel0 --generation 2 \
    --migrate-policy-from "$node1" --confirm-node-id "$node2" "$identity2"; then
    exit 1
fi
test "$("$tool" id -i mel0)" = "$node0"

"$receive" -i mel0 23456 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
printf '%s\n' 1 >"$parameters/disconnected"
if wait "$receiver_pid"; then
    exit 1
fi
receiver_pid=
test "$(cat /sys/class/net/mel0/carrier)" -eq 0
test "$(cat /sys/class/net/mel1/carrier)" -eq 0
printf '%s\n' 0 >"$parameters/disconnected"
test "$(cat /sys/class/net/mel0/carrier)" -eq 1
test "$(cat /sys/class/net/mel1/carrier)" -eq 1

rmmod melodi_loop
test ! -d /sys/class/net/mel1
test -d /sys/class/net/mel0
test "$(cat /sys/class/net/mel0/carrier)" -eq 0
"$tool" status -i mel0 | grep -Fx 'mel0: disconnected'

"$receive" -i mel0 12345 >"$received" 2>"$received_meta" &
receiver_pid=$!
sleep 1
if rmmod melodi_core 2>/dev/null; then
    exit 1
fi
kill "$receiver_pid"
wait "$receiver_pid" 2>/dev/null || true
receiver_pid=
rmmod melodi_core
test ! -d /sys/class/net/mel0
trap - EXIT INT TERM
rm -f "$identity0" "$identity1" "$identity2" "$received" \
    "$received_meta" "$monitored"
