#!/bin/sh
set -eu

build=$1
core="$build/kernel/melodi_core.ko"
loop="$build/kernel/melodi_loop.ko"
tool="$build/bin/melodi"
send="$build/bin/melsend"
receive="$build/bin/melrecv"
identity0="$build/namespace-identity0.key"
identity1="$build/namespace-identity1.key"
left_output="$build/namespace-left.txt"
right_output="$build/namespace-right.txt"
left_meta="$build/namespace-left.meta"
right_meta="$build/namespace-right.meta"
left_pid=
right_pid=

test "$(id -u)" -eq 0 || {
    printf '%s\n' 'namespace-smoke requires root' >&2
    exit 2
}

cleanup()
{
    test -z "$left_pid" || kill "$left_pid" 2>/dev/null || true
    test -z "$right_pid" || kill "$right_pid" 2>/dev/null || true
    ip netns exec melodi-left ip link set mel0 netns 1 2>/dev/null || true
    ip netns exec melodi-right ip link set mel1 netns 1 2>/dev/null || true
    ip netns del melodi-left 2>/dev/null || true
    ip netns del melodi-right 2>/dev/null || true
    rmmod melodi_loop 2>/dev/null || true
    rmmod melodi_core 2>/dev/null || true
    rm -f "$identity0" "$identity1" "$left_output" "$right_output" \
        "$left_meta" "$right_meta"
}
trap cleanup EXIT INT TERM

test ! -d /sys/module/melodi_core
ip netns add melodi-left
ip netns add melodi-right
insmod "$core"
insmod "$loop"
ip link set mel0 netns melodi-left
ip link set mel1 netns melodi-right
ip -n melodi-left link set mel0 up
ip -n melodi-right link set mel1 up
rm -f "$identity0" "$identity1"
"$tool" identity generate "$identity0"
"$tool" identity generate "$identity1"
ip netns exec melodi-left "$tool" identity load -i mel0 --generation 1 \
    "$identity0"
ip netns exec melodi-right "$tool" identity load -i mel1 --generation 1 \
    "$identity1"
node0=$(ip netns exec melodi-left "$tool" id -i mel0)
node1=$(ip netns exec melodi-right "$tool" id -i mel1)
test "$(ip netns exec melodi-left cat /sys/class/net/mel0/carrier)" -eq 1
test "$(ip netns exec melodi-right cat /sys/class/net/mel1/carrier)" -eq 1

ip netns exec melodi-left "$receive" -i mel0 12345 \
    >"$left_output" 2>"$left_meta" &
left_pid=$!
ip netns exec melodi-right "$receive" -i mel1 12345 \
    >"$right_output" 2>"$right_meta" &
right_pid=$!
sleep 1
ip netns exec melodi-left "$send" -i mel0 "$node1" 12345 left-to-right
ip netns exec melodi-right "$send" -i mel1 "$node0" 12345 right-to-left
wait "$left_pid"
left_pid=
wait "$right_pid"
right_pid=
grep -Fx right-to-left "$left_output"
grep -Fx left-to-right "$right_output"
grep -Fx "$node1 49152" "$left_meta"
grep -Fx "$node0 49152" "$right_meta"

ip netns exec melodi-left "$tool" policy -i mel0 trusted
ip netns exec melodi-left "$tool" trust -i mel0 "$node1"
ip netns exec melodi-left "$receive" -i mel0 23456 \
    >"$left_output" 2>"$left_meta" &
left_pid=$!
sleep 1
ip netns exec melodi-left ip link set mel0 down
ip netns exec melodi-left ip link set mel0 netns 1
if wait "$left_pid"; then
    exit 1
fi
left_pid=
grep -F 'melrecv: Input/output error' "$left_meta"
test "$("$tool" id -i mel0)" = "$node0"
test "$("$tool" policy -i mel0)" = authenticated
if "$tool" peers -i mel0 | grep -F "$node1"; then
    exit 1
fi

ip link set mel0 netns melodi-left
ip -n melodi-left link set mel0 up
ip netns exec melodi-left "$tool" discover -i mel0
ip netns exec melodi-right "$tool" discover -i mel1
ip netns exec melodi-left "$build/bin/melping" -i mel0 "$node1" |
    grep -F 'reply from '
ip netns exec melodi-left "$receive" -i mel0 23456 \
    >"$left_output" 2>"$left_meta" &
left_pid=$!
sleep 1
ip netns exec melodi-right "$send" -i mel1 "$node0" 23456 \
    after-namespace-move
wait "$left_pid"
left_pid=
grep -Fx after-namespace-move "$left_output"
grep -Fx "$node1 49152" "$left_meta"

ip netns exec melodi-left ip link set mel0 netns 1
ip netns exec melodi-right ip link set mel1 netns 1
ip netns del melodi-left
ip netns del melodi-right
rmmod melodi_loop
rmmod melodi_core
trap - EXIT INT TERM
rm -f "$identity0" "$identity1" "$left_output" "$right_output" \
    "$left_meta" "$right_meta"
