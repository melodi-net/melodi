#!/bin/sh
set -eu

build=$1
core="$build/kernel/melodi_core.ko"
loop="$build/kernel/melodi_loop.ko"
tool="$build/bin/melodi"
send="$build/bin/melsend"
receive="$build/bin/melrecv"
identity0="$build/language-identity0.key"
identity1="$build/language-identity1.key"
request="$build/language-request.txt"
metadata="$build/language-request.meta"
reply="$build/language-reply.txt"
receiver_pid=
example_pid=

test "$(id -u)" -eq 0 || {
    printf '%s\n' 'language-smoke requires root' >&2
    exit 2
}
test ! -d /sys/module/melodi_core || {
    printf '%s\n' 'melodi_core is already loaded' >&2
    exit 2
}

cleanup()
{
    test -z "$receiver_pid" || kill "$receiver_pid" 2>/dev/null || true
    test -z "$example_pid" || kill "$example_pid" 2>/dev/null || true
    rmmod melodi_loop 2>/dev/null || true
    rmmod melodi_core 2>/dev/null || true
    rm -f "$identity0" "$identity1" "$request" "$metadata" "$reply"
}
trap cleanup EXIT INT TERM

insmod "$core"
insmod "$loop"
ip link set dev mel0 up
ip link set dev mel1 up
"$tool" identity generate "$identity0"
"$tool" identity generate "$identity1"
"$tool" identity load -i mel0 --generation 1 "$identity0"
"$tool" identity load -i mel1 --generation 1 "$identity1"
node0=$("$tool" id -i mel0)
node1=$("$tool" id -i mel1)

exercise()
{
    executable=$1
    language=$2
    local_service=$3
    remote_service=$4
    rm -f "$request" "$metadata" "$reply"
    "$receive" -i mel1 "$remote_service" >"$request" 2>"$metadata" &
    receiver_pid=$!
    sleep 1
    "$executable" mel0 "$local_service" "$node1" "$remote_service" \
        "$language request" >"$reply" 2>&1 &
    example_pid=$!
    wait "$receiver_pid"
    receiver_pid=
    grep -Fx "$language request" "$request"
    grep -Fx "$node0 49152" "$metadata"
    "$send" -i mel1 "$node0" "$local_service" "$language reply"
    wait "$example_pid"
    example_pid=
    grep -F "$node1 49152: $language reply" "$reply"
}

exercise "$build/bin/melodi-example-c" C 12001 13001
exercise "$build/bin/melodi-example-cpp" C++ 12002 13002
exercise "$build/bin/melodi-example-rust" Rust 12003 13003
exercise "$build/bin/melodi-example-go" Go 12004 13004
exercise "$build/bin/melodi-example-zig" Zig 12005 13005

rmmod melodi_loop
rmmod melodi_core
trap - EXIT INT TERM
rm -f "$identity0" "$identity1" "$request" "$metadata" "$reply"
