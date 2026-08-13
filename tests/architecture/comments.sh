#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

status=0
files=$(find src tests -type f \( -name '*.c' -o -name '*.h' -o -name '*.rs' -o -name '*.sh' -o -name '*.awk' -o -name 'Makefile' -o -name 'Kbuild' \) -print 2>/dev/null || true)
files=$(printf '%s\n%s\n' Makefile flake.nix "$files" | sed '/^$/d')
for file in $files; do
    awk -v file="$file" -f tests/architecture/comments.awk "$file" || status=1
done
exit "$status"
