BEGIN {
    code = 0
    comments = 0
    block = 0
    bad = 0
    depth = 0
}
{
    line = $0
    trimmed = line
    sub(/^[[:space:]]+/, "", trimmed)
    if (NR == 1 && trimmed ~ /^#!/)
        next
    if (trimmed ~ /SPDX-License-Identifier:/)
        next
    is_comment = 0
    text = ""
    if (block) {
        is_comment = 1
        text = trimmed
        if (trimmed ~ /\*\//)
            block = 0
    } else if (trimmed ~ /^\/\*/) {
        is_comment = 1
        text = trimmed
        if (trimmed !~ /\*\//)
            block = 1
    } else if (trimmed ~ /^(\/\/|#)/ && trimmed !~ /^#[[:space:]]*(include|define|if|ifdef|ifndef|elif|else|endif|error|pragma|undef)/) {
        is_comment = 1
        text = trimmed
    }
    if (is_comment) {
        comments++
        lower = tolower(text)
        if (lower ~ /(because|workaround|temporary|historical|legacy|rationale|reason|apolog|review note|todo|fixme)/) {
            printf "%s:%d: non-functional comment\n", file, NR > "/dev/stderr"
            bad = 1
        }
    } else if (trimmed != "") {
        code++
    }
    for (level = 1; level <= depth; level++) {
        if (is_comment)
            block_comments[level]++
        else if (trimmed != "")
            block_code[level]++
    }
    close_count = gsub(/}/, "}", line)
    for (i = 0; i < close_count && depth > 0; i++) {
        if (block_comments[depth] * 5 > block_code[depth]) {
            printf "%s:%d: block comments %d exceed 20%% of %d implementation lines\n", file, NR, block_comments[depth], block_code[depth] > "/dev/stderr"
            bad = 1
        }
        delete block_comments[depth]
        delete block_code[depth]
        depth--
    }
    open_count = gsub(/{/, "{", line)
    for (i = 0; i < open_count; i++) {
        depth++
        block_comments[depth] = 0
        block_code[depth] = 0
    }
}
END {
    if (comments * 5 > code) {
        printf "%s: comments %d exceed 20%% of %d implementation lines\n", file, comments, code > "/dev/stderr"
        bad = 1
    }
    exit bad
}
