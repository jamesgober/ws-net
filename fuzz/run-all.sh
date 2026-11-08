#!/usr/bin/env bash
# Runs every fuzz target in parallel for HOURS hours (default 24), each in
# its own process, with the corpus and artifacts outside the repository
# (under $WS_NET_FUZZ_HOME, default ~/.cache/ws-net-fuzz).
#
# WSL steps its wall clock back now and then, and libFuzzer then reports a
# "timeout after 18446744073709551615 seconds" on an input that is fine.
# Such a report is replayed once: if the input passes, it is discarded and
# the target resumes for the time it has left. Any other crash stops that
# target and is kept in its artifacts directory.
#
# Usage: fuzz/run-all.sh [HOURS] [TARGET...]
set -u
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
HOURS="${1:-24}"
shift || true
cd "$(dirname "$0")" || exit 1
HOME_DIR="${WS_NET_FUZZ_HOME:-$HOME/.cache/ws-net-fuzz}"
export CARGO_TARGET_DIR="$HOME_DIR/target"
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(frame_header connection_server connection_client connection_api server_head client_head
             extension_parse origin_policy handshake_key differential_tungstenite deflate_message)
fi
cargo +nightly fuzz build -O >/dev/null 2>&1 || { echo "build failed"; exit 1; }
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"

run_one() {
    local t="$1" total=$((HOURS * 3600)) start now left log
    mkdir -p "$HOME_DIR/corpus/$t" "$HOME_DIR/artifacts/$t"
    log="$HOME_DIR/$t.log"
    start=$(date +%s)
    : > "$log"
    while :; do
        now=$(date +%s)
        left=$((total - (now - start)))
        [ "$left" -le 0 ] && break
        "$BIN/$t" "$HOME_DIR/corpus/$t" -max_total_time="$left" -rss_limit_mb=4096 \
            -timeout=60 -print_final_stats=1 \
            -artifact_prefix="$HOME_DIR/artifacts/$t/" >> "$log" 2>&1
        status=$?
        [ "$status" -eq 0 ] && break
        if grep -q "timeout after 1844674407370955[0-9]* seconds\|Unit for -[0-9]* seconds" "$log"; then
            for a in "$HOME_DIR/artifacts/$t"/timeout-*; do
                [ -e "$a" ] || continue
                if timeout 120 "$BIN/$t" "$a" >/dev/null 2>&1; then
                    echo "replayed $(basename "$a"): passes, resuming" >> "$log"
                    rm -f "$a"
                fi
            done
            # Mark the step as replayed.
            sed -i 's/timeout after 1844674407370955[0-9]* seconds/clock step (replayed)/; s/Unit for -[0-9]* seconds/clock step unit/' "$log"
            continue
        fi
        echo "STOPPED with status $status" >> "$log"
        break
    done
    echo "$t: $(grep -E '^Done [0-9]+ runs|stat::number_of_executed_units' "$log" | tail -1) $(grep -c '^STOPPED' "$log") stops" \
        >> "$HOME_DIR/summary.txt"
}

: > "$HOME_DIR/summary.txt" 2>/dev/null || { mkdir -p "$HOME_DIR"; : > "$HOME_DIR/summary.txt"; }
date -u +"started %Y-%m-%dT%H:%M:%SZ, $HOURS hours" >> "$HOME_DIR/summary.txt"
for t in "${TARGETS[@]}"; do
    run_one "$t" &
done
wait
date -u +"finished %Y-%m-%dT%H:%M:%SZ" >> "$HOME_DIR/summary.txt"
cat "$HOME_DIR/summary.txt"
