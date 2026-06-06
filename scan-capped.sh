#!/usr/bin/env bash
# scan-capped.sh — run phparser on one plugin under a HARD RSS cap.
#
# The engine's in-process circuit-breaker (-mem-limit-mb) reduces memory
# pressure but CANNOT guarantee no OOM: a single statement's interprocedural
# instantiation can allocate a multi-GB burst that outpaces GC, and Go cannot
# abort an allocation mid-flight. This watchdog enforces a hard ceiling by
# polling RSS and killing the scan if it exceeds the cap, so a pathological
# mega-plugin (e.g. WooCommerce-scale) is SKIPPED instead of OOM-killing the
# host. Use it as the outer loop for mass-scanning the plugin tree.
#
# Usage: scan-capped.sh <plugin-dir> <output-dir> [cap_gb] [extra phparser args...]
# Exit:  0 = scanned, 75 = skipped (memory cap), other = phparser's own exit.
set -u

target="${1:?plugin dir required}"
out="${2:?output dir required}"
cap_gb="${3:-10}"
shift 3 || shift $#
cap_kb=$(( cap_gb * 1024 * 1024 ))
bin="${PHPARSER_BIN:-/usr/local/bin/phparser}"

"$bin" -target "$target" -output-dir "$out" -mem-limit-mb $(( cap_gb * 1024 * 3 / 4 )) "$@" &
pid=$!

while kill -0 "$pid" 2>/dev/null; do
  rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
  if [ -n "${rss:-}" ] && [ "$rss" -gt "$cap_kb" ]; then
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    echo "SKIPPED memory>${cap_gb}GB: $target" >&2
    exit 75
  fi
  sleep 0.3
done
wait "$pid"
exit $?
