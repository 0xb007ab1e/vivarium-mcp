#!/usr/bin/env bash
set -uo pipefail
cd /tmp/fulldec || exit 1; W=/tmp/fulldec
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 PATH="/usr/lib/jvm/java-25-openjdk-amd64/bin:$PATH"; unset _JAVA_OPTIONS
export ALLOWLIST="$W/allow.txt" OUT_C="$W/openssl_firstparty_decompiled.c" OUT_IDX="$W/index.csv"
export MAX_PER_RUN=2500 DISPOSE_EVERY=50 MAX_FN_BYTES=40000 MAX_PAYLOAD_MB=30 DECOMP_TIMEOUT=30
date +%s > "$W/cmp_start.ts"
for iter in $(seq 1 8); do
  rm -f "$W"/proj_ossl_saved.lock "$W"/proj_ossl_saved.lock~ 2>/dev/null
  L="$W/complete_iter${iter}.log"
  /usr/share/ghidra/support/analyzeHeadless "$W" proj_ossl_saved -process openssl -noanalysis -readOnly \
    -scriptPath "$W" -postScript ExportChunk.py > "$L" 2>&1
  NEW=$(grep -oE "CHUNK_DONE new=[0-9]+" "$L" | grep -oE "[0-9]+" | head -1)
  echo "iter=$iter new=${NEW:-KILLED} total=$(($(wc -l < "$W/index.csv")-1))"
  [ "${NEW:-x}" = "0" ] && { echo "ALL COMPLETE"; break; }
  [ -z "${NEW:-}" ] && echo "(iter killed mid-run; loop continues, resume skips done)"
done
date +%s > "$W/cmp_end.ts"
echo "TOTAL elapsed=$(( $(cat "$W/cmp_end.ts")-$(cat "$W/cmp_start.ts") ))s"
echo "FINAL: $(($(wc -l < "$W/index.csv")-1)) functions | ok=$(grep -c ',ok$' "$W/index.csv") failed=$(grep -c ',failed$' "$W/index.csv") skipped_large=$(grep -c ',skipped_large$' "$W/index.csv")"
