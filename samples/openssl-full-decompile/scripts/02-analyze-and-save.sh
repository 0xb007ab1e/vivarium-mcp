#!/usr/bin/env bash
set -uo pipefail
cd /tmp/fulldec || exit 1
W=/tmp/fulldec; B=/tmp/blind-openssl/openssl-4.0.1
# fresh project so the save is clean
rm -rf "$W"/proj_ossl_saved* 2>/dev/null
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"; unset _JAVA_OPTIONS
export MAXMEM=4G
date +%s > "$W/an_start.ts"
# import + auto-analyze + SAVE (no postScript, no -deleteProject) -> persists analyzed program "openssl"
/usr/share/ghidra/support/analyzeHeadless "$W" proj_ossl_saved \
  -import "$B/apps/openssl" \
  > "$W/analyze.log" 2>&1
echo $? > "$W/an_rc.txt"; date +%s > "$W/an_end.ts"
echo "ANALYZE rc=$(cat "$W/an_rc.txt") elapsed=$(( $(cat "$W/an_end.ts")-$(cat "$W/an_start.ts") ))s"
tail -4 "$W/analyze.log"
echo "=== project program list ==="
ls -la "$W"/proj_ossl_saved.rep 2>&1 | head -1
