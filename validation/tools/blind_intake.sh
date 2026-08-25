#!/usr/bin/env bash
# Blind malware intake for the Vivarium validation exercise.
#
# Sources N real samples from theZoo (github.com/ytisf/theZoo), keeps them BLIND:
#   - selects random Binaries/ subdirs (no operator sees the family-revealing names),
#   - extracts each password-zip ("infected"), finds a Ghidra-analyzable executable,
#   - hash-renames it to <sha256>.bin under the Vivarium import root,
#   - SEALS the sha256 -> original-theZoo-path mapping to a file OUTSIDE the repo,
#     which the analyst must not read until the post-assessment reveal phase.
# STDOUT emits ONLY sanitized intake facts (sha256, size, file-type, entropy) —
# never the source directory or inner filename.
#
# Samples are inert data: never executed. Vivarium's own worker container is the
# analysis sandbox; this script only downloads + extracts + hashes.
set -euo pipefail
IFS=$'\n\t'

N="${1:-4}"
IMPORT_ROOT="/home/b007ab1e/vivarium-imports"
STAGE="${IMPORT_ROOT}/vld"                 # where blind samples land for Vivarium import
CLONE="/home/b007ab1e/.cache/vivarium-vld/theZoo"
SEAL_DIR="/home/b007ab1e/.cache/vivarium-vld"
SEAL="${SEAL_DIR}/groundtruth.sealed.json" # DO NOT READ until reveal phase
WORK="$(mktemp -d /home/b007ab1e/.cache/vivarium-vld/work.XXXXXX 2>/dev/null || mktemp -d)"
MINSZ=$((2*1024)); MAXSZ=$((16*1024*1024))
PW="infected"

mkdir -p "$STAGE" "$SEAL_DIR"
trap 'rm -rf "$WORK"' EXIT

# --- entropy helper (Shannon, 0-8 bits/byte) via python, no sample content to stdout ---
entropy() { python3 - "$1" <<'PY'
import sys,math,collections
b=open(sys.argv[1],'rb').read()
if not b: print("0.00"); sys.exit()
c=collections.Counter(b); n=len(b)
h=-sum((v/n)*math.log2(v/n) for v in c.values())
print(f"{h:.2f}")
PY
}

# --- clone theZoo (shallow) if absent ---
if [ ! -d "${CLONE}/malware/Binaries" ]; then
  echo "[intake] cloning theZoo (shallow)..." >&2
  rm -rf "$CLONE"
  git clone --depth 1 --quiet https://github.com/ytisf/theZoo.git "$CLONE" >&2
fi

# --- enumerate candidate dirs, shuffle (names never hit stdout) ---
mapfile -t DIRS < <(find "${CLONE}/malware/Binaries" -mindepth 1 -maxdepth 1 -type d | shuf)

echo "[" > "$SEAL"; SEP=""
picked=0; idx=0; total=${#DIRS[@]}
echo "[intake] ${total} candidate families; selecting ${N} blind..." >&2

while [ "$picked" -lt "$N" ] && [ "$idx" -lt "$total" ]; do
  d="${DIRS[$idx]}"; idx=$((idx+1))
  z="$(find "$d" -maxdepth 1 -iname '*.zip' | head -1 || true)"
  [ -z "$z" ] && continue
  ex="${WORK}/x"; rm -rf "$ex"; mkdir -p "$ex"
  unzip -o -qq -P "$PW" "$z" -d "$ex" >/dev/null 2>&1 || continue
  # pick the largest regular file that Ghidra can load (PE/ELF/Mach-O), in size range
  cand=""
  while IFS= read -r f; do
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    [ "$sz" -lt "$MINSZ" ] && continue
    [ "$sz" -gt "$MAXSZ" ] && continue
    ft=$(file -b "$f" 2>/dev/null || echo "")
    case "$ft" in
      *PE32*|*"PE32+"*|*ELF*|*Mach-O*|*"MS-DOS executable"*) cand="$f"; break;;
    esac
  done < <(find "$ex" -type f -printf '%s\t%p\n' | sort -rn | cut -f2)
  [ -z "$cand" ] && continue
  sha=$(sha256sum "$cand" | cut -d' ' -f1)
  md5=$(md5sum "$cand" | cut -d' ' -f1)
  sz=$(stat -c%s "$cand")
  ft=$(file -b "$cand" 2>/dev/null)
  ent=$(entropy "$cand")
  cp "$cand" "${STAGE}/${sha}.bin"
  picked=$((picked+1))
  # sanitized intake line -> stdout (analyst sees this)
  printf 'SAMPLE %d\tsha256=%s\tmd5=%s\tsize=%d\tentropy=%s\ttype=%s\n' \
         "$picked" "$sha" "$md5" "$sz" "$ent" "$ft"
  # sealed ground truth -> OUTSIDE repo (analyst must NOT read until reveal)
  origrel="${d#${CLONE}/}"
  inner="$(basename "$cand")"
  printf '%s{"case":%d,"sha256":"%s","md5":"%s","size":%d,"thezoo_path":"%s","inner_name":"%s"}\n' \
         "$SEP" "$picked" "$sha" "$md5" "$sz" "$origrel" "$inner" >> "$SEAL"
  SEP=","
done
echo "]" >> "$SEAL"

echo "[intake] staged ${picked} blind samples in ${STAGE}" >&2
echo "[intake] sealed ground truth -> ${SEAL} (do not read until reveal)" >&2
[ "$picked" -lt "$N" ] && { echo "[intake] WARNING: only ${picked}/${N} found" >&2; exit 3; }
exit 0
