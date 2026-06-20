# Ghidra Jython: bounded, resume-capable decompile chunk.
# Decompiles at most MAX_PER_RUN not-yet-done first-party functions, then exits
# (so each process frees memory before the decompiler's native growth causes OOM).
# Reuses a pre-analyzed project via -process -noanalysis; run repeatedly until done.
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

allow_path = os.environ["ALLOWLIST"]
out_c   = os.environ["OUT_C"]
out_idx = os.environ["OUT_IDX"]
max_per = int(os.environ.get("MAX_PER_RUN", "3000"))
dispose_every = int(os.environ.get("DISPOSE_EVERY", "800"))
# Guard against pathological functions that balloon the native decompiler to many GB.
# Functions whose body exceeds this many bytes are recorded but not decompiled.
max_fn_bytes = int(os.environ.get("MAX_FN_BYTES", "40000"))
decomp_timeout = int(os.environ.get("DECOMP_TIMEOUT", "45"))

allow = set()
f = open(allow_path)
for line in f:
    s = line.strip()
    if s:
        allow.add(s)
f.close()

done = set()
if os.path.exists(out_idx):
    f = open(out_idx)
    first = True
    for line in f:
        if first:
            first = False
            continue
        p = line.split(",")
        if p and p[0]:
            done.add(p[0])
    f.close()

fm = currentProgram.getFunctionManager()
print("PROJECT_FUNCS=%d allow=%d already_done=%d" % (fm.getFunctionCount(), len(allow), len(done)))

mon = ConsoleTaskMonitor()
from ghidra.app.decompiler import DecompileOptions
max_payload_mb = int(os.environ.get("MAX_PAYLOAD_MB", "30"))
def new_decomp():
    d = DecompInterface()
    opts = DecompileOptions()
    # Cap the marshalled payload so a pathological function aborts instead of
    # ballooning the native decompiler to many GB (which OOMs the whole host).
    opts.setMaxPayloadMBytes(max_payload_mb)
    d.setOptions(opts)
    d.openProgram(currentProgram)
    return d
decomp = new_decomp()

new_file = not os.path.exists(out_c)
cf = open(out_c, "a")
idx = open(out_idx, "a")
if new_file:
    cf.write("/* OpenSSL 4.0.1 first-party decompilation (Ghidra headless, symbol-bearing build) */\n\n")
if len(done) == 0:
    idx.write("name,address,size_bytes,decompiled_lines,status\n")

n = 0
ok = 0
for fn in fm.getFunctions(True):
    name = fn.getName()
    if allow and name not in allow:
        continue
    if name in done:
        continue
    if n >= max_per:
        break
    n += 1
    addr = fn.getEntryPoint().toString()
    sz = fn.getBody().getNumAddresses()
    if sz > max_fn_bytes:
        # Too large: decompiling it can balloon the native decompiler to multiple GB.
        # Record it honestly instead of risking an OOM of the whole run.
        code = "/* skipped: function body %d bytes exceeds MAX_FN_BYTES=%d (decompiler memory guard) */" % (sz, max_fn_bytes)
        status = "skipped_large"
    else:
        res = decomp.decompileFunction(fn, decomp_timeout, mon)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
            ok += 1
            status = "ok"
        else:
            code = "/* decompilation failed */"
            status = "failed"
    nlines = code.count("\n") + 1
    cf.write("/* ===== %s @ %s (%d bytes) ===== */\n" % (name, addr, sz))
    cf.write(code)
    cf.write("\n\n")
    cf.flush()
    idx.write("%s,%s,%d,%d,%s\n" % (name, addr, sz, nlines, status))
    idx.flush()
    if n % dispose_every == 0:
        decomp.dispose()
        decomp = new_decomp()
        print("PROGRESS new=%d ok=%d (decompiler reset)" % (n, ok))
decomp.dispose()
print("CHUNK_DONE new=%d ok=%d total_done=%d" % (n, ok, len(done) + n))
