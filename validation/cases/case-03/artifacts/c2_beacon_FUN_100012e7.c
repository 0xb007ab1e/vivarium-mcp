/* case-03 — C2 beacon loop (Vivarium decompile, ghidra-generated, UNTRUSTED/inert)
 * addr 0x100012e7 in Credential.dll (base 0x10000000). Sample NEVER executed.
 * Behaviour:
 *  - local_fa0[] built byte-by-byte then decrypted via rolling subtract cipher
 *    (7-byte key at local_fbc, `(*p) - key[i%7]`, wrap +0x59) = anti-static-string config.
 *  - Target list assembled: L"dalailamatrustindia.ddns.net:110", L":443",
 *    and DAT_1001a954 (= 5.126.6.16:110).
 *  - srand(time()); loop: pick target (uVar4 % 3), split host:port at ':',
 *    OutputDebugStringA("DLL---Start connect to %ws:%d"),
 *    construct CMyClientMain (vftable @ CMyClientMain::vftable), CreateEventW,
 *    launch transport (FUN_10001fdf / FUN_10001f7d), rand()+Sleep jitter,
 *    infinite: `while (uVar4 != 0)`.
 * Verdict: core beacon of a DLL-form RAT. See report.md.
 */
