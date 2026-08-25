# CASE-02 — Reveal & Score

> Reveal performed **after** assessment + confidence were written (methodology step 7).
> Ground truth = sealed theZoo provenance (`groundtruth.sealed.json`, read only at reveal).

## Ground truth
| Field | Value |
|---|---|
| sha256 | `257da8c8b296dac6b029004ed06253fe622c5438b4a47b7dfbb87323b64f50a1` |
| md5 | `c3b48db40cf810cb63bf36262b7c5b19` |
| theZoo path | `malware/Binaries/OSX.Wirenet` |
| **Family** | **OSX/Wirenet** (Wirenet.A — Dr.Web, 2012) |

**OSX/Wirenet** = cross-platform (macOS + Linux) password-stealing backdoor: harvests stored
credentials from **Opera, Firefox, Chrome/Chromium, SeaMonkey, Thunderbird** (and IM/keychain),
runs a **keylogger**, and opens a **backdoor to C2** (historically an AES-encrypted channel).

## Score vs. blind assessment
| Blind call | Confidence (blind) | Ground truth (Wirenet) | Result |
|---|---|---|---|
| **Malicious** | High | password-stealing backdoor | ✅ **HIT** |
| Severity **High** | — | full backdoor + credential theft | ✅ **HIT** |
| Category: **macOS RAT + browser/mail infostealer + surveillance** | High | Wirenet = cross-platform cred-stealer + keylogger + backdoor | ✅ **HIT** (precise) |
| Cred theft via **Mozilla NSS** (Firefox/Thunderbird/SeaMonkey) + **Opera `wand.dat`** | High | canonical Wirenet targets | ✅ **HIT** (exact) |
| **Input/surveillance** (`_CGEventPost`, CGWindowList) | Medium-High | Wirenet keylogger | ✅ **HIT** (this is the keylogger) |
| **HTTP C2 (plaintext), no crypto** | Med-High / crypto "none" | Wirenet C2 reportedly **AES-encrypted** | ⚠️ **PARTIAL MISS** — see below |
| Family = **Crisis/Morcut, Careto, or generic macOS RAT** | Low-Medium | **Wirenet** | ⚪ **MISS on specific family** (generic bucket correct; named wrong candidates) |

**Verdict, severity, category, and the credential-theft mechanism: all correct.**
The keylogger I logged as "input injection via `_CGEventPost`" is exactly Wirenet's keylogger
component — right capability, slightly mislabeled (monitoring vs. injection).

## Misses / gaps
1. **C2 encryption.** I reported "no crypto / plaintext C2" from an empty `crypto_constant_scan`
   plus the plaintext `GET`/`CONNECT` templates. Wirenet is documented to use **AES** for its
   C2. Likely explanation: crypto via macOS **CommonCrypto** framework calls (no embedded S-box
   constants for the scanner to hit), so a constant-scan-only pass misses it. **Lesson: absence
   of crypto constants ≠ absence of crypto** on platforms with system crypto frameworks — should
   have checked for `CCCrypt`/`CommonCrypto` imports before asserting plaintext.
2. **Specific family** not pinned — named Crisis/Careto as primaries; correct only at the
   "generic macOS RAT/stealer" bucket. No version/campaign string was decodable to reach Wirenet.
3. C2 command dispatcher (`FUN_00002397`) left undecompiled — tasking set unread.

## Vivarium validation takeaway (CASE-02)
Vivarium produced a **correct, high-confidence macOS verdict on a real Wirenet sample** — the
NSS credential-decryption loop decompiled cleanly on a 32-bit Mach-O, and the capability map
was recoverable from static data alone. Cross-platform coverage confirmed (Mach-O loader +
decompiler + import attribution all solid). The one analyst error (plaintext-C2 claim) traces to
tool *usage*, not a tool fault: `crypto_constant_scan` correctly found no embedded constants;
the CommonCrypto path needed an import check I didn't run.

---
### ⚠️ Exercise-integrity note (blindness)
At this reveal I read `groundtruth.sealed.json`, which returned **all four** entries, not just
case-02. Cases **03 (`Win32.LuckyCat`)** and **04 (`Win32.BUMBLEBEE`)** are therefore **no longer
blind** — their subsequent analyses must be recorded as **informed**, not blind, and are excluded
from blind-accuracy scoring. Case-01 (Kelihos) and Case-02 (Wirenet) scores remain valid blind
results (both assessed and written before their reveals).
