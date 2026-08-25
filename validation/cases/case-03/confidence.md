# CASE-03 — Confidence & Predictions (recorded BEFORE reveal)

Scoring key: HIT = matches ground truth; PARTIAL = right bucket, wrong specific; MISS.

| Dimension | Blind call | Confidence | Rationale |
|---|---|---|---|
| Verdict | Malicious | **Certain** | Hardcoded ddns C2 + beacon loop + obfuscated config — unambiguous. |
| Severity | High/Critical | High | Full RAT: remote shell + file transfer + exec on a targeted victim. |
| Category | RAT / backdoor (DLL) | High | CMyClientMain/Tran/MainTrans/TlntTrans/FileTrans + CreatePipe/CreateProcess. |
| Delivery | DLL side-loading / search-order hijack, masquerades as Windows Credential Manager | Medium-High | Credential.dll + faked MS version info + benign GetObjectCount export. |
| C2 | dalailamatrustindia.ddns.net:110/443, 5.126.6.16:110 | Certain | Decompiled from beacon; ioc_scan concurs. |
| Config protection | Custom rolling subtract cipher (not std crypto) | High | Read directly from FUN_100012e7. |
| Targeting | Tibetan community / Dalai Lama Trust — Chinese-nexus APT | Medium (inferential) | Hostname lure; TTP pattern. Attribution not provable statically. |
| Family (specific) | Targeted DLL RAT; guess Gh0st-RAT lineage / PlugX-class (ATL/MFC RAT) | **Low** | No unique family constant recovered; naming + masquerade only. |

## What would change the call
- If ground truth names a specific family (e.g. Gh0st, PlugX, ShadowPad, or a bespoke like
  "Kaba"/"SManager"), family = PARTIAL/MISS but the RAT bucket + Tibetan-APT context should HIT.
- Verdict/severity/category/C2 expected to HIT.
