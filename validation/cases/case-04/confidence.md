# CASE-04 — Confidence & Predictions (recorded BEFORE reveal)

| Dimension | Blind call | Confidence | Rationale |
|---|---|---|---|
| Verdict | Malicious | **High** | regsvr32 self-decoding loader + junk obfuscation + padding + named-pipe IPC. |
| Nature | Loader/packer stage, NOT the final payload | High | Decode loops + indirect dispatch into decoded module; 97.7% undefined. |
| Severity | High | Med-High | Implant loader; true impact depends on the (unseen) stage. |
| Exec vector | regsvr32 (DllRegisterServer export) | High | Export table + entry. |
| C2 | Named-pipe channel; network C2 in decoded stage | Medium | TransactNamedPipe present; no WS2_32 here. |
| Obfuscation | MBA junk code + decoy word-salad strings + size padding | High | Read from decompile + strings. |
| Family (specific) | Qakbot/Qbot ~ or PlugX/Emotet x64 loader class | **Low** | Pattern-match only; payload encoded. |

## Expected scoring
- Verdict = HIT. "Loader/packed modular implant" bucket should HIT.
- Family label likely PARTIAL/MISS (blind, encoded stage). If GT names Qakbot → PARTIAL/HIT;
  if a different family (e.g. Zbot/PlugX/other) → family MISS but nature/verdict HIT.
