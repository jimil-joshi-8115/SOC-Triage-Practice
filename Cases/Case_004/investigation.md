# Investigation — Case 004

## Step 1: Inspect the Command Line

`Process_Command_Line`: `rundll32.exe PcaSvc.dll,PcaPatchSdbTask`

Breaking this down:
- DLL: `PcaSvc.dll` — Program Compatibility Assistant service DLL, a native Windows component.
- Exported function: `PcaPatchSdbTask` — a known, legitimate PCA task function used by Windows to check application compatibility databases.

**Finding:** 🟢 This is a standard `rundll32.exe <dll>,<exported_function>` invocation pattern used natively by Windows itself — not a script or external file being loaded.

---

## Step 2: Cross-Check Against Documented Noise Baseline

Checked `Noise-Baselines/known_legitimate_processes.md`.

**Finding:** 🟢 Exact match found:
> `rundll32.exe + PcaSvc.dll,PcaPatchSdbTask → legitimate (Windows PCA)`

This exact DLL + exported function combination was already identified and documented as known-legitimate noise during the SOC-Lab-Splunk capstone dashboard work (explicitly excluded from that dashboard's suspicious-activity view for this reason).

---

## Step 3: Assess for Red Flags Anyway (Don't Skip Just Because It Matches Baseline)

Even with a baseline match, quickly ran through the standard checklist to avoid confirmation bias:
- **DLL path** — no unusual/non-standard path referenced (no external or user-writable directory)
- **No download, no network indicator, no encoded payload** in the command line
- **No unusual account** — `hp` is the standard interactive user
- **Single event, not repeated/rapid-fire** in a way that would suggest scripted abuse of this specific pattern

**Finding:** 🟢 No secondary indicators present that would override the baseline match.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| DLL + function | Matches known Windows PCA pattern | 🟢 None |
| Baseline match | Exact match in known_legitimate_processes.md | 🟢 None |
| Secondary indicators | None present | 🟢 None |
