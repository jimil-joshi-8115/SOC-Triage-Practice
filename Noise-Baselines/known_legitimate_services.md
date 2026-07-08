# Known Legitimate Services — Noise Baseline

Documented service-related patterns confirmed during Cases 001-020, plus carried-over findings from SOC-Lab-Splunk.

---

## Routine Services (Stop/Restart = Common, Mundane)

| Service | Typical Action Seen | Verdict | Source |
|---|---|---|---|
| Print Spooler (`Spooler`) | Restarted | 🟢 FP | Case_016, Alert AB — well-documented as crash-prone; both automatic recovery and manual restarts are common |
| Windows Update (`wuauserv`) | Stopped | 🟢 FP | Case_019, Alert BF — routinely paused to avoid forced reboots or manage bandwidth |
| Bluetooth Support (`BthServ`) | Stopped/restarted | 🟢 FP | Consistent with routine peripheral-service management |
| GoogleUpdaterService | Running in background | 🟢 FP | Carried over from SOC-Lab-Splunk baseline — legitimate Google background updater |
| HP Audio Analytics (`net.exe start/stop HPAudioAnalytics`) | Start/stop | 🟢 FP | Carried over from SOC-Lab-Splunk baseline — legitimate HP audio driver service |

---

## Security-Critical Services (Disable/Stop = Decisive TP)

| Service | Typical Action Seen | Verdict | Source |
|---|---|---|---|
| Windows Defender (`WinDefend`) | Real-time monitoring disabled / process killed | 🔴 TP — T1562.001 | Case_011 (Alert G), Case_015 (Alert W), drill practice (`taskkill /f /im MsMpEng.exe`) |
| Windows Firewall (`MpsSvc`) | Disabled | 🔴 TP — T1562.004-adjacent | Consistent with Defender-disable reasoning |
| Event Log / Audit Policy (ScriptBlock logging, audit subcategory forcing) | Disabled | 🔴 TP — T1562 | Case_013 (Alert M), Case_018 (Alert AJ) |

**Rule:** The service *type* is the deciding factor, not the fact that "a service was stopped." Routine services have obvious everyday reasons to be paused/restarted by ordinary users or IT. Security-control services (Defender, Firewall, Audit/Event Logging) have no legitimate everyday justification for being disabled by a standard user — treat as TP on content alone, same standard applied consistently from Case_011 onward.

---

## Firewall Rule Direction Reference

| Direction | Action | Verdict Pattern | Source |
|---|---|---|---|
| Inbound (`dir=in`) | Allow, unusual/malicious port (e.g. 4444, 31337) | 🔴 TP | Case_012 (Alert R), Case_016 |
| Outbound (`dir=out`) | Block, named "malicious" target | 🟢 FP | Case_016, Alert X — defensive action, not an attack |

**Rule:** Firewall verdicts depend on **direction + action together**, never on the rule's name alone. A rule that *blocks* outbound traffic to a "malicious" IP is protective; a rule that *allows* inbound traffic on a known backdoor port is the actual threat — these can look superficially similar in a queue view but mean opposite things.

---

## Maintenance Log

Add newly confirmed service patterns here as they're validated in future cases.
