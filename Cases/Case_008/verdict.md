# Verdict — Case 008

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Ingress Tool Transfer | T1105 | File download via `certutil.exe -urlcache` from external IP |
| Trusted Developer Utilities / LOLBin Abuse | T1218 (related) | Abuse of a signed Microsoft binary to bypass simple allow-listing |

---

## Justification

1. **Confirmed LOLBin abuse pattern** — `certutil -urlcache -split -f` is a well-known technique for downloading files while evading detections that trust signed Microsoft binaries by default.
2. **Destination is a raw public IP with no legitimate business purpose** for this host to contact.
3. **Disguised filename** (`payload.txt`) is a common evasion tactic — content type is not verified by extension alone.
4. **No legitimate administrative use case** matches this command pattern; certutil's normal legitimate use is certificate management, not arbitrary file retrieval.

---

## What Would Change This Verdict to FP

- If the destination IP resolved to a documented internal certificate/update server
- If this were a confirmed, authorized IT script using certutil for legitimate certificate operations (not file download)

Neither applies — verdict stands as TP.

---

## Recommended Response Actions

- Block outbound traffic to `185.220.101.45` at firewall/proxy
- Retrieve and inspect `payload.txt` if it was successfully downloaded, in a sandboxed environment
- Escalate to L2 — LOLBin abuse combined with external IP contact warrants deeper host review
- Consider adding a detection rule flagging `certutil.exe` with `-urlcache` flag combined with external destinations

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | 2 minutes (8:02 PM – 8:04 PM) |
| Escalated | Yes |
