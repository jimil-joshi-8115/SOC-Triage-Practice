# Verdict — Case 041

## U-001: 🔴 Verdict: TRUE POSITIVE (established retroactively via U-002 correlation)
## U-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## U-003: 🟢 Verdict: FALSE POSITIVE

**U-001 and U-002 are TP as a single correlated incident. U-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Trojanized DLL delivered via legitimate vendor update mechanism (U-001) |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 | DGA-pattern DNS beaconing to a randomized-subdomain C2 infrastructure (U-002) |

---

## Justification

### U-001 — TP (retroactively established)
At the time it occurred, this alert presented no available indicator of compromise: a validly
signed update from the vendor's official channel, with no malicious hash match. This is not a
gap in this ticket's data — it reflects how the real-world attack this scenario is grounded in
evaded detection for months, by ensuring the trojanized component was properly signed and
initially undetected by hash-based tools. The verdict on this alert cannot be resolved from its
own contents; it depends entirely on U-002.

### U-002 — TP, Critical
A domain generation algorithm-consistent beaconing pattern — randomized subdomains of a single
parent domain, irregular query intervals — to a domain with no legitimate business relationship
to the organization, occurring exactly 14 days after U-001's update. This 14-day gap directly
matches the documented dormancy period of the real-world malware this scenario is grounded in,
a deliberate technique to separate the malicious update from the onset of suspicious network
activity in a defender's timeline.

**Correlation and retroactive re-assessment:** U-002 confirms AURORA-MON01 is compromised, and
the only new software change on that host in the relevant window is the U-001 update. This
establishes U-001 as the delivery vector — not because anything in U-001 itself was flagged as
malicious, but because U-002's confirmed compromise, combined with the precisely-matching
dormancy timing, leaves no other explanation. This is a case where correlation with a later
alert creates the verdict on an earlier one, rather than simply reinforcing an already-suspected
finding.

### U-003 — FP
A fully routine, scheduled Defender definition update from an entirely separate vendor
(Microsoft), matching the standard daily update pattern. Proximity in time to U-002 (3 hours
prior, same host) does not establish correlation without a supporting mechanism connecting the
two — no such mechanism exists here.

---

## What Would Change These Verdicts

- **U-001/U-002 → FP:** confirmation from the monitoring platform vendor that this exact domain
  and beaconing pattern is a documented, legitimate telemetry/licensing-check feature (would
  require explicit vendor documentation, not assumed given the DGA pattern and unrelated
  domain).
- **U-003 → TP:** if the update package were later found to be unsigned, off-schedule, or
  functionally connected to the beaconing behavior.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Isolate AURORA-MON01 from the network immediately** — treat as confirmed compromised.
2. **Do not simply patch/update the monitoring platform in place** — the update mechanism
   itself was the delivery vector; a full rebuild from a verified-clean image is warranted,
   consistent with the real-world guidance following the incident this scenario is grounded in.
3. Audit all other hosts running the same monitoring platform version for the same DLL hash and
   any beaconing to the same or related domains.
4. Review what privileged access AURORA-MON01 had into other systems (monitoring platforms
   typically have broad credentials/access across an environment) and treat those systems as
   potentially exposed.
5. Block the beaconing domain and any related infrastructure at the DNS/firewall level
   organization-wide.
6. Contact the monitoring platform vendor to report the finding and check for a public advisory
   or patched version.
7. Review update-server integrity and code-signing trust assumptions broadly — this incident
   demonstrates that valid signatures and clean hash reputation are insufficient on their own to
   confirm safety for updates from any vendor, however trusted.
8. Escalate to L2/IR immediately given confirmed supply-chain compromise.
9. No action needed on U-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | U-001: TP (retroactive) · U-002: TP (Critical) · U-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — U-001/U-002 (would be, in real SOC, as confirmed supply-chain compromise) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the 2020 SolarWinds/SUNBURST supply chain attack; IOCs and identities fully sanitized/fictional |
