# Verdict — Case 038

## R-001: 🔴 Verdict: TRUE POSITIVE
## R-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## R-003: 🟢 Verdict: FALSE POSITIVE

**R-001 and R-002 are TP as a single correlated incident. R-003 is unrelated and confirms
legitimate practice by contrast.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Unsecured Credentials: Credentials in Files | T1552.001 | Overprivileged SAS token hardcoded and committed to a public repository (R-001) |
| Valid Accounts: Cloud Accounts | T1078.004 | Leaked token used to access storage resources (R-002) |
| Data from Cloud Storage | T1530 | Mass GetBlob/ListBlobs across multiple containers including sensitive data (R-002) |

---

## Justification

### R-001 — TP
A SAS token with account-wide Read+Write+Delete permissions and roughly two years of validity
was found hardcoded in a public GitHub repository, exposed for 6 days prior to discovery. The
excessive scope (entire storage account rather than the single container the client-side widget
actually needs) and long expiration are themselves the finding — this is a severe
misconfiguration independent of whether abuse is later confirmed, given the well-documented
pattern of automated scanning tools that specifically search public repositories for exposed
secrets like this.

### R-002 — TP, Critical
Every dimension of the observed activity contradicts the token's legitimate purpose: the
booking widget only ever performs PutBlob operations to a single container, while this activity
shows 550 GetBlob/ListBlobs operations across 8 containers — including customer invoices and
employee documents — within 40 minutes, immediately following the R-001 discovery alert. This
confirms active exploitation and likely data exposure of sensitive business and personal data,
not merely a theoretical risk.

**Correlation:** R-001 and R-002 are one incident — the exact token identified as leaked in
R-001 was actively exploited in R-002, in the same immediate timeframe.

### R-003 — FP
Every factor is the inverse of R-001: minimal permission level (read-only), narrow scope (a
single, low-sensitivity container), short expiration (7 days), and full documentation tied to a
specific approved business purpose (CHG-9401). This is standard, properly-governed SAS token
issuance and shares no connection to R-001/R-002.

---

## What Would Change These Verdicts

- **R-001 → FP:** essentially not plausible given the confirmed public exposure and excessive
  scope — even absent R-002, this would remain TP on the misconfiguration alone.
- **R-002 → FP:** a documented, approved internal security test explaining this exact access
  pattern and timing (would need explicit verification, not assumed given the severity).
- **R-003 → TP:** if the token's actual usage were later found to deviate from its documented
  read-only, single-container scope, or if CHG-9401 could not be verified as legitimate.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately revoke the leaked SAS token** for `aurorastorageprod` — highest priority, since
   active exploitation is confirmed.
2. Remove the hardcoded token from the `booking-widget` repository's commit history entirely
   (not just the latest commit — SAS tokens in git history remain exposed even after removal
   from the current file version).
3. Generate a new, properly-scoped token for the booking widget: PutBlob-only, scoped to the
   single `booking-uploads` container, with a short expiration and a rotation process.
4. Audit the `customer-invoices` and `employee-documents` containers for what data may have been
   accessed or downloaded during the R-002 window — treat this as a probable data breach
   involving customer and employee information pending confirmation.
5. Review all other public repositories under the organization for similarly hardcoded secrets
   using automated scanning going forward, not just reactive discovery.
6. Notify affected customers/employees per breach-notification requirements if sensitive data
   access is confirmed.
7. Block source IP 91.219.212.44 at the storage account/network level.
8. Establish a policy requiring short-lived, narrowly-scoped SAS tokens by default (mirroring
   R-003's pattern) rather than long-lived, broadly-scoped ones.
9. Escalate to L2/IR immediately.
10. No action needed on R-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | R-001: TP · R-002: TP (Critical) · R-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — R-001/R-002 (would be, in real SOC, as probable data breach) |
| Corrections during investigation | 0 |
| Scenario basis | Grounded in a widely-documented real-world SAS token exposure/exploitation pattern (public repository secret leakage); IOCs and identities fully sanitized/fictional |
