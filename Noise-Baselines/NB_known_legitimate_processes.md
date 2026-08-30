# Known-Legitimate Process & Command Patterns

Confirmed-benign process/command patterns, distilled from confirmed FP verdicts across this
repo. Check an alert against this list before investigating from scratch — if it matches
exactly, it's very likely FP, but always verify the specific context still applies (source,
timing, actor) before closing without further review.

---

## rundll32.exe + PcaSvc.dll,PcaPatchSdbTask

**Pattern:** `rundll32.exe PcaSvc.dll,PcaPatchSdbTask`
**What it is:** Windows Program Compatibility Assistant (PCA) routine compatibility database
check — fires automatically after many software installs/updates.
**Verdict when matched exactly:** FP
**Source case:** Case_004
**Caution:** Confirm the DLL path and function name match exactly — attackers can invoke
rundll32 with different DLLs/functions to LOLBin their way past a "rundll32 is normal" bias.
Case_004's lesson explicitly warns: baseline matches still deserve a quick secondary-indicator
sanity check, not an automatic close.

---

## Signed Microsoft Update Packages (Defender, Edge, Windows Update)

**Pattern:** Scheduled tasks or processes tied to documented Microsoft update mechanisms
(e.g., `MicrosoftEdgeUpdateTaskMachineCore`, Windows Defender definition updates), signed with a
valid Microsoft certificate, occurring on the expected schedule.
**Verdict when matched exactly:** FP
**Source cases:** Case_027 (G-004), Case_036 (P-003), Case_041 (U-003)
**Caution:** Verify the timing genuinely matches the documented schedule and the signature is
valid — don't assume "it's a Microsoft process" alone is sufficient; check schedule and
signature together. Proximity to a confirmed incident on the same host (Case_041's U-003) does
not itself establish correlation without a supporting mechanism.

---

## CI/CD Service Account Context Reads (Automated, In-Schedule)

**Pattern:** A recognized CI/CD or deployment service account reading its own designated
resource/context/ConfigMap, tied to a specific, traceable deployment ID.
**Verdict when matched exactly:** FP
**Source cases:** Case_036 (P-003), Case_037 (baseline comparison)
**Caution:** The same action type (context/secret read) performed by an *interactive* session
rather than the automated service account is a critical severity escalation, not a variant of
this baseline — see Case_037's Q-002. Always check actor type (automated vs. interactive), not
just the action.

---

## Routine, Documented, Ticketed Cloud IAM/Config Changes

**Pattern:** Any cloud configuration change (SAS token issuance, trusted-location update,
firewall rule, lifecycle policy, IAM key rotation) performed by a role-appropriate actor, tied
to a specific change ticket, matching a documented schedule or business justification.
**Verdict when matched exactly:** FP
**Source cases:** Case_026 (F-001, F-003), Case_032 (W-003), Case_037 (Q-003), Case_038 (R-003),
Case_040 (T-001, T-003, T-004), Case_042 (W-003), Case_043 (V-003), Case_044 (X-003)
**Caution:** This is the single most common FP pattern in Phases 4-5. The deciding factor is
**positive, specific, dated confirming evidence** (a real change ticket, a real calendar entry
matching the exact activity) — not merely an absence of red flags. An alert with a real
deviation from baseline but *no* confirming evidence either way is Ambiguous, not FP (see
Case_026's F-003, corrected via this exact distinction in Case_040).

---

## Documented Recurring Benign Failure Patterns

**Pattern:** A specific, named, recurring issue (e.g., "failed logons from an expired
scheduled-task credential") that has occurred multiple times before, always resolved the same
way, with no connection to any other alert in the current queue.
**Verdict when matched exactly:** FP
**Source case:** Case_025 (E-002)
**Caution:** Verify no shared account, host, or IP with any other alert in the current
incident/queue before closing — a documented benign pattern on one account does not make a
similar-looking event on a *different, connected* account automatically benign too.
