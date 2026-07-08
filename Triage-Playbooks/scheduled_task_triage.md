# Scheduled Task Triage Playbook

Built from real triage patterns confirmed across Cases 003, 007, 012, and 015.

---

## Step-by-Step Checklist

1. **Check the task name against the baseline first.** Cross-check `Triage-Playbooks`/`Noise-Baselines/known_legitimate_services.md` and any documented aged/known jobs. An exact match to a documented, legitimate task = FP (e.g., deleting a 2-year-old documented backup job — Case_012/drill practice logic).

2. **Check for masquerading.** Names designed to look like real system/vendor tasks (`WindowsUpdateCheck`, `AdobeUpdateSvc`, `SystemHealthCheck`) that don't match any real Microsoft/vendor naming convention or documented baseline are a red flag — but not decisive alone.

3. **Check the run-as context.** `/ru SYSTEM` grants full system privilege — combined with other factors, this escalates severity. A task running as the creating user (not SYSTEM) is comparatively lower-risk but still evaluate the trigger and payload.

4. **Check the trigger type and timing.**
   - `/sc onlogon`, `/sc daily /st 03:00` (off-hours): persistence + timing chosen to avoid observation — aggravating factor.
   - A trigger alone does not confirm TP — it establishes the *mechanism* is a persistence type, which then needs to be weighed against the payload (see next step).

5. **Apply the technique-vs-outcome distinction — this is the single most important step for this alert type.**
   - Masquerading name + hidden window + SYSTEM + persistence trigger + **harmless payload (e.g., `whoami`)** = **Ambiguous**. Structure suspicious, outcome unconfirmed. (Case_003)
   - Same structural profile + **active malicious payload (e.g., download-and-execute from an external IP)** = **TP**, decisive. (Case_015, Alert T)
   - **Rule of thumb:** ask "has this task *already achieved* something harmful, or is it *set up* to potentially do so later with an as-yet-harmless current action?" The former is TP; the latter is Ambiguous.

6. **Compare to registry Run-key persistence for calibration.** A completed registry write to a Run key is treated as TP even with a harmless current payload, because the persistence mechanism itself is already active upon the write succeeding (Case_007) — there is no "pending trigger" step. A scheduled task differs because the trigger (e.g., `onlogon`) hasn't necessarily fired yet at time of triage, which is part of why Case_003 resolved to Ambiguous rather than TP. Always check: has the mechanism already executed, or is it only configured to execute later?

---

## Verdict Quick Reference

| Pattern | Verdict |
|---|---|
| Task name matches documented, aged, legitimate baseline job | FP |
| Masquerading name + persistence + harmless payload, no evidence it has fired maliciously | Ambiguous |
| Masquerading name + persistence + confirmed malicious payload (download-execute, etc.) | TP |
| SYSTEM privilege + off-hours trigger, stacked with other factors | Escalates severity within TP/Ambiguous call, doesn't independently confirm TP |
