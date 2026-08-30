# Process Creation / Execution Triage Playbook

Step-by-step checklist for process-creation alerts (EventCode 4688), LOLBin abuse, and endpoint
execution chains, including their cloud-native equivalents (container/pod deployment, Lambda
execution). Each rule is tied to the case that established it.

---

## Step 1: Decode/Inspect the Actual Payload First

- **Never rule out malicious intent based on technique alone** — decode base64, inspect
  arguments, resolve obfuscation before judging (Case_001).
- **Suspicious structure ≠ automatic TP** if the decoded/inspected payload is genuinely benign
  (Case_003, Case_014).
- Conversely, **a confirmed technique is TP regardless of a harmless demo payload** — tradecraft
  determines the verdict, not how damaging the specific sample happened to be (Case_011).

---

## Step 2: Check the Parent-Child Process Chain

- **Common parent-child chains are not inherently suspicious** (Case_009) — but **an abnormal
  chain (a parent that shouldn't spawn what it spawned) is itself the red flag**, even before
  looking at the payload (Case_012, Case_014).
- Malicious document/email-driven chains: `winword.exe`/`outlook.exe` → `cmd.exe`/`powershell.exe`
  → LOLBin/download is a consistent, decisive pattern (Case_027 G-001, Case_030 J-001/002,
  Case_048 CC-003).

---

## Step 3: Check for LOLBin Abuse Specifically

- `certutil.exe`, `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `bitsadmin.exe` used for their
  **download/execute** capability rather than their intended purpose is a recurring real-world
  pattern worth specifically checking for (Case_008, Case_027 G-001, Case_029 basis).
- Compare against the documented legitimate baseline for the *specific* DLL/function/argument
  combination (e.g., `rundll32.exe PcaSvc.dll,PcaPatchSdbTask` — Case_004) — a superficial match
  ("it's rundll32") is not the same as an exact match.

---

## Step 4: Check Timing and Repetition Pattern

- **Distinguish scripted/automated repetition from manual rapid typing** — exact millisecond
  intervals suggest a script/loop; slightly variable but still-fast intervals suggest a human
  operator running a short sequence once (Case_002).
- **Volume/rate alone can be decisive evidence**, separate from needing a confirmed downstream
  outcome (e.g., a DNS TXT query flood, an IAM enumeration burst) — Case_019, Case_023.

---

## Step 5: Check Encryption/Resource-Throttling Choices (Cloud/Cryptojacking)

- Deliberately **low resource limits on a compute-intensive process** is a known cryptojacking
  evasion technique — keeping usage low to avoid triggering monitoring (Case_036).
- Deliberate **RC4 instead of AES** in Kerberos ticket requests is the Kerberoasting signature —
  the encryption *downgrade choice* is the tell (Case_028).

---

## Step 6: Check for Persistence Establishment

- A **completed persistence action is TP even with a benign current payload** — the persistence
  mechanism itself is the finding (Case_007).
- Cloud/identity persistence is often more dangerous than a single compromised session: rogue
  IdPs, rogue OAuth apps with broad permissions, and trusted-location/CA policy modifications all
  create standing access that survives a simple password reset (Case_024, Case_028, Case_032,
  Case_042).

---

## Step 7: Correlate or Isolate

- Confirm actor/host/timing overlap before assuming shared incident membership — queue position
  does not imply chain continuation (Case_048's CC-004 correction).
- If the same tool/binary appears legitimate elsewhere in the environment, confirm this specific
  invocation's context (arguments, source, actor) rather than pattern-matching on the binary name
  alone.
