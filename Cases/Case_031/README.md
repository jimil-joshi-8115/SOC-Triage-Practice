# Case_031 — AWS IAM Role Chaining: Unauthorized Privilege Escalation → Production Database Exposure

**Phase:** 5 (Cases 31–50) — AWS, 2-alert batch
**Format:** AWS CloudTrail
**Company:** Aurora Resorts & Casinos (internal alias — sanitized, same as Case_024/029)
**Splunk verified:** No — ticket-only (analyst decision)

**Technique basis:** Grounded in the well-documented "AssumeRole chaining" privilege-escalation
pattern, cataloged extensively in real-world AWS penetration testing and cloud security
research (e.g. Rhino Security Labs' AWS privilege escalation methodology) and observed across
multiple actual cloud incidents — not a single named breach, but a widely-used real technique.

---

## Alerts (as received at trigger time)

```
Alert K-001 — IAM: Unusual sts:AssumeRole Chain
  Severity: High
  Actor: IAMUser: j.mehra (Junior Cloud Engineer)
  Detail: j.mehra assumed role "aurora-readonly-analyst" (normal, matches job
          function), then within 40 seconds used THAT role's session to assume
          a second role: "aurora-prod-admin" — a role j.mehra's user policy
          does NOT have direct sts:AssumeRole permission for, but which
          "aurora-readonly-analyst" (misconfigured) does
  Time: 16:44:02–16:44:41 UTC

Alert K-002 — IAM: Security Group Rule Modified, Broad Ingress Opened
  Severity: Critical
  Actor: assumed-role/aurora-prod-admin/j.mehra (session from K-001)
  Detail: AuthorizeSecurityGroupIngress — added rule allowing 0.0.0.0/0 (any
          IP, the entire internet) on port 3389 (RDP) to security group
          "aurora-prod-db-sg" (attached to production database instances)
  Time: 16:45:17 UTC
```

## Task

TP / FP / Ambiguous for K-001 and K-002. Note correlation, and consider what makes role
chaining specifically dangerous compared to a direct over-permissive grant.
