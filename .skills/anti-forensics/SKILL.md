---
name: anti-forensics
description: Detecting anti-forensic techniques such as timestomping, log wiping, artifact tampering, and inconsistencies.
---

# Anti-Forensic Detection Skill

Specializes in identifying manipulation, evasion, and inconsistency in digital evidence:
- Detect timestamp inconsistencies (e.g. MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` mismatch, sub-second zeroing, nanosecond anomalies).
- Flag out-of-sequence events, missing expected audit logs, or sudden logging gaps.
- Present findings cautiously as "Possible timestamp manipulation" or "Evidence inconsistency indicator", accompanied by confidence ratings, affected artifacts, and recommended verification steps.
- Never automatically assign human or attacker identity; frame findings objectively for forensic scrutiny.

