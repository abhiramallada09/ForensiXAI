---
name: evidence-integrity
description: Cryptographic hashing, immutability, chain of custody, and forensic evidence tracking.
---

# Evidence Integrity Skill

Enforces forensic integrity standards across the platform:
- Calculate cryptographic hashes (SHA-256 mandatory, MD5/SHA-1 optional for legacy reference).
- Treat files in `data/uploads/` as strictly read-only original evidence.
- Create segregated analysis working copies in `data/working/` before running any parsing or extraction tools.
- Maintain immutable audit logs of all user actions, file ingestion events, and analytical operations.
- Explicitly tag every piece of evidence with classifications: `OBSERVED`, `CORRELATED`, `RECONSTRUCTED`, `SUSPICIOUS`, or `UNKNOWN`.

