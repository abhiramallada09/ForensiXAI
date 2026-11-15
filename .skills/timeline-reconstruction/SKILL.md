---
name: timeline-reconstruction
description: Multi-source timestamp correlation, event window determination, and chronological reconstruction.
---

# Timeline Reconstruction Skill

Specializes in correlating multi-source temporal evidence:
- Combine file MACB timestamps, process execution timestamps, network connection logs, Windows Event logs, and CloudTrail entries.
- Distinguish between directly observed timestamps and reconstructed event windows.
- Output probable event windows (e.g., `10:03:18 – 10:03:27`) when multiple disjoint artifacts suggest an action.
- Assign confidence ratings and list all supporting artifact IDs for every reconstructed timeline milestone.

