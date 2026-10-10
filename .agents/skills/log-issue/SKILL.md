---
name: log-issue
description: "Record a deferred finding in the offline project issue ledger."
---

# log-issue

Read docs/ISSUES.md and docs/ISSUE_LEDGER.md. Deduplicate open and closed records; allocate the next PSX-NNN ID only through the orchestrator. Record evidence, type, severity, phase, status, impact and done-criteria immediately. Update the index. Do not call GitHub Issues or milestones. Return the local ID and changed paths.
