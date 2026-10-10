---
name: safe-commit
description: "Create an intended phase checkpoint or completion commit within authorized scope."
---

# Safe Commit

Read Git status, branch, staged and unstaged diffs, and the current phase evidence. Preserve unrelated changes; use a phase branch for substantive edits. Verify that checks cover the final intended content and that no secrets or unrelated generated output enter the commit. Stage named files or intended hunks.

Use the REA Conventional Commit convention (for example feat(psx): description), recording phase and actual issue references in the body. Use plain-text PSX-NNN references; never GitHub issue-closing keywords for local IDs. Finalize progress and ledger wording before the completion commit; record merge as pending until confirmed. Immediate post-merge progress corrections use the direct-main exception in ship-pr. Record the commit and intended files. A checkpoint is not proof of phase completion.
