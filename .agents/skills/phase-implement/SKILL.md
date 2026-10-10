---
name: phase-implement
description: "Implement an authorized phase plan and carry it through its requested completion scope."
---

# Phase Implement

Read the shared execution contract linked from the current phase in
`docs/PLAN.md` (normally `docs/active/phase-N-plan.md`) before dispatch. Give each
implementor/reviewer its absolute path; they must read that file rather than rely
on chat history. If it is missing or its unresolved gates prevent the assigned
task, restore the saved plan through phase-plan before dependent implementation.
The saved plan does not itself grant implementation or delivery authority.

Read the current phase and project profile. Execute its dependency order and the phase-close policy in AGENTS.md. Keep task state current and verify returned subagent work. Immediately record deferred findings in docs/ISSUE_LEDGER.md; automatically close verified local records under docs/ISSUES.md. Complete delivery through ship-pr: ledgers first, commit and PR, user PR approval, merge, then any immediate progress corrections directly on main. Use browser or other direct checks when the criteria require them.

Output completed criteria, verification and review evidence, delivery result, blockers, and pending external operations. Do not start the next phase unless the user's scope includes it.
