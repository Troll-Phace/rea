# Offline issue policy

The user's 2026-10-09 direction supersedes the scaffold's GitHub issue/milestone policy. The canonical backlog is [ISSUE_LEDGER.md](ISSUE_LEDGER.md), versioned with the fork. No GitHub Issues API, publication, synchronization or remote closure is required or allowed by this workflow. GitHub remains the PR destination only.

## Capture

Immediately log verified deferred findings and meaningful follow-up work. Search the entire ledger, including closed records, before allocating the next monotonically increasing PSX-NNN ID. Never reuse IDs. Record title, type (bug/feature/perf/refactor/docs/test/security), severity (critical/high/medium/low), status (open/in-progress/blocked/closed), assigned phase or Backlog, owner, evidence, impact, done-criteria and deferral/dependency reason. Suspicions must be labeled unconfirmed. Phase work can use one umbrella entry with task IDs; split independent deferred findings into separate records.

Maintain the compact index at the top for context loading. Detailed sections are canonical; keep index/status synchronized. Orchestrator owns integration of concurrent reports; reserve IDs before delegating writes to avoid duplicate allocation. No due dates or completed evidence may be invented. Planned tasks are not discovered defects.

## Closure

Automatically close a record only after every done-criterion has evidence against the final relevant content. Record commands/results, commit/PR if applicable, host/provider/target identities for live checks and closure date. Partial tests or generic suite success do not establish missing live gates. If merge is part of the criteria, leave it open until merge is verified. Reopen on a demonstrated regression and retain the prior evidence. Never delete closed entries to clear the backlog.

## Phase and delivery integration

Every phase in PLAN.md references local IDs. Update ledger and PROGRESS.md before verification and delivery. Use plain text 'Local issue PSX-001' in commit/PR bodies; never 'Fixes #001' for these IDs. Commit/push/PR workflows target Troll-Phace/rea using gh through permitted networking. User approval of the concrete PR is required before merge. Immediate documentation-only post-merge corrections follow AGENTS.md, respecting branch protection.

## Offline context

framework.json uses issue_repository null and issue_tracking.mode offline. Runtime context reads the bounded local ledger, does not query GitHub, and labels missing/truncated input. refresh-backlog in offline mode only rereads local state. Hook execution/trust and fresh-client agent discovery remain separately piloted. Local files cannot grant runtime permissions.
