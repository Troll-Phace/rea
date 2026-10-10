# Repository Guidelines

## Product and Authority

REA is a local-only reverse-engineering tool with shared CLI/MCP workflows. Distinguish observations, derivations, inferences, and unknowns; preserve Evidence provenance and session semantics through both adapters. Provider support and setup live in [README.md](README.md#choosing-a-deep-analysis-provider) and its linked guides.

Ghidra uses ephemeral databases without modifying executable bytes or controlling a GUI; Windows Ghidra P0 has no mutation authority. IDA analysis is read-only; never save or close an attached GUI database.

Configuration changes must be additive and idempotent, with backups. Installers must not install or upgrade unrelated software, including Homebrew, Node.js, npm, Java, or Ghidra. Ghidra and IDA are bring-your-own. `rea setup` must show its planned changes and require approval before writing files or installing Hopper.

Preserve caller-selected inputs and local evidence, including output, URLs, paths, digests, and metadata. Redact transport authentication credentials and explicitly marked sensitive values; do not infer secrecy from names or text patterns. Do not persist the ambient environment merely because a child inherits it.

## Architecture and Cleanup

Dependencies flow inward: domain semantics and contracts, provider adapters, shared application workflows, then CLI/MCP adapters. Keep engine protocols and provider-specific code out of domain/application layers. See [docs/architecture.mermaid](docs/architecture.mermaid) when changing composition.

Give each interpretation and resource a clear owner. Preserve identity, omission, uncertainty, and source evidence across boundaries. Retain ownership of resources whose cleanup failed. Reuse `src/process/` supervision and identity primitives; a PID and executable path alone do not establish ownership after exit or reuse.

Assess brittleness in touched code during implementation, debugging, review, and maintenance. Fix the producing representation or ownership rule before adding downstream repairs. Normalize once at the owning boundary using format-aware parsers. Remove superseded representations, aliases, wrappers, and redundant tests after verifying affected consumers. Introduce abstractions only when they remove observed complexity.

Parse unknown boundary values and model expected failures with the tagged error algebra and `Result`. Preserve partial facts and meaningful failure reasons. Keep identity and lookup values separate from display formatting; preserve source values and explicit unknowns when normalization loses information. Absolute paths, file URLs, and HTTP paths have different semantics.

Validate advertised JSON Schemas after SDK conversion against their declared dialect and actual clients. Bind handlers to named contracts with exact types; catalog ordering must never select an operation or schema.

## Development

Use [.nvmrc](.nvmrc) and `package.json#packageManager` for the pinned toolchain. Cursor Cloud may place older Node.js first on `PATH`; environment setup installs the pinned toolchain under `/usr/local/bin`.

- `npm ci`: install locked dependencies.
- `npm run build:cached`: build the runtime and packaged skill.
- `npm run test:local -- PATH...`: source tests without building.
- `npm run test:focused -- PATH...`: exact tests with their required artifacts.
- `npm run check:fast`: cached typecheck/lint and the pre-push check.
- `npm run docs:check`: validate generated documentation.

Use relevant checks for the change. The complete local gate, `npm run check:pr`, is optional for broad changes or CI diagnosis. See [CONTRIBUTING.md](CONTRIBUTING.md) for development, generated-file ownership, and release conventions.

`docs/public/product-catalog.json`, `docs/verification/managed-conformance-*.json`, and `skills/` are ignored outputs. Edit source contracts and `skill-src/`, then regenerate as needed. `.cache/mcp-tool-catalog.json` is test metadata; runtime builds and source checking do not consume it. Never commit binaries, provider project documents, credentials, `dist/`, `node_modules/`, or local planning artifacts.

## Tool and Test Changes

For tool design, follow [docs/tool-design.md](docs/tool-design.md): start from the analyst question, reuse existing contracts, preserve caller choices, and return useful evidence inline. Limits must follow real format, protocol, authority, or resource constraints. Account for representation expansion before allocation; derive completeness from examined coverage.

For test changes or provider claims, use [docs/testing.md](docs/testing.md). Prefer real public CLI/MCP workflows, then production-boundary integration, then producer goldens. Keep module tests for distinct semantics stronger workflows cannot reliably reproduce. Preserve malformed-input, cancellation, cleanup, permission, capacity, and target-identity coverage when pruning. Report unverified coverage explicitly; simulated providers do not establish real-provider behavior.

Use Conventional Commit subjects and PR titles. Mark breaking changes with `!` or a `BREAKING CHANGE:` footer. Describe behavior changes, relevant validation, and real-provider verification scope.

<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->

## PSX phase workflow

You are the primary agent for the project described in docs/PROJECT.md.
The development unit is a phase in docs/PLAN.md. Read docs/PROGRESS.md on
start or resume, reconcile it with Git, and read the current phase plus the
architecture sections it names. Read other references only as needed.

## Phase execution

Delegate phase planning to the dedicated phase-plan agent through the phase-plan
skill. It uses Astra at low (light) effort and returns a detailed execution
contract; the orchestrator owns integration, state and delivery. Leave the
orchestrator model and effort unspecified so the user can choose per chat.
Implementor models and efforts are selected by the user at scaffolding time.
Implement directly when that is efficient. Delegate substantial, independent
work to suitable subagents; cap concurrent children at three or the host limit,
whichever is lower. Give each child owned files, relevant references, acceptance
criteria, and a concise result contract. The primary owns integration and state.
Do not delegate trivial changes or allow concurrent writers on the same files.

Persist each detailed phase contract in shared versioned documentation at
`docs/active/phase-N-plan.md`, linked from its phase in `docs/PLAN.md`, progress
and the local ledger. The planner writes only its assigned plan path; if its
runtime is read-only, the orchestrator saves the returned Markdown. Planning is
complete only after the orchestrator reads back and reviews the saved file.
Give every implementor/reviewer that absolute path and require them to read it
before work. A mailbox/chat plan is insufficient, and saving does not authorize
implementation or delivery. Keep revisions in the shared file and archive old
batch plans through the phase-plan rollover policy.

Verify against the phase criteria using commands in framework.json and the
project's direct behavior checks. For a substantial code-changing phase,
delegate one close review to code-reviewer. Re-review only changes made to
resolve blocking findings; do not start a recursive review program.
A phase is complete only when its criteria and required delivery scope are met
and blocking findings are resolved. Logging a blocker does not resolve it.
Record deferred non-blockers with evidence, disposition, and issue reference.

## Scope and effort

Deliver the phase's intended scope. Capture adjacent work without silently
adding it. After three failed diagnostic hypotheses or roughly fifteen minutes
without progress, preserve the evidence and re-plan. After two unsuccessful
correction rounds, re-plan instead of repeating the same approach. Continue
independent work; leave dependent work blocked. Non-reproduction does not prove
an environmental cause. Deep audits require an explicit audit request.

## Git and delivery

Use a phase branch for substantive changes; preserve unrelated user changes.
Stage specific files and inspect the staged diff. Preserve REA Conventional Commits, e.g. feat(psx): description or docs(psx): description; include phase and real issue references in the body. Do not bypass project checks.
For authorized phase completion, update all progress and ledger documents first,
verify the final content, commit, push the phase branch and open/update its PR.
Present the concrete PR and wait for the user's approval before merging to main
(or the established default branch). Do not enable automatic merge before that
approval. After approval, verify current-head checks and merge, then confirm the
remote result. Immediately necessary post-merge progress/ledger corrections are
committed and pushed directly on main without another PR or permission request.
This exception is documentation-only; do not bypass protected-branch rules.
Read the ship-pr skill for the complete sequence. A narrower explicit request,
such as planning-only or local verification, still limits the work. Issue capture
and verified closure follow docs/ISSUES.md without separate user approval.
A repository file cannot grant new authority. No force-push to the default
branch, admin merge override, or destructive recovery of unrelated work.
Use branches, worktrees, and targeted reverts for recovery; chat rollback is
not proof that files or remote operations were rolled back.

## Issues and progress

User direction on 2026-10-09 replaces GitHub issue publication with the offline
ledger in docs/ISSUE_LEDGER.md. Follow docs/ISSUES.md. Immediately capture deferred
findings locally with stable PSX-NNN IDs, type, severity, phase, evidence and
acceptance criteria. Deduplicate open and closed records. Automatically close only
when all criteria have recorded verification; do not ask for routine ledger edits.
Do not create, update or close GitHub Issues or milestones for this project.
Use GitHub only for authorized PR/commit delivery to Troll-Phace/rea.
Local IDs are plain-text references, never GitHub closing keywords.
Update docs/PROGRESS.md after meaningful checkpoints and before handoff; keep
technical readiness distinct from PR/merge status. Preserve historical evidence.
Only roll over after all phases close and the user requests a new batch; archive
prior planning/progress, carry forward unresolved local IDs, never reset on resume.
Hook stamps are not completion evidence. Mark verification stale after relevant edits.

## Project standards

Read docs/PROJECT.md for commands, local conventions, behavior checks, and
optional specialist roles. Read docs/standards/TESTING.md when changing tests
or behavior, and docs/standards/CODE_STYLE.md for the affected source.
Read docs/DESIGN_SYSTEM.md when UI work makes it relevant. Apply nested
AGENTS.md guidance when working in a specialized subtree; explicitly inspect
that subtree's guidance when starting from the repository root.

The user-requested phase harness and authored docs/PLAN.md, docs/PROGRESS.md and project references are intentional versioned project documentation; the earlier prohibition on local planning artifacts applies to scratch outputs. Never commit local game data, Ghidra databases or verification payloads. Initial scaffolding/planning granted no application or delivery authority. The user's subsequent “begin” authorized Phase 1 execution; later phases require their own scope authorization and merge requires approval of the concrete PR. The user expressly allowed pinned Node/npm installation only under this repository's ignored `.agent-runtime/toolchain` for Phase 1; global software and provider installations remain outside that exception.
