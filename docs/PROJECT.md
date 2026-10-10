# REA PSX support project

## Purpose and scope

Add trustworthy PS-X EXE support to REA's existing CLI/MCP Ghidra workflow. This is a feature batch in the Troll-Phace/rea fork, upstream morluto/rea. Default branch main; initial source baseline 7aa4d768, package 6.3.0. User authorized Phase 1 implementation with “begin”; completion follows the phase PR workflow, with concrete PR approval before merge. Phase 1 is complete and merged through approved PR #1. The user authorized Phase 2 execution after review of its shared contract; Phase 2 technical acceptance and review passed; approved [PR #2](https://github.com/Troll-Phace/rea/pull/2) merged at `51a9f7311d631bbc06dd020f0f6a7cd30b9a8aa0` on 2026-10-10. Phase 2 is complete. Phases 3–5 remain unimplemented and unauthorized.

Repository: /Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/rea. Do not treat the parent AC3 workspace as this Git repository.

The local research baseline is the Load Word translation-patched Japanese AC3 images. Original inputs and extracted files live in the parent workspace, outside Git. Disc 1 boot executable is ../extracted/disc1/files/SLPS_020.20; known header load 0x80120000, payload 0x75000, entry 0x801255ac. These are local observations, not redistributable fixtures. Hash manifest is ../extracted/manifest.json. Never claim retail-original behavior from patched inputs.

## Stack and commands

TypeScript ESM, Node, Zod contracts, shared application layer, CLI/MCP adapters, Java Ghidra headless bridge, Vitest and boundary/conformance tests. Read CONTRIBUTING.md, docs/testing.md and docs/tool-design.md. REA owns its generated documentation workflow.

Pinned development toolchain: Node 24.18.0 (.nvmrc), npm 11.16.0 (packageManager). Scaffold host initially had Node 24.16.0/npm 11.13.0 and no dependencies. The user authorized pinned Node 24.18.0/npm 11.16.0 under ignored `.agent-runtime/toolchain`; locked dependencies are now installed. Prepend its `node_modules/.bin` to PATH for checks. Global software is unchanged.

- npm ci: install locked dependencies, prepare Husky; prerequisite to application checks.
- npm run build:cached: compile runtime and packaged skill.
- npm run check: full static check (Turbo typecheck/lint/format/knip/metadata plus architecture guards); framework verify command. This is not a substitute for behavior tests.
- npm run test:local -- PATH...: source tests; npm run test:focused -- PATH...: required built artifacts and selected tests.
- npm run lint: oxlint and module-boundary verification.
- npm run format:check: oxfmt check.
- npm run docs:check: generated documentation consistency.
- npm run verify:test-discovery: validate added tests are discovered.
- python3 scripts/framework/validate.py --configured: harness structure only.
- python3 -m unittest discover -s tests/framework -v: helper tests only.
  No dev server is relevant; framework dev command is null. Phase-specific checks and proposed scripts are specified in PLAN.md.

## Provider and delivery boundaries

Existing Ghidra 12.1.4 headless install: /opt/homebrew/Cellar/ghidra/12.1.4/libexec; PSX loader release 2026.10.03 installed under Ghidra/Extensions/ghidra_psx_ldr. Provider Java is Temurin 25. GUI launcher uses Java 21 and is a separate workflow. Phase 1 recognizes PS-X EXE identity and explicitly gates all deep providers before import. Neutral `auto` sessions can retain identity without a deep provider binding. GUI success does not prove REA support.

Target initial delivery on macOS/Linux with explicit host evidence. No Windows expansion, generic MIPS format support, ROM extraction, automatic overlay discovery, emulator automation or live GUI synchronization in this batch. Missing runtime bytes remain unknown. Source bytes immutable; temporary provider databases cleaned up; snapshots bound to source and analysis profile.

## Agents and hooks

Planner: phase-plan, gpt-6-astra / low, with writing limited by instructions to its assigned shared plan at `docs/active/phase-N-plan.md`. If the actual planner runtime is read-only, the orchestrator persists the complete returned contract. Planning handoff requires the saved file to be reviewed and linked from PLAN.md, PROGRESS.md and the local ledger; all implementors/reviewers receive and read its absolute path. Backend implementation, test engineering, bounded review and issue triage: gpt-6.1-sol / high, selected by user on 2026-10-09. Orchestrator model/effort inherit user session. Frontend role omitted because no UI implementation is planned. Existing rea-tool-design skill retained. Deep audit is opt-in only.

Agent routes match the published Codex config schema; actual project discovery requires a new chat rooted here. Project-local SessionStart and SessionEnd hooks use the documented schema; SessionEnd timeout is reduced from the draft five seconds to the supported three-second maximum. Hooks require client trust and a fresh-session pilot before claiming automatic execution. Run runtime.py context and session-end explicitly for smoke checks; no hook stamp proves delivery. References: https://learn.chatgpt.com/docs/hooks and https://learn.chatgpt.com/docs/config-schema.json (checked 2026-10-09). Read-only agent defaults and instructions do not override runtime permissions.

## GitHub

PR destination Troll-Phace/rea, never upstream by assumption. User selected offline issue tracking on 2026-10-09: docs/ISSUE_LEDGER.md is canonical, with stable PSX-NNN IDs. GitHub issue integration is intentionally disabled. Follow ISSUES.md for immediate local capture and evidence-based closure. Ledger first, relevant final-content checks, Conventional Commit, push, PR; user approval of concrete PR before merge. The requested harness and shared phase plans are versioned project documentation; scratch and raw evidence remain local and ignored. Preserve original REA rules and generated-output exclusions.
