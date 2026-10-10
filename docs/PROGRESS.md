# PSX support progress

Batch: psx-support-2026-10. Active phase: Phase 1 (technical acceptance complete; PR/merge delivery pending). Scaffold status: complete and locally validated. Branch: `codex/psx-phase-1`, baseline `7aa4d768`. Technical acceptance and bounded close review passed; commit/push/PR preparation is next. Merge remains pending user approval of the concrete PR.

## Planning and implementation history

- Fork cloned at 7aa4d768; origin https://github.com/Troll-Phace/rea.git, default main.
- Existing REA instructions and skill preserved; phase harness adapted locally.
- User chose gpt-6.1-sol/high for retained implementation/review/triage roles; planner gpt-6-astra/low.
- Real prior REA open_binary on patched SLPS_020.20 returned unsupported binary format before import. Ghidra GUI and loader operate independently.

- Dedicated planner produced the reviewed five-phase docs/PLAN.md; at that planning checkpoint all phases remained planned.
- Astra/low produced the detailed shared [Phase 1 execution contract](active/phase-1-plan.md); the orchestrator saved it for all agents. Task IDs P1-00/P1-11/P1-12/P1-13/P1-21/P1-22/P1-90 refine PSX-001; no application task had started at that planning checkpoint.
- Read-only installed-loader source/manifest inspection identified candidate loader/language/options and concrete provenance, inferred-GP and GUI-dialog risks. These were static observations at planning time; actual import evidence is recorded in the final checkpoint below.
- Shared-plan persistence is now required in AGENTS.md, phase-plan/phase-implement skills, planner configuration and PROJECT.md. The planner writes only its assigned plan; a read-only runtime returns full Markdown for orchestrator persistence. All handoffs require saved-file review and the shared absolute path.
- Final planning/harness verification: configured scaffold validator passed; 14 framework helper tests passed; saved plan read back, 27 existing owned paths and the three state links verified; planner TOML parsed with Astra/low preserved; Git whitespace check passed. These checks do not establish application behavior, loader imports or fresh-client discovery.
- P1-00: branch `codex/psx-phase-1` created while preserving the harness; repository-local Node 24.18.0/npm 11.16.0 verified; `npm ci` installed 374 locked dependencies and dependency-install validation passed. Existing provider Java inventory is Temurin 25.0.4.1. P1-11/P1-12, P1-13 and P1-21 are delegated with the shared saved plan and disjoint file ownership.
- P1-11/P1-12 initial checkpoint: PSX parser/identity and explicit Ghidra/Hopper/IDA rejection implemented; 118 local tests across nine files pass. Initial compile failures exposed format/architecture correlation and existing generic subject/array consumers; fixes preserve PE/managed support limits and source values. `npm run build:cached` now passes all three tasks. Full static, boundary, real-loader and close-review evidence was pending at that checkpoint.
- P1-13 command correction: the existing runner rejects `test:local` for the listed filesystem boundary paths. The saved plan now uses `test:focused`; no runner changes. Test-discovery passed with 699 files exactly once at this checkpoint.
- Configured scaffold validator passed; 14 framework unit tests passed, including offline no-network, missing-ledger, truncation and path-confinement cases.
- SessionStart/SessionEnd helpers passed simulated event checks; this does not establish native lifecycle delivery or client discovery.
- Git whitespace checks passed; existing REA instructions and tool-design skill preserved.

## Final technical checkpoint — 2026-10-09

- P1-11/P1-12: pure PS-X EXE parser and format/architecture identity implemented; caller-selected DOS/database choices preserved. Exact magic precedes inferred artifact filenames. Ghidra/Hopper/IDA reject explicit PSX deep analysis before opening resources; `auto` may preserve neutral identity with no deep binding.
- P1-13: 57 focused filesystem and 11 focused MCP/schema/error tests passed; actual SDK schemas are validated under their declared draft2020-12 dialect. Backend/domain suites passed 118 tests; installation/managed regressions passed 50. Affected test restructuring and schema typing fixes passed their suites. All 699 test files are discovered exactly once.
- P1-21/P1-22: exact seven-case real synthetic macOS matrix passed on Ghidra 12.1.4/Temurin 25.0.4.1. See [versioned Phase 1 results](active/phase-1-results.md), [original contract](active/phase-1-plan.md) and [Astra research supplement](active/phase-1-loader-supplement.md). Report `docs/psx-local/loader-contract-runs/run-8keqyf/report.json`, SHA256 `692d534401d9fd7685025973614f2399c339a2bf7e36d77371ea6b2bef1628ff`; fixture/probe/463 extension-asset/core-MIPS hashes unchanged, native inspector closed, exact owned root removed, verified lineage empty.
- Measured outcome: mapping contents match the declared payload; FileBytes provenance is absent, SP context is unknown, declared fill is uninitialized and surrounding coverage differs by variant. Explicit RAM overrides fail despite a zero process exit. PSX-006 and PSX-007 block later production import/attestation; matching defaults and hashes do not close those gates.
- P1-90: one Sol6.1/high bounded code-reviewer completed with no new blocking or deferred findings. It independently checked the final report, current probe fingerprints, fixture oracle, four negative producer cases, ownership/cleanup and saved-plan harness. No recursive audit or later-phase work performed.
- Final source checks: `npm run build:cached`, `npm run check` (six tasks plus architecture guards; 487 existing warnings, zero errors), catalog generation/check and docs check passed. Configured harness validator and all 14 framework tests passed. Final documentation checks run before delivery; commit/PR identifiers are recorded after they exist.

## Pending

- User authorized Phase 1 with “begin” and then explicitly approved a repository-local Node 24.18.0/npm 11.16.0 installation exception under `.agent-runtime/toolchain`, after automatic approval review rejected the initial installation. Global software and provider installations remain unchanged; P1-00 prerequisites are complete.
- Phase 1 technical acceptance and review passed; PR/merge delivery remains pending. Later application phases, actual PSX public-provider support, Linux loader lane, local AC3 pilot and package/client integration remain unperformed and unauthorized.
- Final delivery checks use the verified local pinned toolchain; the ambient older toolchain is unchanged. PSX-001 remains in progress until all delivery criteria, including approved merge, are satisfied.
- New project-rooted client pilot for agent/skill discovery; hook definitions configured; automatic execution pending lifecycle/trust pilot.
- Skill-creator quick validation could not run because the current Python lacks PyYAML; configured repository harness validation covers its existing structural checks only. Planner write permissions and saved-file handoff discovery still require a fresh client pilot.

## Offline issue tracking

User selected local issue management on 2026-10-09. docs/ISSUE_LEDGER.md is canonical; PSX-001 through PSX-005 track the planned phases. issue_repository is null; no GitHub issue/milestone publication or closure is expected. This is an intentional workflow, not a blocker. PR delivery remains Troll-Phace/rea with user merge approval.

## Next action

Finalize documentation and intended staged content, commit/push `codex/psx-phase-1` and prepare its reviewable PR. Concrete PR approval is required before merge; Phase 2 is not authorized and requires a new plan accounting for PSX-006/PSX-007 and the measured register/fill/mapping limitations.
