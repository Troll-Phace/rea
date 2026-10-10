# PS-X EXE support — phased implementation plan

Status: Phase 1 implementation authorized by the user; later phases remain planned and unauthorized. Follow the phase delivery workflow through a reviewable PR; merging requires approval of that concrete PR. This document grants no new authority. Repository: `/Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/rea`; fork `Troll-Phace/rea`, baseline handoff `7aa4d768`, package `6.3.0`.

## Outcome and boundaries

Support validated PS-X EXE executables through REA's existing Ghidra provider on macOS and Linux, preserving immutable executable snapshots, ephemeral databases, shared CLI/MCP semantics, provenance, and deterministic provider binding. Complete means tested detection, loader availability and identity, deterministic import, independent mapping/entry evidence, useful analysis operations including MIPS delay slots, snapshot/schema/package coverage, documentation, and separate real-provider host evidence.

Excluded: disc extraction, automatic overlay discovery/loading, arbitrary MIPS executable formats, emulator automation/runtime claims, GUI database attachment/sharing, and Windows PSX expansion. Never modify the Java 21 GUI wrapper to accommodate the separate Java 25 headless provider. Never commit user game bytes, extracted assets, Ghidra projects, or evidence containing executable payloads.

The current scaffold's `framework.json` selects `npm run check`, `npm run test:local`, `npm run lint`, and `npm run format:check`. The user's explicit offline issue-tracking instruction governs this batch: `docs/ISSUE_LEDGER.md` is canonical, `framework.json` has `issue_repository: null` and `issue_tracking.mode: offline`. No GitHub issue publication, closure, or milestones are part of this workflow. PRs still target the fork and require user approval before merge.

## Proposed design contract

- Canonical format `ps-x-exe`; architecture family `mips`. Do not add MIPS machine IDs to ELF/PE parsers or expand other providers' architecture support.
- Detect the exact eight-byte `PS-X EXE` signature, independent of filename; no new user format hint.
- Parse a fixed `0x800`-byte header and little-endian unsigned fields: PC `0x10`, GP `0x14`, payload address/size `0x18/0x1c`, memory-fill address/size `0x28/0x2c`, stack base/offset `0x30/0x34`. These are the proposed supported interpretation to validate against the installed loader and documented format evidence in Phase 1, not a claim that all possible PS-X EXE producers obey stronger restrictions.
- Parser returns declared fields and bounded extents. Structural malformedness and unsupported import policy remain distinct. Exact-signature truncated headers, short declared payloads, and unsigned address extents that exceed `0xffffffff` are malformed. Zero payload, unaligned entry, entry outside the payload, and otherwise representable layouts that the supported loader/profile cannot honor are recognized but unsupported. Do not label these policy restrictions universally invalid PS-X EXE files.
- Compute extents with checked arithmetic: nonempty payload/fill uses `start + size - 1`; zero fill has no extent. Preserve stack base/offset separately. For nonzero stack base, checked `base + offset` must fit 32 bits; overflow is malformed for this supported interpretation. Zero stack base means unspecified initial stack: retain the offset as a declaration and do not infer SP. Zero GP is a declaration, not proof of usable register context.
- Keep trailing bytes visible but outside the declared payload. Preserve raw declarations and exact virtual addresses. Optional physical alias derivations must be labeled derivations and may never replace address identity.
- Loader availability is PSX-target-specific. Ordinary Ghidra availability must survive missing PSX support. No generic BinaryLoader fallback and no silent provider switch.
- Bind profile identity to effective Ghidra version, PSX loader identity/fingerprint, language/compiler, import options, and relevant analysis assets. Keep loader discovery/provider protocol out of domain code.
- Concrete loader class/name, language/compiler IDs, options, and measured mapping behavior are Phase 1 evidence gates. The installed extension directory alone proves none of them. The custom NativeAOT extension protocol is not a generic PSX plugin API.

## Repository evidence and ownership

Existing source paths inspected: `src/domain/binaryTarget.ts`, `binaryTargetTypes.ts`, `src/application/BinaryTargetResolver.ts`, `src/ghidra/GhidraProvider.ts`, `GhidraInstallation.ts`, `GhidraDoctor.ts`, `GhidraAnalysisProfile.ts`, `GhidraLauncher.ts`, `GhidraClientStartup.ts`, `GhidraClientTypes.ts`, `GhidraLoadImageAttest.ts`, `GhidraLoadImageValues.ts`, `GhidraFunctionValues.ts`, `bridge/ghidra/ReaGhidraBridge.java`, `src/domain/native/nativeLoadImage.ts`, `nativeInstruction.ts`, `src/domain/analysisSnapshot.ts`, `evidence.ts`, `artifactGraph.ts`, and the output contracts named below.

Existing relevant tests include `src/ghidra/GhidraLoadImageValues.test.ts`, `GhidraDosComLoadImage.test.ts`, `GhidraInstallation.test.ts`, `GhidraDoctor.test.ts`, `GhidraProvider.behavior.test.ts`, `tests/boundary/filesystem/binaryTarget.test.ts`, and `tests/boundary/providers/ghidra/ghidraLauncher.test.ts` and `ghidraClient.test.ts`. Existing skill source files are `skill-src/reverse-engineer-anything/references/native-and-artifacts.md` and `evidence-workflows.md`.

Follow `AGENTS.md`, `docs/architecture.mermaid`, `docs/tool-design.md`, `docs/testing.md`, and `CONTRIBUTING.md`. Generated `skills/`, catalogs, and local planning/evidence artifacts follow existing ignore/source ownership rules. Paths explicitly labeled Create below are proposals, not claims of existing files.

## Phase 1 — format contract and actual loader evidence

Detailed shared execution contract: [Phase 1 plan](active/phase-1-plan.md).
This contract refines the overview below and is the required input for all
Phase 1 implementors/reviewers. Detailed task IDs are P1-00, P1-11, P1-12,
P1-13, P1-21, P1-22 and P1-90; overview P1.1 maps to P1-11/P1-12/P1-13 and
P1.2 maps to P1-21/P1-22. Phase 1 technical acceptance and bounded review passed; [PR #1](https://github.com/Troll-Phace/rea/pull/1) is open; approved merge remains pending. [Measured results](active/phase-1-results.md) freeze loader facts and downstream blockers; [P1-21R](active/phase-1-loader-supplement.md) records the authorized research continuation.

Objective: recognize PSX coherently across domain/public identity without advertising provider support, and establish an exact real loader contract. Dependencies: implementation authority and pinned toolchain. Delivery endpoint: independently compiling/tested recognition with explicit provider rejection; no claim of usable PSX analysis.

### P1.1 — parser and coherent identity propagation

Owner: backend-dev.

Owned files: Create `src/domain/psxExe.ts`, `src/domain/psxExe.test.ts`; edit `src/domain/binaryTarget.ts`, `binaryTargetTypes.ts`, `src/application/BinaryTargetResolver.ts`, `src/domain/analysisSnapshot.ts`, `evidence.ts`, `artifactGraph.ts`, `src/contracts/toolOutputSchemaPrimitives.ts`, `toolOutputSchemaGroups.ts`, and existing domain/boundary identity tests. Edit provider rejection diagnostics/tests only as required to make the new recognized target explicitly unsupported until Phase 2.

Ordered work:

1. Implement a pure Result-returning header parser; it performs no I/O and has no Ghidra types. Distinguish malformed structure from recognized-but-unsupported profile policy in its result/reason representation. Map this through existing target-error machinery without inventing a broad unrelated error framework.
2. Validate exact signature/header availability, declared payload availability against actual file size, and checked payload/fill/stack arithmetic. Parser input must permit a bounded header probe plus actual file size; do not require loading the full executable for detection.
3. Apply the initial import policy (nonempty payload, aligned PC within declared payload) with explicit unsupported reasons. Preserve trailing bytes and optional raw fields.
4. Add canonical format/family identities and every necessary executable identity/schema consumer in the same phase. Search all narrow architecture/format unions and exhaustive switches; update applicable generic consumers, not unrelated managed/platform-specific schemas.
5. Preserve rejection in Ghidra and other deep providers until Phase 2. A recognized file may be classified correctly but may not enter a usable unsupported session.
6. Add snapshot/evidence identity tests now, so Phase 1 does not depend on Phase 4 to compile or serialize correctly.

Edge cases: full signature followed by truncated header, declared payload exceeding file, entry at end boundary, high-bit addresses, payload/fill wraparound, stack overflow, zero fill, zero stack base with nonzero offset, trailing bytes, malformed versus unsupported diagnostic distinction, generic MIPS ELF remaining unsupported.

Checks: use the exact source and focused-boundary commands in the shared Phase 1 plan; the source runner does not accept filesystem boundary paths. Run `npm run check` and the framework lint/format gates. Expected: all pass, existing formats unchanged, PSX identity serializes but deep provider refuses it explicitly.

### P1.2 — measured loader contract and redistributable fixture

Owner: test-engineer; loader inventory can run alongside P1.1, fixture layout freezes with parser contract.

Owned files: Create `tests/conformance/ghidra/psx-exe-fixture.mjs`; create local evidence document `docs/psx-local/loader-contract.md` under established local planning ignore policy. No runtime source edits in this task.

Inspect `/opt/homebrew/Cellar/ghidra/12.1.4/libexec/Ghidra/Extensions/ghidra_psx_ldr` manifest/JAR and the selected provider installation. Establish exact loader identity, language/compiler, import options, enabled analyzers/assets, extension compatibility, and entry/register behavior. Generate a tiny original executable; import into a disposable headless project. Record actual source offsets, original FileBytes provenance, split/alias/extra blocks, entry points, GP/SP context, and payload mutations if any. Inventory installation and user extension discovery locations and duplicate-candidate behavior.

Acceptance: real headless import with recorded Ghidra/Java/loader/host/digest identity and exact arguments; no unchanged-source violation; awaited cleanup. Document loader-derived behavior separately from independent header expectations. Missing/incompatible loader or inability to establish source provenance is a named blocker for dependent design, not permission to substitute a raw loader. This probe proves loader behavior only, not public REA support. Linux findings remain separate.

Phase gate: P1.1 passes all source gates; P1.2 settles the concrete loader contract. If a supported policy conflicts with measured loader behavior, resolve and document the narrower supported policy before Phase 2; do not leave implementors to improvise.

## Phase 2 — target-specific availability and deterministic import

Objective: open/close valid PSX through real REA/Ghidra with stable identity. Dependencies: Phase 1 accepted, PSX-006 supported-option replan and effective selected-asset identity; account for the measured register/fill/mapping limits. Defaults-only research does not establish production admission. Delivery endpoint: synthetic real open/close with honest capability scope.

### P2.1 — PSX loader inspection and profile

Owner: backend-dev.

Owned files: Create `src/ghidra/GhidraPsxLoader.ts` and `.test.ts`; edit `GhidraInstallation.ts`, `GhidraDoctor.ts`, `GhidraAnalysisProfile.ts`, `GhidraProvider.ts`; extend existing installation/doctor/provider tests.

Implement target-specific available/missing/incompatible/ambiguous states based on the selected installation. Record relevant manifest identity and deterministic fingerprints of code/assets affecting import/analysis; do not snapshot ambient environment. Use discovery semantics proven in P1.2. An unresolved duplicate loader is a PSX-specific rejection. Never disable ordinary Ghidra targets for missing PSX support. Admit mips only for ps-x-exe on macOS/Linux; explicit Windows rejection remains. Canonical profile includes fixed loader/language/compiler/options, payload interpretation version, and PSX evidence/instruction semantics versions. Effective asset changes must invalidate profile identity.

Acceptance: missing/ambiguous/incompatible fixtures give useful target-specific diagnostics; ordinary Ghidra availability stays passing; no environment persistence. Existing test command: `npm run test:local -- src/ghidra/GhidraPsxLoader.test.ts src/ghidra/GhidraInstallation.test.ts src/ghidra/GhidraDoctor.test.ts src/ghidra/GhidraProvider.behavior.test.ts`.

### P2.2 — launch transport and startup agreement

Owner: backend-dev, after P2.1.

Owned files: edit `GhidraLauncher.ts`, `GhidraClientStartup.ts`, `GhidraClientTypes.ts`, `GhidraProvider.ts`, and `bridge/ghidra/ReaGhidraBridge.java`; extend existing launcher/client boundary tests.

Transport one discriminated import configuration, avoiding contradictory DOS/PSX flags. Build exact arguments from the accepted loader contract. Compare imported language/compiler/executable facts against resolved profile before usable-session success. Preserve snapshot ownership, cancellation, startup diagnostics and cleanup. Do not mutate original bytes or GUI projects. If an added packaged pre-import script is actually necessary from P1.2, declare its creation path and package ownership before implementation; default design requires no additional script.

Acceptance: no import starts for missing loader; import/profile disagreement fails and cleans up; synthetic real open/close retains source digest; existing DOS/native launches stay unchanged. Existing checks: `npm run test:local -- tests/boundary/providers/ghidra/ghidraLauncher.test.ts tests/boundary/providers/ghidra/ghidraClient.test.ts`; all framework gates.

## Phase 3 — independent PSX memory and entry evidence

Objective: make verified mean declared and examined coverage. Dependencies: Phase 2 and an explicit PSX-007 producer-provenance adaptation plan; equal mapped bytes cannot establish source offsets. Delivery endpoint: independently checked real synthetic load image, with unsupported/unknown facts explicit.

### P3.1 — PSX result variant and attestation

Owner: backend-dev.

Owned files: edit `src/domain/native/nativeLoadImage.ts`, `src/ghidra/GhidraLoadImageAttest.ts`, `bridge/ghidra/ReaGhidraBridge.java`; Create `src/ghidra/GhidraPsxLoadImageValues.ts` and `.test.ts`. Update corresponding producer/schema tests in this phase, not later.

Add a PSX-specific verified/mismatch result alongside existing DOS JSON shapes: format, target digest, header/payload/trailing byte counts, declared payload extent and entry, raw GP/fill/stack declarations, observations, individual expected/observed checks, coverage and limitations. Never force DOS segment fields onto PSX.

Attest from the immutable source snapshot independently of the bridge: digest/source identity; payload extent; full file-backed coverage starting at offset 0x800; no gaps/conflicting overlaps/duplicate claimed coverage; mapped-byte hashes; declared external entry and mapped instruction location; measured GP/SP facts only where actually available. Accept valid split blocks rather than coupling to block names. Classify auxiliary initialized/uninitialized RAM, hardware, BIOS, aliases and fill areas separately. Zero-filled memory cannot count as file-backed payload. Verify fill/stack semantics only where independently supported by declarations and measured observations; otherwise retain unknown with limitations.

A contradiction produces mismatch. Missing provenance must not become verified simply because bytes match. Overall verified may apply only to explicitly enumerated successful coverage; required payload/source/entry checks must all succeed. Optional unobserved runtime/register facts stay unknown. Neither profile identity nor attestation proves runtime correctness.

Acceptance: independent semantic mutations to start, source offset, digest, payload bytes, entry, register facts, and coverage defeat appropriate checks; valid split mappings pass; trailing bytes do not enter payload. Real synthetic result succeeds within stated coverage. Existing command: `npm run test:local -- src/ghidra/GhidraPsxLoadImageValues.test.ts src/ghidra/GhidraLoadImageValues.test.ts src/ghidra/GhidraDosComLoadImage.test.ts`; framework gates.

## Phase 4 — MIPS operations, delay slots, and public parity

Objective: useful existing queries without x86-derived assumptions or unsupported runtime claims. Dependencies: Phase 3; Phase 1 already completed generic identity propagation. Delivery endpoint: complete source/boundary contracts and real synthetic operation assertions ready for full public lane.

### P4.1 — decoded instruction and function semantics

Owner: backend-dev.

Owned files: edit `src/domain/native/nativeInstruction.ts`, `bridge/ghidra/ReaGhidraBridge.java`, `src/ghidra/GhidraFunctionValues.ts` only if producer validation requires changes; extend PSX fixture; Create `scripts/lib/real-ghidra-psx-instruction-flow.mjs` and focused contract tests beside the owning domain/provider.

Add optional structured delay-slot evidence for compatibility: queried-instruction-in-slot status, decoded delay-slot depth, and measured slot addresses where obtainable. Null is unknown; zero is measured absence. Do not infer execution order from sequential addresses alone. Prefer decoded RETURN evidence before generic jump classification when present; never classify return solely by mnemonic. Preserve listing/p-code sources as classification evidence.

Fixture includes direct jal with non-NOP slot, conditional branch, jump, jr ra, unresolved jalr, known string/data references, interior/misaligned addresses, and function tail delay-slot coverage. Assert procedure inventory, exact-address lookup, disassembly, decompilation, dossier, incoming/outgoing references, call targets, and instruction queries. Do not require a specific unstable decompiler text; require meaningful output and correct identity when available. Real decompile failures are explicit failures/limitations, not invented C. Completeness refers to examined static body/reference coverage only.

Acceptance: slot belongs to observed function body where Ghidra reports it; return and indirect-call classifications match measured decoder evidence; not-instruction-boundary/data/outside-memory states retain correct distinctions; non-MIPS regressions pass. Version profile semantics when output interpretation changes.

### P4.2 — CLI/MCP schemas and snapshots

Owner: backend-dev for producer/contracts; test-engineer for tests after contract freeze.

Owned files: edit `src/contracts/sessionToolContracts.ts` and applicable output schemas only for operation additions/documentation; extend existing domain snapshot/evidence tests; Create `tests/boundary/mcp/ghidraPsxMcp.test.ts`, `tests/boundary/cli/ghidraPsxCli.test.ts`; reuse existing `tests/boundary/mcp/ghidraMcpHarness.ts`.

Exercise equivalent CLI/MCP identity, load-image/instruction results, error semantics, provider binding, and snapshot round-trip. Same digest/provider/profile reopens successfully. Changed digest, loader fingerprint, options, or semantic version rejects snapshot reuse atomically. Preserve existing old/non-PSX valid snapshots wherever intentionally compatible. Validate JSON Schemas after MCP SDK conversion against actual dialect/client behavior. Audit Phase 1 propagation for omissions without deferring required type compatibility to this phase.

Acceptance: focused new tests and existing Ghidra routing/evidence/snapshot tests pass; `npm run mcp-catalog:generate`; `npm run mcp-catalog:check`; framework gates. Generated catalogs are regenerated from source, not manually edited. Fake-provider tests prove boundary behavior only.

## Phase 5 — real public workflows, local AC3 smoke, package and docs

Objective: establish actual support with separated evidence lanes. Dependencies: Phase 4. Delivery endpoint: supported host/version matrix verified, packaging complete, source unchanged, no hidden live gates.

### P5.1 — real synthetic CLI/MCP lane

Owner: test-engineer.

Owned files: Create `scripts/verify-real-ghidra-psx.mjs`; edit `package.json` to add proposed `verify:ghidra:psx`; extend `tests/conformance/ghidra/README.md`; reuse existing real-Ghidra lifecycle/boundary helpers where appropriate.

Proposed command after creation: `npm run verify:ghidra:psx`. It builds the runtime and runs generated original fixtures through public compiled CLI and MCP, checking mapping/instruction/function/reference assertions, snapshot lifecycle, cancellation, source immutability, and awaited cleanup. Run independently on macOS and Linux. Record runtime, host, Ghidra, Java, loader/assets fingerprints, target hashes, commands, and outcomes. Missing Linux execution remains a named pending support gate, never inferred from macOS or fake providers.

### P5.2 — bounded local AC3 smoke

Owner: test-engineer; after synthetic real lane succeeds on the local host.

Owned file: Create `scripts/verify-local-ghidra-psx.mjs`, requiring explicit `--binary`; no hardcoded user path or game-derived fixture.

Proposed command: `node scripts/verify-local-ghidra-psx.mjs --binary /Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/extracted/disc1/files/SLPS_020.20`.

Re-read current digest/header. Handoff observations are load 0x80120000, payload 0x75000, entry 0x801255ac; report disagreement before applying fixed expected assertions. Run open, load-image attestation, entry instruction/function/disassembly, one bounded decompile, one bounded reference query, snapshot reopen, close and unchanged-source digest. Preserve partial/unavailable analysis honestly. This proves one local Load Word patched boot image, not all AC3 executables or game completeness. Do not extract discs, auto-load overlays, launch emulator, or modify bytes.

### P5.3 — packaging and documentation

Owner: backend-dev after behavior stabilizes.

Owned files: Create `docs/ghidra-psx.md`; edit `README.md`, `docs/ghidra-provider.md`, `docs/testing.md`, existing `skill-src/reverse-engineer-anything/references/native-and-artifacts.md` and `evidence-workflows.md`; edit `scripts/verify-package.mjs` and `package.json` package assets only when new runtime resources require it.

Document bring-your-own loader setup, exact verified matrix, useful diagnostics, memory/source evidence scope, virtual addresses, delay slots, snapshot identity, unsupported overlays/runtime/Windows behavior, and local-only immutable workflow. Existing commands: `npm run build:cached`, `npm run verify:package`, `npm run docs:check`, `npm run check`, `npm run test:local -- <changed relevant test paths>`, `npm run lint`, `npm run format:check`. Do not edit ignored generated skill/catalog artifacts as source or redistribute third-party loader assets without a separate deliberate decision.

## Delegation, evidence, and delivery

Roles: backend-dev, test-engineer, code-reviewer, issue-triage, each user-selected gpt-6.1-sol/high. Planner remains separate. Do not introduce additional agents. P1 parser and loader inventory may proceed independently; backend runtime phases are ordered. Test-engineer prepares independent fixture expectations after format freeze. Only one agent edits the Java bridge or a shared contract at a time. Phase 3 attestor and Phase 4 contract planning can overlap, but implementation integrates sequentially at passing checkpoints. Review follows implementation; triage may run read-only alongside review.

Each task handoff returns exact files/task IDs, decisions, commands/results, fixture and target identities, evidence depth, limitations, outstanding risks and cleanup outcomes. The reviewer checks malformed/unsupported distinctions, source provenance, delayed flow, snapshot invalidation, source immutability, error handling, cleanup, and regressions. Shared source dependencies must compile at every phase endpoint, even when later capabilities remain unsupported.

Local issue mapping in `docs/ISSUE_LEDGER.md`: PSX-001 — Phase 1 recognition and loader contract; PSX-002 — Phase 2 deterministic import; PSX-003 — Phase 3 independent attestation; PSX-004 — Phase 4 analysis and public API parity; PSX-005 — Phase 5 real verification, package and docs. These records already exist as open, planned entries; maintain their linked task IDs, scope, dependencies, owner, acceptance criteria and required closure evidence. Allowed states are pending, open, in-progress, blocked and closed. Move an entry to closed only when its required acceptance and delivery evidence is recorded; retain unavailable live gates explicitly. Triage records verified deferred defects in this local ledger with the next PSX ID, evidence, impact and done criteria. There is no remote issue or milestone gate. Reference local IDs as plain text in commits/PRs; never use GitHub closing keywords for these IDs.

For each future authorized implementation phase: update progress and local issue-ledger wording first; run final-content verification; create Conventional Commit, push and PR; obtain required user PR approval; merge only after that approval; verify final merged SHA and reconcile status. Approval to scaffold/plan is not approval for implementation or delivery now. Keep synthetic, boundary, macOS real-provider, Linux real-provider, local AC3 and packaged-artifact evidence distinct.

Pinned toolchain is Node 24.18.0/npm 11.16.0; handoff reports Node 24.16/npm 11.13 and dependencies absent. Establish pinned versions and `npm ci` only once implementation authority exists; baseline checks are currently unrun. Read installed Turborepo documentation before altering its configuration; this plan requires no such change.

## Risks and next action

Loader discovery/class identity and effective options are Phase 1 blockers, not guessed constants. Loss of FileBytes provenance requires explicit unsupported coverage or a producer-boundary fix. Relevant SDK assets may alter analysis and must participate in profile identity. Delay-slot/p-code behavior requires actual synthetic decoding. Linux evidence is unavailable until run. The AC3 smoke may expose decompiler limitations without implying payload import failure.

Next action: obtain implementation authority for Phase 1, then establish the pinned toolchain and execute P1.1/P1.2. Do not declare any implementation or live gate complete from this planning document.
