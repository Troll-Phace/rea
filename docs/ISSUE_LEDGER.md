# PSX issue ledger

Canonical offline ledger. Batch psx-support-2026-10. Next ID: PSX-009.
No GitHub issue numbers are assigned. Phase 1 is complete and merged through PR #1; PSX-001 is closed. Phase 2 execution is authorized; PSX-002 is technically accepted with [PR #2](https://github.com/Troll-Phace/rea/pull/2) open and user merge approval pending; PSX-006 is closed by the verified default-only production policy. PSX-007 remains a Phase 3 blocker; Phases 3–5 remain planned and unauthorized.

| ID      | Type    | Severity | Status      | Phase   | Title                                               |
| ------- | ------- | -------- | ----------- | ------- | --------------------------------------------------- |
| PSX-001 | feature | high     | closed      | 1       | Format and loader contract                          |
| PSX-002 | feature | high     | in-progress | 2       | Deterministic Ghidra PSX import                     |
| PSX-003 | feature | high     | open        | 3       | Independent memory and entry evidence               |
| PSX-004 | feature | medium   | open        | 4       | MIPS queries and public contract parity             |
| PSX-005 | test    | high     | open        | 5       | Real-provider, package and local acceptance         |
| PSX-006 | bug     | high     | closed      | 2       | Installed PSX RAM option value-class mismatch       |
| PSX-007 | feature | high     | open        | 3       | Installed PSX loader lacks original file provenance |
| PSX-008 | test    | low      | open        | Backlog | PSX startup diagnostic truncation coverage gap      |

## PSX-001 — Format and loader contract

- Status: closed; type: feature; severity: high; phase: 1.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: parser/identity and deep-provider rejection implemented and verified. [Phase 1 results](active/phase-1-results.md) records exact checks, final seven-case macOS synthetic Ghidra matrix, actual loader/asset/report digests and verified cleanup. [Shared plan](active/phase-1-plan.md) and [research supplement](active/phase-1-loader-supplement.md) remain the execution contract. One bounded close review found no new blockers.
- Dependencies: pinned toolchain established with explicit repository-local user authorization; technical gates passed. Approved PR #1 merge verified; all closure criteria satisfied.
- Done-criteria: Validated parser and identity contracts; negative format cases; measured loader contract from synthetic real Ghidra import; Phase 1 exact checks and delivery satisfied.
- Tasks and exact verification contract: [shared Phase 1 plan](active/phase-1-plan.md), P1-00/P1-11/P1-12/P1-13/P1-21/P1-22/P1-90; overview in PLAN.md. Measured loader facts and downstream blockers are frozen in the versioned results; production defaults/profile and source-backed attestation remain future gates.
- Closure evidence/date/commit/PR: technical acceptance recorded 2026-10-09; final report SHA256 `692d534401d9fd7685025973614f2399c339a2bf7e36d77371ea6b2bef1628ff`. Implementation commit `0a8b033ac7bbd2f6e6a5f8f48b55504463f3f000`; [PR #1](https://github.com/Troll-Phace/rea/pull/1) merged at `7fdb2657cb9839e56272763a3d1a0e19fd5041d6` on 2026-10-09 (2026-10-10T03:02:01Z), after user approval. Verified current head `920fe67ced432fbe405181f15a17d446030f3492`, clean merge requirements and passing `npm run check`; GitHub merged state and remote/local main synchronization confirmed. Closed 2026-10-09; downstream PSX-006/PSX-007 remain open.

## PSX-002 — Deterministic Ghidra PSX import

- Status: in-progress; type: feature; severity: high; phase: 2.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: Phase 2 planning complete; Astra/low saved the [shared Phase 2 contract](active/phase-2-plan.md), read back and reviewed by the orchestrator against `3e36f98d10d3a631ed134ae3b4ff4b2d05c1e168`. It specifies default-only RAM policy, target-specific inspection, canonical asset/profile identity, before/after observed startup agreement, inventory-only queries and scoped real-host verification. P2-11/P2-12 implement target-specific inspection, default-only import and strict observed startup agreement. Final source and focused boundary checks pass; the macOS synthetic production matrix passed nine imports and four policy refusals with stable source/asset identity and exact cleanup. See [Phase 2 results](active/phase-2-results.md). Final static/docs/package checks and one bounded close review passed; PR/approved-merge delivery remains pending. Preserved timing, path and verifier failures remain historical evidence.
- Dependencies: Phase 1 accepted; PSX-006 measured RAM-option defect requires a deterministic supported configuration and production profile replan. Default-only research does not close this gate. Effective duplicate analyzer selection must participate in fingerprint decisions. Account explicitly for missing SP context, uninitialized declared fill and variant-dependent surrounding mapping before admission.
- Done-criteria: Target-specific loader diagnostics, stable profile identity, supported-host admission and real synthetic open/close verified; Phase 2 checks and delivery satisfied.
- Tasks and exact verification contract: [shared Phase 2 plan](active/phase-2-plan.md), P2-00/P2-11/P2-12/P2-21/P2-22/P2-90; overview in PLAN.md. User authorized execution after planning; branch `codex/psx-phase-2`. PSX-006 closed only after its actual production criteria passed; PSX-007 remains a Phase 3 blocker.
- Closure evidence/date/commit/PR: technical acceptance passed 2026-10-10, final report SHA-256 `68936261cfdc08b7cce99a1466aa85bb8e168ccf0ae1fce57926f3f0c6b97cd8`; bounded review found no new source findings. Implementation commit `a625ac9186e274a33873646674bcf7fb5cd9a896`; [PR #2](https://github.com/Troll-Phace/rea/pull/2) is open with normal commit/push hooks passed and no remote checks advertised. User approval and verified merge remain pending, so this record remains in progress.

## PSX-003 — Independent memory and entry evidence

- Status: open; type: feature; severity: high; phase: 3.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 2 now admits the verified default-only PSX import subset, while source-backed attestation and function/instruction semantics remain unavailable. No implementation of this later phase is claimed.
- Dependencies: Phase 2 accepted; PSX-007 measured absence of FileBytes must be resolved by a planned producer-boundary provenance contract before verified source-backed attestation.
- Done-criteria: Payload coverage, source offsets, entry/context and contradictions independently checked; mutation tests and real evidence pass; Phase 3 delivery satisfied.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-006 — Installed PSX RAM option value-class mismatch

- Status: closed; type: bug; severity: high; phase: 2; owner: orchestrator/provider implementor.
- Evidence: actual synthetic macOS Ghidra 12.1.4/Temurin 25.0.4.1 run `docs/psx-local/loader-contract-runs/run-2iooT6/report.json`, log `1-baseline-explicit-noanalysis.log`: `-loader-ramStart 0x80000000 -loader-ramSize 0x200000` fails with expected `psx.PsxBaseChooser` versus actual `java.lang.String`. Installed source confirms constructor/advertised value-class disagreement. Ghidra exits zero despite import failure. Loader JAR SHA256 `481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`; report SHA256 `70315521552048711c8f93538280b54e4073c2142d22f139a5a4c7339d0d213d`.
- Impact: planned explicit RAM transport cannot be treated as usable or deterministic; exit status alone can misreport import success.
- Disposition: Phase 1 failure preserved. The [Phase 2 contract](active/phase-2-plan.md) replaces the unusable override transport with an explicit default-only KSEG0 2 MiB policy, rejects layouts requiring other RAM settings, and validates independently observed effective facts. The third-party override defect remains documented; no installation patch was applied.
- Done-criteria: supported unattended production import configuration is explicitly planned, implemented and verified with actual import/observer completion, effective options/profile identity, source integrity and awaited cleanup. If RAM overrides remain unsupported, target-specific policy must refuse layouts requiring them and document that limit. Do not patch third-party installations as an implicit workaround.
- Closure evidence/date/commit/PR: closed 2026-10-10. [Phase 2 results](active/phase-2-results.md) record nine actual production imports, omitted RAM options, observed base/size/defaults, source/profile/asset agreement, exact cleanup and verified empty lineage. Report SHA-256 `68936261cfdc08b7cce99a1466aa85bb8e168ccf0ae1fce57926f3f0c6b97cd8`. Final 171 source tests, 101 focused boundary tests (one Windows skip), TypeScript/static/docs/package gates and bounded close review passed. Implementation commit `a625ac9186e274a33873646674bcf7fb5cd9a896`, [PR #2](https://github.com/Troll-Phace/rea/pull/2) open. This closes the REA production-policy criteria; approved-merge delivery is tracked separately by PSX-002.

## PSX-007 — Installed PSX loader lacks original file provenance

- Status: open; type: feature; severity: high; phase: 3; owner: orchestrator/provider implementor.
- Evidence: actual automatic baseline observation in `docs/psx-local/loader-contract-runs/run-2iooT6/report.json` records an empty FileBytes collection while mapped payload hash matches independently generated source bytes. Same installed loader identity as PSX-006. Source before/after digests match; workspace removal and empty verifier lineage were verified.
- Final confirmation: all seven cases in `run-8keqyf/report.json` have empty before/after FileBytes collections; see the versioned results/report digest above.
- Impact: byte equality establishes measured mapping content, but cannot establish original file offsets/source-backed mapping coverage for promised independent attestation.
- Disposition: deferred from Phase 1 measurement; blocks PSX-003 verified source-backed coverage. Separate from the already planned attestation umbrella because this is a demonstrated producer capability gap.
- Done-criteria: an explicit producer-boundary adaptation/evidence contract is planned and verified using actual source provenance, mapped coverage and independent source-offset/digest mutations. Missing provenance must remain unsupported/unknown, and matching bytes alone must never satisfy verified attestation.
- Closure evidence/date/commit/PR: none.

## PSX-004 — MIPS queries and public contract parity

- Status: open; type: feature; severity: medium; phase: 4.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 2 now admits the verified default-only PSX import subset, while source-backed attestation and function/instruction semantics remain unavailable. No implementation of this later phase is claimed.
- Dependencies: Phase 3 accepted.
- Done-criteria: Delay-slot and reference evidence truthful; CLI/MCP and snapshots preserve PSX identities; Phase 4 checks and delivery satisfied.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-005 — Real-provider, package and local acceptance

- Status: open; type: test; severity: high; phase: 5.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 2 now admits the verified default-only PSX import subset, while source-backed attestation and function/instruction semantics remain unavailable. No implementation of this later phase is claimed.
- Dependencies: Phase 4 accepted.
- Done-criteria: Synthetic public CLI/MCP lanes, declared-host coverage, local patched-AC3 smoke, package/docs and final delivery gates satisfied; missing coverage explicitly blocks corresponding claims.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-008 — PSX startup diagnostic truncation coverage gap

- Status: open; type: test; severity: low; phase: Backlog; owner: orchestrator/test engineer.
- Evidence: `src/ghidra/GhidraClient.ts` constructs `ProviderProcessSupervisor` without `maxDiagnosticBytes` in both launch paths. `src/process/ProviderProcess.ts` captures complete streams when that optional budget is absent, so the PSX `diagnosticTruncated` rejection guard cannot be exercised through the existing Client seam. The process-level boundary test `tests/boundary/process/providerProcessOutput.test.ts` verifies capped capture and complete draining with a configured budget; it does not establish the PSX startup negative. The Phase 2 timing correction exposes this test-coverage gap.
- Impact: dynamic PSX-specific truncation rejection is unverified. Normal complete-stream startup and the other missing/contradictory report failures remain independently tested; no observed production failure is attributed to truncation.
- Disposition: nonblocking deferred coverage work. Preserve complete-stream behavior and the fail-closed guard; do not invent an arbitrary production capture cap only to activate a test.
- Done-criteria: add a meaningful production-boundary injection or independently justified capture policy that exercises the PSX startup rejection for truncated diagnostics, with retained cleanup and non-PSX regression coverage. Record the exact passing test and clarify its relationship to process-level capacity coverage.
- Closure evidence/date/commit/PR: none.
