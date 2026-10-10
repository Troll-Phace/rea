# PSX issue ledger

Canonical offline ledger. Batch psx-support-2026-10. Next ID: PSX-008.
No GitHub issue numbers are assigned. Phase 1 technical acceptance and review passed; PR #1 is open; approved merge remains pending. Later phases remain planned and unauthorized.

| ID      | Type    | Severity | Status      | Phase | Title                                               |
| ------- | ------- | -------- | ----------- | ----- | --------------------------------------------------- |
| PSX-001 | feature | high     | in-progress | 1     | Format and loader contract                          |
| PSX-002 | feature | high     | open        | 2     | Deterministic Ghidra PSX import                     |
| PSX-003 | feature | high     | open        | 3     | Independent memory and entry evidence               |
| PSX-004 | feature | medium   | open        | 4     | MIPS queries and public contract parity             |
| PSX-005 | test    | high     | open        | 5     | Real-provider, package and local acceptance         |
| PSX-006 | bug     | high     | open        | 2     | Installed PSX RAM option value-class mismatch       |
| PSX-007 | feature | high     | open        | 3     | Installed PSX loader lacks original file provenance |

## PSX-001 — Format and loader contract

- Status: in-progress; type: feature; severity: high; phase: 1.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: parser/identity and deep-provider rejection implemented and verified. [Phase 1 results](active/phase-1-results.md) records exact checks, final seven-case macOS synthetic Ghidra matrix, actual loader/asset/report digests and verified cleanup. [Shared plan](active/phase-1-plan.md) and [research supplement](active/phase-1-loader-supplement.md) remain the execution contract. One bounded close review found no new blockers.
- Dependencies: pinned toolchain established with explicit repository-local user authorization; technical gates passed. PR #1 is open; approved merge remains pending.
- Done-criteria: Validated parser and identity contracts; negative format cases; measured loader contract from synthetic real Ghidra import; Phase 1 exact checks and delivery satisfied.
- Tasks and exact verification contract: [shared Phase 1 plan](active/phase-1-plan.md), P1-00/P1-11/P1-12/P1-13/P1-21/P1-22/P1-90; overview in PLAN.md. Measured loader facts and downstream blockers are frozen in the versioned results; production defaults/profile and source-backed attestation remain future gates.
- Closure evidence/date/commit/PR: technical acceptance recorded 2026-10-09; final report SHA256 `692d534401d9fd7685025973614f2399c339a2bf7e36d77371ea6b2bef1628ff`. Implementation commit `0a8b033ac7bbd2f6e6a5f8f48b55504463f3f000`; [PR #1](https://github.com/Troll-Phace/rea/pull/1) open. Still in progress pending approved merge; no closure claimed.

## PSX-002 — Deterministic Ghidra PSX import

- Status: open; type: feature; severity: high; phase: 2.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 1 now recognizes PSX identity but still rejects deep-provider import. No implementation of this later phase is claimed.
- Dependencies: Phase 1 accepted; PSX-006 measured RAM-option defect requires a deterministic supported configuration and production profile replan. Default-only research does not close this gate. Effective duplicate analyzer selection must participate in fingerprint decisions. Account explicitly for missing SP context, uninitialized declared fill and variant-dependent surrounding mapping before admission.
- Done-criteria: Target-specific loader diagnostics, stable profile identity, supported-host admission and real synthetic open/close verified; Phase 2 checks and delivery satisfied.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-003 — Independent memory and entry evidence

- Status: open; type: feature; severity: high; phase: 3.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 1 now recognizes PSX identity but still rejects deep-provider import. No implementation of this later phase is claimed.
- Dependencies: Phase 2 accepted; PSX-007 measured absence of FileBytes must be resolved by a planned producer-boundary provenance contract before verified source-backed attestation.
- Done-criteria: Payload coverage, source offsets, entry/context and contradictions independently checked; mutation tests and real evidence pass; Phase 3 delivery satisfied.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-006 — Installed PSX RAM option value-class mismatch

- Status: open; type: bug; severity: high; phase: 2; owner: orchestrator/provider implementor.
- Evidence: actual synthetic macOS Ghidra 12.1.4/Temurin 25.0.4.1 run `docs/psx-local/loader-contract-runs/run-2iooT6/report.json`, log `1-baseline-explicit-noanalysis.log`: `-loader-ramStart 0x80000000 -loader-ramSize 0x200000` fails with expected `psx.PsxBaseChooser` versus actual `java.lang.String`. Installed source confirms constructor/advertised value-class disagreement. Ghidra exits zero despite import failure. Loader JAR SHA256 `481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`; report SHA256 `70315521552048711c8f93538280b54e4073c2142d22f139a5a4c7339d0d213d`.
- Impact: planned explicit RAM transport cannot be treated as usable or deterministic; exit status alone can misreport import success.
- Disposition: deferred from Phase 1 research; blocks PSX-002 production admission until its supported configuration is replanned. Preserve failed experiment; only the bounded [P1-21R research supplement](active/phase-1-loader-supplement.md) may use matching defaults.
- Done-criteria: supported unattended production import configuration is explicitly planned, implemented and verified with actual import/observer completion, effective options/profile identity, source integrity and awaited cleanup. If RAM overrides remain unsupported, target-specific policy must refuse layouts requiring them and document that limit. Do not patch third-party installations as an implicit workaround.
- Closure evidence/date/commit/PR: none.

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
- Evidence: planned later-phase work; Phase 1 now recognizes PSX identity but still rejects deep-provider import. No implementation of this later phase is claimed.
- Dependencies: Phase 3 accepted.
- Done-criteria: Delay-slot and reference evidence truthful; CLI/MCP and snapshots preserve PSX identities; Phase 4 checks and delivery satisfied.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.

## PSX-005 — Real-provider, package and local acceptance

- Status: open; type: test; severity: high; phase: 5.
- Owner: orchestrator, with task delegation per PLAN.md.
- Evidence: planned later-phase work; Phase 1 now recognizes PSX identity but still rejects deep-provider import. No implementation of this later phase is claimed.
- Dependencies: Phase 4 accepted.
- Done-criteria: Synthetic public CLI/MCP lanes, declared-host coverage, local patched-AC3 smoke, package/docs and final delivery gates satisfied; missing coverage explicitly blocks corresponding claims.
- Tasks and exact verification contract: corresponding phase in PLAN.md.
- Closure evidence/date/commit/PR: none.
