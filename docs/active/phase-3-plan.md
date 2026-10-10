# Phase 3 execution contract — independent PSX memory and entry evidence

Batch: `psx-support-2026-10`. Phase: 3. Local records: PSX-003 and PSX-007; PSX-008 remains deferred. Baseline: clean `main` / local `origin/main` reference, `c498013fee5a61d4900a5edb7a9743f2a42b5c75`, following approved Phase 2 PR #2 merge `51a9f7311d631bbc06dd020f0f6a7cd30b9a8aa0`. Planning date: 2026-10-10. Status: saved contract read back, reviewed and linked by the orchestrator. Implementation, required real macOS synthetic lanes, package validation and bounded close review passed; final-content checks passed; PR delivery and approved merge remain pending. The R1/R2 planning checkpoints below are historical; their gates were subsequently satisfied. User authorized execution on 2026-10-10 with “You can execute the Phase 3 plan when ready.” Implementation and scoped synthetic verification proceed on `codex/psx-phase-3`, with delivery through a reviewable PR; merge requires concrete PR approval. Saving the plan alone grants no authority. No batch rollover applies.

Assigned shared path: `/Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/rea/docs/active/phase-3-plan.md`. Every implementor and reviewer must read this file before work. Planner owns this file only; orchestrator owns integration, revisions, state and delivery.

## Objective, scope and authority

Answer through the existing `inspect_native_load_image` operation: which exact source bytes back the admitted PSX analysis image, does the complete declared payload agree, and is its declared entry observed at a mapped instruction boundary? Keep source declarations, loader observations, REA adaptation, independently checked facts and unavailable runtime facts distinct.

Deliver a PSX-specific result, producer provenance adaptation for the demonstrated empty FileBytes gap, independent source/offset/coverage/digest/entry checks, meaningful semantic mutation tests, current schema projections and a scoped macOS real synthetic lane. Verified refers only to the enumerated adapted static image coverage. It never establishes original-loader source lineage or runtime correctness.

Preserve Phase 2 default-only KSEG0 2 MiB admission, explicit Ghidra binding, isolated headless imports, immutable source/snapshot bytes, owned cleanup and all non-PSX behavior. Function/instruction query admission, MIPS delay-slot interpretation, generic snapshot/public parity expansion, Linux proof, patched AC3 input, installed-package/fresh-client acceptance and release readiness belong to Phases 4–5. No game files, installation changes, new dependencies, global toolchain operations, GUI attachment, loader installation patch, overlays discovered from discs or RAM option overrides. PSX-008 is not silently added.

Authorization to implement this reviewed plan includes the following disclosed internal effect (no separate per-transaction approval is needed): a bounded pre-analysis transaction may replace payload blocks in REA's disposable Program with FileBytes-backed blocks created from its immutable snapshot. This is analysis-database adaptation, not executable mutation. Public inspection remains read-only; preparation is part of opening the ephemeral analysis session. Keep `-readOnly`/`-deleteProject`; never save an attached GUI database. The existing Java helper's “never writes Program state” description must change wherever it becomes false.

## Evidence and design decisions

Read together: [project](../PROJECT.md), [phase overview](../PLAN.md), [progress](../PROGRESS.md), [ledger](../ISSUE_LEDGER.md), [architecture](../ARCHITECTURE.md), [dependency map](../architecture.mermaid), [code standards](../standards/CODE_STYLE.md), [test standards](../standards/TESTING.md), [testing guide](../testing.md), [tool design](../tool-design.md), [contributing](../../CONTRIBUTING.md), [Phase 2 contract](phase-2-plan.md), [Phase 2 results](phase-2-results.md) and [Phase 1 results](phase-1-results.md). Root AGENTS.md applies; no nested AGENTS.md exists in the affected source/bridge/tests/scripts trees (website guidance is unrelated).

Repository inspection confirms:

- `src/domain/native/nativeLoadImage.ts` has strict shared observations, a legacy unsupported result and DOS-only verified/mismatch shape. `src/contracts/toolOutputSchemaGroups.ts` already binds the operation to this schema; `GhidraInventoryValues.ts` validates the producer observation. Update these consumers now, not in Phase 4.
- `GhidraLoadImageAttest.ts` reads the immutable snapshot for DOS only; PSX currently returns unsupported. `GhidraProviderClient.ts` owns dispatch into this attestor. Reuse that path and `GhidraClient.readTargetSnapshot`, not caller-path rereads.
- `ReaGhidraBridge.java` obtains genuine `MemoryBlockSourceInfo`/FileBytes and currently queries only CS/DS/ES/SS contexts. It needs PSX-specific GP/SP and exact listing-entry observations; that does not enable general instruction queries.
- All seven Phase 1 imports and the Phase 2 production matrix expose no FileBytes. Byte equality is therefore insufficient. Phase 1 measured GP (including zero), missing SP, and uninitialized fill; surrounding blocks vary with declarations. Never assert a universal block count or block-name layout.
- Read-only inspection of installed `SoftwareModeling-src.zip` confirms public `Memory.createFileBytes(filename, offset, size, InputStream, monitor)` and `createInitializedBlock(name, address, FileBytes, offset, size, overlay)`. `convertToInitialized` accepts a fill byte, not FileBytes; there is no verified public in-place provenance setter. Do not use private database internals or invent one.
- Installed `ghidra_psx_ldr-src.zip` shows stream-based payload creation, entry disassembly/function seeding, GP context and optional compiler/main discovery before analysis. Replacing memory can delete listing metadata. A transaction and exact preservation gate are mandatory, not optional cleanup after a naive rebind.

The selected producer solution is a **REA-owned transactional payload rebind**, with original observations retained and its identity exposed. It creates actual FileBytes from source bytes and actual memory source links. It does not populate source fields from header arithmetic while leaving the original unbacked mappings intact. The independent TypeScript verifier then checks the resulting API observations against its separately parsed snapshot. Equality of original bytes is a prerequisite to avoid repairing a bad loader silently; it is never the provenance proof.

## Frozen contracts

**Revision precedence:** the original contract below is retained as execution history. The appended **P3-R1 — label-history evidence retention** revision supersedes its v1 provenance method, v2 startup wire, whole-state restoration equality and affected-label-history refusal only as explicitly listed there. The appended **P3-R2 — sole transaction ownership** additionally supersedes nested adaptation transaction entry/closure assumptions only. All other scope, ownership, failure, coverage and delivery requirements remain active. P3-13 is gated on the latest revised real feasibility result.

### Public domain result and wire observations

Keep old DOS and legacy unsupported JSON shapes valid and unchanged. Use a union arrangement that does not put duplicate `status` discriminator values into one Zod discriminated union. Add the PSX branch discriminated by `format: "ps-x-exe"`; do not force `load_segment`, segmented entry, `module_bytes` or `overlay_bytes` onto PSX.

All new objects are strict. Counts are nonnegative safe integers, SHA-256 values lowercase 64 hex, addresses canonical lowercase `0x` unsigned 32-bit values in the default space. Provider source strings remain unmodified in generic observation fields. Parse PSX coordinates at the provider boundary; malformed or non-default-space coordinates cannot silently normalize into default RAM. Inclusive address ends and exclusive file-range ends are explicit. Null means unavailable; zero remains a measured/declaration value. No executable byte arrays are returned.

Add optional `psx` to `nativeLoadImageObservationSchema`, required by the PSX attestor for a supported result, omitted by other formats:

```ts
type PsxObservation = {
  schema_version: 1;
  provenance: {
    method: "rea-psx-filebytes-rebind-v1";
    status: "applied" | "unavailable";
    reason: string | null; // null exactly for applied
    source_sha256: string;
    source_file_bytes: number;
    before: {
      source_files: SourceFile[];
      mappings: Mapping[];
      entry_points: string[];
      entry_context: EntryContext[];
    }; // same row schemas as generic observation, captured before mutation
    rebound_ranges: Array<{
      start: string;
      end: string;
      length: number;
      file_offset: number;
      source_file_index: number;
      before_sha256: string;
      after_sha256: string;
    }>;
    preserved_state_sha256: string | null;
    restored_state_sha256: string | null;
  };
  entry_instruction: {
    address: string; // declared PC queried from independently read snapshot
    status: "instruction" | "not-instruction" | "unmapped";
    length: number | null;
  };
};
```

`SourceFile`, `Mapping`, `EntryContext` refer to the existing exact domain row schemas, exported/reused internally rather than copied incompatible definitions. Generic top-level observations are fresh **after-analysis** facts, not the adaptation record. For PSX, context rows report registers named `gp` and `sp` from Ghidra register lookup and ProgramContext at each external entry; value is hex or null, including a null row if a register is unavailable. DOS context output stays unchanged. The listing observation uses exact `getInstructionAt(PC)`, not containing-instruction lookup and not disassembly invented by inspection. Do not expose flow/delay-slot assertions in Phase 3.

PSX result fields:

```ts
type PsxLoadImage = {
  status: "verified" | "mismatch" | "unsupported";
  format: "ps-x-exe";
  reason: string | null; // required nonempty for unsupported
  target_sha256: string;
  header_bytes: 2048;
  payload_bytes: number;
  trailing_bytes: number;
  payload: { file_offset: 2048; start: string; end: string };
  entry: { declared_pc: string };
  declarations: {
    initial_gp: string;
    data_address: string;
    data_bytes: number;
    fill_address: string;
    fill_bytes: number;
    stack_base: string;
    stack_offset: string;
    initial_sp: string | null;
  };
  observations: NativeLoadImageObservation;
  checks: Array<{
    name: string;
    status: "matched" | "mismatch" | "unknown";
    required: boolean;
    expected: JsonValue;
    observed: JsonValue;
    file_offset: number | null;
    address: string | null;
    reason: string | null;
  }>;
  coverage: {
    scope: "rea-adapted-static-payload-v1";
    expected_payload_bytes: number;
    examined_payload_bytes: number;
    verified_payload_bytes: number;
    complete: boolean;
    auxiliary: Array<{
      mapping_index: number;
      classification:
        | "uninitialized-memory"
        | "initialized-auxiliary"
        | "alias-or-overlay"
        | "declared-fill"
        | "unknown";
    }>;
  };
  limitations: string[];
};
```

Hardware/BIOS labels cannot be deduced solely from block names: include measured block names in observations; use conservative classifications above. `declared-fill` means intersection with a header-declared interval, not proof of zero content. Do not double-count overlapping rows in counts. Examined counts are union extents actually inspected; verified counts include only successfully source-backed and hash-checked unique intervals. Complete requires exact expected coverage, not a lack of recorded failures.

The existing boolean DOS check schema remains intact. PSX tri-state checks are separate so unknown never becomes false mismatch or true success. Schema acceptance is not a substitute for semantic verification.

### Preparation record version and ownership

Freeze the Phase 2 wire extension as follows. `PsxImportCommitment.schema_version` becomes `2` and gains required `source_provenance: "rea-psx-filebytes-rebind-v1"`; all other commitment fields/policy remain as defined by Phase 2. `PsxImportObservation.schema_version` and `PsxImportAgreement.schema_version` become `2`. The before and after observation objects gain a required top-level `provenance` field of the exact `PsxObservation["provenance"]` shape above, outside `observed` to distinguish retained adaptation evidence from fresh Program observations. The before record holds the committed adaptation outcome; after revalidates its source/run/profile correlation and retains the same adaptation record without pretending to redo adaptation. Fresh post-analysis mappings/context/instruction remain the load-image operation's observations. Agreement requires identical before/after provenance records plus the existing independently observed source/assets/startup agreement. Set profile `startup_agreement: "psx-observed-import-and-provenance-v2"`.

Keep the fixed private `psx-import-before.json` location, atomic publication, current marker syntax and exact-byte marker digest. The marker covers the complete version-2 record. Old version-1 PSX metadata is rejected under the new profile, not silently upgraded. Non-PSX descriptors/session metadata remain unchanged. Unavailable provenance requires nonempty reason, empty rebound ranges and null preservation hashes; applied provenance requires null reason, nonempty ranges and equal non-null preservation hashes. Missing metadata is distinct from a valid unavailable outcome. TypeScript P3-13 owns these schemas; Java P3-12 owns their producer. They agree on this frozen extension before editing. The early feasibility probe uses the Java version-2 contract directly; it does not require a version-1 production Client to accept version-2 startup.

### Status and error precedence

1. Malformed bridge JSON/schema, inaccessible or digest-changed owned snapshot, cancellation and transport faults return existing typed errors through Result/ProviderAdapterError mapping; no thrown parser exception escapes the owning adapter. Missing snapshot read capability is an adapter error, as for DOS.
2. Valid contradictory observations yield PSX `mismatch`, retaining all checks and observations, even when another facet is unknown. Examples: wrong source digest, wrong offset, overlap, stale after facts, mapped bytes differ, wrong GP where an applicable nonzero declaration exists.
3. With no contradiction but absent required provenance/coverage/entry observation, yield PSX `unsupported` and required unknown checks. Preserve inventory usability. An unavailable adaptation never becomes verified because bytes match.
4. `verified` requires all required checks matched and complete payload coverage. Optional missing SP, uninitialized fill and zero-GP usability remain unknown with limitations. Any observed applicable register contradiction makes mismatch even though unobserved register state is optional.

An absent source collection under unavailable provenance produces unknown provenance/coverage checks, not a synthetic source-count contradiction. A present source with the wrong digest/index, or an applied record claiming absent mappings, is a contradiction. Likewise missing entry observation is unknown; a measured `not-instruction`, `unmapped` or wrong-length result is a contradiction.

During startup, attempted adaptation failure, rollback failure, malformed/stale/missing preparation record or marker, and source/profile correlation failure are hard typed startup failures followed by owned cleanup. A supported, atomically published preparation record that explicitly says adaptation is unavailable is not an import failure: retain Phase 2 inventory and return unsupported load-image evidence. Never serve a partially rebound Program.

### Independent attestation algorithm

Create `attestGhidraPsxLoadImage(bytes, targetSha256, observations): Result<NativeLoadImage, string>` in `GhidraPsxLoadImageValues.ts`, matching the existing pure provider attestor pattern. Reparse with `parsePsxExeHeader`; verify snapshot hash before comparing observations. The parser remains domain-owned; no Ghidra imports enter domain/application layers.

Required checks, each individually observable:

- PSX format/language/compiler/default address space and admitted image base; adaptation method/status/source identity and preserved/restored-state agreement.
- One complete source FileBytes object for this rebind, original and modified digest equal to snapshot digest, actual source size equal to file bytes. Header and trailing bytes participate in source identity but must never enter initialized payload coverage. A future native loader provenance mode requires its own explicit contract rather than silently accepting a changed producer.
- Sort source-backed rows by numeric address/file coordinate, preserving duplicates. Require every payload byte covered exactly once in default RAM, initialized, loaded, non-overlay, source index valid, `file_offset = 0x800 + (start - payloadStart)`, length/end agreement, and corresponding snapshot-slice SHA-256 equal to measured mapping SHA-256. Reject gaps, duplicate coverage, overlaps, out-of-range source extents, header/trailing mappings, aliases counted as payload and unbacked overlap with the declared payload. Accept arbitrary valid split blocks and names/order changes.
- Require all rebound rows to match actual post-analysis source-linked mapping coverage and retained pre-adaptation range hashes. The producer record is checked for consistency; it is not an independent source oracle. An after-analysis byte change fails the current static image even if pre-analysis bytes passed.
- Declared PC must occur in observed external entries and lie within complete verified coverage for a four-byte instruction. Extra observed external entries are retained, not automatically contradictions. Exact listing entry address and length must equal declared PC and four. No function/flow/runtime assertion is inferred.
- Nonzero declared GP compared with measured GP when available. Zero declared GP is preserved; the loader can derive a GP from instructions, so a nonzero observed GP against a zero declaration is reported as observation with unknown declaration-agreement, not automatically a contradiction. Nonzero stack base yields checked declared SP; compare if measured, otherwise unknown. Zero stack base preserves raw offset and unspecified SP, never assumes zero. Preserve unexpected/duplicate context rows as contradictions rather than silently selecting one.
- Fill existence/initialization is reported by interval intersection; uninitialized fill content remains unknown. Do not initialize fill or SP to make checks pass. Unexpected relocations affecting payload contradict unchanged source-backed coverage; retain auxiliary relocations outside coverage as limitations without importing DOS semantics.

Example: baseline source is 4096 bytes; header 2048, payload `[0x800,0x1000)` maps `[0x80010000,0x800107ff]`, entry `0x80010000`. Split source mappings `[0x800,0xc00)` and `[0xc00,0x1000)` pass with matching independent hashes. Mutating the second source offset to `0xbfc` fails even if all mapped memory hashes still match. Adding 16 trailing bytes changes complete source identity and `trailing_bytes`, never expected payload coverage. Applied provenance with absent SP can still verify with an explicit SP unknown.

## Tasks and ownership

Roles backend-dev, test-engineer, code-reviewer and issue-triage use configured gpt-6.1-sol/high. Orchestrator settings stay unspecified. Workers are not alone in the repository: preserve others' changes, read the shared contract and do not write another owner's files. All proposed creation paths below are new files, not claims of existing code.

### P3-00 — authority and baseline checkpoint

Owner orchestrator. Dependencies: saved-plan review and user authorization. Owned files: `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/ISSUE_LEDGER.md`; orchestration branch state. Link the saved plan in all three now during planning reconciliation; after implementation authorization create `codex/psx-phase-3` from reconciled current main, inspect unrelated changes and verify existing pinned Node/npm. No reinstall. Read current installed source/API identities before the early gate; do not assume historic hashes still match.

Acceptance: plan readback complete, exact baseline recorded, Phase 3 scope/ephemeral adaptation authorization recorded, issue records in progress only when implementation starts, source changes isolated on the phase branch. Architecture: provider ownership and immutable session binding.

### P3-11 — domain/wire contracts and independent verifier

Owner backend-dev (TypeScript). Dependencies P3-00; freeze schemas before other workers consume them. Owned edits: `src/domain/native/nativeLoadImage.ts`, `src/ghidra/GhidraLoadImageAttest.ts`, `src/ghidra/GhidraInventoryValues.ts`, `src/contracts/toolOutputSchemaGroups.ts` only if necessary for schema binding. Create `src/ghidra/GhidraPsxLoadImageValues.ts`, `src/ghidra/GhidraPsxLoadImageValues.test.ts`, `src/ghidra/GhidraPsxLoadImage.fixture.ts`, `src/domain/native/nativeLoadImage.test.ts`. Existing DOS attestors/tests remain the regression oracle; do not rewrite them to the PSX shape. Ownership extension after implementation typecheck: `src/ghidra/GhidraLoadImageValues.ts` may narrow its DOS return/parse to the exported legacy schema/type, preserving its unchanged boolean-check contract rather than weakening consumer tests.

Steps: implement strict schemas and exported exact types; independent fixture builder without production parser expectations; implement the complete algorithm above; route PSX snapshot reads through existing attestor; validate boundary input once with Result mapping; test each semantic category below; make the output schema available to all callers immediately. Domain contains only neutral values, not Java adapter metadata interpretation. Do not change provider capability gates or profile yet.

Acceptance: verified split payload, unsupported missing provenance, mismatch offset/digest/coverage/entry/register contradictions, truthful optional unknowns, schema rejection of malformed fields, unchanged DOS JSON compatibility. Source tests pass. Architecture: domain contracts inward, provider interprets engine facts, shared operation reused. Return frozen types and representative verified/unsupported/mismatch JSON to P3-12/P3-21.

### P3-12 — bounded producer feasibility and transactional provenance

Owner backend-dev (Java/producer), separate worker only with disjoint files. Dependencies P3-00 and frozen P3-11 schemas. Owned edits: `bridge/ghidra/ReaGhidraPreparePsx.java`, `bridge/ghidra/ReaGhidraPsxImport.java`, `bridge/ghidra/ReaGhidraBridge.java`. Create `bridge/ghidra/ReaGhidraPsxProvenance.java`. No TypeScript/state/package edits by this worker.

Implement the following ordered state machine: original import observed -> adaptation preflight -> transaction -> source-backed image verified -> preparation record atomically published -> auto-analysis -> authenticated fresh load-image observation. Never publish success before transaction completion. Retain original import observation and block/source facts in the record; use the same fixed owned record and completion-marker lifecycle already established by Phase 2, with an explicitly versioned extended schema. Reuse the bridge's observation routines through a narrowly owned shared helper if needed; do not create two divergent memory observation algorithms.

Preflight:

1. Validate admitted snapshot/run/profile/source and exact default-only policy. Enumerate payload-intersecting blocks/source intervals with checked arithmetic; require a complete nonoverlapping initialized default-RAM payload with exact independently read source content. Refuse adaptation for a block straddling the payload boundary, mixed-source/overlay state or unexplained initialized overlap. Valid split blocks wholly inside payload are supported. Unavailable preflight publishes an explicit reason and unchanged original state, never fake provenance.
2. Capture block names, comments, source names and read/write/execute/volatile/artificial attributes, starts/lengths; all affected register-context ranges including masks, external entries, symbols with namespace/source/primary identity, listing instruction boundaries/prototypes and references, and function entry/name/source/body. Capture the original static state before clearing anything. Implementation API review also requires public Program tree ownership/order/ranges and default register-context masks/ranges in this manifest: memory removal visits TreeManager as well as listing managers. Support ordinary root fragments; refuse custom affected tree ownership before mutation if exact restoration is unavailable.
3. This version supports ordinary loader-seeded instruction code units, default-context disassembly and plain functions/symbols/references reproducible via public APIs. Detect and refuse before mutation if affected data definitions, overlays, custom storage/prototypes, flow overrides, bookmarks/comments/properties or other address-associated metadata cannot be preserved exactly. Do not write a general database copier. Installed API review identifies label history as another affected category: SymbolManager deletion removes it, and public SymbolTable exposes reads without a restoration API. Enumerate affected history and refuse before mutation when it cannot be preserved; actual loader baseline feasibility must establish whether this prevents the positive gate. State enumeration must cover the affected address range, including outgoing/incoming reference edges whose removal would otherwise be lost; absence must be measured, not assumed from fixture names.
4. Freeze a deterministic state manifest using full values, with separate block-source provenance fields excluded from the preservation comparison. Hashes accompany the record, but compare full internal manifests to prevent omission from masquerading as preservation. Preserve gp/sp masks/ranges, not just their values at entry. If installed APIs do not permit a complete enumeration of a relevant state category, mark adaptation unavailable and stop the positive gate for a bounded replan.

Transaction:

1. `Program.startTransaction` on the owned disposable Program. Create one FileBytes from the complete immutable source stream at offset zero; use try-with-resources and monitor cancellation. Hash and verify it; cancellation can leave incomplete buffers per Ghidra API documentation, so rollback is required.
2. Remove only preflight-approved payload blocks and recreate them via `Memory.createInitializedBlock(name, start, fileBytes, 0x800 + start - payloadStart, length, false)`. Restore exact permissions/metadata. Do not manufacture file backing for auxiliary RAM, fill, BIOS/hardware or aliases. No source byte patching.
3. Restore admitted context before redisassembly; recreate exact measured entry/function/symbol/reference state using public APIs. Redisassemble only the exact captured instruction-start set, with incremental code analysis disabled, and compare boundaries/prototypes/references; do not infer that bytes alone preserve metadata. Restore all measured external entries. Verify all affected state against the captured manifest and that unaffected block/state inventories remain unchanged. Duplicate restoration that changes source/primary identities fails.
4. On any mismatch/cancellation/error, end transaction with rollback. Verify rollback restored original state; report the original failure and rollback failure together if both occur. Never proceed with a best-effort partially restored image. Startup fails after attempted adaptation failure; retained process/root ownership remains with existing supervisors until cleanup succeeds.
5. Commit only after exact comparison and real FileBytes source links/digests match. Publish adaptation record and before marker atomically afterward. Repeated preparation must not rebind an already adapted Program; existing-record refusal remains idempotent protection. A record alone cannot establish current state: after-analysis and each inspection read fresh FileBytes/mappings/context/listing.

Early feasibility gate: the orchestrator provides the minimal helper package/build registration and direct feasibility wiring at this checkpoint, under its P3-90 file ownership but without waiting for that final task. The test engineer prepares the P3-22 feasibility runner now. Ghidra compiles each script directory as an isolated bundle: the runner must materialize exact bridge helper sources and the test-only probe together in one owned temporary script directory, verify copy digests against source fingerprints, and launch that bundle. Separate default-package helper/probe directories fail class resolution even when direct javac succeeds; preserve the first failed real report as evidence. Integrate only enough build/package wiring for P3-22's generated baseline and declared-registers-fill cases. Run this **after implementation authorization**, before P3-13 capability/profile completion. Both must preserve loader state, obtain actual FileBytes offsets, and cleanly close. Also exercise a controlled transaction failure in a disposable synthetic test Program and establish rollback, using a test-only Java script rather than a production mutation flag. Create `tests/conformance/ghidra/ReaPsxProvenanceContractProbe.java` for this probe; it may operate only on generated synthetic imports and may not be packaged. If preservation APIs or bounded state support fail, preserve evidence and re-plan. Do not silently replace this design with copying the plugin loader, patching installations, an overlay witness, or echoing source-offset calculations.

Acceptance: actual producer lineage, preserved pre-adaptation evidence, bounded supported state and truthful unavailable state, rollback/cleanup evidence. Installed source presence is design evidence only; it is not a passing gate. Architecture: adapter owns Program/resources; no GUI/source authority and no provider internals in domain.

### P3-13 — authenticated lifecycle, profile and inventory integration

Owner P3-11 TypeScript backend worker, sequential after its work. Dependencies P3-12 early gate passes and wire freeze. Owned edits: `src/ghidra/GhidraImportConfiguration.ts`, `GhidraSessionValues.ts`, `GhidraAnalysisProfile.ts`, `GhidraClient.ts`, `GhidraClientTypes.ts`, `GhidraLauncher.ts`, `GhidraProviderClient.ts` only where needed; colocated `GhidraSessionValues.test.ts`, `GhidraAnalysisProfile.test.ts`, `GhidraSnapshotCache.test.ts`, `GhidraProvider.behavior.test.ts`. Paths without a repeated directory in this paragraph are all under `src/ghidra/`.

Steps: version extended PSX preparation/commitment schema consistently in Java and TS; require method/profile/run/source/record-digest agreement through the existing authenticated channel; freeze expected provenance method in the commitment rather than accept producer-selected policy. Include `psx_source_provenance: "rea-psx-filebytes-rebind-v1"`, `load_image_evidence: "independent-psx-adapted-payload-entry-v1"`, and `psx_operation_scope: "inventory-and-load-image-v1"` in canonical profile parameters. Preserve instruction/function unavailable semantics. Keep transient source coordinates/run IDs out of semantic profiles; snapshot/profile drift invalidates cached reuse atomically. Bump startup agreement identity to reflect the extended record. Existing non-PSX profile identities remain unchanged.

Attestation must check fresh runtime facts against snapshot, not treat a matching preparation digest as proof. Validate absence/unsupported record versus actual contradiction distinctly. Do not introduce independent credential files, ambient directory scans, new process ownership rules or arbitrary capture caps. Keep PSX-008 deferred. Update older simulated tests that intentionally asserted PSX unsupported to their new truthful branch, preserving explicit missing-provenance coverage.

Acceptance: stale/missing/forged record and profile/source mismatches fail at startup with awaited cleanup; honest unavailable adaptation permits inventory but no verified result; current applied facts route to verifier; Phase 2 snapshot identity rejects reuse, new same-identity snapshot round-trip passes, DOS/COM unchanged. Architecture: session identity, adapter lifecycle, shared public workflow.

### P3-21 — independent boundary and advertised-schema verification

Owner test-engineer. Dependencies P3-11 frozen contracts; final integration follows P3-13. Owned edits: `tests/fixtures/ghidraPsxImport.ts`, `tests/boundary/providers/ghidra/ghidraPsxImport.test.ts`, `tests/boundary/providers/ghidra/ghidraClient.test.ts`, `tests/boundary/providers/ghidra/ghidraLauncher.test.ts`, `tests/boundary/mcp/ghidraPsxImport.test.ts`, `tests/boundary/cli/ghidraPsxImport.test.ts`, `tests/boundary/mcp/toolSchemaValidity.test.ts`, `scripts/verify-packed-bridge.mjs`. Create `tests/boundary/providers/ghidra/ghidraPsxLoadImage.test.ts` only for distinct attestation/owned-snapshot boundary scenarios rather than duplicating source tests.

Steps: reuse immutable fixture/seams; add actual filesystem snapshot failure/change and cancellation cases; mutate strict startup evidence independently of profile echoes; verify public CLI/MCP load-image envelopes, Evidence identity, all three statuses and retained unknowns through recording providers; validate outputs against SDK-converted advertised schema and exact named operation binding. The public contract is already the correct operation; add no tool or ordering-based dispatch. Update packaged bridge required-file list for the helper. New tests must be discovered exactly once. Fake-provider success proves integration only.

Required semantic mutations: mapping start/end/length; valid address spelling versus a different space; source index; source offset while mapped hash is unchanged; original/modified/source digest; payload hash; gap, duplicate, overlap and unbacked intersection; header/trailing mapped as payload; extra unrelated initialized auxiliary block; valid split/order/name changes; absent provenance with perfect equality; forged applied record with no API links; stale after-analysis data; omitted/misaligned/wrong external entry; containing but not exact instruction; wrong instruction length; nonzero GP and SP contradictions; null GP/SP; zero GP with loader-derived value; zero stack base with nonzero offset; uninitialized declared fill. At least offset and digest mutations must reach the production attestation boundary, not only a self-built result validator.

Acceptance: correct branch and failed named check, not merely “not verified”; unknown observations retained; no selected input/provenance loss; cancellation and failed cleanup retain ownership; old DOS shapes parse and pass; converted schemas match real result variants. Architecture: exact schema contracts and shared CLI/MCP Evidence path.

### P3-22 — scoped real synthetic evidence and regression

Owner test-engineer. Author the feasibility runner alongside P3-12 after contract freeze; it runs the Java probe directly with explicit version-2 commitments and owned lifecycle. Full-lane work follows P3-21 for shared files. Dependencies P3-12 feasibility subset; full lane depends on P3-13/P3-21 integration. Create `scripts/verify-real-ghidra-psx-load-image.mjs` and `docs/active/phase-3-results.md`; edit `tests/conformance/ghidra/README.md`, `tests/conformance/ghidra/psx-exe-fixture.mjs` only for new original synthetic cases, and `scripts/verify-real-ghidra-psx-import.mjs` to replace obsolete “always unsupported” assertions while preserving its admission/ownership cases. Do not rewrite historical reports or results. P3-12 owns the test-only Java probe; coordinate its invocation, not its edits.

New proposed npm command: `verify:ghidra:psx-load-image` = `npm run build:cached && node scripts/verify-real-ghidra-psx-load-image.mjs`. The script accepts no caller binary path. Reuse `scripts/lib/verifier-run.mjs` and Phase 2's corrected capture/cleanup pattern. Explicit host prerequisites are existing Ghidra 12.1.4/PSX extension and Temurin 25, with real identities refreshed. Reports reside under ignored `docs/psx-local/phase-3-load-image-runs/`; a proposed `REA_PSX_LOAD_IMAGE_PROOF_CAPTURE_DIR` must be absolute and explicitly selected. Never serialize ambient environment or credential descriptors.

Full lane: generated baseline, declared-registers-fill and trailing-bytes through public stdio MCP and CLI load-image inspection; separately identified direct provider session for authenticated preparation evidence. Require verified declared payload with real post-adaptation FileBytes, original empty provenance retained, exact source offset and digests, entry instruction, GP observations, explicit SP/fill unknowns, unchanged sources/assets and matching adapter/profile identity. Public and direct sessions have separate run IDs/evidence; never join records merely because source SHA matches.

Add a synthetic split-block probe case and a controlled preflight-unsupported state (for example an explicitly created affected data definition) in disposable Programs: valid split rebind passes; unsupported preflight makes no mutation and yields unavailable provenance; injected failure rolls back. These are **producer-boundary synthetic probes**, not production CLI positive evidence. Do not add runtime fault switches to the packaged product. Replay actual captured observations through the production TypeScript attestor with independent source-offset and digest mutations to demonstrate rejection of real producer-shaped evidence. Label replay separately from actual live tampering.

Measure source hash before/after, all snapshot/source identities, code/plan hashes and dirty diff, profile parameters, loader/Java/Ghidra/asset identity, source-linked coverage, raw declaration/observation separation, exact process argv with credential redaction, exact owned roots, awaited closes and empty verified lineage. Use fixed owned files and authenticated coordinates; never read session credentials or scan ambient temp directories. Establish outer cleanup immediately after workspace allocation. Attempt all closes even after one fails, retain both primary and cleanup errors, and do not delete uncertain roots to make evidence pass. No successful report with cleanup/rollback failure or unresolved owned resources.

Run existing real PSX import, DOS and COM regressions after integration. macOS is the required current-host Phase 3 evidence. Linux is separately unperformed unless an authorized suitable host is provided; no simulated platform test substitutes. No game executable, target execution, emulator, GUI, Phase 4 operation or installed-package workflow is part of this lane.

Acceptance: complete actual positive matrix, declared negative/replay/probe coverage, truthful limits, source preservation and exact cleanup, with sanitized versioned results and report digest. A failure remains preserved; after three diagnostic hypotheses or about fifteen minutes without progress, or two failed correction rounds, stop the dependent lane and re-plan.

### P3-90 — integration, close review and delivery

Owner orchestrator. Dependencies all required tasks/gates. Owned edits: `package.json`, `knip.json`, `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/ISSUE_LEDGER.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `docs/ghidra-provider.md`, `docs/testing.md`, and plan revisions after handoff. Register new verifier/helper in explicit package/knip ownership as needed. No new dependency or Turbo configuration change. Update authored docs to distinguish adaptation from original loader provenance and static verification from runtime behavior. Generated catalogs/skills remain ignored outputs.

Run final checks, inspect full diff and give one code-reviewer the absolute shared plan plus exact reports/code identity. Review scope: source provenance authority, memory/metadata preservation, independent coverage checks, strict converted schemas, profile invalidation, unknown/error semantics, failure cleanup and non-PSX regressions. Resolve blockers; re-review only blocking fixes. Issue-triage may reconcile actual findings, not launch a deep audit.

PSX-007 closes only after actual producer adaptation, source-offset/digest mutations and real coverage pass; retain historical missing FileBytes fact and state that original loader provenance remains unavailable. PSX-003 closes only when technical criteria, bounded review and authorized delivery scope are complete. PSX-008 stays open unless separately authorized and verified. Record adjacent deferred findings with stable local IDs and acceptance evidence; no GitHub issue operations.

For authorized phase completion: finalize state/ledger first, verify final content, stage specific files and inspect staged diff, use Conventional `feat(psx): ...` with Phase 3/PSX-003/PSX-007 references, commit/push phase branch and open PR to Troll-Phace/rea. Present the concrete PR and wait for user approval before merging; no automatic merge. Verify actual current-head checks, merge normally, confirm remote/local main and perform necessary documentation-only reconciliation under existing policy. Planning-only does none of these delivery actions.

## Scheduling and exact checks

P3-00 -> P3-11 contract freeze -> P3-12 producer and P3-21 independent test preparation may overlap on disjoint files. P3-11 pure verifier can continue alongside P3-12. P3-12 early real feasibility runs serialize with all bridge edits/builds; do not begin broad P3-13 integration before it passes. P3-13 follows; P3-21 final boundary checks integrate afterward. P3-22 full real matrix follows focused checks. P3-90 final review/state/delivery comes last. Orchestrator package/knip edits serialize with workers. Cap children at three or host capacity. Every handoff names owned files; Java and TS workers coordinate schema versions before either changes the other's contract.

Existing commands, using the already installed pinned toolchain:

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
node --version
npm --version
npm run test:local -- src/domain/native/nativeLoadImage.test.ts src/ghidra/GhidraPsxLoadImageValues.test.ts src/ghidra/GhidraLoadImageValues.test.ts src/ghidra/GhidraDosComLoadImage.test.ts src/domain/psxExe.test.ts
npm run test:local -- src/ghidra/GhidraAnalysisProfile.test.ts src/ghidra/GhidraSessionValues.test.ts src/ghidra/GhidraSnapshotCache.test.ts src/ghidra/GhidraProvider.behavior.test.ts
npm run test:focused -- tests/boundary/providers/ghidra/ghidraPsxImport.test.ts tests/boundary/providers/ghidra/ghidraPsxLoadImage.test.ts tests/boundary/providers/ghidra/ghidraClient.test.ts tests/boundary/providers/ghidra/ghidraLauncher.test.ts tests/boundary/mcp/ghidraPsxImport.test.ts tests/boundary/cli/ghidraPsxImport.test.ts tests/boundary/mcp/toolSchemaValidity.test.ts
npm run mcp-catalog:generate
npm run mcp-catalog:check
npm run build:cached
npm run check
npm run lint
npm run format:check
npm run docs:check
npm run verify:test-discovery
npm run verify:package
npm pack --dry-run
python3 scripts/framework/validate.py --configured
git diff --check
```

New paths become runnable after creation; omit the optional new boundary file only if its distinct scenarios live in the assigned existing file, and record that choice. Never pass boundary/filesystem/provider paths to `test:local`; focused mode supplies needed artifacts. Expected Node/npm: 24.18.0/11.16.0. `check` includes framework static verification, not behavior. Lint/format may be recorded as covered by the same final-content full static run when output demonstrates execution. Package checks prove distribution integrity, not real installed PSX behavior. No `npm ci` or installation in this phase. Full `check:pr` is optional, not a substitute for these targeted lanes.

After implementation authorization and refreshed host-coordinate checks:

```sh
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:psx-load-image
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:psx-import
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:dos
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:com
```

Only `verify:ghidra:psx-load-image` is new. The early feasibility subset must be exposed by its proposed `--stage feasibility` argument, so the exact early command is the first command above followed by `-- --stage feasibility`; default execution is the complete matrix. The feasibility stage may use direct production preparation/probe imports before final public integration, and must label that narrower evidence. It cannot be reported as full acceptance.

## Gates, risks and result contract

No unresolved product-choice question is delegated to implementors. Required authority gate: Phase 3 implementation including the explicit disposable Program effect. Required technical gate: transactional rebind must preserve the installed loader's measured state through supported public APIs. This has **not** been proven during planning. If enumeration/restoration cannot satisfy P3-12, positive provenance remains blocked and requires a bounded revised plan; “best effort,” digest-only equality, header-derived source fields or broader import restriction are not permitted silent substitutes. Existing inventory may remain usable with explicit unavailable adaptation.

Other gates: complete source-linked payload and exact entry checks; current schema/client validation; real macOS synthetic matrix and regression; awaited cleanup and retained ownership; bounded close review; concrete PR approval before merge. Linux, AC3, instruction semantics, package/fresh-client and release gates remain separate and unperformed.

Risks include source-snapshot size and repeated hashing (reuse existing bounded snapshot acquisition and chunked Java hashing; do not allocate per-address arrays), metadata loss during block replacement, Ghidra transaction behavior, producer output drift, and overclaiming original provenance. Preserve full partial observations, cap work by actual admitted payload/format and existing resource boundaries, and fail closed with explicit reasons. Do not invent arbitrary row/byte limits merely to simplify tests. Large trailing data participates in existing snapshot/resource constraints and streamed FileBytes hashing, never a payload-sized assumption.

Each worker returns task IDs, exact files changed, contract/behavior decisions, commands and outcomes, failed attempts preserved, source/profile/code/report identities, actual versus simulated coverage, unknown/unavailable facets, resource cleanup and retained ownership, issue mapping and requested plan revisions. P3-12 additionally returns its supported-state enumeration and exact before/restored comparison evidence. P3-22 returns sanitized results with report SHA-256 and separate session/host/probe/replay scope. Orchestrator records actual final HEAD; relevant code/schema/Java/profile edits stale affected checks and live evidence. Documentation-only edits require final content/format/link checks without rewriting historical measurements.

Planning completion requires this saved contract to be read back and reviewed, then linked by the orchestrator. Phase completion requires the contracted technical evidence, resolved blocking review findings and explicitly authorized delivery endpoint. No historical phase evidence is reset or archived by this plan.

## P3-R1 — label-history evidence retention (2026-10-10)

Historical status at R1 planning: bounded replan saved for orchestrator review. Phase 3 implementation remains authorized by “You can execute the Phase 3 plan when ready.” This revision is a scoped engineering response to the required feasibility gate; no additional user approval is needed for the documented ephemeral adaptation. P3-13 integration remains unstarted and gated until this revision is read back and the revised real gate passes. No implementation, import or test success is claimed by this planning revision.

### Evidence, failed assumption and chosen correction

Preserve both failed reports unchanged:

| Report                                                          | SHA-256                                                            | Outcome                                                                                                                                                       |
| --------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/psx-local/phase-3-load-image-runs/run-ydmYGM/report.json` | `7308211599dbc533a0734b6a0b99febc7a536dc67397f7b05d6a322ed34ab2f3` | Probe helper compilation failed before producer execution; missing probe output caused ENOENT.                                                                |
| `docs/psx-local/phase-3-load-image-runs/run-LW5dxy/report.json` | `b09e84b61b56d6f656555b11024050fe40e96932e33a0e1bade4c78781505775` | Corrected owned script bundle reached actual v2 preparation; provenance unavailable: “Affected label history cannot be restored exactly through public APIs”. |

The second report used `-noanalysis`; it proves neither auto-analysis nor public CLI/MCP success. It contains no rebound ranges and retains original empty FileBytes. Baseline source and snapshot before/after SHA-256 are `be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a`; complete enumerated state before/after is `9e480e53416fad7a3f24501b8e02ce6aa23aef9acb51b170b3c7f10e27df5712`. Both reports verify workspace removal, no retained roots, empty supervised descendant lineage and no cleanup errors. P3-11's reported 153 source tests/typechecking/module-boundary checks are partial implementation evidence for the original schema; affected verification becomes stale with R1 changes. No existing failure is retroactively converted to a pass.

Current source `ReaGhidraPsxProvenance.capture` preserves label-history fields but refuses every affected history row. The baseline loader's user-defined `start` symbol supplies such a row. Read-only inspection of installed Ghidra 12.1.4 `SoftwareModeling-src.zip` confirms:

- `MemoryMapDB.removeBlock` calls `Program.deleteAddressRange` before removing memory.
- `SymbolManager.deleteAddressRange` deletes corresponding label-history records.
- Public `SymbolTable.getLabelHistory()` and `getLabelHistory(Address)` expose reads, not insertion/restoration with original user/date. `LabelHistory` is a value container; constructing one does not restore database history.
- `LabelHistory` exposes address, label string, action ID, username and modification date. ADD/REMOVE/RENAME constants are 0/1/2. Symbol restoration can create fresh journal events with fresh dates; replaying names cannot recover original events.
- Public block movement relocates address-associated state and does not attach FileBytes. Public initialized-block creation provides real FileBytes backing but requires vacant address space. No supported public in-place source rebinding path was established by this inspection. A private DB mutation, replacement third-party loader or general state copier is outside this bounded correction.

Selected correction: retain the complete original label-history journal as explicit evidence before adaptation, expose the adapted journal and its exact differences, and restore every other enumerated state category exactly. The journal is not omitted from preservation analysis. Full Program-state equality is no longer claimed for successful adaptation; its actual original and adapted hashes are retained separately. Source FileBytes, source-offset coverage, entry semantics and all existing independent mutations stay mandatory. The method remains an REA-adapted image, never recovered original-loader lineage.

The only allowed successful metadata difference is label-history rows at payload addresses caused by the documented restoration operations. Unaffected journal rows remain exactly equal as a multiset. All previously unsupported data definitions, custom function state, comments, properties, source maps, equates, relocations, symbol namespaces/pinning and other unmodeled state remain unsupported. This revision does not broaden import restrictions: an honest unavailable adaptation still preserves Phase 2 inventory usability.

### R1 frozen row, lineage and state contracts

Replace the original method with `rea-psx-filebytes-rebind-v2`. Replace `PsxObservation.schema_version: 1` with `2`. Replace PSX commitment/observation/agreement version `2` with `3`; the commitment's `source_provenance` and profile's `psx_source_provenance` equal the new method. Use profile `startup_agreement: "psx-observed-import-and-provenance-v3"` and `load_image_evidence: "independent-psx-adapted-payload-entry-v2"`. `psx_operation_scope: "inventory-and-load-image-v1"` and payload coverage scope remain unchanged. Old PSX wire versions are rejected under the new profile, never silently upgraded. Existing DOS/non-PSX profiles and JSON remain unchanged.

Public exact label-history row, reflecting the installed public API:

```ts
type PsxLabelHistoryRow = {
  ordinal: number; // nonnegative safe integer, exact iterator order, contiguous from zero
  address: string; // existing lossless provider address coordinate, not forced default RAM
  label: string | null; // getLabelString, preserve exactly; no trimming or parsing rename text
  action: number; // signed byte [-128,127] from getActionID; preserve unknown values
  user: string | null; // getUserName, preserve exactly; never infer sensitive status
  modification_time_ms: string | null; // getModificationDate().getTime() as signed decimal long
};
```

Use a canonical signed decimal string for the Java date long (no plus sign, leading zeros or `-0`), avoiding JavaScript precision loss. Null preserves a null API value; it is never substituted with current time or username. Do not serialize ambient environment to obtain this user value. Ordinals are independently scoped to each before/after/current enumeration. Never sort these public arrays or deduplicate equal rows. Multiset comparison ignores `ordinal` but compares every other field, including nulls, exact strings and date. For repeated identical rows, pair the earliest unmatched after ordinal with each before row in before-ordinal order. `removed_before_ordinals` is the unmatched before ordinals in ascending order; `added_after_ordinals` is the unmatched after ordinals in ascending order. This gives deterministic duplicate-preserving differences while retaining observed ordering.

Retain existing provenance fields `method`, `status`, `reason`, `source_sha256`, `source_file_bytes`, `before`, `rebound_ranges`. Remove the ambiguous `preserved_state_sha256`/`restored_state_sha256` fields from the new strict schema; they remain only in historic v1 records. Add:

```ts
type PsxMetadataPreservation = {
  comparison: "exact-enumerated-state-except-label-history-v1";
  original_state_sha256: string;
  adapted_state_sha256: string;
  original_operational_state_sha256: string;
  adapted_operational_state_sha256: string;
  operational_state_matched: boolean;
  original_record_sha256: string;
  label_history: {
    scope: "complete-program-label-history";
    before: PsxLabelHistoryRow[];
    after: PsxLabelHistoryRow[]; // immediately after preparation transaction, before auto-analysis
    removed_before_ordinals: number[];
    added_after_ordinals: number[];
    program_journal: "unchanged" | "recreated-at-payload-addresses";
  };
};
// Added to provenance:
metadata_preservation: PsxMetadataPreservation;
// Added to PsxObservation, alongside provenance and entry_instruction:
current_label_history: PsxLabelHistoryRow[]; // freshly observed when inspection runs
```

All digests use the existing lowercase SHA-256 type. Enumerated state means the current producer manifest's named categories (blocks, context, default context/disassembly context, symbols, label history, functions, instructions, data, references, entries, bookmarks, comments, property maps, trees, source maps, equates, relocations), not an assertion that every private Ghidra database property was copied. Operational manifest is an explicit projection of the captured full manifest deleting **only** its `label_history` key; it retains every other key unchanged, with a fixed expected-key inventory. Reject an unexpected/missing category rather than allow unknown fields to disappear in a filter. Full manifest hashes include label history using the same canonical duplicate-preserving multiset representation used for original comparison; public source ordering is retained separately. Source/FileBytes identity remains separately checked, as in the original design.

For applied adaptation, operational hashes must be equal, `operational_state_matched` true, and exact full operational manifests must have compared equal inside Java before commit. Complete hashes are observations and may differ; never set them equal to satisfy the old gate. `program_journal` is `unchanged` exactly if the before/after row multisets are equal, otherwise `recreated-at-payload-addresses`. The latter requires differences wholly inside the declared payload and the allowed generated-history checks below. Its public limitations explicitly say original history was retained as evidence and not restored as the adapted Program's journal.

For unavailable adaptation, the new metadata object is still required after successful capture: no mutation, exact full-state equality, equal operational hashes, `operational_state_matched: true`, before/after journal multiset equality, empty delta ordinal arrays and `program_journal: "unchanged"`. `rebound_ranges` stays empty and reason nonempty. A failed/incomplete journal enumeration cannot produce “complete” arrays or a valid unavailable proof: return a typed preparation failure with partial diagnostics and owned cleanup, rather than publish a successful record with invented emptiness. For rollback after any attempted adaptation, require original complete manifest **and original source/memory observation** equality, including journal values and duplicate multiplicities. The successful journal exception never applies to rollback.

Strict structural parsing checks row fields, byte action bounds, lossless date syntax and valid digest shapes. Semantic checks validate ordinal continuity and branch invariants: malformed field types are adapter errors; well-shaped conflicting values are named mismatches in attestation (and hard validation failures when read as startup records). The TypeScript attestor independently recomputes journal multiset differences and checks supplied ordinal arrays, unaffected equality and status consistency. It does not claim to independently reconstruct the private Ghidra full-state manifest from its hashes. Those are authenticated producer comparisons; independent source bytes/offsets/coverage remain the separate oracle.

`current_label_history` is fresh after-analysis/inspection evidence, while `metadata_preservation.label_history.after` is the committed pre-analysis adaptation snapshot. Auto-analysis may add journal events; do not compare these two as though analysis had not run or attribute later events to adaptation. Return both with these stages explicit in descriptions. General instruction/function operations remain gated.

### R1 original-evidence publication and producer sequence

The producer owns one additional fixed private session file, `psx-provenance-original.json`, alongside `psx-import-before.json`. It contains no credentials or executable bytes. Freeze its strict shape:

```ts
{
  schema_version: 1,
  commitment: { run_id: string, profile_digest: string, source_sha256: string },
  state_sha256: string,
  operational_state_sha256: string,
  label_history: PsxLabelHistoryRow[]
}
```

1. Preserve the corrected verifier's exact owned Java source bundle and canonical snapshot coordinate. Capture the original complete state, source observations and entire journal before any mutation. Store exact source-order rows with ordinals and a duplicate-preserving comparison representation; no early “affected label history” refusal. All other preflight exclusions remain.
2. Before entering the rebind transaction, atomically publish this original-evidence file using the established CREATE_NEW/private-permission/pending-file pattern. Hash its exact bytes, not a later reserialization. Refuse an existing file. Immediately register its fixed location with the session's existing ownership; it creates no independent process or cleanup owner. A failed write/atomic move is a preparation failure before mutation. Retain the pending-file cleanup error if cleanup fails.
3. Run the original real FileBytes transaction. Restore exact operational state through the existing public APIs. Do not call history internals, spoof a user/date, replay old journal rows into Ghidra or change symbols from USER_DEFINED to ANALYSIS to suppress history. Original source bytes and installation remain untouched.
4. Capture journal after payload-block removal and require all original rows outside the payload still present with exact multiplicity and no unexplained outside changes. Capture before/after each operation that can create symbols/history (restricted redisassembly, function creation, label creation, primary selection), retaining the operation kind and target in internal diagnostics. New surviving affected history rows must be ADD (`0`) for an exact `(address,label)` of a restored measured symbol/function. The public API may generate zero or multiple duplicate ADD rows; preserve them and require each added row to be observed during one of these restoration operations at its recorded target. A REMOVE/RENAME/unknown action newly surviving at an affected address, an event outside payload, or an event unrelated to a restored symbol fails the transaction for bounded replan; do not widen a whitelist to make a run pass. Historical before rows may contain any action; their raw values are retained even when they concern a deleted old name.
5. Compare complete operational manifests exactly. Compare all nonaffected journal rows exactly as multisets. Derive the before/after journal deltas; retain all rows, including repeated equal events and observed dates/user strings. Record complete before/adapted hashes without requiring their equality on applied success. Recheck actual source-linked mappings/digests/coverage exactly as in the original gate.
6. Before commit, verify the fixed original-evidence file is stable, digest matches its recorded exact bytes, and contents equal the captured original journal/state/source/run/profile. An unreadable/tampered record aborts and rolls back. Commit only after all checks. Publish the final version-3 before record with the full metadata object and original-record digest; emit the existing completion marker only after complete atomic publication. If final publication fails after commit, the session must not become ready; existing owned cleanup applies and the original evidence file remains available for diagnostic capture until owned root cleanup.
7. At authenticated agreement, reread and validate the exact fixed original-evidence file against the retained provenance and run/profile/source; compare its exact-byte digest. Do not follow a path from the target or bridge response. Preserve the existing complete before-record marker verification and before/after provenance equality. Each public inspection reads fresh memory and current journal while retaining the committed original/adapted metadata history.
8. On transaction failure/cancellation, rollback and compare complete original state, including label history; cancelled monitors must not prevent rollback verification. Capture original and post-failure differences in typed diagnostics, retain primary plus rollback/cleanup errors. A rollback discrepancy remains a startup failure and cleanup/ownership gate; it is not accepted as the successful journal exception. Original evidence and partial diagnostics stay owned until normal cleanup succeeds. Verifiers capture them before cleanup; never make absence pass by deleting uncertain roots manually.

No arbitrary journal cap is added. Enumerate with monitor cancellation and preserve complete records. Account for the additional retained JSON before publication/transport using existing provider output/resource constraints; no truncation can be labeled complete. If actual scale exceeds an existing hard boundary, report the boundary failure and re-plan representation rather than silently dropping rows or using a digest-only replacement for original journal evidence.

### R1 acceptance, ownership and integration order

R1 is a revision of P3-11/P3-12/P3-21/P3-22, not a new broad phase. Existing workers remain owners and must read the revised absolute plan before proceeding:

- **P3-R1-11**, TypeScript backend: own existing `src/domain/native/nativeLoadImage.ts`, `src/ghidra/GhidraPsxLoadImageValues.ts`, its `.test.ts`/`.fixture.ts`, and `src/domain/native/nativeLoadImage.test.ts`. Freeze new exact row/schema types, method and metadata branches; remove superseded v1 preservation fields from current producers/fixtures. Add named checks `provenance.operational_state`, `provenance.label_history_delta`, `provenance.label_history_scope`, `provenance.journal_disposition` and original-evidence linkage consistency. Missing required metadata is unsupported only if the observation contract allows absence; malformed v2 fields are adapter errors, and well-formed contradictions yield mismatch. Legacy DOS/non-PSX values remain valid. Do not begin P3-13 integration yet.
- **P3-R1-12**, Java backend: own existing `bridge/ghidra/ReaGhidraPsxProvenance.java`, `ReaGhidraPsxImport.java`, `ReaGhidraPreparePsx.java`, `ReaGhidraBridge.java` and `tests/conformance/ghidra/ReaPsxProvenanceContractProbe.java`. Implement record/file/journal contracts, state projection and operation-correlated journal checks; preserve every other preflight refusal. Add test-only probe mutations through ordinary public APIs, no packaged runtime fault flags. Its probe's `preservation` evidence must now separately report `operational_state_matched`, actual complete before/after hashes and `journal_disposition`; do not keep a misleading top-level whole-state `matched: true` for successful adaptation. Rollback still reports full equality.
- **P3-R1-22**, test engineer: own `scripts/verify-real-ghidra-psx-load-image.mjs`, existing assigned fixtures/boundary tests, `docs/active/phase-3-results.md` and conformance README. Update direct version-3 commitment/profile construction, capture fixed original-evidence bytes/digest, compare journal rows/deltas independently, and retain exact code/plan/report identities. Existing Phase 2 import verifier update remains later integration work. Orchestrator owns plan/state/package/knip and any helper registration; no overlapping writers.

P3-13 ownership extension confirmed from current source: the same TypeScript backend worker also owns `src/ghidra/GhidraPsxLoader.ts` and `src/ghidra/GhidraPsxLoader.test.ts`, whose `createGhidraPsxCommitment` produces the version/method fields, and `src/ghidra/GhidraProviderCapabilities.ts`, whose Phase 2 unsupported limitation must become the truthful adapted static-image disclosure after the revised gate. P3-11 owns all domain row/version changes. The test engineer updates its prepared but unrun v2 boundary examples to the frozen v3 method/wire before running them; prepared tests are not acceptance evidence. No consumer may keep a v2 expectation through a type cast or permissive parsing.

After the reviewed R2 gate pass, the orchestrator extended the same P3-13 owner's
scope to `src/ghidra/GhidraClientStartup.ts` and its existing colocated tests.
Startup must await stable fixed-file original-record reads and exact-byte digest
validation through the existing callback boundary. Preserve non-PSX startup and
owned cleanup semantics; do not block the event loop with synchronous journal
file reads or introduce an arbitrary record cap.

Safe order: orchestrator reads back R1 -> R1-11 schema freeze -> Java R1-12 and independent R1-22 fixture preparation in parallel on disjoint paths -> source/type checks and Java compile -> serialized real feasibility command -> orchestrator evaluates complete gate. P3-13 begins only if all required feasibility cases below pass. Then remaining original boundary/full public/real regression/review/delivery work resumes with new versions. No new planner, extra dependency, installation patch or game input.

Required early cases, all generated and separately labeled direct producer/noanalysis evidence:

1. Baseline with actual loader `start` history: applied real FileBytes, exact operational equality, complete retained original journal, truthful changed/unchanged adapted journal and complete source/cleanup evidence. Do not require complete hashes to differ if two observed journal multisets happen to coincide; disposition derives from actual rows.
2. Declared-registers-fill: same operational/journal checks plus original GP, absent SP and uninitialized fill retained; do not use the journal exception to bypass context differences.
3. Split payload: exact coverage across actual FileBytes segments and preserved operational state, with both journals and differences retained.
4. Journal multiplicity/order probe: create a synthetic affected label through public APIs and rename it away/back before capture, producing multiple observed history events. Ensure complete original rows, raw dates/actions/user/label and source ordinals survive inline; expected differences account for deleted old journal rows and newly added current-symbol rows. Preserve a separately created outside-payload history row exactly. No guessed hard-coded date values.
5. Unsupported data-definition probe: original preflight refusal remains; no adaptation, full state/journal equality and a complete unchanged original-evidence record.
6. Forced transaction failure after real block removal/restoration has begun: use the existing test-only cancellation/mismatch seam, assert full rollback including original journal, empty FileBytes and no ready marker. A failure before mutation is insufficient rollback evidence.
7. Original-evidence file tamper/missing-file probe: fail before readiness, demonstrate the appropriate pre-transaction refusal or attempted-transaction rollback, retain typed cause and cleanup. It must use only the owned fixed file in a disposable synthetic run, never installed assets or ambient files.

Source and boundary mutations additionally cover lost/duplicated/reordered journal rows, forged ordinal arrays, wrong user/date/action, null versus empty string, duplicate multiset events, signed date outside JS safe-integer range, scope change, unrelated-address added row, incorrectly `unchanged` disposition, mismatched operational hashes, removed/missing original-record linkage, and v1/v2 wire rejection under v3 profile. Reordering with preserved valid source ordinals is not silently sorted away; a separately observed enumeration order can differ while the journal multiset remains equal. Apply independent mutation expectations, not a mirror of producer comparison logic. Keep all existing source offset/digest/coverage/entry and cleanup cases.

Exact early invocation (existing new Phase 3 script registration, with R1 implementation):

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
npm run test:local -- src/domain/native/nativeLoadImage.test.ts src/ghidra/GhidraPsxLoadImageValues.test.ts src/ghidra/GhidraLoadImageValues.test.ts src/ghidra/GhidraDosComLoadImage.test.ts
npm run build:cached
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:psx-load-image -- --stage feasibility
```

The same original focused boundary, converted-schema, static, discovery, docs and package commands remain required after integration. The full default real lane must additionally exercise current journal output through CLI/MCP and independently retained original/adapted journal metadata in direct authenticated sessions. Rerun PSX import, DOS and COM regressions at affected final content. No noanalysis feasibility result stands in for auto-analysis/public or Linux evidence. Preserve the current original failed reports and publish a new distinct report/digest; do not edit old expectations or recompute their historic “success”.

### R1 gates and handoff

This is an explicit change to a false preservation assumption, not permission to ignore metadata. Acceptance now proves: all original journal evidence retained, actual adapted journal differences disclosed and constrained, exact operational state restored, original source bytes immutable, genuine FileBytes coverage independently checked, and full state restored on rollback/unavailable paths. Required limitation wording: “Original label history is retained as evidence. The adapted Program may contain newly generated label-history events from REA restoration; its original journal was not restored in place.” Do not claim whole-Program preservation or original-loader source offsets.

No unresolved user product decision remains for this bounded revision. Technical viability is still unproven: Java transaction rollback and the allowed new-history event envelope must pass actual probes. An additional metadata loss, unmodeled journal action, failed rollback, incomplete enumeration or new mismatch stops dependent work for another evidence-based replan under the existing diagnostic/correction budget. Do not incrementally exclude more manifest fields. PSX-003/PSX-007 remain open; PSX-008 remains deferred. Orchestrator updates state/ledger after reviewed readback and records exactly which prior checks became stale.

## P3-R2 — sole transaction ownership (2026-10-10)

Status: second bounded replan saved, read back and reviewed by the orchestrator. All nine real feasibility cases passed in `run-GSE38p/report.json` (SHA-256 `d1f19c48e804ee35202279c7a9d6e77acead0406087e39c894021a79b3adcdda`); P3-13 integration is unblocked. P3-13 subsequently integrated and the full public matrix and PSX/DOS/COM regressions passed. Required package and bounded review checks subsequently passed; final-content checks passed; PR delivery and approved merge remain pending. Implementation remains authorized within Phase 3. This revision changes transaction ownership and the time at which commit/rollback is proven. It does **not** reduce R1's complete rollback requirement or add another metadata exception. R1's journal evidence, operational equality, source provenance, unsupported preflight and all original phase boundaries remain mandatory.

### Preserved failure and API evidence

Retain `docs/psx-local/phase-3-load-image-runs/run-dd9PJz/report.json` unchanged, SHA-256 `dc6602b3ed6d70b5d5026c944d5f6487c09b314e6e5ade8b562e5e03f7ff0d73`, and raw `.agent-runtime/phase-3-feasibility-attempt-3.log`. The actual noanalysis run passed baseline, declared-registers-fill, split, journal-multiplicity and unsupported-data cases. Cancellation after actual source-linked FileBytes rebind raised `CancelledException` with suppressed `IllegalStateException: Rollback did not restore original state and provenance`. Required rollback output was absent and original-record tamper did not run. Ghidra's zero process exit did not make the lane pass. Source/snapshot, the 2,170-asset installation inventory and recorded code/dist/bundle postchecks remained unchanged. The workspace was removed with no retained roots, empty verified descendant lineage and no cleanup errors. Cleanup success is not rollback proof.

Read-only inspection of the installed 12.1.4 source establishes the relevant public lifecycle:

- `Features/Base/lib/Base-src.zip`, `ghidra/app/script/GhidraScript.java`, `executeNormal`: calls inherited `start()` before `run()` and inherited `end(true)` in `finally` after it. The wrapper's final close occurs after the current helper's immediate rollback comparison.
- The same archive's `ghidra/program/flatapi/FlatProgramAPI.java`: public final `start()` stores its own private `transactionID`; public final `end(boolean)` calls `currentProgram.endTransaction` for only that stored ID and resets it to `-1`. It is the supported API for the script to release **its own** transaction. When already released, the later framework `end(true)` is a no-op.
- `Framework/Project/lib/Project-src.zip`, `ghidra/framework/model/DomainObject.java`: `startTransaction` nests if a transaction exists. `endTransaction` documents that the complete transaction ends only after all outstanding transactions end; any false commit request causes rollback when the final transaction closes. Its boolean return is true only for final committed completion.
- `ghidra/framework/model/TransactionInfo.java` exposes read-only ID, description, open-subtransaction descriptions and status. An ID observed through this interface is diagnostic information, never authority to end someone else's transaction.
- `HeadlessAnalyzer.analyzeProgram` runs preScripts before opening the separate `Analysis` transaction. This provides a supported sole-transaction window after the REA preScript releases its own initial wrapper transaction. No GUI/live Program is admitted here.

The producer independently confirmed the same ordering in `DomainObjectDBTransaction.endEntry(false)` (status `NOT_DONE_BUT_ABORTED` while another entry remains) and `DomainObjectTransactionManager.endTransaction` (actual database rollback/restoration notification only after the final entry ends). These are inspected implementation facts used to interpret the public API, not permission to call private managers.

This source trace explains why the existing helper's nested `endTransaction(false)` cannot establish completed rollback before returning to its enclosing script. It is a source-grounded diagnosis, not a claim that the corrected runtime has passed. The new guard and actual failure probes below must demonstrate final closure and full restoration. If they do not, keep the gate blocked and preserve the new evidence.

### R2 production ownership contract

`ReaGhidraPreparePsx` owns the script-wrapper transaction. `ReaGhidraPsxProvenance.adapt` owns exactly one subsequent top-level adaptation transaction. Neither owns arbitrary existing transactions, a Ghidra GUI or another script's transaction. No private fields/reflection, `forceLock`, transaction termination by guessed ID, undo/redo, polling for someone else's transaction or general database recovery is permitted.

1. In `ReaGhidraPreparePsx.run`, validate its argument count, imported Program and headless execution before any Program mutation. Call the inherited public `end(true)` on **this script instance**, releasing the framework-started transaction. This commits no REA adaptation because none has begun. Do not call `start()` again afterward. Require `currentProgram.getCurrentTransactionInfo() == null`; if any transaction remains, stop before preparation/evidence publication or mutation with an explicit transaction-ownership failure. Do not attempt to close it. The script's eventual framework `end(true)` remains safely inactive through the public API's reset behavior.
2. The test-only probe must follow the same wrapper release at entry. Its optional synthetic setup uses its own explicit, independently completed top-level transaction after wrapper release. Require successful final commit and no active transaction before capturing the adaptation baseline. If setup fails, end only its owned transaction, verify no active transaction remains and report setup failure; never mix setup changes into the adaptation rollback expectation. The baseline includes deliberately committed fixture setup such as split blocks/history/data.
3. `adapt` itself requires no active transaction at entry, before publishing the original-evidence record. This protects direct callers, not just the script path. Validate again immediately before `startTransaction`, because capture/publication must not silently introduce a transaction. Existing preflight-unavailable paths must stay mutation-free and transaction-free. A caller that supplies an active transaction gets a typed preparation failure; no FileBytes, original-evidence file or before marker may be created by that rejected invocation.
4. After preflight/original-evidence publication, start one explicit transaction and retain only the ID returned by that call. All R1 mutations belong within it. Existing public commands may open nested transactions internally, but they must close before returning. Preserve the original adaptation exception independently of close exceptions; avoid a `finally` exception replacing the cause. A boolean named `committed` must not mean merely “the mutation body succeeded”: separate intended commit from actual completed commit.
5. End the owned transaction exactly once. On intended success call `program.endTransaction(ownedId, true)` and require both its return value `true` and `getCurrentTransactionInfo() == null`. A false return or remaining transaction is a hard closure/ownership failure, not successful preparation. Do not publish the before record or emit a readiness marker. Do not close a remaining foreign/internal ID or loop on end calls. Retain process/root ownership for normal failure cleanup.
6. On body failure/cancellation call `program.endTransaction(ownedId, false)`. The boolean is expected to be false; it does **not** by itself prove rollback. Require `getCurrentTransactionInfo() == null` before capturing rollback state, then compare the complete original manifest, complete journal multiset, original memory/source observation and empty original FileBytes state exactly as R1 requires. Use a noncancelled monitor for this verification. Retain the original failure and append transaction-close and/or restoration failures without dropping either. A transaction still active after close is a distinct `transaction-not-finalized` diagnostic and must never be reported as a proven content mismatch or successful rollback.
7. After confirmed successful final commit, recapture the adapted state/source observations and compare them to the already checked in-transaction adapted manifest and R1 provenance. Only then can `adapt` return applied metadata and `prepare` atomically publish `psx-import-before.json`/emit the existing marker. Read-only capture after transaction closure must not leave a new active transaction. This postcommit comparison prevents an intended-commit flag from substituting for actual persisted-in-Program state. “Commit” here means the ephemeral Program transaction, never saving source bytes or a Ghidra project.
8. If `endTransaction` itself throws, retain that failure and the primary mutation failure, query transaction state only for diagnostics, and fail startup. Do not double-end a possibly closed transaction, call undo or claim restoration. Report an unresolved transaction state if introspection also fails. Existing owned process/database/root cleanup still runs and must retain resources whose cleanup fails. A final before-record publication failure after commit still cannot produce readiness, as in R1.

A narrow helper may provide read-only transaction diagnostics (`id` as lossless decimal string, description, status, open-subtransaction descriptions); it cannot confer mutation authority. Keep returned transaction IDs separate from display descriptions. The production entry guard is the actual null current-transaction test, not string matching the expected script name. Do not add general transaction orchestration abstractions or use finalizers/timeouts to approximate closure.

### R2 identity, output and evidence contract

R1 public method `rea-psx-filebytes-rebind-v2`, PSX observation version 2, startup/commitment/agreement version 3 and exact journal schemas remain unchanged: this correction makes their existing atomic commit/rollback promise true, rather than changing the evidence meaning. Add canonical profile parameter `psx_preparation_transaction: "exclusive-top-level-v1"` in the feasibility profile now and production P3-13 profile later. It contains no transaction ID, run ID or transient path. This makes reuse distinguish the corrected lifecycle without altering non-PSX profiles. Do not emit a new public operation or admit Phase 4 capabilities.

Add exact `transaction_ownership` to the test-only probe report (not to the public load-image result):

```ts
type PsxProbeTransactionOwnership = {
  policy: "exclusive-top-level-v1";
  script_transaction_observed: boolean;
  wrapper_released: boolean;
  setup_transaction_performed: boolean;
  setup_finalized: boolean; // true also when no setup was needed
  before_adaptation_active: boolean;
  after_adaptation_active: boolean;
  outcome:
    | "committed"
    | "rolled-back"
    | "unavailable"
    | "rejected-active-transaction";
};
```

For ordinary positive/negative feasibility, `wrapper_released` and `setup_finalized` must be true and both active flags false. `script_transaction_observed` is retained as measured data; the installed source predicts true on the actual script path, and the current-host lane must assert that it actually observed the wrapper before releasing it. `outcome` is derived from final completion plus state verification, not from the requested commit flag. Existing report fields retain full rollback evidence and `fired_after_rebind`. Successful public preparation still requires no active transaction at the point the final before record is published; the actual production-preScript case below verifies this path.

For the dedicated active-transaction refusal case, the test owns and intentionally opens the extra transaction **after** releasing the script wrapper. It calls `adapt`, requires pre-entry refusal and no original/before record, then closes only its own extra transaction. Set `before_adaptation_active: true`, `after_adaptation_active: true` for the rejected invocation and add its final owned-close outcome in the case diagnostics; do not label a foreign active transaction as successfully released by `adapt`. Record unchanged complete state and sources before/after the test's final close. This case proves the helper cannot silently join caller-owned state.

Errors must identify whether failure occurred in wrapper release, pre-entry ownership, mutation, final transaction close, postcommit validation or full rollback comparison. Preserve suppressed exceptions in the retained report/log. Do not treat absence of a before marker, Ghidra zero exit, database deletion or empty process lineage as full rollback proof.

### R2 tasks, checks and acceptance

No new file owner is introduced. All workers reread this revision before resuming:

- **P3-R2-12**, Java backend owns `bridge/ghidra/ReaGhidraPreparePsx.java`, `ReaGhidraPsxProvenance.java`, `ReaGhidraPsxImport.java` and `tests/conformance/ghidra/ReaPsxProvenanceContractProbe.java`. Implement public wrapper release, direct-call guard, sole transaction ownership, exactly-once close, postcommit validation and failure diagnostics. Leave bridge/schema/journal semantics unchanged. Remove the superseded nested-close assumption; do not retain both execution paths behind a fallback. Test setup must also finalize before baseline capture. The helper's typed guard occurs before publishing original evidence.
- **P3-R2-22**, test engineer owns `scripts/verify-real-ghidra-psx-load-image.mjs`, its report assertions and `docs/active/phase-3-results.md`. Add the new profile parameter to direct feasibility construction and assert transaction ownership/full rollback. Preserve source/bundle/postcheck/asset/cleanup discipline. Create a test-only final-state observer script under `tests/conformance/ghidra/ReaPsxPreparationTransactionProbe.java` only if needed to inspect the actual production preScript after its return; it is owned by the Java backend by explicit handoff, never concurrently edited or packaged. Existing helpers/probe output are preferred if they can establish that exact sequence without copying adaptation logic.
- **P3-R2-13**, existing TypeScript backend ownership stays deferred until the revised gate passes. Its subsequent `GhidraAnalysisProfile.ts` update must include `psx_preparation_transaction`. No current public schema migration or method bump is necessary; R1 boundary/schema work remains pending as previously recorded.
- Orchestrator owns plan readback, state/ledger, early build/package coordination and evaluation of the complete gate. Neither test infrastructure nor documentation can waive failed rollback.

Safe sequence: readback -> focused source-level API diagnostic/Java edits -> compile exact helper/probe sources -> serialize the owned real feasibility run -> inspect source/code/asset postchecks and every case -> resume P3-13 only after all pass. The producer's read-only diagnostic may refine source-line evidence but cannot replace the required live comparison.

Required revised feasibility is all seven R1 cases, plus these bounded lifecycle assertions:

1. Baseline, declared-registers-fill, split and journal-multiplicity: sole final commit confirmed; complete operational/journal/source proof remains R1. Unsupported-data remains transaction-free, complete state unchanged.
2. Cancellation must still fire after observing real source-linked payload FileBytes, then show no active transaction and exact restored full state/journal/source with original empty FileBytes before returning its expected-failure report. No suppressed rollback failure may be ignored. Retain original immutable journal file evidence.
3. Original-record tamper must now actually run after cancellation passes. Require its expected typed failure, completed rollback and full original equality before readiness; it is not covered by the cancellation result.
4. Active-transaction refusal: helper rejects an intentionally test-owned outer transaction before any adaptation/evidence publication; test closes only its owned transaction and verifies unchanged state.
5. Actual production preScript path: run the current production `ReaGhidraPreparePsx.java` entrypoint without test-only modifications on the generated baseline, followed by a test-only read-only observer/probe that releases its own empty script wrapper before observation. Require successful preparation marker and record, source-linked image and no active transaction after the preparation script has returned. Do not replace the production preScript with a duplicate call to `adapt` and call that production-wrapper proof. This remains noanalysis/direct producer evidence, separate from the full public auto-analysis lane.

The original report's five successful cases remain historical partial evidence. Rerun the complete revised feasibility matrix at current source rather than splicing those successes into a new report. Keep `run-dd9PJz` failed and tamper unperformed in that report. The test engineer may first use an exact targeted rollback mode only if the existing runner already supports it; do not invent an undocumented flag. The acceptance command remains:

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
npm run build:cached
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:psx-load-image -- --stage feasibility
```

Require new distinct report, exact helper/probe/plan/dist hashes, unchanged source/snapshot and installation identity, observed transaction lifecycle, awaited owned cleanup and verified empty descendants. Exact Java compilation plus source tests are structural evidence only. After the gate, all remaining original/R1 source, focused boundary, public schema, full auto-analysis CLI/MCP, PSX/DOS/COM, package, bounded close review and delivery requirements still apply.

### R2 failure-evidence correction

The failed R1 cancellation case produced only the retained stack trace: there is no probe JSON, captured original-record copy, fault-time observation or category-level state comparison for that case. Keep those facts explicitly unavailable. The runner currently reads probe output before capturing the fixed original-evidence file and then cleans the owned root; correct that evidence ordering now. Neither source reasoning nor successful cleanup fills in missing runtime facts.

The Java backend adds bounded partial failure diagnostics to the existing helper/probe ownership. When adaptation fails, retain the original failure, all suppressed close/rollback failures and, where capture succeeds, the checkpoint, whether a transaction remains, differing named manifest categories, complete-state before/after hashes, journal before/after metadata and a projection of current source/mapping observations (source identities, ranges/offsets/hashes, no executable payload). A failed diagnostic read is recorded as unavailable with its own cause. Do not replace a thrown failure with a successful Result or invent empty arrays. Use an explicit exception payload or same-call return ownership available to the test probe; no process-global last-error cache, arbitrary output path in production or extra provider protocol.

The test-only probe catches failures at its outer owned reporting boundary, attempts to write available diagnostics to its assigned output file, then preserves the original thrown failure/nonpassing outcome. A partial report has `ok: false`, `evidence_complete: false`, `failure.stage`, `failure.name`, `failure.message`, `failure.suppressed`, and `failure.available_diagnostics`; it does not emit `REA_PSX_PROVENANCE_PROBE_COMPLETE` or a readiness marker. Missing diagnostic facets are explicit null/unavailable values with reasons, never false success. If writing the partial report fails, retain that reporting error together with the primary exception in the log. A partial JSON file does not satisfy a success-case assertion merely because it exists.

The test engineer places safe capture of the exact fixed `psx-provenance-original.json` in each case's `finally`, before that case/root cleanup, even when probe output is absent. Read only the path derived from the already validated owned descriptor/root, require regular-file/no-follow handling and existing bounded-read discipline, and retain exact bytes/digest and observed identity where available. Do not read `session.json`, arbitrary sibling paths or ambient temporary directories. Label the captured file stage `current-at-failure` or `current-after-success`; add content status `validated-original`, `tampered-or-invalid`, `partial`, `absent` or `unreadable` based on actual checks. A captured current file after tampering is not retroactively the original pre-tamper file. Preserve the pre-tamper copy only when the probe actually captured it, with its independent stage/hash.

Always attempt this capture and all owned closes/cleanup even after an earlier error. Retain primary, capture, reporting and cleanup errors separately, without allowing a failed capture to skip cleanup or mask the original gate failure. Report success remains false if required evidence is absent, partial or contradictory. Add deterministic runner/probe error-path checks only through the existing source-owned seam and assigned files; do not manufacture a real rollback pass with fake output. The actual revised cancellation/tamper cases still must demonstrate full original rollback. This evidence correction affects future runs only; `run-dd9PJz` remains unchanged and incomplete for these diagnostic facets.

### R2 decision and stop conditions

This is a routine scoped ownership correction supported by public installed APIs; no new user product decision or installation authority is needed. The plan does not claim the runtime root cause or remedy verified until the revised probe observes final transaction closure and full state restoration. If wrapper release leaves another transaction, public commands leave a nested transaction open, final close throws, rollback still differs or postcommit state disagrees, preserve precise checkpoint/state-category evidence and stop dependent work. Do not end someone else's transaction, omit a manifest category, accept only operational rollback, recreate the source image as a substitute for original journal restoration, or infer success from cleanup. The existing diagnostic/replan budget applies. PSX-003/PSX-007 stay open; P3-13 stays gated until the complete revised feasibility result is reviewed.

## Final technical checkpoint — 2026-10-10

The original contract and reviewed R1/R2 revisions are implemented. P3-11/P3-12/P3-13/P3-21/P3-22 technical acceptance passed. Nine real feasibility cases, nine distinct public MCP/CLI/direct imports and nine real-observation replay mutations passed; PSX, DOS and COM regressions passed. Exact commands, identities and preserved failed attempts are recorded in [Phase 3 results](phase-3-results.md). One bounded close review found one verifier handle-ownership blocker; its scoped correction and four deterministic failure cases were independently re-reviewed successfully. No unresolved blocking or deferred review findings remain. Original-loader FileBytes and in-place original journal restoration are not claimed. Linux, game inputs, runtime behavior, Phase 4 semantics and installed-package PSX/fresh-client acceptance remain unperformed.

P3-90 final-content validation and PR delivery follow this checkpoint. PSX-007 is closed on measured producer/mutation criteria; PSX-003 remains in progress until approved merge delivery. No later-phase authorization is implied. Documentation wording was reconciled after native runs; the immutable reports retain the source/plan identities observed during each run. No runtime, schema, producer, attestor or profile semantics changed during this reconciliation.
