# Phase 2 execution contract — target-specific availability and deterministic PSX import

Batch: `psx-support-2026-10`. Phase: 2. Local issues: PSX-002 and PSX-006; PSX-007 remains a Phase 3 blocker. Planning baseline: `main` at `3e36f98d10d3a631ed134ae3b4ff4b2d05c1e168`, synchronized with the orchestrator's observed `origin/main`. Phase 1 was accepted through approved PR #1, merge `7fdb2657cb9839e56272763a3d1a0e19fd5041d6`.

Status: detailed plan saved, read back and reviewed by the orchestrator on 2026-10-09; linked from PLAN, PROGRESS and the local ledger. The user subsequently authorized execution with “you can execute the plan when ready.” Phase 2 implementation and its verification/PR delivery are authorized; merging requires approval of the concrete PR. Every implementor and reviewer must read `/Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/rea/docs/active/phase-2-plan.md` first. No batch rollover applies.

## Outcome and exclusions

Open and close original synthetic PS-X EXE targets through production REA/Ghidra with deterministic loader configuration, observed startup agreement, immutable source ownership and useful target-specific failures. Ordinary Ghidra availability and native/DOS behavior remain intact. Supported implementation hosts are macOS/Linux; actual Phase 2 acceptance is a measured macOS lane, with Linux explicitly unverified until its own host lane runs. This is import readiness, not complete PSX analysis or release readiness.

Excluded: installed extension patches, new dependencies or installations, game inputs, extracted AC3 files, GUI changes, Windows PSX, generic MIPS formats, overlays, RAM overrides, independent source-backed attestation, MIPS operation semantics, complete public parity, package/client discovery and release claims. Source and package-integrity tests needed for the added Java sources are included; the Phase 5 installed-package/provider acceptance lane remains separate.

Authority references: root AGENTS.md; `.agents/skills/phase-plan/SKILL.md`; docs/PROJECT.md; docs/PLAN.md Phase 2 and later-phase boundaries; full docs/PROGRESS.md and ISSUE_LEDGER.md; framework.json; docs/ARCHITECTURE.md; docs/architecture.mermaid; docs/tool-design.md; docs/testing.md; CONTRIBUTING.md; docs/standards/TESTING.md and CODE_STYLE.md. No nested AGENTS.md was found under src, bridge, tests or scripts at planning time. Recheck before edits. Apply the rea-tool-design skill when implementing these provider contracts.

## Evidence and settled decisions

The authoritative measured baseline is [Phase 1 results](phase-1-results.md), with the preserved failure and limited research permission in [the supplement](phase-1-loader-supplement.md). Actual loader: `psx.PsxLoader`, display/executable format `PSX Executables Loader`, selector `PsxLoader`, language `PSX:LE:32:default`, compiler `default`. Ghidra 12.1.4 / Temurin 25.0.4.1 / macOS arm64 were measured. Extension JAR digest `481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`; selected standard MIPS JAR digest `905a4da889e7f69062f699b7dce48346f2b7a2ccd114ac189a974dfb72850080`. These are evidence baselines, not permanent hardcoded binary allowlists.

The installed source ZIP was inspected read-only during planning: `PsxLoader.java` stores effective RAM size under Program Information key `PSX RAM Size`; computes the RAM bank as `initialPc & 0xff000000`; may derive GP when its declaration is zero; and creates a separate data segment when declared data address is nonzero. Source inspection is weaker than the measured adjacent JAR, so production startup must verify effective facts.

1. **Default-only production policy.** Supply exactly `-loader PsxLoader -processor PSX:LE:32:default -cspec default`; omit both RAM option arguments. Commit `option_mode: loader-defaults`, an empty supplied-loader-options object, expected default base `0x80000000` and size `0x200000`, and policy version `psx-kseg0-2m-defaults-v1`. Do not retry with another loader, bank, provider, or options. This resolves the design part of PSX-006; only implementation plus actual production evidence can close it.
2. **Narrow admission.** Use the existing pure `parsePsxExeHeader` and eligibility assessment. Require payload and the complete four-byte entry instruction within `0x80000000..0x801fffff`; require the inclusive entry range `[initial_pc, initial_pc + 3]` entirely within the declared payload. Require entry alignment, nonempty payload and four-byte payload-start alignment. Require any nonempty fill extent within the same bank and disjoint from payload. Require both declared data address and size to be zero for this initial policy. A zero fill size imposes no address restriction. Stack and GP declarations remain raw declarations; missing SP and loader-derived GP are not admission failures or established runtime state. Header structure errors remain malformed; additional restrictions are provider policy failures, never universal format invalidity. Preserve zero-stack/nonzero-offset and trailing bytes. No address alias normalization. A profile policy failure must identify the failed declaration/range and expected policy.
3. **Defaults are not settings attestation.** A new instance's `getDefaultOptions` reports advertised defaults, not the original loader object's chosen values. Record them separately. Effective agreement uses observed Program image base, default address space and `PSX RAM Size`, plus explicit argv, executable format, unique runtime selector resolution, selected code source, actual language/compiler, and fresh asset digests. Do not label replayed descriptor fields as observations. If the RAM-size property is absent, malformed or contradictory, reject startup rather than infer from total memory blocks.
4. **Bounded capability scope.** Existing inventory operations remain available as observations. Existing `inspect_native_load_image` continues through `attestGhidraNativeLoadImage` and returns `status: unsupported` with measured observations, never verified PSX coverage. For PSX only, reject every operation in `GHIDRA_FUNCTION_OPERATIONS` before bridge dispatch with `AnalysisCapabilityUnavailableError`, reason that PSX function/instruction analysis is deferred pending Phase 4 semantics. This explicit temporary subset avoids exposing unverified return/call/delay-slot interpretations or annotations. Do not alter generic provider capability registration APIs merely for this phase. Health limitations and profile parameters enumerate the subset and explain provider-wide declarations versus target-specific execution support. Test one inventory success, load-image unsupported, instruction rejection, decompile rejection and annotation rejection through both adapter projections. Phase 4 removes this gate only with its own tests/profile version.
5. **No provenance repair.** Empty FileBytes, missing original offsets, uninitialized fill and variant-dependent surrounding memory remain observed limitations. Do not synthesize FileBytes, rewrite segments, seed SP, zero fill or change GP. Never equate mapped hashes with source-backed coverage. PSX-007 stays open.

## Provider representations and lifecycle

Create `src/ghidra/GhidraPsxLoader.ts` as the provider-owned inspection/profile-policy boundary and `src/ghidra/GhidraImportConfiguration.ts` as the discriminated launch/expectation contract. No Ghidra types enter domain or application files.

The conceptual types below specify semantics; use readonly exact types and the existing Result/error algebra, with boundary schemas for untrusted JSON:

```ts
type PsxLoaderInspection =
  | { status: "available"; candidate: PsxLoaderCandidate }
  | {
      status: "missing" | "incompatible" | "ambiguous";
      reason: string;
      diagnostics: JsonObject;
    };
type GhidraImportConfiguration =
  | { kind: "automatic" }
  | { kind: "dos-mz" }
  | { kind: "dos-com" }
  | { kind: "psx"; commitment: PsxImportCommitment };
```

`available` means statically eligible candidate, not proof of a successful import. Candidate includes selected installation identity, extension manifest, selector/class/display identity, expected language/compiler, canonical asset inventory/digest and inventory version. The commitment adds policy/default expectations, source SHA-256 and parsed declaration expectations. Do not include temporary paths, run IDs, tokens, timestamps or the ambient environment in semantic profile parameters. Absolute caller and code-source paths remain in local diagnostics; path identity must not be replaced by display names.

### Exact PSX transport shape

P2-11 owns the TypeScript types and strict Zod schemas below in `GhidraImportConfiguration.ts`; P2-12 owns the matching Java producer in `ReaGhidraPsxImport.java`, descriptor wiring and SessionValues parsing. P2-11's `GhidraAnalysisProfile.test.ts`, P2-12's `GhidraSessionValues.test.ts` and P2-21's boundary tests own respective commitment, mutation and transport coverage. Use snake_case on the Java/JSON boundary and do not create a second equivalent wire representation. Every object is strict; no additional properties. Digests are 64 lowercase hexadecimal characters. Addresses use canonical `0x` lowercase hexadecimal strings and lengths are nonnegative safe integers. Arrays are deterministically sorted and unique by identity; duplicates are errors, not deduplicated observations.

The descriptor's optional `psx_import` field is required exactly when the discriminant is PSX. Existing top-level descriptor `target_path`, `target_sha256`, `run_id` and `profile_digest` remain their current ownership; `source_snapshot_path` must equal its owned target path. Form the final transport commitment after the launcher creates its owned snapshot; `source_snapshot_path` is a launch-time coordinate, not a profile parameter. At the PSX Client snapshot boundary, resolve the owned immutable snapshot to its canonical filesystem coordinate once before passing it to the launcher, descriptor and startup expectation. Preserve the caller-selected source path in the original options/diagnostics and preserve the JVM observation values; the strict pure metadata parser must not repair alias differences downstream. The second actual run exposed `/var` versus `/private/var` disagreement, and a real-file/symlink parser reproducer confirms the representation mismatch. Canonical commitment acceptance and the Client transport-boundary behavior must be tested before the next real run. Source declarations come from TypeScript's source parser and are checked again against that snapshot:

```ts
type PsxImportCommitment = {
  schema_version: 1;
  policy: "psx-kseg0-2m-defaults-v1";
  source_snapshot_path: string; // absolute owned snapshot, transport only
  source_sha256: string;
  declarations: {
    file_bytes: number;
    payload_file_offset: 2048;
    payload_address: string;
    payload_bytes: number;
    trailing_bytes: number;
    initial_pc: string;
    initial_gp: string;
    data_address: string;
    data_bytes: number;
    fill_address: string;
    fill_bytes: number;
    stack_base: string;
    stack_offset: string;
    initial_sp: string | null;
  };
  loader: {
    selector: "PsxLoader";
    class_name: "psx.PsxLoader";
    display_name: "PSX Executables Loader";
    code_source_relative: string;
    code_source_sha256: string;
  };
  language_id: "PSX:LE:32:default";
  compiler_spec_id: "default";
  option_mode: "loader-defaults";
  supplied_loader_options: {};
  expected_ram_base: "0x80000000";
  expected_ram_size: 2097152;
  asset_inventory_version: "ghidra-code-data-v1";
  asset_inventory_digest: string;
};
type PsxSelectedClass = {
  class_name: string;
  role: "loader" | "analyzer";
  code_source_url: string;
  code_source_relative: string;
  code_source_sha256: string;
  class_resource_url: string;
  enabled: boolean | null; // loader: null; analyzer: measured option, null if unavailable
};
type PsxImportObservation = {
  schema_version: 1;
  stage: "before-analysis" | "after-analysis";
  commitment: { run_id: string; profile_digest: string; source_sha256: string };
  observed: {
    ghidra_version: string;
    source: { snapshot_path: string; sha256: string; file_bytes: number };
    program: {
      executable_path: string;
      executable_format: string;
      language_id: string;
      compiler_spec_id: string;
      image_base: string;
      default_address_space: string;
      ram_size: number;
      external_entries: string[];
    };
    loader_selector: string;
    loader_class: string;
    advertised_defaults: {
      ram_start: {
        argument: "-loader-ramStart";
        value_class: "java.lang.String";
        value: string;
      };
      ram_size: {
        argument: "-loader-ramSize";
        value_class: "java.lang.String";
        value: string;
      };
    };
    selected_classes: PsxSelectedClass[];
    language_assets: { relative_path: string; sha256: string }[];
    asset_inventory_version: "ghidra-code-data-v1";
    asset_inventory_digest: string;
  };
};
type PsxImportAgreement = {
  schema_version: 1;
  before_record_sha256: string;
  before: PsxImportObservation;
  after: PsxImportObservation;
};
```

`PsxImportAgreement` is the authenticated sessionInfo `psx_import` value. `before` must have stage `before-analysis`; `after` must have stage `after-analysis`. Missing metadata is invalid for PSX; non-PSX sessionInfo omits this property entirely. The advertised option value classes and full arguments above match the retained Phase 1 runtime report (`run-8keqyf`); they are distinct from the `psx.PsxBaseChooser` constructor-type mismatch in the failed override experiment. The only nullable fields above are `initial_sp` and `enabled`; missing required observations are errors rather than fabricated nulls. Unobserved GP/SP/fill facts do not belong in this startup record. They remain available through later measured load-image observations with existing unknown semantics. `selected_classes` must contain the loader and all relevant discovered PSX/MIPS analyzer classes, including core MipsPreAnalyzer; its selected code source must be a hashed inventory member. The loader's enabled field is null. An unavailable analyzer enabled option may remain null, is exposed as unknown, and must not become an execution claim. `language_assets` includes the uniquely selected ldefs and its referenced SLA, processor/compiler specs and included language resources, all members of the full inventory.

The helper independently reads/hashes the snapshot and program properties to produce `observed`; the descriptor is only the expected commitment. The snapshot absolute path, observed Program executable path and descriptor target path must identify the same owned immutable file using filesystem-path semantics (not URL parsing or display-name comparison); the recomputed digest and size must match the commitment. Source declarations are independently read for policy/entry agreement, not copied into an observed field. `commitment` is explicitly echoed correlation metadata and cannot prove any observed field. Code-source URLs are preserved as URLs, resolved with URI-aware APIs to inventory paths for comparison, and not string-stripped.

Write the before record atomically as UTF-8 JSON at the fixed private session path `psx-import-before.json`; hash its exact bytes. Emit the single marker `REA_PSX_IMPORT_BEFORE_COMPLETE <run_id> <record_sha256>` after a complete successful validation. The bridge reads and strictly validates that exact owned path, computes its byte digest, creates its after record from fresh observations and emits the agreement. TypeScript startup diagnostics verifies the completion marker against the returned before-record digest. No arbitrary report path supplied by a target is followed. A preScript exception yields no completion marker and the bridge must refuse startup. TypeScript checks before/after run/profile/source links, observed values against the expected commitment, code-source membership/digests, and fresh inventory agreement. Advertised base/size values must parse to the expected defaults; effective image base and Program RAM-size property must independently equal the expected values. The descriptor's empty supplied-loader-options does not itself prove omission: launcher argv tests and real retained argv provide that evidence.

**Discovery and fingerprints:** use the selected installation and the launch's isolated home, not the user's GUI extensions. Inspect installed extension directories under the selected installation, including directories with a renamed PSX extension; parse manifest properties using the repository's property conventions. Duplicate PSX manifests/candidate resources are ambiguous; missing extension is missing; unreadable assets, incompatible manifest version, conflicting language definitions and unmodeled selection are incompatible. Exact candidate class/resource resolution is confirmed in the JVM. A duplicate extension `MipsPreAnalyzer` is not automatically ambiguous: the measured core MIPS selection is allowed only when runtime class/code-source identity agrees.

Initial inventory is conservative: hash regular code JARs and module `data/` resources across the selected Ghidra installation, plus extension manifest/module metadata. This captures core analyzers, processor/language/compiler resources, PSX loader and PsyQ resources rather than only the extension folder. Exclude source ZIPs, documentation, generated caches, logs and native host executables from this analysis-resource inventory; existing installation inspection still verifies host executables. Include sorted relative resource names, byte lengths and SHA-256, preserving exact case. The canonical digest stream is one UTF-8 row per resource: base64 of UTF-8 relative path, tab, decimal byte length, tab, lowercase SHA-256, newline. Sort by the unencoded relative path using UTF-16 ordinal ordering (JavaScript default string ordering / Java String.compareTo). Base64 prevents delimiter collisions while observations retain the original path. Stream file hashes, do not load entire archives/assets. Record the inventory algorithm/version. Conservative invalidation by an unused data asset is acceptable and documented; claims of minimal effective dependency coverage are not. Resolve the installation root once; refuse asset symlinks escaping it, unstable files, incomplete directory enumeration, or resources that cannot be hashed. No success from truncated inventories. Do not change the selected installation or load real user extension directories to find another candidate.

Synchronous `inspectTargetSupport` keeps format/host/coarse candidate admission distinct from asynchronous complete profile resolution. If full inspection needs async I/O, coarse support diagnostics must explicitly say `profile inspection pending`; full missing/incompatible/ambiguous decisions occur in `resolveAnalysisProfile` before import. Never put async provider launch in constructors or generic discovery. Missing PSX support does not change `inspectAvailability` or generic doctor's `available` status. `GhidraInstallation.ts` owns generic installation facts; expose/reuse coordinates without adding PSX as a required installation check. Generic doctor remains generic; target diagnostics are the authoritative PSX report.

Map missing/incompatible/ambiguous PSX inspection to existing `target_format_unsupported` target-support code where available, with `psx_loader.status` and reason diagnostics; PSX host refusal uses the existing `target_format_unsupported` target-support code with explicit `host_platform` and policy reason because ProviderTargetSupport does not include `unsupported_host`. Generic provider availability retains its existing host error contract. Async profile failures use `ProviderAdapterError` with the same structured diagnostics and actionable reason. Policy rejection uses existing target/profile error machinery with `psx_import_policy` diagnostics. Do not add broad public error enums for internal states. Expected cancellation uses `AnalysisCancelledError`; changed source uses `AnalysisArtifactChangedError`; I/O permission failures retain existing access-denied classification.

**Source and race boundary:** BinaryTarget does not carry parsed PSX declarations. Resolve them using a bounded `0x800` header plus file size, checking the resolved source identity with existing immutable/hash primitives. Do not add header details to all public target schemas. At launch, parse/validate the actual owned immutable snapshot again before spawning; compare its hash/declarations with the commitment. Reinventory assets immediately before spawn and after startup. An asset change after profile resolution fails this attempt; do not silently rebuild a different profile under the old binding. In-process caches must not mask later asset changes; no indefinite `#installation`-style PSX inventory cache.

**Observed agreement:** add packaged `bridge/ghidra/ReaGhidraPsxImport.java` (shared observer/validator) and `bridge/ghidra/ReaGhidraPreparePsx.java` (HeadlessScript called with `-preScript`). Ghidra's preScript runs after import and before auto-analysis; call it a pre-analysis observer, never a pre-import hook. It does not edit Program state. It validates the PSX descriptor, independent source declarations/digest, selected loader class/resource/code source, unique matching language definition and selected language assets, advertised default option names/value classes/values, effective Program base/RAM-size property/format, and entry presence. It records relevant selected analyzer classes and their code sources, especially core MipsPreAnalyzer and enabled PSX/PsyQ analyzers. Parse option values by their known type/format; do not treat arbitrary `toString()` as authoritative. Selected class is not proof that an analyzer executed.

The helper creates a strict before-analysis record in the private session directory and completion marker bound to run/source/profile identity. It must fail closed: missing record or exception prevents the later bridge from accepting the session even if Ghidra continues after a preScript failure. `ReaGhidraBridge.java` re-observes after analysis and emits `psx_import` agreement metadata through authenticated sessionInfo. The TypeScript strict parser requires it exactly for PSX; rejects absence, extra contradictions, changed assets, wrong source/program/run/profile, unknown code sources, timeouts, or wrong language/compiler/base/size. Program base is `ram:80000000`, default space `ram`, size `0x200000`; exact declared PC is an external entry in mapped memory. Full payload mapping/offset attestation remains Phase 3. Effective RAM size does not promise continuous RAM block coverage.

Supplied argv and descriptor are commitments; program and JVM readings are observations. Give them distinct fields. The bridge's existing echoed SHA/profile alone is insufficient. Use the newly independently computed source digest and observed identities in addition to existing echo checks. Verify the target-bound successful analysis report and pre-observer completion in retained startup diagnostics using the corrected timing contract below; a zero process exit, socket connection, or copied digest alone cannot satisfy success. An authenticated post-analysis bridge with valid before/after agreement and no analysis timeout is required.

### P2-12/P2-21 correction — serving-bridge completion timing (2026-10-09)

The first actual production baseline is preserved as a failed attempt in `docs/psx-local/phase-2-import-runs/run-5pBJ2X/report.json` (SHA-256 `2b8cb343c2b90eba4c6ef6fe2a3a333d77f3371d5ad51a74f58bb3e9989adcb7`) and `.agent-runtime/phase-2-psx-import-output.json`. Its diagnostics contain the pre-analysis completion marker, `REPORT: Analysis succeeded for file:` naming the owned snapshot, and invocation of the serving postScript bridge. TypeScript rejected it because `REPORT: Import succeeded` was absent. The report remains `ok: false`; cleanup records workspace removal, no retained roots and verified empty descendant lineage. This attempt is correction evidence, not Phase 2 acceptance.

Read-only inspection of installed Ghidra 12.1.4 `Ghidra/Features/Base/lib/Base-src.zip`, entry `ghidra/app/util/headless/HeadlessAnalyzer.java`, explains the ordering: analysis success is emitted after `mgr.startAnalysis` at lines 1054/1077; postScripts run synchronously at line 1093; terminal import success is emitted at line 1651 after import processing returns. The long-lived REA bridge serves inside that postScript. Installed source supports the lifecycle explanation; the retained actual diagnostics establish the observed baseline. Terminal import success cannot be a prerequisite for opening that live bridge.

Corrected startup contract, owned by the existing P2-12 TypeScript implementor in `src/ghidra/GhidraClient.ts` (and existing handshake wiring only if needed):

1. Retain complete, nontruncated startup diagnostics and require exactly one recognized `REPORT: Analysis succeeded for file: <file-URI>` report from the owned launch. Parse its file URI with URI-aware APIs, resolve filesystem identity, and compare it with the owned immutable snapshot. Preserve the original URI/path in diagnostics. Wrong target, malformed/non-file URI, missing or duplicate success reports, unreadable identity, or truncated diagnostics fail closed. Do not compare only basenames or display strings; account for `/var` versus `/private/var` aliases, spaces, percent escapes and non-ASCII paths.
2. Require exactly one pre-analysis completion marker with the active run ID and exact before-record digest, plus the authenticated sessionInfo with independently validated before/after agreement. Preserve all existing run/profile/source, loader/language/compiler, RAM, selected-resource and fresh-inventory checks. A successful analysis log alone does not establish observer completion or import agreement.
3. Reject contradictory import/analysis failure reports and analysis timeout, even if a success report or valid-looking agreement is present. Preserve cancellation, dead-process rejection, startup deadline and awaited cleanup/retained-resource semantics. Missing evidence must not become a successful zero-exit, socket-only or final-import-report fallback.
4. `REPORT: Import succeeded` is a terminal lifecycle observation that may be retained after close; it is neither required nor sufficient for startup. This correction does not claim all analyzers succeeded semantically, independent source provenance, or successful final project disposal. Existing close/cleanup gates remain mandatory.

P2-21 test-engineer retains sole ownership of `tests/boundary/providers/ghidra/ghidraClient.test.ts` for this correction. Replace the fake startup's terminal import success with the producer-shaped target-bound analysis report; prove live startup succeeds without terminal import success when all authenticated evidence agrees. Add/preserve independent negatives for absent/duplicate/wrong-target/malformed success reports, contradictory failure, timeout, truncation, missing/wrong pre-marker or digest, and mutated authenticated observations. Exercise URI/path alias and escaping semantics with the actual owned snapshot rather than a hardcoded target. Preserve existing cleanup assertions and non-PSX coverage. P2-12 and P2-21 coordinate the report shape before running the existing focused client command in the matrix.

Integration order: orchestrator reads this saved correction; P2-12 changes the predicate and P2-21 updates its independently owned boundary tests; focused client and affected SessionValues tests pass; P2-22 reruns the actual synthetic production lane and records a new report without overwriting the failed attempt. The new report must retain the startup analysis report, observer/agreement evidence and verified close/cleanup outcome. Startup verification predating this correction is stale for the changed predicate. No new user decision is unresolved; actual corrected production success remains an unmet technical gate until rerun. PSX-002/PSX-006 stay in progress and PSX-007 stays open.

**Profile/snapshot identity:** preserve ordinary/DOS profiles. PSX profile commits loader identity, Ghidra version, inventory digest/version, language/compiler, omitted versus expected defaults, admission-policy version, `startup_agreement: psx-observed-import-v1`, `load_image_evidence: unsupported-psx-source-provenance-v1`, `instruction_flow_evidence: unavailable-pending-psx-semantics-v1`, target operation subset/version, and default analyzer preset. Preserve target digest as existing snapshot identity; declaration expectations may travel in launch configuration without unnecessary duplication in general profile identity. Any semantics/assets/options change changes profile digest; unchanged source/profile reopens, changed source/profile rejects existing cached snapshot under established machinery. Later Phase 3/4 must bump their specific semantics and invalidate Phase 2 snapshots.

**Resources:** use existing GhidraTargetSnapshot, GhidraSessionRoot, GhidraLauncher, ProviderDeadline and `src/process/` supervision. No new detached discovery processes. All Java observations run inside the owned import. Abort during inventory, snapshot, launch, handshake or close retains the established cancellation type. Await process settlement and exact private-root cleanup before success; if rollback fails, keep partialLaunch/resource ownership and combine primary/cleanup errors. Never glob-delete temp roots or infer process ownership from PID/path. Preserve observations on failure and redact transport credentials, not source paths or benign names.

## Task contracts and ownership

Owners use the user-selected backend-dev/test-engineer/code-reviewer/issue-triage roles at gpt-6.1-sol/high. The orchestrator remains user-selected. Nobody is alone in this codebase: preserve others' edits. No simultaneous writers on the same file. Each task's contracts include all settled rules above; tests must exercise producing boundaries rather than echo implementation constants.

### P2-00 — authorization, evidence and branch checkpoint

Owner: orchestrator. Dependencies: saved-file review and explicit Phase 2 execution authorization. Owned state: docs/PLAN.md, docs/PROGRESS.md, docs/ISSUE_LEDGER.md; branch only once authorized.

Steps: reconcile Git and preserve unrelated changes; link this contract; confirm Phase 1 accepted and PSX-006/007 open; use a phase branch such as `codex/psx-phase-2`; verify pinned Node 24.18.0/npm 11.16.0 already under `.agent-runtime/toolchain/node_modules/.bin`. No install is needed. Dispatch exact file ownership below. Read real-host prerequisites before any provider run. Acceptance: recorded HEAD, clean/unrelated-change inventory, tool versions, authority scope and shared-plan readback. Architecture: root policy/PROJECT and phase state.

### P2-11 — provider inspection, policy and canonical profile

Owner: backend-dev. Dependencies: P2-00. Create `src/ghidra/GhidraPsxLoader.ts`, `src/ghidra/GhidraPsxLoader.test.ts`, `src/ghidra/GhidraImportConfiguration.ts`, `src/ghidra/GhidraAnalysisProfile.test.ts`. Edit `src/ghidra/GhidraAnalysisProfile.ts`, `src/ghidra/GhidraProvider.ts`, and `src/ghidra/GhidraInstallation.ts` only for reusable coordinates/seams. Own related edits in `GhidraInstallation.test.ts`, `GhidraDoctor.test.ts`, `GhidraProvider.behavior.test.ts`. Do not change generic Doctor production semantics.

Steps: (1) define discriminated configuration and strict commitment/inspection values; (2) implement installation candidate inspection and streamed canonical resource inventory via injectable I/O seams; (3) parse header and implement narrowed policy without changing pure format classification; (4) integrate async profile resolution and target diagnostics, with fresh inventories and cancellation; (5) include profile semantics and operation-subset identity; (6) add tests for single/missing/incompatible/ambiguous candidates, renamed extension, duplicate analyzer distinction, unreadable/changed resources, digest order determinism, source changes and all policy boundaries. Do not invoke Ghidra in module tests. Filesystem behavior belongs to P2-21.

Acceptance: local suites pass; generic available Ghidra and DOS/native profiles stay identical when PSX is missing; Windows PSX and arbitrary MIPS never admitted; asset/version/option/policy changes invalidate profile; unsupported layouts fail before launcher calls. Errors retain typed causes and raw declarations. Relevant architecture: provider discovery/profile separation in architecture.mermaid and ARCHITECTURE.md; tool-design identity/uncertainty rules.

### P2-12 — deterministic launch and observed startup agreement

Owner: TypeScript backend-dev, sequential after P2-11 contract freeze; a separate backend-dev owns the three Java files below after the shared wire contract freezes. No simultaneous writers. Edit `src/ghidra/GhidraProviderClient.ts`, `GhidraLauncher.ts`, `GhidraClientTypes.ts`, `GhidraClient.ts`, `GhidraSessionValues.ts`, `GhidraSessionValues.test.ts`, `GhidraClientStartup.ts` only where handshake wiring requires it, `GhidraProviderCapabilities.ts` for PSX limitation helpers. TypeScript owner does not edit Java. Java owner exclusively edits `bridge/ghidra/ReaGhidraBridge.java` and creates `bridge/ghidra/ReaGhidraPsxImport.java` / `bridge/ghidra/ReaGhidraPreparePsx.java`, reading the same saved strict wire contract and canonical inventory algorithm before work. P2-11 owner retains `GhidraImportConfiguration.ts`; same owner may refine it here. No edits to Phase 3 attestation/domain schemas.

Steps: (1) replace `dosMz`/`dosCom` booleans with one configuration everywhere, preserving exact existing DOS argv/preScript behavior; (2) validate PSX commitment/source snapshot/assets before spawn; (3) serialize PSX descriptor separately from NativeAOT extensions; (4) implement packaged pre-analysis observer, fail-closed completion and post-analysis re-observation; (5) pass typed expectations through Client to SessionValues and verify observed agreement; (6) enforce PSX function-operation rejection before bridge dispatch, attach honest inventory/health limitations; (7) retain cancellation and cleanup ownership on every failure.

Edges: spaces/non-ASCII in installation/runtime/source paths; no cwd script shadowing (absolute packaged script paths); zero exit/import failure; preScript exception with continued postScript; missing/wrong marker; forged echoed commitments; source/asset changes between resolution and launch/startup; duplicate class resources; absent RAM-size property; advertised default class/value mismatch; SP absent; inferred GP; trailing bytes; analysis timeout; cancellation before spawn/after connection; failed cleanup and retry. NativeAOT protocol must remain independent. Do not silently accept a configured incompatible extension combination.

Acceptance: P2-21 integration tests and real P2-22 gate; SessionValues rejects one-field mutations independently; old strict non-PSX handshakes continue to parse; no rejected operation reaches fake/real bridge. Architecture: launcher/client lifecycle and provider-owned boundary validation; docs/testing.md production-boundary coverage.

### P2-21 — deterministic boundary, snapshot and package evidence

Owner: test-engineer. Dependencies: P2-11 type freeze; run against integrated P2-12. Create `tests/fixtures/ghidraPsxImport.ts` for shared original generated fixture, temporary-install and recording-provider helpers; preserve independent test expectations. Create `tests/boundary/providers/ghidra/ghidraPsxImport.test.ts` for actual filesystem inventory/snapshot boundaries using recording launcher and producer-shaped metadata. Edit `tests/boundary/providers/ghidra/ghidraLauncher.test.ts`, `ghidraClient.test.ts`; edit `src/ghidra/GhidraSnapshotCache.test.ts` only for profile/source invalidation scenarios. Create `tests/boundary/mcp/ghidraPsxImport.test.ts` and `tests/boundary/cli/ghidraPsxImport.test.ts`; reuse existing provider/MCP harnesses without broadening their responsibilities. Edit `scripts/verify-packed-bridge.mjs` to require both new packaged Java files. Orchestrator owns package.json additions and knip.json registration, not this worker.

Steps: (1) construct original header boundary fixtures independent of policy implementation; (2) assert missing/duplicate/changed assets, defaults omitted and exact selector argv, preserved DOS launch, asset/source changes and no fallback; (3) mutate each required handshake observation while leaving echoed digest untouched and assert failure/cleanup; (4) exercise public open/close, binding, inventory success and function-operation failures via recording-provider integration, labeling synthetic responses; (5) assert load-image remains unsupported with empty source provenance; (6) test snapshot same identity success and changed source/profile rejection; (7) require packaged helper/observer presence and no fixture/report payload packaging.

Acceptance: exact source/focused suites in command matrix pass; observable resource cleanup/ownership assertions on cancellation and malformed metadata; no ambient environment or token persisted; schema projections remain valid. Tests must not claim real-provider behavior. Relevant architecture: snapshot boundary and shared CLI/MCP workflows; TESTING and docs/testing.md.

### P2-22 — actual synthetic import, failure and regression lane

Owner: test-engineer, sequential after its P2-21 edits and integrated P2-12. Create `scripts/verify-real-ghidra-psx-import.mjs`; extend `tests/conformance/ghidra/README.md`; create `docs/active/phase-2-results.md` for sanitized conclusions. Reuse `tests/conformance/ghidra/psx-exe-fixture.mjs` unchanged for existing variants; additional negative fixtures are header mutations in the verifier, never game inputs. Reuse `scripts/lib/verifier-run.mjs` and established production MCP/CLI verifier lifecycle. No changes to old Phase 1 raw evidence or probe.

Proposed command, created by this task: `node scripts/verify-real-ghidra-psx-import.mjs`. It accepts no input binary path and uses only generated fixtures. The orchestrator adds `verify:ghidra:psx-import` in package.json as `npm run build:cached && node scripts/verify-real-ghidra-psx-import.mjs`; this is a new command, not an existing gate. Use existing `GHIDRA_INSTALL_DIR` and `JAVA_HOME`. Optional new `REA_PSX_IMPORT_PROOF_CAPTURE_DIR` must be absolute and point under ignored local evidence; report only explicit selected environment fields, never the ambient environment.

Steps: execute baseline, declared-registers-fill and trailing-bytes through actual production stdio MCP `open_binary`, health/session observation and `close_binary`; exercise the established CLI `node scripts/rea.mjs inspect-native-load-image <generated-fixture> --provider ghidra --json` and assert the same unsupported-with-observations scope (no verified result). Require explicit ghidra binding/profile, before/post observed agreement, omitted options, unchanged source digest, unsupported load-image verification, gated function query and awaited cleanup. Generate policy-negative alternate-bank, crossing-RAM-end, overlapping fill and nonzero data-declaration inputs; assert refusal before provider process allocation. Simulated missing/ambiguous installations are P2-21 evidence; do not rename/remove installed assets to provoke failure. Run existing real DOS and COM lanes on the same host for changed launch regression.

Required report: source SHA, profile digest and full canonical parameters, code/plan HEAD plus dirty-diff state, host/Ghidra/Java identity, exact argv with credential redaction, supplied/default/effective separation, loader selector/class/code source, selected analyzer assets, pre-analysis completion marker, authenticated post-analysis agreement and target-bound successful analysis report (terminal import report separately if observed after close), unsupported/unknown facets, snapshot source hashes before/after, cleanup status and verified empty lineage. No binary payloads or tokens. Import failure with zero exit is a negative assertion, never success. Private observer record/program identity and authenticated final session must agree. If provider APIs differ or facts cannot be observed, stop dependent admission work and report evidence; no fallback.

Acceptance: all three production cases, policy-negative cases and DOS/COM regressions pass on macOS. Linux is a separate named unperformed gate if no authorized suitable host is available, not inferred from macOS or simulated platform tests. Neither host run establishes MIPS semantics, source-backed provenance, patched AC3 behavior, installed-package operation, or fresh-client discovery. Relevant architecture: ephemeral ownership and testing real-toolchain lane guidance.

### P2-22 correction — capture coordinates and cleanup ownership (2026-10-09)

This bounded replan follows two failed verifier capture assumptions; it changes the verifier contract only. P2-22 test-engineer owns `scripts/verify-real-ghidra-psx-import.mjs` and its results/runbook updates; the orchestrator owns state reconciliation. No runtime TypeScript, Java, descriptor-lifetime or provider API changes are authorized by this correction. Read this saved section before implementing. The orchestrator reports 171 source checks and independent baseline public MCP/CLI plus direct production health agreement passing; these are partial evidence, not acceptance of the full matrix.

Preserve both failed reports unchanged: `docs/psx-local/phase-2-import-runs/run-TmQMni/report.json`, SHA-256 `95ca9fdcaae427b50570a274be92ef20a2f46e76730d196598485bb6cd8815de`, failed reading deleted `session.json`; `docs/psx-local/phase-2-import-runs/run-2Feacs/report.json`, SHA-256 `2ec73736e0b9d867e2813d9567e55bd6e9be9c687a3362709cc589e7cce9edba`, failed expecting the in-process provider beneath the child-only runtime directory. Both retain failed status and report workspace removal with empty verified lineage. The second report did not independently establish absence of the direct provider's exact root; preserve that limitation rather than retroactively upgrading its cleanup proof.

Source evidence: `ReaGhidraBridge.java` deletes its credential descriptor after reading it. `GhidraClient.ts` initializes `SESSION_ROOT = ghidraSessionRoot()` at module load and uses it as launch parent. Passing a separate environment object to an in-process provider does not relocate that already selected parent. Public child processes receive explicit `TMPDIR` before module loading; the direct provider's coordinates must instead come from its authenticated observation.

Ordered implementation contract:

1. Perform `captureRoot()` validation/creation and `codeIdentity()` before allocating the temporary verification workspace. Once `mkdtemp` succeeds, immediately establish the outer cleanup guard; runtime subdirectory creation and every subsequent fallible setup operation belong inside it. Early failure must not strand a workspace merely because the normal report loop has not started. Retain explicit capture coordinates as intentional evidence output, distinct from disposable runtime state.
2. Public MCP/CLI children retain their explicit dedicated runtime parent. Enumeration is allowed only within that verifier-owned directory, with the expected single live session root and matching public session run ID; never enumerate ambient temporary directories. For direct production health, obtain the absolute snapshot path from authenticated `psx_import.before.observed.source.snapshot_path`, require before/after source agreement, and derive the candidate root as its exact dirname. Register that candidate for post-close existence checks immediately, before subsequent fallible capture assertions. A candidate path is not by itself deletion authority.
3. Before treating a candidate as captured owned evidence, read only its fixed `ownership.json` and require its `run_id` to match the active authenticated run. Require retained argv to name exactly the same immutable snapshot via its `-import` argument, with expected selector, read-only/delete-project flags and omitted RAM overrides. Read the fixed before record, hash its exact bytes, verify run/profile/source correlation and snapshot SHA-256, and compare the record/digest with authenticated agreement in the direct lane. Preserve public and direct runs as separate evidence; do not join metadata merely because their fixture hashes match. Use filesystem identity semantics for path aliases and URI-aware parsing only for logged file URIs.
4. Capture while the provider is alive. Use ownership argv, canonical profile commitments, the private before record, authenticated health agreement where available and bounded fixed logs. Never read or retain `session.json`, credentials or transport tokens; do not add watchers, raw socket clients, guessed descriptor fallbacks or ambient scans. Preserve selected report/marker evidence as specified above; do not claim echoed profile parameters are observed effective state. Logs and records remain subject to existing size, identity and failure checks.
5. Every public client/transport and direct provider close must be awaited even after capture assertions fail. Attempt all owned closes despite an earlier close failure and retain primary plus cleanup errors. After direct close, check absence of the exact registered candidate root; a successful scan of the child-only runtime parent cannot substitute. Retain candidate roots whose identity could not be validated as unresolved coordinates, without deleting them. If direct startup fails before returning coordinates, use existing typed failure diagnostics/retained ownership where available and verified lineage; missing coordinates remain explicitly unknown, never an ambient search or invented exact-root proof.
6. Outer finalization checks all registered exact direct roots and the dedicated child runtime parent, completes verifier lineage supervision, and records cleanup failures without losing the primary failure or report. Recursive workspace deletion is permitted only for the exact verifier-owned workspace after all provider roots are absent and verified lineage is empty. Failed close, unreadable existence checks, retained roots or incomplete lineage keep `ok: false` and preserve needed ownership/evidence. A report-writing failure cannot skip already-required resource cleanup. Never manually remove a provider root merely to make absence assertions pass.

Acceptance: inspect the changed verifier for each pre-run and post-open failure path; rerun the existing actual synthetic matrix under P2-22 after integrating this bounded correction. A successful report contains separate public MCP, CLI and direct-boundary evidence for all required fixtures, exact direct-root absence after close, empty dedicated runtime directory, unchanged source/assets and verified empty lineage. Capture or cleanup errors remain failures. Reuse the existing focused/source checks when their files are unchanged; no runtime fallback or additional live diagnostic hypotheses are part of this correction. The final full matrix and DOS/COM gates remain required; no new user decision is outstanding. Preserve all earlier failed timing, alias and capture attempts alongside the new run, including `run-S42RyB/report.json` (the separately reported runtime alias failure).

### P2-90 — integration, bounded review and authorized delivery

Owner: orchestrator; one code-reviewer close review, optional issue-triage for actual findings. Dependencies: all tasks and required macOS evidence passing. Owned files: package.json, knip.json, docs/PLAN.md, docs/PROGRESS.md, docs/ISSUE_LEDGER.md, docs/ARCHITECTURE.md (refresh actual feature state), docs/ghidra-provider.md and docs/testing.md (document exact limited lane/policy). Own final plan revisions after planner handoff. Make configuration edits additive/idempotent and retain local backups without committing them. Regenerate metadata only if existing ownership requires it; no arbitrary generated edits.

Integrate Java files into explicit package files list, new verifier script entry and knip entry only as needed. Confirm no new runtime dependency or Turbo configuration change. Run checks below and inspect complete diff. Delegate one close review focused on admission/profile/startup/cleanup, unavailable claims and regression boundaries; give this plan and evidence paths. Resolve blocking findings and re-review only fixes. After three failed diagnostic hypotheses or roughly fifteen minutes without progress, or two unsuccessful correction rounds, preserve evidence and re-plan dependent work.

PSX-006 may close as the verified default-only production policy with overrides explicitly unsupported; its third-party defect and original failure remain historical evidence. PSX-002 closes only after Phase 2 required technical and authorized delivery criteria. PSX-007 remains open with no altered source-provenance claim. Capture deferred nonblockers locally with stable IDs, evidence, severity, disposition and acceptance. No GitHub issue operations.

If phase completion/delivery is authorized, finalize state and ledger first, check final content, stage specific intended files and inspect staged diff, Conventional commit, push phase branch and open/update PR to Troll-Phace/rea. Present concrete PR and wait for user approval before merge; do not enable auto-merge. Then verify actual head/checks, merge normally and confirm remote outcome/main synchronization. Necessary documentation-only post-merge reconciliation follows existing policy. Planning-only authority does none of this.

## Scheduling and exact verification matrix

Safe parallelism: after P2-00, P2-11 implementation and P2-21 independent test-fixture preparation can overlap only after the named type contract freezes; tests must not edit backend files. P2-12 follows P2-11 wire-contract freeze; its TypeScript lifecycle and Java observation halves may run concurrently under disjoint backend ownership. Integrate their startup contract before boundary/real acceptance. P2-21 boundary work can run alongside P2-12 on disjoint files. P2-22 starts only after integration and passing focused tests. Orchestrator package/state edits are serialized with workers. Cap concurrent children at three or host limit. No additional planner or recursive review program.

Prepend the existing repository-local toolchain for commands:

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
```

Existing commands below gain new file arguments only after those files are created:

```sh
npm run test:local -- src/ghidra/GhidraPsxLoader.test.ts src/ghidra/GhidraAnalysisProfile.test.ts src/ghidra/GhidraInstallation.test.ts src/ghidra/GhidraDoctor.test.ts src/ghidra/GhidraProvider.behavior.test.ts src/ghidra/GhidraSessionValues.test.ts src/ghidra/GhidraSnapshotCache.test.ts
npm run test:focused -- tests/boundary/providers/ghidra/ghidraLauncher.test.ts tests/boundary/providers/ghidra/ghidraClient.test.ts tests/boundary/providers/ghidra/ghidraPsxImport.test.ts tests/boundary/mcp/ghidraPsxImport.test.ts tests/boundary/cli/ghidraPsxImport.test.ts
npm run test:local -- src/domain/psxExe.test.ts src/ghidra/GhidraLoadImageValues.test.ts src/ghidra/GhidraDosComLoadImage.test.ts
npm run build:cached
npm run check
npm run lint
npm run format:check
npm run docs:check
npm run verify:test-discovery
npm run verify:package
npm pack --dry-run
```

The runner's `scripts/lib/development-tests.mjs` explicitly rejects boundary paths in local mode; use focused for all provider/CLI/MCP boundary paths above. `npm run check` is framework verification and includes static checks, not behavior. Lint/format may be recorded as covered by the full check when its output proves they ran at the same content. `check:pr` is optional. If public schemas change despite this provider-only design, add existing `npm run mcp-catalog:generate`, `npm run mcp-catalog:check` and focused `tests/boundary/mcp/toolSchemaValidity.test.ts`; do not edit ignored catalogs. New tests require discovery exactly once.

Authorized real macOS commands, after implementation:

```sh
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:psx-import
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:dos
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home npm run verify:ghidra:com
```

Only the first npm script is proposed. Verify existing host coordinates still match before use. Do not rerun the old research probe as a substitute for production open/close. Package checks prove distribution integrity and simulated integration; real provider evidence remains separate. Keep reports/fixtures/projects in ignored directories and await cleanup even when preserving diagnostic logs.

## Gates, risks and result contract

No unresolved user product decision remains for this scoped plan. Required pre-execution gate is user Phase 2 implementation authorization. Required technical gates are the actual Java observer compiling on the selected Ghidra, effective RAM property and class/resource selection agreement, and macOS production open/close. These are testable implementation gates, not permission to invent alternative behavior. If selected resources cannot be modeled, RAM facts cannot be observed, or changed import behavior violates this contract, mark the affected task blocked and request a bounded replan; independent tests/docs may continue. Do not silently expand loader policy or substitute equality for provenance.

Risks: conservative installation hashing can cost startup time and overinvalidate snapshots; stream/cancel it and measure rather than silently cache stale identity. Runtime ClassSearcher resolution can differ from directory inventory; require observed code source. External concurrent installation mutation cannot be made impossible without controlling third-party files: before/after consistency checks detect ordinary changes but do not claim protection against hostile ABA modification. User extension discovery is intentionally isolated; a GUI-only PSX extension is missing for this production lane. Phase 1 measured only three fixtures on one host, so broader policy needs negative boundary tests and the production lane. Generic doctor health is not PSX readiness.

Each implementor returns: task IDs, files changed, concrete contract/behavior changes, exact commands and outcomes, evidence/report paths and SHA/profile identities, unresolved/unknown facets, cleanup and retained ownership, issue mapping, and any requested plan revision. Distinguish source tests, simulated boundaries, real host evidence, package integrity and delivery status. Report warnings separately from failures. Orchestrator records final HEAD and marks affected verification stale after relevant edits; changes to code, Java resources, asset inventory, policy or profile expectations require rerunning affected behavior/real lanes. Documentation-only corrections do not retroactively invalidate unchanged measured code, but final formatting/link/content gates still apply.

Completion means the saved contract is implemented within its scope, target-specific refusal and startup agreement pass, macOS synthetic production and launch regressions pass, bounded review has no unresolved blocker, and the explicitly authorized delivery endpoint is reached. Planning completion alone means only this file was saved, reviewed and linked.
