# Phase 1 — PS-X EXE identity and measured loader contract

Batch: `psx-support-2026-10`. Status: execution contract authorized by the user's “begin”; Phase 1 technical acceptance and bounded review passed. [PR #1](https://github.com/Troll-Phace/rea/pull/1) is open; approved merge remains pending; [measured results](phase-1-results.md) freeze the downstream research contract.

Shared plan: `docs/active/phase-1-plan.md`. Astra/low produced this contract; the orchestrator persisted it because the current planner runtime was read-only. The orchestrator owns review and subsequent state updates. Local issue: **PSX-001**. No batch rollover applies.

## Outcome and authority

Phase 1 has two required outcomes:

1. REA recognizes supported PS-X EXE header layouts as `format: "ps-x-exe"` and `architecture: "mips"` consistently across target resolution, generic evidence, snapshots and advertised schemas, while every deep provider explicitly refuses PSX analysis.
2. An original generated fixture establishes the actual behavior of the installed PSX loader through disposable Ghidra headless imports, including its identity, options, mappings, source provenance, entry/register observations and cleanup.

Phase 1 does **not** enable deep-provider PSX analysis. Existing neutral target sessions under `auto` may retain PSX identity for provider-independent operations with no deep binding; explicit deep-provider selection rejects PSX. Phase 1 does not implement deterministic production import, load-image attestation, MIPS instruction semantics, generic MIPS ELF/PE support, Windows PSX support, overlays, emulator workflows, extraction, or local AC3 analysis.

The user subsequently authorized Phase 1 with “begin,” including its synthetic loader measurements and phase delivery through a PR. The user separately authorized repository-local pinned Node/npm installation after automatic approval review rejected it. Preserve the existing intentional harness work. Merge requires approval of the concrete PR; this plan grants no new authority.

## Reconciled baseline and evidence

Planning baseline: `main == origin/main` at `7aa4d768`, with intentional uncommitted harness/documentation changes. Preserve these changes. The orchestrator independently verified Node `24.16.0`, npm `11.13.0`, and absent `node_modules`; required versions remain Node `24.18.0` and npm `11.16.0`.

Repository inspection established:

- `src/domain/binaryTarget.ts` currently returns `Result<ExecutableMetadata, string>`.
- `src/application/BinaryTargetResolver.ts` reads a bounded 4,096-byte executable prefix, passes actual file length to the parser, hashes through 64 KiB chunks, verifies file identity/state, and awaits handle closure.
- Filename-based artifact recognition currently precedes executable recognition. Exact PSX magic must not be obscured by `.js`, `.map`, `.plist`, `.asar`, or implicit `.hop` classification.
- Ghidra has an architecture allowlist, but Hopper and IDA accept broad executable categories. Adding recognition alone would accidentally admit PSX to those providers.
- Generic format/architecture enums are repeated in snapshot, evidence and output schema modules.
- `HopperAnalysisProfile.ts` has exhaustive format/architecture handling; `HopperMachOImage.ts` indexes an x86/ARM CPU map with `BinaryArchitecture`. These need honest narrowing after adding `mips`.
- `ArtifactGraphConstruction.ts` independently classifies storage bytes. Its PSX classification should share the pure structural parser.
- `src/artifacts/ArtifactHash.ts` already retains an 8,192-byte classification prefix and the actual byte count, sufficient for the fixed PSX header. Keep this existing bound; no additional full-payload classification allocation is needed.
- `runOwnedCommand` in `src/process/OwnedCommand.ts` provides supervised, bounded execution with retained cleanup failures. Reuse it for the development probe.
- Existing verification-only Java scripts live under `tests/conformance/ghidra/`; they are not packaged runtime assets.

References: root `AGENTS.md`, phase-plan skill and agent configuration, `docs/PROJECT.md`, `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/ARCHITECTURE.md`, `docs/architecture.mermaid`, `docs/tool-design.md`, `docs/testing.md`, `CONTRIBUTING.md`, `docs/standards/CODE_STYLE.md`, `docs/standards/TESTING.md`, `framework.json`, `docs/ISSUES.md`, and `docs/ISSUE_LEDGER.md`. No nested `AGENTS.md` was found in the affected source, scripts or tests subtrees.

No local game executable or game manifest was read. No application checks, imports or installations were performed during planning.

### Static installed-loader evidence

The following are **source/manifest observations**, not runtime confirmation:

Installed extension root:

```text
/opt/homebrew/Cellar/ghidra/12.1.4/libexec/Ghidra/Extensions/ghidra_psx_ldr
```

- `extension.properties` declares `name=ghidra_psx_ldr`, description `Loader for PSX executables`, author `DrMefistO`, and version `12.1.4`. The release label `2026.10.03` comes from prior handoff; this manifest does not establish it.
- `lib/ghidra_psx_ldr-src.zip!/src/main/java/psx/PsxExe.java`, lines 13–30 and 55–68, declares the eight-byte signature, 0x800 header, little-endian fields, and additional raw declarations at offsets `0x20/0x24`.
- `lib/ghidra_psx_ldr-src.zip!/src/main/java/psx/PsxLoader.java`, lines 151–179, gives candidate class `psx.PsxLoader`, name `PSX Executables Loader`, language `PSX:LE:32:default`, compiler `default`.
- The same source, lines 185–208, declares custom RAM base/size options and command-line suffixes `-ramStart` and `-ramSize`. Exact accepted headless syntax and value behavior remain a live gate.
- Lines 228–250 contain a RAM-base adjustment and a GUI-dialog path when a conflicting nondefault base is supplied.
- Lines 269–309 create an entry function and may derive GP from instructions when the declared GP is zero.
- Lines 1150–1159 use stream-backed `createMemoryBlock`; explicit `FileBytes` provenance must be measured rather than assumed.
- `data/languages/mips.ldefs` declares the candidate language/compiler and references processor, compiler and SLA assets.
- The extension includes PsyQ data archives, signature data and scripts. Effective interpretation assets must be inventoried for the downstream profile contract.

Live confirmation must identify the actually loaded class and code-source JAR, not merely repeat source constants. A source ZIP need not prove the behavior of its neighboring JAR.

## Decisions fixed for implementation

### Parser and policy contract

Create `src/domain/psxExe.ts`, with no filesystem or provider dependencies:

```ts
interface PsxAddressExtent {
  readonly start: number;
  readonly size: number;
  readonly endInclusive: number;
}

interface PsxExeHeader {
  readonly headerBytes: 0x800;
  readonly fileBytes: number;
  readonly payloadFileOffset: 0x800;
  readonly payloadBytes: number;
  readonly trailingBytes: number;
  readonly initialPc: number;
  readonly initialGp: number;
  readonly payloadAddress: number;
  readonly payloadExtent: PsxAddressExtent | null;
  // Raw declarations only; no initialized-data interpretation in P1.
  readonly declaredDataAddress: number;
  readonly declaredDataBytes: number;
  readonly fillAddress: number;
  readonly fillBytes: number;
  readonly fillExtent: PsxAddressExtent | null;
  readonly stackBase: number;
  readonly stackOffset: number;
  readonly initialSp: number | null;
}

type PsxExeParseError = {
  readonly kind: "malformed";
  readonly code:
    | "signature"
    | "file_size"
    | "header_truncated"
    | "payload_truncated"
    | "payload_address_overflow"
    | "fill_address_overflow"
    | "stack_address_overflow";
  readonly reason: string;
};

type PsxExePolicyReason = {
  readonly code: "empty_payload" | "unaligned_entry" | "entry_outside_payload";
  readonly reason: string;
};

type PsxExePolicy =
  | { readonly status: "eligible" }
  | {
      readonly status: "unsupported";
      readonly reasons: readonly PsxExePolicyReason[];
    };

hasPsxExeSignature(bytes: Buffer): boolean;
parsePsxExeHeader(
  bytes: Buffer,
  fileSize?: number,
): Result<PsxExeHeader, PsxExeParseError>;
inspectPsxExePolicy(header: PsxExeHeader): PsxExePolicy;
```

`eligible` means eligible under the initial header policy; it does not mean any REA provider supports it.

Use the existing `Result`, `ok` and `err` functions. Do not add a new global exception family or change unrelated parser error contracts.

Ordered structural behavior:

1. Require exact bytes `50 53 2d 58 20 45 58 45`. Avoid ASCII decoding that masks high-bit differences.
2. Reject an unsafe, negative, noninteger file length or one smaller than the supplied buffer.
3. Require at least `0x800` available header bytes and actual file length.
4. Read unsigned little-endian declarations: PC/GP at `0x10/0x14`, payload address/size at `0x18/0x1c`, raw data address/size at `0x20/0x24`, fill address/size at `0x28/0x2c`, stack base/offset at `0x30/0x34`.
5. Require `0x800 + payloadBytes <= fileSize`.
6. For nonempty payload/fill, compute `start + size - 1` using ordinary safe arithmetic and reject values above `0xffffffff`. Do not use signed bitwise arithmetic.
7. For nonzero stack base, require `base + offset <= 0xffffffff`; expose that sum as `initialSp`.
8. For zero stack base, preserve the offset and return `initialSp: null`.
9. Return trailing bytes separately. Do not consume them as payload.

The raw data declarations at `0x20/0x24` are preserved because the inspected loader reads them. Their meaning is not independently validated here; do not create a data extent, load them, or reject the file merely because they are nonzero.

Policy evaluation occurs **after** structural parsing and returns all applicable reasons in stable order: empty payload, unaligned PC, PC outside the nonempty payload. Do not report “outside payload” redundantly for an empty payload.

No PSX RAM window, sector alignment, filename, checksum, physical alias or GP validity restriction is added in Phase 1.

### Mapping through existing target errors

Keep `parseExecutableHeader`’s existing return type:

- Structural failure becomes `err("malformed PS-X EXE: " + reason)`.
- Policy failure becomes `err("recognized PS-X EXE is unsupported by the initial import policy: " + joinedReasons)`.
- Eligible headers produce exactly:

```ts
{
  format: "ps-x-exe",
  architecture: "mips",
  availableArchitectures: ["mips"],
}
```

`BinaryTargetResolver` continues wrapping parser failures in `BinaryTargetError`. Do not extend `BinaryTargetError.constraint` or the global error schema solely for PSX.

Encode format/architecture correlation in both `BinaryTarget` and `ExecutableMetadata`: PSX is MIPS-only; existing formats keep the existing x86/ARM subset. Generic Evidence subjects still retain their source-declared architecture. The managed graph service's subject forwarding helper should use existing `EvidenceSubjectTarget` rather than a duplicated local architecture union; managed analysis schemas/support remain unchanged.

The pure parser preserves declared facts even when policy rejects them. Public target resolution remains an admission operation; it need not fabricate a successful target for an unsupported layout.

### Classification precedence

Preserve explicit `formatHint: "dos-com"` and explicit `targetKind: "database"` behavior.

For automatic detection, exact PSX signature takes precedence over filename-derived artifacts and implicit `.hop` database selection. A full signature with a malformed header must return its PSX error, not fall through to a suffix classification.

Retain the existing 4,096-byte executable prefix and bounded hashing. Detection must not allocate or read the declared payload to classify it.

Replace the two broad `Exclude<BinaryTarget["format"], ...>` artifact helper types with a positive alias derived from `Extract<BinaryTarget, { kind: "archive" | "artifact" }>["format"]`. This fixes the owning representation instead of perpetually appending every future executable format to exclusions.

### Provider rejection

Add an explicit PSX guard after target-kind validation and before architecture, host-specific import or provider setup work in:

- `GhidraProvider.inspectTargetSupport`
- `HopperProvider.inspectTargetSupport`
- `IdaProvider.inspectTargetSupport`

Return:

```ts
{
  status: "unsupported",
  code: "target_format_unsupported",
  reason: "PS-X EXE is recognized, but PSX analysis is not supported by this REA provider.",
  diagnostics: /* existing target diagnostics */
}
```

Provider-specific wording may name the provider; it must not advise a working alternative.

Keep Ghidra’s architecture allowlist unchanged. Do not make ordinary Ghidra availability depend on PSX extension presence. No profile resolution or client creation may occur after selection rejects the target.

## Task P1-00 — establish the authorized execution baseline

**Owner:** orchestrator.

**Dependencies:** explicit implementation authority.

**Owned state paths:** `docs/PROGRESS.md`, `docs/ISSUE_LEDGER.md`; branch/workspace reconciliation.

**Exclusions:** global upgrades, modifying Java installations or GUI wrappers, disc/game access.

Steps:

1. Reconcile current Git status and preserve all existing work.
2. Create the phase branch without resetting the worktree.
3. Recheck `.nvmrc`, `package.json#packageManager`, `node --version`, `npm --version` and dependency presence.
4. Select the pinned toolchain using an existing installation. If unavailable, report the prerequisite; do not install unrelated software as a side effect.
   The user subsequently authorized the specific exception to install Node 24.18.0/npm 11.16.0 under ignored `.agent-runtime/toolchain`; use its `node_modules/.bin` first on PATH for phase commands. Do not change global software or provider installations.
5. Once authorized prerequisites are available, run `npm ci`.
6. Record PSX-001 as in progress and note exact baseline/toolchain.

Acceptance: exact pinned versions recorded, locked dependencies installed, baseline failures separated from Phase 1 failures. No unrelated work lost.

Checks: `git status --short`, `git branch --show-current`, `node --version`, `npm --version`, `npm ci`. Expected: preserved changes, phase branch, pinned versions and successful locked installation.

References: `CONTRIBUTING.md`, project commands, root authority and delivery rules.

## Task P1-11 — parser, target resolution and generic identity

**Owner:** backend-dev, `gpt-6.1-sol/high`.

**Dependencies:** P1-00; parser contract above.

**Exclusions:** provider import enablement, public new tools, instruction/load-image contracts, generic MIPS parsing.

Exact owned paths:

Create:

- `src/domain/psxExe.ts`
- `src/domain/psxExe.test.ts`

Edit:

- `src/domain/binaryTarget.ts`
- `src/domain/binaryTargetTypes.ts`
- `src/application/BinaryTargetResolver.ts`
- `src/domain/analysisSnapshot.ts`
- `src/domain/evidence.ts`
- `src/domain/artifactGraph.ts`
- `src/contracts/toolOutputSchemaPrimitives.ts`
- `src/contracts/toolOutputSchemaGroups.ts`
- `src/artifacts/inventory/ArtifactGraphConstruction.ts`
- `src/domain/binaryTarget.test.ts`
- `src/domain/analysisSnapshot.test.ts`
- `src/domain/evidence.test.ts`
- `src/domain/artifactGraph.test.ts`

Ordered work:

1. Implement and test the pure parser and separate policy evaluation.
2. Add `ps-x-exe` and `mips` to provider-neutral target identity.
3. Integrate header recognition before generic unsupported detection.
4. Correct automatic detection precedence and artifact helper typing in the resolver.
5. Add format/family to generic evidence, snapshot, target output and artifact schemas.
6. In `classifyArtifactBytes`, use the shared signature/parser: structurally valid PSX is `ps-x-exe`, including policy-unsupported layouts; exact-signature malformed PSX is `unknown`. Do not apply provider admission policy to artifact content identity.
7. Preserve serialized identities through domain round trips.
8. Check all affected exhaustive handling with typecheck. Do not broaden managed, Mach-O, DOS load-image or platform-specific contracts.

Required cases:

- Exact signature versus near matches/high-bit byte mutations.
- Complete signature followed by 8-, 55-, and 2,047-byte truncations.
- Header-only zero payload: structural success, policy rejection.
- Payload exactly fits file; one-byte short file; trailing bytes.
- PC at payload start, last aligned address, end-exclusive, before start, and misaligned.
- High-bit addresses remain unsigned.
- Extent ending exactly at `0xffffffff`; one-byte wraparound.
- Fill size zero versus wrapping nonzero fill.
- Stack sum exactly at max, overflow, zero base with nonzero offset.
- Nonzero raw data fields survive without invented semantics.
- 4,096-byte probe with a larger actual file length succeeds without full payload bytes.
- Unsafe/inconsistent file length fails.
- MIPS ELF machine 8 and representative MIPS PE remain unsupported.
- Existing non-PSX snapshots/evidence remain accepted.

Acceptance evidence: parser branch assertions, stable malformed/unsupported messages, exact identity round trips, unchanged existing format behavior.

Existing commands:

```bash
npm run test:local -- src/domain/psxExe.test.ts src/domain/binaryTarget.test.ts src/domain/analysisSnapshot.test.ts src/domain/evidence.test.ts src/domain/artifactGraph.test.ts
npm run check
```

Expected: tests pass; static checks pass after P1-12’s dependent narrowing changes are integrated.

References: parser contract, `docs/ARCHITECTURE.md`, inward dependencies in `architecture.mermaid`, testing/code standards.

## Task P1-12 — reject PSX before every deep-provider launch

**Owner:** same backend-dev as P1-11.

**Dependencies:** P1-11 target identity.

**Exclusions:** loader discovery, profile fingerprint implementation, runtime Java bridge changes, provider feature claims.

Exact owned paths:

- `src/ghidra/GhidraProvider.ts`
- `src/ghidra/GhidraInstallation.ts` (type-safe architecture-table comparison only)
- `src/application/managed/ManagedApplicationGraphService.ts` (generic Evidence subject return annotation only)
- `src/hopper/HopperProvider.ts`
- `src/ida/IdaProvider.ts`
- `src/hopper/HopperAnalysisProfile.ts`
- `src/hopper/HopperMachOImage.ts`
- `src/ghidra/GhidraProvider.behavior.test.ts`
- `src/hopper/HopperProvider.test.ts`
- `tests/composition/idaProvider.test.ts`
- `tests/composition/analysis-sessions/providerBinding.test.ts`

Ordered work:

1. Add explicit PSX target-format rejection in all three providers.
2. Extend Hopper’s format switch with the unsupported PSX branch.
3. Narrow Hopper architecture before computing a loader flag; never invent a MIPS flag.
4. Narrow the FAT64 CPU lookup to its supported x86/ARM keys before indexing. Reject an impossible unsupported architecture through the existing typed result rather than assertion/cast.
5. Test explicit provider selection and deterministic automatic selection using recording factories. Assert no profile resolver/client factory is invoked for PSX.
6. Preserve ordinary Ghidra availability regardless of PSX loader installation.
7. Align existing consumers with correlated target variants: use type-safe iteration for installation architecture membership instead of a union-array `includes` call, remove unreachable Hopper format handling after its MIPS guard, and reuse the generic Evidence subject type at the managed service forwarding boundary. Do not broaden managed-provider schemas or drop declared source facts.

Edge behavior: supported/unsupported hosts still refuse PSX; unavailable provider configuration does not result in fallback import; malformed PSX fails at target resolution before provider selection.

Acceptance: every deep provider rejects with `target_format_unsupported`; no deep launch/binding or successful explicit deep-provider session; `auto` retains existing unbound target-session semantics, with native deep operations unavailable. Existing DOS/ELF/PE/Mach-O admission tests pass.

Existing commands:

```bash
npm run test:local -- src/ghidra/GhidraProvider.behavior.test.ts src/hopper/HopperProvider.test.ts tests/composition/idaProvider.test.ts tests/composition/analysis-sessions/providerBinding.test.ts src/ghidra/GhidraInstallation.test.ts tests/composition/analysis-sessions/managedApplicationGraph.test.ts
npm run check
```

References: provider registry/session architecture, root no-fallback rule, existing provider rejection contracts.

## Task P1-13 — filesystem and advertised-schema acceptance

**Owner:** test-engineer, `gpt-6.1-sol/high`.

**Dependencies:** P1-11/P1-12 merged locally and contract frozen.

**Exclusions:** changing implementation contracts independently, real-provider support claims, full PSX CLI/MCP analysis journeys reserved for later phases.

Exact owned paths:

- `tests/boundary/filesystem/binaryTarget.test.ts`
- `tests/boundary/filesystem/artifactInventoryRegularRoot.test.ts`
- `tests/boundary/mcp/toolSchemaValidity.test.ts`
- `tests/boundary/mcp/outputSchemaSemanticConstraints.test.ts`
- `tests/boundary/mcp/toolErrorSchemaDelivery.test.ts`

Use existing test temporary-directory ownership helpers. Do not introduce independent temporary-root cleanup conventions.

Ordered work:

1. Materialize original PSX headers/payloads using local immutable test builders; no game-derived bytes.
2. Verify extensionless and misleading-suffix resolution, including implicit `.hop`.
3. Verify explicit DOS COM and explicit database selection retain caller authority.
4. Assert exact-signature malformed inputs do not fall through to artifact recognition.
5. Cover actual file size larger than the header probe, unchanged digest/source path, cancellation and existing filesystem failure behavior.
6. Verify standalone artifact inventory retains PSX content identity and preserves uncertainty for malformed input.
7. Obtain converted SDK schemas using the existing harness and named tool contracts. Validate their declared dialect and compile with the repository’s existing validator.
8. Validate PSX/MIPS identity shapes against `open_binary` and relevant session schemas as **contract examples**, not real successful PSX sessions.
9. Exercise provider rejection/error projection through existing transport tests. Explicit Ghidra/Hopper/IDA selection rejects with no deep binding; `auto` may open an unbound neutral target session, preserving identity and candidate rejections while native analysis returns its existing typed unavailable error. Close the neutral session before testing malformed open; a failed open must not be assumed to clear prior session state.

Acceptance: source resolver and artifact identity agree within their distinct policy roles; schemas admit new identity values; real public errors remain errors and do not publish fabricated success content.

Execution clarification: production stdio testing confirmed existing automatic selection returns an unbound neutral session when all deep candidates reject. Preserve this behavior and assert no usable deep analysis; do not introduce a PSX-only router rejection or describe neutral identity success as provider support.

Existing commands:

```bash
npm run test:focused -- tests/boundary/filesystem/binaryTarget.test.ts tests/boundary/filesystem/artifactInventoryRegularRoot.test.ts
npm run test:focused -- tests/boundary/mcp/toolSchemaValidity.test.ts tests/boundary/mcp/outputSchemaSemanticConstraints.test.ts tests/boundary/mcp/toolErrorSchemaDelivery.test.ts
npm run verify:test-discovery
npm run mcp-catalog:generate
npm run mcp-catalog:check
npm run docs:check
```

Expected: all selected tests/checks pass; new tests are discovered; generated ignored catalogs are fresh. Do not commit ignored outputs.

Execution correction: the existing development runner rejects `test:local` for these boundary paths and requires `test:focused` with its artifact prerequisites. The command above reflects that observed routing; this is a plan correction, not a runner change.

References: `docs/testing.md`, `CONTRIBUTING.md`, tool-design schema rules, P1 identity contract.

## Task P1-21 — original fixture and development-only loader probe

Execution replan: [P1-21R default-option research continuation](phase-1-loader-supplement.md) supersedes the RAM-option stop condition only for its exact synthetic measurement matrix. Failed override evidence remains a downstream blocker.

**Owner:** test-engineer, `gpt-6.1-sol/high`.

**Dependencies:** P1-00. Static inventory and fixture preparation may overlap P1-11. Freeze fixture/header expectations before live execution.

**Exclusions:** production launcher/bridge edits, installed extension edits, NativeAOT protocol reuse, packaged probe assets, game bytes, GUI control.

Exact owned paths:

Create:

- `tests/conformance/ghidra/psx-exe-fixture.mjs`
- `tests/conformance/ghidra/ReaPsxLoaderContractProbe.java`
- `scripts/probe-ghidra-psx-loader.mjs`
- `scripts/lib/psx-loader-observations.mjs` (approved integration extraction: log/observer normalization and validation only; runner retains orchestration/resource ownership)

Edit:

- `tests/conformance/ghidra/README.md`

Local ignored evidence:

- `docs/psx-local/loader-contract.md`
- Unique per-run directories below `docs/psx-local/loader-contract-runs/`

These are source-owned development/conformance assets. Do not add them to `package.json#files`, `bridge/ghidra/`, or runtime packaging.

### Fixture interface

Export:

```js
buildPsxExeFixture(({ variant = "baseline" } = {}));
// -> { bytes: Buffer, expected: JSON-compatible object }
```

Supported variants:

- `baseline`
- `declared-registers-fill`
- `trailing-bytes`

Use a `0x800` header and `0x800` payload mapped at `0x80010000`; PC is `0x80010000`. Baseline GP/fill/stack declarations are zero.

Initialize the whole `0x1000`-byte baseline file to zero, write the exact signature at offset zero, and write header fields using `writeUInt32LE`. Raw data declarations are zero. Write these original words little-endian; file offset is `0x800 + address - 0x80010000`. Keep the byte oracle independent of the production parser.

| Address      | Word         | Instruction/purpose                              |
| ------------ | ------------ | ------------------------------------------------ |
| `0x80010000` | `0x27bdfff0` | `addiu sp, sp, -16`                              |
| `0x80010004` | `0xafbf000c` | `sw ra, 12(sp)`                                  |
| `0x80010008` | `0x0c004010` | `jal 0x80010040`                                 |
| `0x8001000c` | `0x24040007` | `addiu a0, zero, 7`; non-NOP call delay slot     |
| `0x80010010` | `0x3c088001` | `lui t0, 0x8001`                                 |
| `0x80010014` | `0x25080100` | `addiu t0, t0, 0x100`; data address construction |
| `0x80010018` | `0x91090000` | `lbu t1, 0(t0)`                                  |
| `0x8001001c` | `0x8fbf000c` | `lw ra, 12(sp)`                                  |
| `0x80010020` | `0x27bd0010` | `addiu sp, sp, 16`                               |
| `0x80010024` | `0x03e00008` | `jr ra`                                          |
| `0x80010028` | `0x00000000` | NOP return delay slot                            |
| `0x80010040` | `0x03e00008` | Callee `jr ra`                                   |
| `0x80010044` | `0x24820001` | `addiu v0, a0, 1`; non-NOP return delay slot     |

At `0x80010100` (file offset `0x900`), write exactly `52 45 41 2d 50 53 58 2d 50 31 00 7f 80 fe ff 55` (`REA-PSX-P1`, NUL and distinctive binary bytes). Unspecified bytes stay zero. No fixture instructions are executed.

`declared-registers-fill` changes only GP to `0x80010800`, fill address/size to `0x80011000`/`0x20`, stack base/offset to `0x801fff00`/`0x80`. Declared SP is `0x801fff80`; fill is `0x80011000..0x8001101f`, outside the payload. These are declarations to compare with observations, not proof of loader behavior.

`trailing-bytes` appends exactly `50 31 2d 54 52 41 49 4c de ad be ef 00 7f 80 ff` to the baseline. File size is `0x1010`, declared payload stays `0x800`, trailing count is `0x10`.

The expected object includes field values, payload file interval, declared virtual extent, code/data offsets and trailing byte count. Compute the file digest in the verifier from actual generated bytes.

Do not treat absence of fixture instruction analysis in Phase 1 as a Phase 4 success.

### Probe command interface

Proposed command after creation:

```bash
node scripts/probe-ghidra-psx-loader.mjs --output-dir /absolute/ignored/output/directory
```

Require:

- Explicit `GHIDRA_INSTALL_DIR`
- Explicit `JAVA_HOME`
- macOS or Linux host
- Absolute output directory; create a unique run subdirectory, never overwrite evidence
- No `--binary` option

The script generates its own fixtures. No user/game input is accepted.

Run `npm run build:cached` first so the script can reuse:

- `dist/ghidra/GhidraInstallation.js`
- `dist/process/OwnedCommand.js`
- `createVerifierRun` and `completeVerifierRun` from `scripts/lib/verifier-run.mjs`

Do not add a package command named as public PSX support. This is a loader research probe.

### Ordered probe implementation

1. Validate arguments and selected installation/Java before creating a project.
2. Read installed manifests and candidate assets; record digests and inventory without modifying them.
3. Inspect selected Ghidra’s loader API and installed PSX source to implement the Java probe against that exact version. Compile failure is a failed prerequisite, not evidence of missing loader support.
4. Generate fixture files in an owned private temporary root. Hash every source before launch.
5. Use supervised `runOwnedCommand` with argv arrays, unique run identity, deadline and bounded diagnostics. Pass only necessary explicit environment overrides; never serialize the inherited environment.
6. Perform one automatic-loader import as a discovery observation, then a separately owned explicit-loader import using the observed selector/language/compiler/options.
7. Run the verification Java script as a post-import observer. Use `-noanalysis` for the baseline import-only observation, then a separate ordinary-analysis run to identify analysis-dependent differences.
8. Capture exact arguments and loader/program facts for every run.
9. Verify source hashes after each import, including failures.
10. Await process settlement before project/root deletion; verify owned paths are absent.
11. Only after cleanup, finalize the success report. Cleanup failure makes the run unsuccessful and records retained resource paths for recovery.

Use the existing ownership API; do not implement PID/path-only process killing. Do not delete a root whose process cleanup remains unresolved.

Existing compiled process API and verifier identity helpers:

```js
import {
  runOwnedCommand,
  OwnedCommandFailure,
} from "../dist/process/OwnedCommand.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const run = createVerifierRun();
await runOwnedCommand(
  {
    command: analyzeHeadlessPath,
    arguments: argv,
    runId: run.run_id,
    expectedCommand: null,
    cwd: ownedWorkspace,
    env: explicitOverrides,
    hostEnvironment: process.env,
    platform: process.platform,
    signal,
  },
  { timeoutMs: 180_000, diagnosticBytes: 4 * 1024 * 1024 },
  { signal },
);
// Await exact-path root removal and verify absence after process settlement.
const finalRunIdentity = await completeVerifierRun(run);
// Include finalRunIdentity in the evidence report; never persist the ambient environment.
```

`runOwnedCommand` awaits supervisor stop, inspects its snapshot and disposes it. `OwnedCommandFailure` exposes `reason`, `snapshot`, `cleanupFailure` and `resources`. On non-null cleanup failure, preserve the root and report retained resources. On ordinary command failure with successful process cleanup, capture source digests and await filesystem cleanup. Finalize verifier lineage reporting on failure too; it supplements process ownership rather than replacing it. Never serialize `hostEnvironment`.

Resource bounds are verifier controls, not format limits: accept a configurable positive timeout with a documented initial default of 180 seconds per import; bound retained diagnostic output and fail explicitly on overflow. Record limits in evidence. Hash mapped bytes in chunks rather than allocating a block-sized buffer.

### Java observation contract

The script writes JSON to the exact supplied evidence path and never mutates imported bytes, annotations or register state.

Record:

- Ghidra version and selected Java/runtime identity.
- Actual loader class/name, code-source location, candidate inventory and load-spec information.
- Language/compiler IDs and executable format recorded by the program.
- Default option names, types, command-line names and serialized values; supplied/effective values separately.
- Enabled analysis options before/after analysis; relevant asset references.
- Image base, address spaces, all blocks, initialized state, permissions and mapped/overlay status.
- For each block/source range: original file offsets, source filename/identity, available `FileBytes` metadata and original-byte hashes; absent provenance explicitly null/unknown.
- Payload mapped-byte hashes in bounded chunks.
- External entry points and entry instruction availability.
- GP/SP register-context observations at relevant addresses, with absent values distinguished from zero.
- Fill-region mapping/initialization observations.
- Trailing-byte observations and whether any were mapped.
- Exceptions, incomplete enumeration and observation limitations.

Do not equate equal bytes with file provenance. Do not equate a GP derived by the loader with the raw header declaration. Do not label an uninitialized block as observed zero-filled runtime memory.

### Discovery and options gate

Confirm installation and user-extension lookup behavior for the selected Ghidra version from its own code/docs and actual runtime inventory. Record:

- Searched roots.
- Candidate manifests/JARs/language assets.
- Actual selected class code source.
- Duplicate candidate/loader/language identities.
- Whether duplicate resolution is observable or unresolved.

Do not install/remove duplicate extensions in the user’s real installation. If duplicates cannot be tested in an isolated environment, record that limitation and require downstream rejection when selection cannot be proven.

Use candidate values found in static source only as initial probe inputs. Confirm the no-GUI path and exact accepted RAM option syntax. Do not enter the source-observed dialog path deliberately. If explicit options cannot ensure unattended behavior, stop and report a Phase 2 blocker.

### Binding the actual imported loader

Additional static evidence is in the selected Ghidra `Ghidra/Features/Base/lib/Base-src.zip`:

- `ghidra/app/util/headless/HeadlessOptions.java:510–515` resolves the supplied loader name through `LoaderService.getLoaderClassByName`.
- `ghidra/app/util/opinion/LoaderService.java:97–103` matches the simple class name and takes the first match.
- `ghidra/app/util/headless/HeadlessAnalyzer.java:1560–1564` passes the resolved class into `ProgramLoader.loaders`.
- `ghidra/app/util/importer/ProgramLoader.java:487–497` logs `Using Loader:` and `Using Language/Compiler:` immediately before invoking the selected loader.

Use candidate selector `-loader PsxLoader`, whose live acceptance remains a gate. For explicit import, bind exact argv and the same process's loader/language log records to post-import resolution of `LoaderService.getLoaderClassByName("PsxLoader")`. Record class name, protection-domain code-source URL, class-resource URL and current program format/language/compiler/fixture identity. Hash the resolved JAR before and after; require agreement with inventory and reject ambiguous candidates or changed assets. This is combined proof grounded in the pinned headless implementation; class inventory alone is insufficient.

For automatic import, logs establish loader display name. Associate it with a class/code source only when runtime candidates make that association unique; otherwise retain ambiguous identity and fail the gate. Do not infer class identity from the expected extension name.

### Acceptance and commands

Existing prerequisite command:

```bash
npm run build:cached
```

Proposed live command:

```bash
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec JAVA_HOME=<verified-Temurin-25-home> node scripts/probe-ghidra-psx-loader.mjs --output-dir /Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/rea/docs/psx-local/loader-contract-runs
```

Replace the Java placeholder with the verified absolute selected home; never substitute the GUI Java 21 wrapper.

Expected: original fixture imports complete, runtime identity and observations are captured, before/after source digests match, every owned process/project/root is settled and removed, and the report names limitations. Nonzero exit, timeout, missing observation or cleanup failure is not success.

Manual/live acceptance is mandatory on the available macOS host. Linux remains a distinct unperformed lane unless actually executed there.

References: static evidence above, `src/process/OwnedCommand.ts`, existing real Ghidra verifier conventions, `tests/conformance/ghidra/ReaSwitchEvidenceProbe.java`, cleanup/testing rules.

## Task P1-22 — interpret the loader result and freeze the downstream contract

**Owner:** orchestrator, informed by test-engineer.

**Dependencies:** P1-21 real evidence.

**Owned paths:** `docs/active/phase-1-plan.md`, `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/ISSUE_LEDGER.md`; test-engineer supplies the local report.

**Exclusions:** production loader adaptation or weakening attestation semantics.

Steps:

1. Separate source-derived expectations from runtime observations.
2. Record the confirmed selector, class fingerprint, language/compiler, options, address interpretation, analysis assets, entry/register behavior and cleanup evidence.
3. Compare declared payload, trailing bytes and observed mappings across fixture variants.
4. Decide whether Phase 2 can proceed with the unmodified loader or requires an explicit adaptation plan.
5. Carry actual missing capabilities into PSX-002/PSX-003 dependency notes. Allocate a new local issue only for a distinct deferred finding after deduplication.
6. Store a concise versioned evidence summary with report paths/digests, commands, host and conclusions. Keep raw outputs/projects/payloads out of Git.

Critical outcome distinction:

- **P1 incomplete:** actual import was not executed, selected identity is ambiguous, required observations are missing without a meaningful measurement result, source integrity failed, or cleanup is unresolved.
- **P1 measured; P2/P3 blocked:** imports and observations completed correctly, but the loader lacks required provenance, mapping guarantees or unattended options. Phase 1 can finish its research objective while explicitly blocking downstream production work.
- **P1 measured; downstream viable:** evidence supports an explicit deterministic import plan, without claiming later attestation or public analysis already works.

If `FileBytes` provenance is absent, record that directly. Future attestation may not call the payload verified merely because its bytes equal the source. A producer-boundary adaptation and independent provenance evidence must be planned before claiming full source-backed coverage.

Acceptance: no guessed loader constants remain labeled confirmed; downstream blockers have concrete evidence and done criteria; technical Phase 1 outcome and shipping status remain separate.

## Task P1-90 — integration, bounded review and delivery

**Owner:** orchestrator. One code-reviewer at `gpt-6.1-sol/high`; issue-triage may inspect concurrently without writing shared state.

**Dependencies:** P1-11 through P1-22.

**Owned paths:** phase/progress/ledger documents and integration edits assigned explicitly after handoff.

Integration ownership addition: `knip.json` registers the new development-only probe as an explicit entry point; preserve the rest of its configuration and retain a local backup. This satisfies the existing unused-file gate without creating a public PSX-support package command or suppressing unused-code checks.
**Exclusions:** deeper audit, Phase 2 implementation, release publication, automatic merge.

Ordered steps:

1. Integrate backend identity/rejection work.
2. Run independent filesystem/schema acceptance.
3. Reconcile measured loader outcome and limitations.
4. Run final relevant checks.
5. Request one bounded close review covering parser arithmetic, classification precedence, provider gates, schema propagation, source preservation and probe ownership/cleanup.
6. Resolve blockers. Re-review only changed blocker fixes.
7. Deduplicate and record deferred findings; unresolved blockers keep dependent work blocked.
8. Update all progress/ledger wording before final-content verification.
9. Under future authorized phase-delivery scope, stage specific intended files, inspect staged diff, commit, push and open/update the PR in `Troll-Phace/rea`.
10. Present the concrete PR and wait for user approval before merging. After approval, verify current-head checks, merge, confirm remote result and reconcile documentation.

Final existing checks:

```bash
npm run check
npm run lint
npm run format:check
npm run verify:test-discovery
npm run docs:check
```

Also run the focused commands assigned above and the required live loader probe. `npm run check:pr` is optional if broader regression investigation warrants it.

If pre-commit or later edits change relevant content, rerun the affected checks. Preserve failure evidence rather than treating a previous passing head as current.

Delivery acceptance: final checks and review findings recorded; concrete commit/PR identifiers recorded when authorized; merge status remains pending until approved and verified. PSX-001 closes only when its complete technical and required delivery criteria are satisfied.

## Parallel groups and integration order

- **Group A:** backend-dev executes P1-11 then P1-12.
- **Group B:** test-engineer prepares P1-21 static inventory, fixture and probe independently. It does not edit backend-owned tests.
- **After contract freeze:** test-engineer executes P1-13 and the authorized real P1-21 lane.
- **Integration:** P1-11 → P1-12 → P1-13; P1-11/P1-12 form one compiling identity/rejection checkpoint rather than separately shipping an intermediate state. P1-21 feeds P1-22; all feed P1-90.
- Review and read-only triage can run together after implementation stabilizes. The orchestrator alone integrates shared state/ledger edits.
- No concurrent writers on any owned file. Every worker must preserve the other agents’ changes.

Each handoff returns:

1. Task IDs and exact files changed.
2. Contract decisions and deviations requiring replanning.
3. Commands, results and whether evidence is domain, boundary, schema, or real-provider.
4. Fixture/source/tool identities and report locations.
5. Before/after source digests and awaited cleanup outcome.
6. Remaining blockers, unavailable lanes and deferred findings.
7. Confirmation that no game bytes, raw payloads, provider databases or ambient environment were committed.

## Remaining gates and next action

The parser, identity propagation and deep-provider rejection are implemented and verified. The exact seven-case research matrix and cleanup passed; [Phase 1 results](phase-1-results.md) records observed loader identity, options, mappings, entries/registers, provenance, selected assets and limitations. PSX-006 blocks deterministic production option/profile admission; PSX-007 blocks source-backed attestation. Defaults-only import and matching payload hashes do not resolve those blockers.

One bounded close review found no new blocking or deferred findings. Final delivery follows P1-90: verify final content, commit/push the phase branch and prepare the concrete PR. Merge requires user approval. Later phases and Linux/local-game/package acceptance remain unperformed; Phase 2 needs a newly authorized plan using the measured facts.
