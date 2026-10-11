# Phase 5 verification results

Execution contract: [phase-5-plan.md](phase-5-plan.md), P5-R0 with bounded P5-R1/P5-R2/P5-R3/P5-R4/P5-R5/P5-R6/P5-R7/P5-R8/P5-R9/P5-R10/P5-R11/P5-R12/P5-R13/P5-R14/P5-R15/P5-R16/P5-R17/P5-R18, PSX-005.
The user authorized execution on 2026-10-10. Implementation and acceptance were completed on `codex/psx-phase-5`, from reconciled `main`
`d35f97c314cfb3f5a60f5ff00ce92b03a3784727`. Implementation commit `439f56c77e3fa9d85f2d668c3f9d625996ea077f` is delivered through user-approved [PR #5](https://github.com/Troll-Phace/rea/pull/5), merged at `1205e45502fe436ce05aff9601402da5b1951b00` on `2026-10-11T00:51:57Z`. Phase 5 is complete under P5-R18 macOS scope.

## Prerequisites and external gates

Pinned repository-local Node 24.18.0/npm 11.16.0 and locked dependency validation
pass. Current host is macOS arm64. Existing Ghidra 12.1.4, Temurin 25.0.4.1 and
PSX loader inspection report available; no software was installed. Selected
loader JAR SHA-256 is
`481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`;
selected code/data inventory digest is
`31db2c95632ade2fb2b15e3d7320f411125dc0e24fc26f65796aea7721fba869`.
These are read-only prerequisite observations, not native workflow acceptance.

The user confirmed no Linux host is available and subsequently removed Linux from completion gates on 2026-10-10 (P5-R18). Linux source and installed-package behavior remain unverified; these rows are optional and do not block delivery. All required macOS technical acceptance now passes. The three user-supplied fresh-client scenarios pass actual invocation/full snapshot review; trust transition and source-harness lifecycle remain separately unobserved. Complete selected patched Disc 1 smoke passes; earlier failures and historical scope decisions remain unchanged below.

## Gate status

| Gate                  | Status                                  | Evidence                                                                                                                                                          |
| --------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G1 public macOS       | renewed repaired candidate passes       | Complete fresh CLI/MCP, snapshots, negatives, native cancellation and cleanup.                                                                                    |
| G2 public Linux       | Optional; unverified                    | User-approved P5-R18 removes this completion gate; no Linux host available.                                                                                       |
| G3 installed package  | Complete fresh macOS acceptance passes  | Exact cold-tested tarball, all nine cases/45 fresh CLI comparisons/52 roots; source/assets/resources and cleanup pass.                                            |
| G4 local AC3          | Complete fresh macOS smoke passes       | All eight cases, five facets, snapshot, independently authenticated CLI image and exact CLI entry pass; no runtime/retail/Disc 2/overlay claim.                   |
| G5 fresh client       | Three actual synthetic scenarios pass   | Exact installed artifact, distinct completed chats, 39 successful calls matched to full snapshot Evidence; separate unobserved harness/trust/OS lifecycle limits. |
| G6 regressions/review | Required local renewals and review pass | Lifecycle/bookmark/local comparator controls and reviews, real producer/full image lanes, PSX import, DOS, COM and host-native renewal pass.                      |
| G7 delivery           | Passed; approved verified merge         | PR #5, approved head `23cd442d`, merge `1205e45502fe436ce05aff9601402da5b1951b00`; synchronized main and documentation reconciliation.                            |

PSX-008 diagnostic truncation and PSX-010 Mach-O named non-entry-label coverage
remain deferred and separate. Historical Phases 1–4 reports remain unchanged.

## Initial deterministic integration checkpoint

The six planned existing regression files passed 63 tests in 4.39 seconds with
`npm run test:focused -- tests/boundary/cli/ghidraPsxCli.test.ts
tests/boundary/mcp/ghidraPsxMcp.test.ts
tests/boundary/providers/ghidra/ghidraPsxOperationsVerifier.test.ts
tests/boundary/providers/ghidra/ghidraPsxImport.test.ts
tests/boundary/providers/ghidra/ghidraPsxLoadImage.test.ts
tests/boundary/filesystem/analysisSnapshot.test.ts`. This includes simulated
bridge CLI/SDK parity, named converted schemas, snapshot boundaries and the
independent oracle; it is not real-provider Phase 5 evidence.

Package-owner focused validation passed 14 tests, including actual supervised
child and filesystem isolation/cleanup failure cases. Typecheck and targeted
formatting passed; lint has no errors and one verifier file-length warning.
Integrated new public/local/package verification then passed 43 tests across
four files in 4.58 seconds (17 public, 12 local, 13 package and the existing
package-pack isolation test). Actual filesystem, SDK stdio and supervised-child
boundaries exercise failures; their controlled providers do not establish
native success. Test discovery finds all 714 files exactly once.
`npm run check` passed six tasks, formatting, typecheck, knip, metadata, resolved
module boundaries in 1,324 source files and architecture guards in 1,016 files.
Whole-repository lint reports 576 warnings and zero errors. Real native gates
and the bounded close review remain pending.
Configured framework validation and Git whitespace checks passed. They do not
establish fresh-client discovery or hooks.

`npm run docs:check` initially failed the existing invariant that localized
README documentation destinations match English. Required guide links were
added to all 16 localized provider sections; the fresh six-task check passed.
No catalog or generated skill output was hand-edited.

`npm run verify:package` passed with normal lifecycle hooks: 139 MCP tools, six
prompts, four setup clients, generated skill/reference checks and verified empty
process lineage. This is engine-independent installation evidence. Normal
`npm pack --dry-run --json` passed with 1,062 files; ignored inventory
`docs/psx-local/phase-5-regressions/package-dry-run.json` has SHA-256
`acda77d6b283e0e88d931e64e62878b4f3bc7db1d1370e912b03740175e0eb88`.
Neither check establishes installed PSX or fresh-client behavior.

After final transport-ownership and nested-error projection corrections, a fresh
full static check passed all six tasks and the four focused suites again passed
43 tests in 5.27 seconds. Complete logs are ignored under
`docs/psx-local/phase-5-regressions/final-{static,focused}.log`. An overlapping
artifact command was refused before test execution; its separate log is retained
and the serial retry passed. All tracked writers are frozen for G1; no native
result is claimed by this checkpoint.

## First real public macOS attempt

`npm run verify:ghidra:psx` failed in
`docs/psx-local/phase-5-public-runs/run-nAto4z/report.json`, SHA-256
`2c2df015fff7fa8b75e3b504c99ddc5018d5ae3f373b2acfedc01cec7b227757`.
Events 339–343 retain the actual `binary_overview` reply and Evidence before the
verifier's blanket `provider.id === "ghidra"` assertion failed on
`"rea-workflow"`. The fixed operation oracle returned before this additional
workflow call, but the required case and overall G1 remain failed. No snapshot,
CLI, policy or cancellation acceptance is claimed from this attempt.

Independent code/asset/source postchecks pass; exact runtime and workspace
cleanup pass, no owner remains unresolved and process lineage is verified empty.
This is a verifier identity contradiction pending bounded source-grounded R1
planning; no provider defect or environmental cause is asserted. G3 and G4
remain dependent on a fresh full G1 pass. The failed report remains immutable.

P5-R1 is saved, read back and reviewed. Independent source inspection and replay
of the parsed observation reproduce the verifier error: only `binary_overview`
in the frozen route matrix is a composed workflow. Its outer `rea-workflow`
revision-2 profile retains a committed Ghidra upstream equal to the recorded
native profile. R1 changes only named verifier identity and CLI startup binding,
plus runner revision labels and deterministic controls. Original outer Evidence
and native ownership remain intact. Actual raw named-Evidence replay and new
controls must pass before a fresh complete G1; relevant pre-correction verifier
checks are stale until rerun. No production/oracle/fixture changes are authorized.

R1 correction and integrated verification now pass: 62 focused tests across four
files in 6.02 seconds (35 public, 13 local, 13 package and one pack-isolation
test), plus the fresh six-task static check and architecture guards. The original
named SDK reply/catalog and observed native startup commitment pass offline
replay through the corrected real validator. Evidence remains unchanged;
independent session/profile mismatch, outer workflow digest used as native
startup identity and workflow-wrapped native Evidence are rejected.
Ignored replay report `docs/psx-local/phase-5-regressions/r1-evidence-replay.json`
has SHA-256 `680aa17985d5b3cdbbebef9092bd9d18c2ad4337aa75663bd99cc67db747cf0f`;
original event stream SHA-256 is
`d5a2b892cc2fd02c2f1676ae37db5ae07dcc5bf27de1ee62e86e0366360f83e4`.
This proves the verifier correction against actual producer output, not a new
native pass. All tracked writers are frozen for a fresh complete R1 G1.

## Fresh R1 real public macOS attempt

Fresh `run-CipH6a/report.json` has SHA-256
`21d636114ae45aaa6a1c0cbe0530bee89e3d5c1f71eb9bb72abf9d161792ddf8`.
The complete real MCP independent oracle and named workflow/native binding case
passes. The later strict-image extra-`document` negative fails the verifier's
error parser: event 376 retains the SDK's `isError:true` text refusal, while the
verifier assumes JSON and tests the resulting `SyntaxError` fragment.
The SDK rejects this input before the REA handler; no product acceptance of the
forbidden field is demonstrated. Overall G1 remains failed; snapshots, CLI,
remaining policy and cancellation gates remain unperformed.

Source/assets/code postchecks, exact cleanup and verified empty lineage pass;
no owner remains unresolved. The failed report remains immutable. Bounded R2
planning will fix the owning reply representation with actual SDK controls and
captured-reply replay before another full G1. No regex widening or replacement
of the production error algebra is authorized by this finding.

P5-R2 is saved, read back and reviewed. Installed SDK producer inspection
confirms strict input validation precedes the REA handler and returns plain-text
`isError:true`; typed application errors remain their JSON representation.
R2 separates unstructured wire-error observations from tagged REA errors and
permits only the exact strict-image SDK refusal in its deliberate negative mode,
with independent named-schema invalidity proof. Actual SDK/production-registration
non-dispatch controls and captured event 376 replay are required before another
complete G1. Relevant verifier checks remain stale during this correction.

## R2 deterministic and captured-reply checkpoint

The exact public/MCP/local focused suites pass 80 tests (52 public, 15 MCP,
13 local). The actual installed SDK and production named registration reject
the forbidden image field without advancing simulated provider queries or
Evidence, then dispatch a valid empty-input image query. This establishes SDK
admission, not native behavior. Typecheck and targeted formatting pass; lint
reports zero errors and 14 warnings, including two existing MCP depth warnings.
All 714 test files are discovered once.

Offline event 376 replay verifies the immutable R1 report/event digests before
decoding the actual reply against catalog event 6 and invocation 374. The exact
SDK refusal and independent additional-property schema proof pass; ordinary
and tagged-error modes, independent wrong-tool text and malformed JSON controls
reject. Raw event JSON remains unchanged. Ignored replay result
`docs/psx-local/phase-5-regressions/r2-admission-replay.json` has SHA-256
`20d2a1faa45c5f238e603b246a6fea001e03f864e5e542b6ad0073f724977259`.
No provider was allocated. Fresh full static/integrated checks precede the
complete R2 G1. A plan-formatting issue detected by the first static attempt is
corrected through the project formatter; that attempt is not a passing gate.

Final R2 integration passes all 94 tests in five focused suites (12.95 seconds),
including the package/owned-child controls. The fresh full static gate passes
six tasks, module boundaries and architecture guards. Its previous knip failure
identified a transitive SDK import; the helper now uses the declared client's
public Standard Schema validation export without dependency changes. Actual
captured-reply replay passes again with identical result digest after this
correction, saved separately as `r2-final-admission-replay.json`. Production,
bridge, original fixture and independent oracle have no Phase 5 diff. All tracked
writers are frozen for complete R2 G1; this checkpoint is not a native pass.

## Fresh R2 real public macOS attempt

`run-topqfE/report.json` has SHA-256
`54df1429b6136ad7d4a9475e7ea18c02d8af53ad9b98a3abf9ab1abdf6c4fa65`;
its event stream has SHA-256
`eb0f45b3aeb5060e9f462411f5a20c0b45e066baa308e615cd4da391bc864f64`.
The complete real MCP oracle and selector/capability refusal cases pass. The
four-family snapshot case fails: event 396 retains a saved snapshot with five
entries (four function dossiers and load image), without the required single
instruction or call-target cache entries. Event 397 records the exact assertion.
Overall G1 fails; later CLI, stale-snapshot and cancellation cases are unperformed.

Code fingerprints and installed assets are unchanged; recorded source checks
pass. Exact runtime/workspace cleanup passes with no retained roots/unresolved
owners and verified empty lineage. No remaining native session is active.
The immutable failure triggers bounded R3 producing-boundary diagnosis; no cache
or provider defect is yet asserted. G3/G4 remain dependent on a complete G1.

R3 is saved/read back and source-grounded: named instruction/call-target inputs
are document-scoped, and immutable caching requires an explicit string document.
Original address-only queries retain Evidence but are correctly not cacheable.
The existing Phase 4 four-family SDK control already supplies that selector.
The correction will observe actual public Program identity and use exact scoped
population/replay keys, preserving unscoped oracle/CLI calls and strict image
input. The identical local snapshot caller omission is included in bounded
R3 caller integration before any game run; no production cache change is needed.

Independent retained-snapshot replay verifies report/event/snapshot digests,
reproduces cache exclusion for actual retained instruction/call-target parameters,
and confirms existing image/dossier keys. A distinct policy-only explicit-document
counterfactual proves schema/cache eligibility without claiming it was observed
or executed. Historical bytes remain unchanged. Ignored proof
`docs/psx-local/phase-5-regressions/r3-cache-policy-replay.json` has SHA-256
`975ce444e3cf2ad17375e7ec161e3b230b952c851de140ebdd05aa511fff0d21`.
No native provider or game was opened for this proof.

R3 implementation and its final 93 focused controls pass (59 public, 16 MCP,
18 local; 8.56 seconds). Actual SDK/production-registration controls retain
unscoped Evidence, populate exact observed-document cache keys and replay four
synthetic/two local queries without recorded provider dispatch, measuring document
discovery separately. Changed Program identity fails with capture and cleanup.
Typecheck, knip, targeted formatting, discovery and whitespace pass; lint has
zero errors and 14 size/complexity/depth warnings. Original production, bridge,
fixture, oracle and dependency declarations remain unchanged by these corrections.
Root integrated checks and fresh full R3 G1 remain pending.

Final R3 integrated verification passes 156 tests across ten files in 13.39
seconds, including all required existing PSX regressions and current
public/MCP/local/package/pack-isolation controls. The full six-task static gate,
module boundaries and architecture guards pass. Production/bridge/original
fixture/oracle identity remains unchanged. All tracked writers freeze for fresh
complete R3 G1; no native acceptance is inferred from this deterministic gate.

## Fresh R3 real public macOS attempt

Report run-mVkFo2/report.json has SHA-256
aac9f62cbda87a8ce4202e0e96ed0416f7d7b7ac11196a12c2a76baeceef9c9e;
event stream SHA-256 is
64d1f23bc4ff1571ccd2644fddf765b0d6bd6a09713c3603bf46555d97430637.
The complete real MCP oracle, refusal cases, exact four-family scoped snapshot
replay and atomic stale-snapshot rejection pass. First fresh CLI image comparison
fails: the expected record was overwritten by cached MCP Evidence with the
truthful additional snapshot limitation. Original live MCP image is event 47,
cached image event 527 and fresh CLI image event 557. CLI remainder/policy and
cancellation cases remain unperformed; overall G1 fails.

Independent code/assets/source postchecks pass. Runtime/workspace cleanup passes,
no root or owner remains and process lineage is verified empty. The report is
immutable. Source-grounded replay also identifies six per-import image path
families: three metadata preservation commitments and journal modification dates
that differ across separately created Programs. Their original values remain
captured; no producer defect or environmental cause is asserted.

Saved/readback R4 freezes complete first live expectations, gives all 45 base
CLI routes fresh execution, and separates two explicit dossier snapshot hits
using original persisted Evidence. It replaces snapshot-flag startup heuristics
with explicit native versus owned-snapshot invocation expectations. Full outer
metadata parity remains strict. Only the six image paths receive exact own-run
record/startup/journal validation instead of cross-import equality; every other
normalized field stays exact. Actual captured comparison proof and SDK/ownership
controls must pass before another complete G1. Local code gets only the necessary
shared image-binding handoff; its facets and snapshot query sequence stay intact.

### R4 captured comparison proof

Independent replay of the unchanged R3 report/event bytes passed using the
corrected shared comparator and captured records belonging to each import.
Proof: `docs/psx-local/phase-5-regressions/r4-final-live-parity-replay.json`, SHA-256
`094f4598a54870ef6c0c37be13eb5faa9f5fd7e0edba2c5cf17444a88867803c`.
The actual live image event 47 and fresh CLI image event 557 have identical
outer metadata and stable image facts. All 1,244 differing leaves belong to the
six specified commitment/journal-time families and pass their own-run source,
profile, raw-record hash, preparation and strict image/journal checks. Full
normalized equality still fails, as preserved in the diagnostic control.
Fresh CLI versus cached image event 527 is rejected with its limitation intact;
the frozen collector retains complete first live event 47 after observing 527.

Actual snapshot event 416 resolves both exact dossier queries to their complete
original persisted Evidence: entry event 259 and leaf event 275. The observed
marked entry replay event 474 fails the original-Evidence CLI expectation;
unexpected native allocation also fails. Historical leaf MCP replay was not
performed in R3 and is explicitly absent in the replay result. Report/event
digests remain unchanged. This proof allocated no provider and establishes
neither unrun fresh CLI routes nor complete G1 acceptance.

Initial R4 integrated focused gate: 178 of 181 tests pass across ten suites
(17.14 seconds). Two new controls constructed cache Evidence by changing
limitations without recommitting its semantic Evidence ID; the authenticator
correctly rejected the fixture before the intended assertion. The actual SDK
strict-input control additionally caught an R4 observation-sequence bookkeeping
field attached to a non-Evidence refusal, violating its exact parsed shape.
Corrections preserve authenticated fixture ownership and the original strict
error representation; they do not relax production or comparison validation.
Final integrated checks and native retry remain pending.

### Final R4 pre-native checkpoint

Fresh integrated gate passes 181 tests in ten suites (14.78 seconds). The two
fixture controls now recommit modified Evidence through its production owner;
the capture adapter attaches association sequence only to Evidence, preserving
strict refusal/error results and durable events. Full static gate initially
reported two oversized test registration groups. Splitting those groups changes
no assertions; the affected 81-test suite passes again in 4.06 seconds.
`npm run check` then passes all six tasks, module boundaries across 1,324 source
files and architecture guards across 1,016 files, with 578 warnings and no lint
errors. `npm run build:cached` passes three tasks and regenerates the authored
skill reference; `npm run docs:check` passes six tasks. All 714 test files are
discovered exactly once; configured framework structure and whitespace pass.

The final frozen helper repeats the actual captured proof with the same digest
`094f4598a54870ef6c0c37be13eb5faa9f5fd7e0edba2c5cf17444a88867803c`.
Production, bridge, original fixture/oracle, prior operations runner and lockfile
match the Phase 4 baseline. All tracked writers freeze for fresh complete R4
G1. G3/G4 remain dependent on its full pass; Linux, fresh-client, bounded review
and delivery remain pending.

## Fresh R4 native failure and R5 readback

Fresh complete R4 G1 passed all four MCP cases and 33 fresh CLI comparisons.
Report `docs/psx-local/phase-5-public-runs/run-ycS3HF/report.json` has SHA-256
`406f65d83a92f1138eb7375215c589b0d57a0688ac13e6b1241aaa5b03013f56`;
events SHA-256 is
`f77f6eb983779d3eca77fccdffa9eaf1a13466e369ecf58fe0afb959a2ca1938`.
Route 33, outside-memory call targets at `0x90000000`, returned complete raw
Evidence with exit zero at event 1628 during finalization. Normal parsing and
parity were skipped because polling had already failed on ENOENT reopening the
owned snapshot while recursive cleanup left its root briefly present. Its source
hash and both fixed records had already been captured. No product defect or
environmental cause is inferred. Overall G1 is failed; subsequent matrix cases
and cancellation remain unperformed.

Final source/code/assets checks, exact workspace removal and verified empty
lineage pass, with no retained roots or unresolved owners. Root read back and
reviewed saved R5: capture completeness and process lifetime are separate facts;
retained complete capture survives file retirement, while incomplete capture,
changed ownership, contradictions and failed durable writes remain failures.
Disjoint helper and synchronized filesystem/process controls are underway.
Actual retained final-result parity proof and a fresh complete G1 are required;
G3/G4 remain dependent, Linux unavailable, and G5/review/delivery pending.

### R5 actual retained-capture replay

The corrected stable retained-capture APIs qualify actual allocation event 1598
and fixed-record events 1615/1616, then parse raw CLI event 1628 under its named
contract and source/profile/native binding. Exact unchanged parity against first
live MCP event 179 passes for outside-memory call targets at `0x90000000`.
Both historical snapshots are absent; a filesystem seam forbids any access to
them and observes zero accesses. Changed retained run, source, profile, record
digest and missing original record all fail closed. Original report/events
hashes remain unchanged.

Ignored proof `docs/psx-local/phase-5-regressions/r5-retained-lifetime-replay.json`
has SHA-256 `7f56009934bf1b79725b908e4fdcfee59228b45b70687c6d7ce2d22ff776870c`.
No provider was allocated. This proves only retained capture and parity for that
historical final reply; original G1 remains failed and later cases unperformed.
Deterministic deletion/cancellation/settlement controls, final integrated checks
and complete fresh G1 remain required.

### R5 first integrated control run

The eleven-file focused gate passes 203 of 209 tests in 54.56 seconds; two files
contain six failures. Both synchronized CLI deletion scenarios pass, as do
complete/partial cancellation, separate raw-capture failure, delayed components,
failed durable writes and source/record/manifest contradiction guards. This is
controlled filesystem/SDK/child-process evidence, not native acceptance.

Three replacement-manifest controls correctly reject the changed owner, then
expect active exit code `null` where the supervisor represents it as `undefined`.
An older native execution control supplies an R4 capture association instead of
a qualified durable R5 allocation owner. Those fixtures require correction;
no validator compatibility inference is permitted. Two cleanup-retry controls
fail (one timeout and one root-presence assertion); their producing-owner cause
is still under diagnosis. Exact log is ignored at
`docs/psx-local/phase-5-regressions/r5-focused.log`.

First bounded R5 correction round is authorized with disjoint test ownership;
helper cleanup semantics stay frozen unless concrete diagnosis justifies a
scoped correction. Final retained replay proofs still pass unchanged. Full G1
and dependent gates remain pending.

The two cleanup-control diagnoses are test producer errors. Token-owned group
cleanup intentionally uses SIGKILL, so a SIGTERM-only marker cannot establish
its behavior; an acknowledged child retirement barrier replaces that assumption.
The failed-close control injected its error into a generic producer wrapper,
while the independent native-root owner still had valid cleanup authority and
removed its root without erasing the wrapper failure or retained handle. The
corrected control injects removal failure into the actual native-root filesystem
boundary. No generic cleanup ordering dependency or helper relaxation is added.
The older native-mode fixture now explicitly qualifies its generated durable
records; its targeted regression passes 1/1. Complete integrated rerun follows
all test writers freezing; this targeted check does not replace it.

### Final R5 deterministic checkpoint

Fresh complete focused integration passes all 209 tests across eleven suites in
20.04 seconds, including all 28 synchronized capture/lifetime controls. The
corrected tests use actual child liveness, acknowledged retirement during close,
and removal failure at the exact native-root owner. Failed test processes and
temporary parents are fully settled. Helper code remains unchanged from the
passing retained replay. Both replay artifacts repeat with their original hashes.

Build passes three cached tasks. Full static passes six tasks, module boundaries
in 1,324 files and architecture guards in 1,016 files, with 584 warnings and zero
errors. All 715 test files are discovered exactly once. Configured framework
structure and whitespace pass; structural checks do not prove client discovery.
Production, bridge, original fixture/oracle, old operations runner and lockfile
are unchanged. Final documentation checks precede full fresh R5 G1; all tracked
writers then freeze. No new native, installed-package, game or client acceptance
is claimed by these deterministic checks.

## Fresh R5 native failure and R6 readback

Fresh R5 passes four MCP cases, all 45 fresh CLI comparisons and both exact
persisted function Evidence hits. The first truncated-input CLI refusal fails
because the verifier expects a nested error instead of the declared flat CLI
envelope. Report `docs/psx-local/phase-5-public-runs/run-XeYfGR/report.json`,
SHA-256 `c35d22ff8199e5d1d7ea9d354b83ca1bbab73b1f3454ffa5d9d6791f98527201`,
and events SHA-256
`0b9c5013a2665d32fb49080d1ee21afd1d1f42769b8b457ac2d09960bf0323bf`
remain immutable. Source, code and assets are unchanged; exact workspace cleanup
and verified empty lineage pass, with no unresolved owners. Later malformed,
layout and cancellation checks are unperformed. Overall G1 remains failed.

Root read back and reviewed saved P5-R6. Actual CLI event 2243 validates against
`analysisCliErrorEnvelopeSchema`, exits 1 without a signal, and its complete
canonical projection equals actual nested MCP event 2236 and observation 2237.
The correction preserves the full CLI label/input diagnostics, uses existing
named schemas, validates terminal status and compares whole canonical errors.
Disjoint real compiled CLI/SDK malformed-input controls precede full fresh G1;
no production, bridge, fixture or oracle changes are authorized. Relevant checks
are stale during implementation. G3/G4 remain blocked; Linux and fresh-client
coverage, bounded review and delivery remain pending.

### R6 immutable actual-refusal replay

Exact CLI raw event 2243 and actual advertised-schema MCP raw event 2236 parse
through the corrected helper and match retained observation 2237 and each other
in full. The original CLI envelope, exit 1, null signal, empty stderr and raw
identities are preserved. Twelve wrong-envelope/projection, diagnostic-mutation,
status and default-deny controls reject as required. Original report/event hashes
remain unchanged. Proof
`docs/psx-local/phase-5-regressions/r6-error-envelope-replay.json`, SHA-256
`e4b3a76742e7f695d48df56b17838ba6a537acab3398bf829b02a18a7f79ca43`,
allocates no provider and establishes no later case or full G1 acceptance.

### R6 first integrated control run

All twelve suites execute: 247/250 tests pass in 24.38 seconds, including the
actual compiled CLI/SDK malformed-input workflow. Three optional-diagnostic
controls reject schema-produced field reordering in the returned envelope.
Raw stdout remains complete; the canonical projections and all other controls
pass. Bounded correction round one preserves the original parsed envelope after
named schema validation instead of returning the schema's reconstructed object.
The strict canonical projection and status requirements remain unchanged; no
test relaxation or native retry is authorized until affected controls pass.

### Final R6 deterministic checkpoint

The bounded envelope-preservation correction passes all 122 affected tests in
14.66 seconds. Fresh full integration then passes all 250 tests across twelve
suites in 26.99 seconds, including forty new error-boundary controls and all
capture/lifetime regressions. Actual malformed/truncated CLI/SDK calls preserve
whole canonical parity, original source values and complete cleanup; this proves
pre-native admission, not native-provider acceptance. The immutable actual-refusal
proof repeats with SHA-256
`e4b3a76742e7f695d48df56b17838ba6a537acab3398bf829b02a18a7f79ca43`.
Earlier image/snapshot and capture-lifetime proofs remain byte-identical. All
716 test files are discovered exactly once. Full static/docs checks precede
fresh complete G1; production, bridge, original oracle/fixture and lockfile
remain unchanged.

Final R6 build passes three cached tasks. Full static passes all six tasks with
584 warnings and zero errors; 1,324-file module boundaries and 1,016-file
architecture guards pass. Generated documentation passes six tasks, retaining
thirteen claims with `complete: false`. Framework structure, final touched-doc
formatting and whitespace pass. All writers are frozen for full fresh R6 G1;
no installed-package, game, Linux or fresh-client acceptance is inferred.

## Fresh R6 cancellation inconclusive and R7 diagnosis

Fresh R6 passes all four MCP cases, all 45 fresh CLI comparisons, both exact
persisted function Evidence hits and all three malformed/layout refusals with
complete canonical error parity. The first SDK cancellation probe then completes
`open_binary` successfully before native allocation; it does not establish an
in-flight cancelled operation. The second transport-disconnect case is unperformed.
Overall G1 remains unaccepted. Immutable report
`docs/psx-local/phase-5-public-runs/run-tiahrK/report.json`, SHA-256
`42a49ec1ed41f41e0e95d5b4123ba2f00843ae188ac3ee36c47de6752e497be1`,
and events SHA-256
`0ca36c365136e12ee31d06d89f38932e5cf74fe9164325dcc6bd1ec9981aa385`
preserve valid source-open replies at events 2295/2296/2297. Exact workspace
cleanup and verified empty lineage pass with no remaining roots or unresolved
owners; source/code/assets and all 43 supplemental frozen file hashes are
unchanged. No environmental or production defect is inferred from fast success.

Bounded producer diagnosis and Astra R7 replanning identify the actual public
operation that owns lazy native initialization, then require synchronized SDK
and retained-reply controls before another complete native retry. Success is
not reclassified as cancellation. G3/G4 remain blocked behind full G1; Linux,
fresh-client acceptance, bounded close review and delivery remain pending.

Root read back and reviewed saved R7. `BinarySession.open` executes health,
which `CompositeProvider` answers without loading the lazy native client. The
first deep operation owns native startup. Both probes now require ordinary
successful admission and selected source/profile observation, followed by a
pending image query, exact new owned allocation and actual abort/disconnect.
Explicit SDK/startup barriers and historical successful-admission replay precede
full fresh G1. No production, bridge, fixture/oracle or dependency edits are
authorized. Relevant checks are stale during implementation.

### R7 immutable lazy-admission replay

Exact invocation 2294 and protocol/raw/observation events 2295–2297 validate
under the actual named open contract and advertised SDK schema. The successful
source/format/architecture/digest values remain exact. No allocation or
cancellation event exists in that interval; replay through the old coordinator
returns inconclusive with zero cancel triggers. Immutable proof
`docs/psx-local/phase-5-regressions/r7-lazy-admission-replay.json`, SHA-256
`620547d37d574926e9ee1f05d1b7b229882235c3251f235520ffd7114d280a29`,
preserves original report/events and allocates no provider. Corrected deep-query
cancellation still requires actual controlled SDK/startup and full native gates.

### R7 first controlled runtime checkpoint

The first focused run passes 91/98 tests in 63.21 seconds: all 89 existing public
controls and two new controls. Both actual SDK cancellation triggers reach the
bound partial-startup path; later fixture recovery assertions incorrectly expect
an `open` field on the named admission result. Two deadline controls expect a
failure event without invoking the owning case recorder. Capture-failure and
cleanup-retry cases retain unresolved SDK cleanup owners and expose `Not connected`
during settlement. Those actual owners/errors remain evidence; no clean-test or
native acceptance is claimed. Bounded correction round one is assigned to
separate test and helper lifecycle owners, including exact failed-test resource
settlement and producer-state diagnosis. First log
`docs/psx-local/phase-5-regressions/r7-initial-focused.log` remains preserved.

### R7 round-one runtime checkpoint

The first correction rerun passes 95/98 tests in 60.59 seconds. Both actual SDK
abort/disconnect and recovery workflows reach final settlement, where their
fixtures lack a committed owning case; empty failure lists do not override the
required nonempty case set. Exact cleanup retry now passes after the helper
observes actual SDK transport closure before lifecycle probing. Capture failure
still retains one SDK cleanup owner; producer diagnosis must distinguish its
original capture error from actual child/stream cleanup. Reported SDK PIDs and
owned fixture processes are verified absent. Bounded correction round two
records actual workflows in their owning cases and diagnoses capture ownership;
no weakened acceptance or native retry is permitted. Another unsuccessful
correction round requires replanning. Log
`docs/psx-local/phase-5-regressions/r7-round1-focused.log` is preserved.

### R7 capture diagnosis and final correction round

The single-case diagnostic `r7-capture-diagnostic-built.log` preserves the
expected capture-failure result; eight deliberately filtered controls are not
gate evidence. Both cleanup attempts stopped on recurring allocation capture
before physical SDK close, with original `controlled durable capture failure`
causes. The wire chain was resolved. Exact reported SDK PID 52515 and its owned
fixture processes and roots were verified absent; no unrelated resources were
signaled or removed.

Root saved and read back the round-two ownership clarification. The emitter now
retains each failed event and its original cause/event identity independently.
After actual capture failure, SDK cleanup avoids capture-dependent lifecycle
probes while still awaiting physical transport, child and stream settlement.
Final tracing failures remain capture failures; actual cleanup failures retain
retry ownership. The helper is frozen at SHA-256
`599b27ded583a07747f72b1235d6c1e44e5b73146761868e47d8685e5d3b3774`.
Final correction-round runtime verification passes 98/98 tests across both
affected files in 66.39 seconds. Actual SDK abort and disconnect reach the pending
production startup boundary, recover with separately bound allocations, and
settle exact owned resources. Capture failure remains unsuccessful with retained
original errors and no unresolved SDK owner; actual cleanup failure retains its
retry owner until awaited cleanup succeeds. Log
`docs/psx-local/phase-5-regressions/r7-round2-focused.log` is preserved. These are
controlled producer tests, not native-provider acceptance. Full regression,
static/document and immutable replay checks precede a fresh complete G1.

### R7 final integrated pre-native checkpoint

All 266 tests across thirteen focused suites pass in 108.11 seconds, including
the nine actual SDK/startup cancellation controls, forty full-error controls and
twenty-eight capture-lifetime controls. All 717 test files are discovered once;
configured framework structure and whitespace pass. Immutable R4/R5/R6/R7
replays retain their previously recorded proof hashes with no historical edits.
Production, bridge, original fixture/oracle, old operations runner and lockfile
match the Phase 4 baseline. Three-task build and six-task static verification,
including module boundaries and architecture guards, pass. Six-task generated
documentation checks pass with thirteen claims and completion remaining false.
All tracked and new authored writers, including root state writers, are frozen
for the fresh complete R7 native G1. Linux remains unavailable; no package-native,
AC3, fresh-client or phase-closure claim follows.

## R7 complete macOS public acceptance

`npm run verify:ghidra:psx` passes all nine aggregate cases through compiled CLI
and actual SDK MCP on macOS arm64, Node 24.18.0, Ghidra 12.1.4 and Temurin
25.0.4.1. This includes the independent MCP oracle, selector/capability refusals,
four-family snapshot replay, atomic rejection, all 45 fresh CLI comparisons,
both exact persisted function-Evidence hits, all three malformed/layout
full-error comparisons, actual pending image abort and owned transport
disconnect, separately bound recovery, and awaited cleanup. Successful admission
is preserved separately from the pending native operation.

Ignored report `docs/psx-local/phase-5-public-runs/run-Oe3Y16/report.json` has
SHA-256 `fcc322f4b8e68d29810db93d963f56b87a74535d51a653895d7420a0263c0a09`;
events SHA-256 is
`755eb621fb9b8df14acad74d58259c48491d1eb05f51d8dc3fb3f6e9cf2aeb64`.
The original fixture digest, loader JAR and complete asset inventory remain
unchanged. All 52 native allocations are settled, exact workspace is removed,
retained roots and unresolved owners are empty, and lineage is verified empty.
No primary, capture, cleanup or postcheck failures remain in this successful run.
Earlier failed/inconclusive reports retain their original bytes and outcomes.

Root independently verifies the exact 44-file set, every authored file digest and
tracked diff against frozen manifest SHA-256
`096d781a054dab85affaac873d7b429221f5245506bffdac2032472279220084`.
These post-run state edits are identified separately from the immutable measured
fingerprints. G1 is accepted for this recorded macOS host; installed-package and
explicit local AC3 measurements are now permitted. Linux and actual fresh-client
acceptance, bounded close review and delivery remain pending.

## First installed-package native failure and bounded review

The exact local tarball installs in an isolated prefix and its loaded identity,
compiled modules, Java resources and generated skill bytes match packaged source.
Its first actual SDK image query fails before a native ownership manifest is
observed. The canonical public error retains `execution_failure` with
`GhidraLaunchError: Ghidra headless launch failed`. No underlying prelaunch cause
is established; this is not attributed to the environment. The full installed
matrix is unperformed after that failure and G3 remains failed.

Ignored report `docs/psx-local/phase-5-package-runs/run-nmnnbK/report.json` has
SHA-256 `3ce8fc2907469a6535d0d068f90fd9c9f6ec3b835370ab387765e7910b5ef504`;
events SHA-256 is
`b13901fb062d9028f775bf23d39b156efe578d494079aa5a32532de58b52800e`.
Retained tarball SHA-256 is
`14281fea4735e6c98395f37cea8795b11f6805430324a7ca633b461495d40057`.
Source/assets/code and all 44 package-frozen authored files remain unchanged;
manifest SHA-256 is
`754b665099a3028fb470d753d10c54ef6c55ae09927f939add51c55cb7156106`.
Public and package cleanup remove exact workspace/roots, retain no unresolved
owners, and verify empty lineage. Earlier G1 acceptance remains bounded to its
unchanged source implementation; it does not substitute for installed acceptance.

The single read-only close review verifies G1 and reports two blocking P2 findings
in the package verifier: final command streams/status can be lost after early
capture failure or timeout, and failed workspace removal returns no retry owner.
Both require producing-boundary fixes and meaningful failure controls; logging
does not resolve them. No other confirmed finding or deferred issue was reported.
Bounded Astra R8 planning covers diagnosis and those corrections. Re-review is
limited to changes resolving these blockers. G5 preparation remains blocked until
a complete installed matrix passes; Linux remains unavailable and required.

## Authorized local input prerequisite

After complete G1 passed, the explicit selected path
`/Users/anthonygrimaldi/Documents/VSCode-Projects/ac3-decomp/extracted/disc1/files/SLPS_020.20`
was read through the existing local runner's strict parser. Current SHA-256 is
`daddca3ac3299372370a8cf7a046eb066537a39cf53216904009c46f2924b0e5`.
The header matches load address `0x80120000`, payload size `0x75000` and entry
`0x801255ac`; file size is 481,280 bytes with no trailing bytes. This is a local
Load Word translation-patched Disc 1 boot executable prerequisite only. No game
bytes or decompilations are versioned or transferred; actual G4 workflows remain
pending and make no retail, Disc 2, overlay or runtime claim.

### R8 saved-contract readback

Root read back and reviewed the saved package-only R8 contract. It authorizes
final post-settlement command capture, independent failure fallback, an exact
retained workspace retry owner and meaningful controlled failure tests. The
prelaunch cause remains unresolved. A bounded ignored diagnostic will use the
exact retained tarball and installed exports, stop at the first causal failure,
and remain separate from installed acceptance. No production or shared public
helper edits are authorized. Package owner implements the two runner/test files;
root owns diagnostic execution/state and all native writer freezes. Full source
G1 remains accepted, G4 independently permitted, and G5 waits for a complete
installed matrix. Reviewer follow-up is limited to blocking corrections.

### R8 package correction checkpoint

The two package failure-path corrections are frozen at runner SHA-256
`ac1006c5ed5b9ad34cf046f4318225907b7d07e4151434e58989dea351e16585`
and test SHA-256
`7c4a224beb90899d5807596d18b774056a987eab035594a75a77fbf38dc60a32`.
Final exact focused controls pass **21/21 in 2.22 seconds**, recorded in ignored
`r8-package-final-identity.log`. The first 17/19 run exposed changed primary
error wording; the producing aggregate message was corrected without weakening
assertions. Failed command outcomes retain independent failures, final EOF/status
and exact unpersisted events; workspace cleanup retains a device/inode-bound
awaited close/retry owner and historical errors. No production/shared helper
changes were made. The bounded blocking-correction re-review resolves both P2s without additional
findings. Fresh integration passes **274 tests across thirteen suites in 86.05
seconds**. Six static tasks, module boundaries and architecture guards pass.

Root read back the ignored installed diagnostic at SHA-256
`c321d8d3c2217c18edc5b6768de1d187e5214d0cc43c20a51afddd739e0c9f96`.
It installs the exact retained failed-G3 tarball, reproduces the actual Unicode
public-root cwd/TMPDIR, checks installed ownership preparation and LaunchSupport,
and stops at the first failure. Execution follows writer freeze; this diagnostic
cannot establish installed acceptance. Local G4 remains independently authorized.

### R8 installed boundary diagnostic

Exact failed-G3 tarball installation, resources and assets pass. Cold installed
ownership preparation fails in `/usr/bin/xcrun swiftc` with nested `code:null`,
`signal:SIGTRAP` and empty compiler stdout/stderr. LaunchSupport was unperformed;
the trigger remains unknown. Report SHA-256
`441a41facd81063a0a8cab41d767944f89a7b70d88e3587e1928f2285b6cd19b`,
events `813a7052ab1dab7fd098b2ab413525959a9bc8b28e635d087f15c92cfacf6b82`.
Corrected package capture records complete EOF/status with no fallback loss;
exact workspace removal, unchanged resources/assets/tarball and empty verified
lineage pass. Root separately verified 44 authored files, 2,371 runtime/original
files and Git diff unchanged at frozen manifest SHA-256
`85a2147cc9168499aa9af3978161bed3ff7d626a34ae0abd897076c131a7a718`.
This diagnostic establishes no installed acceptance or compiler root cause.
Astra's R9 two-arm comparison was persisted and read back after AC3 settlement.

### First real local patched-AC3 smoke

Only the explicitly selected translation-patched Disc 1 boot executable was
read. Source SHA-256 remains
`daddca3ac3299372370a8cf7a046eb066537a39cf53216904009c46f2924b0e5`;
load `0x80120000`, payload `0x75000`, entry `0x801255ac` match the declared
prerequisite. Actual public image inspection returns **unsupported**, with
required provenance unavailable: `Affected bookmark metadata cannot be restored
by plain loader adaptation`. This is the production adaptation's explicit
preservation refusal, not a verified source-backed image. It examined all
479,232 payload bytes but verified zero; later instruction/function/CLI/snapshot
facets were unperformed. G4 stays failed/pending correction, without lowering
its criteria or claiming AC3 support from synthetic success.

Ignored report `docs/psx-local/phase-5-local-runs/run-eWMPUM/report.json`, SHA-256
`1235f87fe9fd062498d1904ef033d0f254c0023b8665c0488f812b7f8df5284e`;
events SHA-256 `3c2372332b5b5b0641129267de84f2e16d753f7f590871da6d7f4295d3b3beab`.
The input, code, assets and root freeze remain unchanged; native owner and exact
workspace settle with empty verified lineage. No game bytes, disassembly or
provider database is versioned. Production changes require a separately
reviewed narrow contract; the package diagnostic does not include this work.

R8 final ancillary checks pass: build three cached tasks; static six tasks plus
module/architecture boundaries; docs six tasks; all 717 tests discovered once;
generic package integrity including 139 tools/six prompts/four setup clients,
backups/idempotence and empty owned lineage. Configured framework structure and
Git whitespace pass; fresh-client/hook behavior remains unverified.

### R9 installed cold comparison

The exact retained tarball was installed once; two fresh installed-export
children used the same executable/eval argv, Unicode cwd, HOME/XDG/provider
coordinates and inherited execution environment. Only TMPDIR changed. Arm A's
Unicode public-root temporary path reproduced compiler SIGTRAP; arm B's owned
ASCII sibling passed. Each arm's preparation artifacts settled before the next;
raw EOF/status, unchanged resources/assets/tarball and final workspace/lineage
checks pass. No LaunchSupport, SDK matrix or production correction was executed.

Ignored report `r9-ownership-pair-WNaEsF/report.json`, SHA-256
`d601dca7e76898dd9e8e525af227a93ba0ce145cb5845c9f16c91d530d10ff72`;
events SHA-256 `0a46003f5e8ef58a1cf78005f1fd46c08d4f4c62ef911f086c548808ec12f831`.
Ignored harness SHA-256
`2d0344a4bd5d15f672082e9f003be9a3bec182d918955922be1b5d0a103cadaa`;
44 authored files, 2,371 runtime/original files and Git diff remain unchanged
at manifest SHA-256
`774251dc2cca85c5700b8638af5ef520d8b1e271c4d5b38a85d8461cbc7192e0`.
The comparison establishes temporary-path geometry sensitivity only, without
separating Unicode, spaces, length or nesting. Public helper admission requires
TMPDIR equal to its empty workspace; an environment-only override would violate
that ownership contract. A shorter canonical OS temporary base retaining the
Unicode public cwd therefore needs a separately reviewed installed probe and
package-caller allocation correction, not a shared-helper workaround.

### R10 shorter Unicode prelaunch probe — failed, no allocation fix

The one reviewed canonical `/tmp` probe retained all internal Unicode public-cwd
names, HOME/XDG isolation and exact public TMPDIR ownership. Cold installed
Swift preparation still exits SIGTRAP. LaunchSupport remains unperformed.
Report `r10-short-unicode-IFGjA3/report.json`, SHA-256
`1a33f1c78dbc99106450c74d6245781499b4545a9f3fce98222f55d08923a98a`;
events `d7090ad04cf1de552741bfa39967eb4479ac467efea567e103890e87afdd0c7e`.
Tarball/resources/assets and all 44 authored plus 2,371 runtime/original files
remain unchanged (root manifest SHA-256
`07a82bcf4557317687474ec22869e4cdaff26df4d09ff80102025138f846240c`).
Complete output/status, exact workspace removal and empty lineage pass.
The conditional allocation correction was not authorized and no runtime or
package allocation change was made. Shortening alone did not resolve the
measured failure; no Unicode-specific compiler root cause is asserted.

The proposed producing correction concerns the shared Darwin helper's internal
compiler-temporary ownership, currently derived from ambient `os.tmpdir()`.
This lies outside the current package-only contract. AC3's deliberately refused
bookmark state separately needs synthetic exact-ID preservation feasibility,
not simple text recreation. Narrow proposed supplements must be reviewed before
any production scope decision; full fresh acceptance remains mandatory after
any approved relevant resource change. No full phase/PR/client readiness claim.

### Proposed production supplements and current handoff

Astra saved R11 (shared Darwin compiler temporary ownership) and R12 (synthetic
exact bookmark-ID feasibility, then conditional provenance integration). Root
read back both saved contracts and verified existing owned paths. Their scope
exceeds R8–R10 package-only corrections and the earlier deliberate bookmark
refusal policy; they are **proposed, not authorized**. All currently authorized
corrections are checked. No production edits, new compiler trials, repeated
AC3 attempt, full installed retry, client handoff, commit or PR followed the
failed R10 probe. The user can choose the two extensions independently; Linux
remains required and unavailable even if macOS gates later pass.

The user subsequently explicitly approved both R11/R12 supplements on
2026-10-10. Bounded compiler ownership implementation and synthetic bookmark
feasibility may proceed; production bookmark integration remains conditional
on the real feasibility gate. Renewed native acceptance and Linux/client
boundaries remain required. The proposal checkpoint above is historical.

## R11 compiler controls and R13 lifecycle review correction

The user-approved Darwin compiler ownership source/test checkpoint passes 49/49 focused tests (28 compiler and 21 package controls) in 12.88 seconds and cached runtime build. Private logs: `docs/psx-local/phase-5-regressions/r11-compiler-focused.log` and `r11-build.log`. Source SHA-256 `003389932940ff0aa30f315b12e7896315476e2868c7b92630b1b6f0d64d5d11`; test SHA-256 `2775c472a9fc6c621311fedf349b7e16df71e1cabe298f763319afd21b743932`.

Bounded R11 review found one blocking P2: the independent compiler root is outside caller TMPDIR, but production CLI/MCP termination does not await its owner. Existing best-effort process exit cleanup is insufficient. Saved R13 was root-read and authorized as necessary integration within the already approved R11 ownership repair: provider/child settlement precedes inspector close; failures retain callable retries. This is pending implementation and blocking-correction re-review, not native acceptance. R12 retains separate synthetic probe ownership. Full candidate source G1/installed G3 and conditional local G4 remain required; Linux is still unavailable, G5 is not ready and no delivery occurred.

## R14/R15 producing cleanup receipts

Source-grounded CLI investigation found that application cleanup is projected into public JSON before the dispatcher can retain the actual failed provider owner. The root-reviewed R14 selects a CLI-scoped composition receipt, observing the same BinarySession/Android close outcomes without parsing rendered output. Root-reviewed R15 retains exact process owners at shared spawn/supervisor boundaries and the existing PTY/Electron launch exceptions, with an explicitly activated invocation scope and no default registry. These changes are necessary integration of the user-approved R11 terminal ownership repair; implementation and actual entrypoint verification remain in progress.

R12's separate verification addendum assigns real filesystem/capture and producer-manifest mutation controls to `tests/boundary/providers/ghidra/ghidraPsxBookmarkVerifier.test.ts`. The draft contains 17 controls, not yet run. No native retry may begin until all authored writers freeze, controls pass and the single R11 review blocker is resolved. Historical reports stay immutable; Linux, local AC3 and fresh-client gates remain distinct and pending.

## R12 installed API compilation checkpoint

The frozen synthetic probe and unchanged PSX import/provenance helpers compile successfully with the existing Temurin 25.0.4.1 `javac -proc:none` against the installed Ghidra 12.1.4 classpath (196 JARs). Nineteen generated classes were removed from their exact owned directory; all three source digests remain unchanged. Private capture: `docs/psx-local/phase-5-regressions/r12-java-api-s1bzexcv/report.json` and `compiler.log`. This is API compilation evidence only, not bookmark transaction feasibility, Ghidra execution or local-game acceptance. The 21-case native probe still awaits lifecycle verification and the complete writer freeze.

## R15 required build and R12 deterministic controls

Runtime compilation and packaged-skill prerequisites pass against the frozen lifecycle source. All 17 real-filesystem/raw-capture/producer-manifest bookmark controls pass in 349 ms with the focused runner. Private successful log: `docs/psx-local/phase-5-regressions/r15-bookmark-focused-final.log`. The two earlier 16/17 logs remain preserved (`round1` and `round2`): the test inspected `AbortController.reason`, then mistakenly treated the failure as ordering; the actual reason belongs to `AbortController.signal.reason`. The final correction preserves exact original-error identity and all byte/lease assertions. No production behavior was weakened.

Runner SHA-256 `90f1834c6c7011d684c3bd88ea136fb76fd5eff788bb4e9f5c464df22587ec70`; control SHA-256 `ecdc3cbe557f90c6fb781aa1a6574d928f142286c81c9df8968889188e108636`. Root also makes the new project directory private and sets the native probe report to 0600 before reading it; frozen Java source is unchanged. Lifecycle controls remain under implementation and the R11 blocking-correction source review is underway. G1/G3/G4 renewal, real bookmark feasibility, Linux and actual G5 remain pending.

## R15 retained close-event correction

The bounded correction review identifies one blocking P2 in supervisor adoption: the pending child owner records actual `close`, but a supervisor constructed after that event subscribes only to future closure. Its scoped stop can therefore remain unresolved despite actual settlement. Ghidra's awaited manifest publication between spawn and supervisor construction provides a concrete ordering path. The correction is limited to transferring the same child's exact recorded closure proof while preserving complete buffered output, with a real already-closed-child control. Exit status alone must never imply EOF. This necessary R11/R15 ownership correction is in progress; affected source verification is stale and native execution remains suspended. The review otherwise accepts provider-before-inspector ordering and retained cleanup. No additional production capability or delivery authority is introduced.

Root's first ten-suite lifecycle run records 49 passes, nine failures and 33 skipped controls under sandbox process-inspection restrictions. The unchanged narrowly permitted rerun records 88 passes, three failures and no skips in 33.50 seconds. Private immutable logs are `r15-lifecycle-focused-round1.log` and `r15-lifecycle-focused-permission.log`. The explicit spawn EPERM failures disappear in the unchanged permitted run. Preparation's fake removal function fails the real absence guard; Electron's asserted raw primary differs from the existing provider wrapper, and its cleanup-retry control remains unresolved. These three controls require source-grounded correction; no whole lifecycle pass is claimed.

The backend confirms pinned Node's exit flush can discard unread bytes before adoption, so close-event transfer alone cannot satisfy the strict output control. Astra saves R16 and root reads back the producing representation: acquire one capture/lifecycle state synchronously before process publication; move existing stdout/budget policy to acquisition, and install JADX's existing protocol listeners through a synchronous acquisition hook. A late supervisor adopts that same state. Missing historical capture remains unavailable, independently of process cleanup. Necessary source ownership and independent capture/protocol controls are assigned in the saved plan; no guessed buffer, delayed timing workaround, native run or new capability is introduced.

The actual public dispatcher/SDK baseline exercises eleven controlled cases against the built R15 runtime: six pass and five fail in 79.97 seconds. Ordinary complete-output CLI execution, both compiler cancellation signals, both SDK close/disconnect cases with two session cycles, and allocated-inspector startup rejection pass. Retained owned-command cleanup retry, PTY projection, inspector retry and both active-command cancellation cases remain unresolved. Private immutable log: `r15-entrypoint-baseline.log`. This is controlled boundary evidence, not real Ghidra, fresh-client discovery or full lifecycle acceptance. Diagnostic capture precedes further correction of these cases; source R16 remains in progress.

The preparation control now verifies real removal/absence and passes. The first Electron correction still fails three controls; its diagnostic run identifies the test host reporting a killed child live until Node delivers its exit event. The second correction queries actual kernel state only for the exact acquired PID, preserving zombie/absence semantics and all ownership assertions. Prior two-file and diagnostic logs remain immutable (`r15-two-corrections.log`, `r15-electron-diagnostic.log`); the second correction is pending root verification, with replan required if it fails.

## R16 deterministic acquisition integration

Runtime compilation passes after the necessary never-returning acquisition helper branches explicitly return their throwing helper; the first TS2366 compile log remains preserved. The integrated focused run passes 284 of 285 tests across nineteen suites. All eleven actual public CLI/SDK lifecycle cases pass, including complete raw output, active cancellation, same-owner cleanup retry, real PTY projection, inspector removal retry, controlled compiler cancellation, SDK disconnect and session ordering. The sole failing legacy OwnedCommand launcher fixture omitted the new acquisition boundary; its producer now acquires observation before publishing, with all original failure/output/cleanup assertions preserved. The final focused OwnedCommand run passes all thirteen tests. Private immutable logs: `r16-integrated-focused-round1.log`, `r16-integrated-focused-round2.log`, and `r16-owned-command-final.log`.

Independent capture controls cover actual child close before publication, exact split UTF-8 bytes, acquisition-time budgets, unavailable legacy coverage, and outside-scope failed acquisition retaining its same callable owner and original capture/cleanup causes. All eleven output-boundary, nine cleanup-scope, five JADX, four Electron and twenty-eight Darwin compiler-reader controls pass in the integrated run. The prior preparation/Electron failures were resolved at their test-producing seams without relaxing cleanup: a real owned temporary root and exact child kernel-liveness observation replace nonexistent-path and delayed Node-event assumptions. Controlled compiler/provider fixtures do not establish real Ghidra, Swift compilation, Windows/Linux or fresh-client acceptance.

Finite Ghidra/Hopper direct controlled launchers and the bookmark runner are being migrated to the same synchronous acquisition contract before affected regression checks. The bookmark Java feasibility probe and production affected-bookmark refusal remain unchanged. Correction-only source re-review, static/docs/discovery, all-writer freeze, real twenty-one-case bookmark feasibility and fresh full G1/G3/G4 remain pending; prior native reports remain historical. Linux remains unavailable and G5 is not ready.

## R16 affected regressions and correction-only review

Affected Ghidra/Hopper controls pass 172 tests with one existing platform skip; all three initially failing separate Hopper lifecycle models pass after observation is acquired at model creation before awaited socket publication. Source-map eleven and recovery seven pass. All twenty-one bookmark-runner controls pass in `r16-bookmark-firmware-focused.log`; one available firmware refusal control passes and three Linux-only controls are skipped on macOS. These explicit skips do not establish Linux behavior. The first provider and JavaScript failures remain in their immutable logs, with narrow producer migrations and unchanged assertions recorded in the saved contract.

The bounded R16 correction-only review reports no blocking findings. One shared byte/lifecycle state is acquired before publication, immutable policies apply before first output, and late adoption retains EOF, counters, errors and same-owner retry. Existing JADX protocol listeners attach synchronously without diagnostic stdout consumption; frozen public/package verifier hooks preserve raw capture. This resolves the earlier R15 blocker. The mutable bookmark and provider fixture files were excluded from this source review; their real controlled boundary checks pass.

Generated documentation passes six tasks, and all 722 tests are discovered exactly once. The first static attempt stops on formatting of the Darwin reader; the renewed attempt exposes three max-lines-per-function errors in new controlled test helpers. Both logs are preserved. Required factoring is assigned without suppressions or assertion changes. Static/typecheck completion, renewed factored controls, fresh build and all-writer freeze precede native feasibility. No new native acceptance or full phase closure is claimed.

## R16 final deterministic acceptance and native freeze

All sixty-four renewed bookmark, actual entrypoint, Electron and Darwin reader controls pass in `r16-factored-controls-final.log` (23.92 seconds), after meaningful setup factoring preserves every original test body and barrier. Final test-only Error-field ordering and immutable guarded PID corrections pass all seventeen OwnedCommand/Electron controls in `r16-typecheck-controls-final.log` (3.63 seconds). Full configured static passes six tasks, zero errors/611 warnings, 1,326 module-boundary files and 1,018 architecture guards in `r16-static-verified.log`. Earlier formatting, function-size and typecheck logs remain immutable. Generated docs pass six tasks; all 722 test files are discovered once.

Reviewed early-observation source SHA-256: `1fa580cc67a865bb0779fd70a9dce2ca11d3e4896721b4671b84d772d9446e40`. Formatted Darwin reader: `b39d539776435c32575770d1e26f6f706c137a3445315d105ba230e0381bb97d`. Current public helper: `c4379e17f1b4b88af0dabcab811abf825ee85bb4f403ed625fe6a86956b0a637`; package runner: `5884dc8cb2da9be049c31d8ee6b9a8c12d998531cb4367875fb9d6dae38e1ffb`. Bookmark runner: `1da1a4c9be20a6649b4b89c123d4117409b4722dfb11f8685e34ffa0e9766296`; its Java probe remains `9c314342f66799c3cb1d2bbbdb8ea328b3f0aba917ecdcd2e5b2c29d390e3bdc`. These replace historical candidate bindings only for this new verification; old reports are unchanged.

All authored/source/test/documentation writers now freeze for the exact twenty-one-case real synthetic bookmark feasibility using installed Ghidra 12.1.4 and JDK 25.0.4.1. Its distinct private `r16-bookmark-feasibility-frozen.json` binds authored files, Git HEAD/diff, all runtime/source/bridge files and original fixture/oracle/lockfile; root verifies it after native settlement. Production bookmark adaptation remains conditional on the complete real report. Renewed full G1/G3/G4, fresh-client G5, Linux and delivery remain pending.

## R12 first native feasibility attempt — probe admission failure

The full twenty-one-case runner stops in `zero` before adaptation, because its separate witness constructor receives the imported program's compiler-spec wrapper. Actual Ghidra 12.1.4 throws `Cannot instantiate ProgramCompilerSpec from another ProgramCompilerSpec`; the producer records failure at admission, no mutation stages and `owned_program_released:false` because witness construction never returns. This is a failed native feasibility attempt, not a bookmark preservation result. Later twenty cases are unperformed.

Report: `docs/psx-local/phase-5-bookmark-runs/run-lNjtQ1/report.json`, SHA-256 `07f7359b6425fba4a7c30e43a15713ad2debc16605403150349e6461a4baa70a`. Both raw streams are complete (7,990 stdout/2,887 stderr bytes), with no capture or cleanup failures. Source/probe/runtime/asset identities and the 93-file authored freeze remain unchanged, exact workspace is absent, and actual point-in-time lineage is verified empty. Zero exit alone was correctly refused by semantic acceptance. The original report and probe output stay immutable.

Installed source proves the constructor expects the base compiler specification rather than another program wrapper. The root-read saved correction resolves that base using the exact imported compiler-spec ID and verifies the independent witness retains its imported language/spec identity. It changes only probe admission and preserves all twenty-one scenarios, metadata/identity/transaction/source/release requirements. Production bridge and affected-bookmark refusal remain unchanged. A new immutable candidate freeze precedes the complete retry; no native gate or phase closure passes from this correction.

## R12 real feasibility accepted — all twenty-one scenarios

The complete fresh retry passes all twenty-one cases: zero/one/multiple/boundary/adjacent/split/outside bookmark states; occupied destination, insufficient range, overflow, unsupported manager and unexpected generated bookmark refusals; cancellation/failure at parking, replacement and return; and commit/rollback caller-boundary finalization failures with actual finalized rollback. Finalization injection does not establish Ghidra-internal finalization-failure behavior.

Private report `docs/psx-local/phase-5-bookmark-runs/run-maxDHj/report.json`, SHA-256 `a9eeab3de30ef10afeaeb27b9e5ef259d5085a2a759ce39282deca408c751257`, records macOS arm64, Node 24.18.0, Ghidra 12.1.4 and Temurin 25.0.4.1. Root independently verifies all twenty-one probe output digests and exact bookmark identity/state equality; every owned ProgramDB releases, each capture is complete with no error/unpersisted bytes, source/asset/code identities stay fixed, owned workspace is absent and actual final lineage is verified empty. Run UUID `15f8e553-742b-44a9-8f13-c1adadff8118`, verifier PID 62168, finished. The fresh 93-authored/2,375-runtime-original freeze remains unchanged at SHA-256 `8b0d90b9fa22d3eb7f4185ce05e85054553266ff2a7828fab3ad6f9730f55ab3`. Corrected probe SHA-256 `0e20b9dc3c21cfbdd764de65879cb075b68dfd700a1bcb3c372e4747e9dc8649`.

Root accepts the R12 synthetic prerequisite and dispatches only its existing conditional provenance-helper production assignment. Production behavior, existing loader-seeded metadata restoration, AC3, installed artifact, other host and fresh-client claims remain unverified. All other source/test writers stay frozen until their exact required assignment; original failed reports and feasibility evidence remain immutable. Renewed full G1/G3/G4 and Linux/client/delivery gates still apply.

## R12 conditional production source checkpoint

The only production bridge edit is frozen at SHA-256 `333cf78952cd3b397a28e6c5083e40a16507be4d0c9307d8fb5ef10375001104`. Its internal bookmark capture includes exact keys, type IDs and representable headless type state; it parks existing records in a computed disjoint empty interval and returns those same keys, with full identity/type/value checks before/after real operations and original transaction/rollback/journal/full-state comparisons. Unsupported manager, unsafe destination, opaque icon state and unrelated unsupported metadata retain explicit refusals. Internal digest inputs strengthen; fixed public record fields, versions, METHOD, comparison string and STATE_KEYS remain unchanged.

API compilation passes using existing Temurin25/Ghidra12.1.4 against the observed 203-JAR classpath. Nineteen generated classes are removed from the exact owned class directory after source identities remain unchanged. Private report `docs/psx-local/phase-5-regressions/r12-production-api-fdo_p8zz/report.json`, SHA-256 `faa443c62ac509687c9b3eaa19525fcd9631816bac031652ed8bfa9c185d8ab1`. This is compilation-only evidence. The bounded substantial bridge review reports no blocking findings; mutable production probes/runner are excluded.

Root assigns the minimum missing actual production verification: retain all nine existing preparation feasibility cases, plus ordinary/split bookmark commits, cancellation after parking/rebind/return and unsupported-data refusal with bookmarks. Independent IDs/type state and actual reached-boundary facts are required in addition to production digests. Probe and native-runner authoring is in progress; no native integration, AC3, package, host/client or phase acceptance follows from compilation/review.

## R12 actual production verification preparation

The six production bookmark cases are frozen alongside the unchanged nine feasibility cases. Probe SHA-256 `b3725e5bc709f1db12a96a40b080fa64678af22dbdf29acf182c45c645e33074`; runner SHA-256 `d752c6da05dfc2aeea1b661271a619861b138885a5c1dbb8073de6494c78bd00`. They independently enumerate exact bookmark identities/type state, observe actual park/rebind/return before selected cancellation, and require whole-state rollback/refusal and unchanged original evidence bytes. No native result follows from implementation alone.

The production helper and both probes compile against the existing Ghidra/JDK APIs: 203 installed JARs, 24 generated classes removed from the exact owned directory; source hashes unchanged. Private report SHA-256 `8604f4456a60a335e4a9341521e6f3c8c50f78b5b587bc8d53b7a3361e4c42fc`. First focused invocation passes 111 tests and fails four Darwin ownership cases with an explicit sandbox-denied Swift module-cache write. Its original log is retained; the unchanged permitted retry follows. This does not establish native, package or AC3 acceptance.

The unchanged permitted focused retry passes all 115 tests in four files (2.53 seconds). Full configured static passes six tasks and architecture guards; documentation passes six tasks; cached build passes; discovery finds all 722 test files exactly once. Git whitespace and frozen Java/runner identities pass. All authored/source/test/docs writers are frozen for fifteen-case actual production feasibility and the unchanged full load-image lane. No native pass is claimed by this checkpoint.

## R12 actual production native acceptance

R12 actual production acceptance passes all fifteen real feasibility cases, retaining nine originals and six bookmark controls; root verifies independent exact IDs/type/operational state, actual cancellation checkpoints, immutable evidence and finalized rollback/refusal. Report SHA-256 `96ada9af708e84805f0a5a89a992f88fc4ea90b3426f091a0e8b3168ea92d821`. Unchanged full load-image lane passes all three fixtures/nine separate MCP/CLI/direct sessions and actual-observation replay, report SHA-256 `8b54f7df3acd5032ad91bbb225418a35292fd7af59290439a4879a3b180b6868`. Frozen authored/runtime manifest `969cb3aae058f187dc9dc1bd732f560f2bd99574941848139dbf3f15d4ea9ab6` remains unchanged; exact workspaces and verified lineage settle with no unresolved owners. Full renewed G1/G3/G4/client and Linux remain independent/pending.

Production helper review has no blockers. Native run UUIDs are `726ad530-2c01-4822-9b9d-e03d6825bf0b` (feasibility) and the full-lane verifier identity retained in its report. All six bookmark modes preserve seven independently enumerated IDs across four types, exact category/comment/address-space fields, full representable type state, unaffected adjacent rows and original evidence bytes. Each selected cancellation observes the actual preceding mutation before throwing; final rollback restores the complete original manifest. Unsupported affected data refuses before any bookmark mutation. No game, installed-package, Linux or fresh-client acceptance follows from this lane.

## Fresh candidate package preparation

Normal npm pack hooks produce 1,064 files in the fresh local 6.3.0 tarball, SHA-256 `d4a7f8631fe85150f2ab20246d6a138f1bf475ce2e587cbeaf24aea01ed04acd`. Root verifies excluded local artifacts are absent and selected ownership/provenance/Swift resources exactly match source/build. The first invocation was denied access to the ambient npm cache and repository Git configuration; its log remains unchanged. The permitted retry uses a new isolated ignored npm cache and normal hooks, without modifying the ambient cache or installing software. This is packaging only; cold preparation, complete source/installed/native acceptance and client/Linux gates remain pending.

## R11 cold installed comparison

R11 cold installed comparison passes its intended discrimination: exact retained old tarball reproduces Swift SIGTRAP, report SHA-256 `2e4c3f62bbc47cada4014bb09b96d168f8dc06031bda33fc1002b055f8a11fde`; repaired candidate `d4a7f8631fe85150f2ab20246d6a138f1bf475ce2e587cbeaf24aea01ed04acd` passes cold ownership preparation and installed LaunchSupport, report SHA-256 `a0da0fe17d3baff4d4a33ef33e38a4be907b5b39d5b80a447bc3063c9b36c2a8`. Root verifies equal Unicode cwd/TMPDIR byte geometry, same host/JDK/Swift resources, complete capture, stable artifacts/assets/source freeze and exact workspace/lineage settlement. This is a bounded prelaunch comparison, not full G1/G3 acceptance. Full source/installed matrices follow with all cases retained.

Fresh general `npm run verify:package` passes normal hooks, exact installed CLI/MCP/skill checks, 139 tools/six prompts/four setup clients and verified empty lineage. Run UUID `3c7cdc41-95b1-4557-a0b9-896d5be7cd36`; private `r12-package-integrity.log` retains complete output. This remains independent of real installed PSX and fresh-client gates.

## Complete renewed G1 source acceptance

Renewed complete G1 macOS source acceptance passes all nine aggregate cases on the repaired candidate, including 45 fresh CLI parity commands, exact persisted function Evidence, four-family SDK snapshots/atomic rejections, malformed policy and both native cancellation/recovery paths. Report SHA-256 `b50285b256c2af61c279b4c60f717d894a6bf12a975e29f3d9988ab45245e826`, events `e2da22b755465a2450fbfb2a70aa18278fb68d79648894dc947416332fc386db`. Root independently verifies stable code/assets, all 52 native runtime roots absent, no capture/report failures or unresolved owners, verified empty lineage and unchanged freeze `813df30e66d046518fa50d207cbc28163aedb13c9c3977b9afdc9a739be6f3c9`. Full G3, renewed G4 and actual G5 remain pending; Linux remains required/unavailable.

## Renewed G4 source verification and remaining CLI comparison

Renewed G4 selected AC3 smoke remains failed overall: source image verifies all 479,232 declared bytes and the entry; containing-function/instruction/assembly/decompile/reference facets and snapshot roundtrip pass. First fresh CLI image comparison fails cross-session journal equality; later CLI entry is unperformed. Report SHA-256 `57cb3a04bbd9d1fb2a002cd0875600e0667df760e825297120d323989ead68fb`. Root measures only journal/per-run digest differences: 234-row original/preparation journals match without clocks/ordinals, but 3,946-row current journals have 274 differing rows each even after that reduction. No pure-order or harmlessness claim follows. Input, source/assets/freeze unchanged; exact workspace/owners and lineage settle. Bounded R17 planning investigates the local comparison while preserving full per-run evidence and unchanged production/synthetic G1/G3 rules.

The renewal retains actual decompiler warnings and unavailable runtime facts. Successful facets are not a complete smoke pass; original failure `run-eWMPUM` remains immutable. The new failure is an observed verifier comparison disagreement, not attributed to environment or provider correctness without investigation.

## R17 local comparison contract

R17 scoped local comparator contract is saved/read back and assigned with disjoint local-runner/test ownership. Root independently verifies the four unmatched complete VARIABLE ADD-history groups have a unique whole-group bijection; installed primary source confirms Program-local allocation keys. Underlying storage/function ownership remains unproved and explicitly excluded. Full ordered per-run evidence and static attestation stay mandatory; only named cross-import journal representation differences are permitted. Shared synthetic comparator, production/bridge/contracts/assets/oracle/fixtures/lock and exact candidate tarball remain unchanged, so the renewed G1 runtime evidence remains applicable despite a transparently changed aggregate documentation/plan fingerprint. R17 controls/retained replay/review and fresh complete G4 remain pending; full G3/client/Linux/delivery remain pending.

### R17 retained native comparison checkpoint

Root replays the complete retained MCP event 64 and CLI event 246 with their independently captured startup/original records and the authorized source bytes. Local comparison passes; full journal counts are 234/234 preparation and 3946 current rows per import, with four unique complete VARIABLE ADD-group mappings containing 1, 12, 50 and 211 rows. Full ordered inputs, own attestations, all multiplicities, lossless row references and 5407 permitted difference records remain in ignored evidence. Shared synthetic comparison still refuses this pair; seven source/capture/static/metadata/journal/mode/run mutations are refused, with inputs and original report/events/source unchanged. Proof SHA-256 `83ece8470320c6471002e5a3c6b1f4fa606de987462e94ead3e848596083120c`. This is historical-observation replay, not fresh G4 acceptance.

Root verifies all runtime/original-file identities from the renewed G1 freeze remain unchanged. Changed authored files are exactly the two R17 local files plus plan/progress/ledger/results/PSX guide. Aggregate authored fingerprint has changed transparently; unchanged production/shared synthetic G1/G3 behavior retains the renewed source evidence. R17 controls/review/static, fresh full G4, installed G3 and fresh-client G5 remain pending. Linux remains required and unavailable.

### Final R17 pre-native controls

Root runs the exact local/public focused gate: all 185 tests pass in 12.15 seconds, including 78 new R17 synthetic controls. Earlier immutable failure logs retain the Buffer-to-Uint8Array snapshot mismatch, sandbox process `EPERM` and two provider/profile fixture mismatches; corrections preserve complete byte/record comparisons and valid Evidence construction before actual refusal. The bounded source/control review and the two correction-only fixture reviews pass with no blockers. Final source SHA-256 `4e0f087664fdfc3fd81c5d8b2c3670734d2c185a58cddf5700b4b6d7ed631a9f`; controls `3e7e24fc2b54eb078d1bb5a7ea1017acc82f9e6ea2a40d2ec0092da1727f1290`.

All 722 test files are discovered exactly once. Full configured static gate passes six tasks, 617 warnings/zero errors, 1326 source boundaries and 1018 architecture guards. Actual complete local routing remains for fresh G4; simulated controls and historical replay establish neither a fresh provider pass nor variable storage/function semantics. Documentation checks and final all-writer freeze precede complete fresh G4. Full installed G3 and client/Linux/delivery gates remain pending.

## Complete fresh R17 G4 acceptance

The selected patched AC3 Disc 1 boot image passes all eight original cases: full source-backed 479232-byte image and entry, containing-function/instructions/assembly/decompile/references, immutable snapshot roundtrip, fresh CLI image and subsequent exact CLI entry comparison. Report SHA-256 `67c166ef4fa4022b6fd749271de1ccc5ff22823dd821856508b62efb9461cc69`; events `7563ae81561c5afd16ee00865af4f9bb7d25265021e14ec2a2f668f9dcff2989`; run `55197f97-d9a8-4dfe-8d7c-fc24ab5ec7af`.

Local image comparison retains both complete original inputs/own attestations, 234 original and 234 adapted preparation rows plus 3946 current rows per import, lossless whole-journal references/counts, seven unique complete VARIABLE ADD-history mappings and 5124 permitted difference records. Mapped row counts are 50, 211, 1, 12, 1, 1 and 1. These are the same explicitly permitted difference category, not a new comparison relaxation. Event chronology, database keys, variable storage/function ownership and deterministic scheduling remain unproved. CLI entry has zero differences under the unchanged exact shared comparison.

Root independently verifies complete indexed row coverage and multiplicities, ADD-only group signatures, two original observations, exact source/code/assets and immutable freeze `410e21aa48108215be402233d4f416a7fed4d181988dd9d8a3fc68a5d502fcbc`. All four native roots and workspace are absent; primary/capture/cleanup failures, unpersisted events, unresolved owners and process lineage are empty. Prior failed reports retain their failed status. Full installed G3 is next; actual G5/Linux and delivery remain separate.

## Complete installed R17 G3 acceptance

Normal build/pack hooks produce the exact cold-tested candidate tarball `d4a7f8631fe85150f2ab20246d6a138f1bf475ce2e587cbeaf24aea01ed04acd`. Its isolated installed public CLI/MCP matrix passes all nine aggregate cases: independent oracle, capability/selectors, four-family snapshots/atomic rejection, 45 fresh strict CLI comparisons, both exact persisted function Evidence checks, malformed-policy parity and actual in-flight image cancellation/native disconnect with separately bound recovery. Report SHA-256 `4cc9a1a90b3f7c2da373d929ea325d04261de891a5a4862f95bff0be6cd9779a`; events `a93905b46924e1ec94e27efef1255e66b63d95ce4fd4cc5f0a6125afcbd0894b`; run `821f8e0d-5271-4482-92f5-61003ea684c8`.

Root independently verifies exact retained tarball, installed module/resource isolation and resource equality before/after, source/assets/code equality and frozen manifest `8e0ca4a1f64f19f0c294bc2456be9de58ef94d0c31bd6c59308c111618b58248`. All 52 native roots and the isolated package workspace are absent. Public and outer settlements have no failures/unpersisted captures/unresolved or retained owners; both verifier/public process lineage observations are verified and empty. Historical failed installed reports remain failed. This proves this exact artifact on the recorded macOS host, not Linux or fresh-client discovery. G5 staging follows the accepted artifact; Linux remains required/unavailable and full delivery/closure remains pending.

## G5 exact installed-client preparation

The accepted exact G3 tarball is installed in intentionally retained `/private/tmp/rea-psx-client-nWJKWT/project` with original Unicode synthetic fixture SHA-256 `b2fb15c8af2b4f379e3421d7414ef66ea15c4cf7215e0569d4e3721cdba8a5a3`, scoped `.codex/config.toml` and the installed generated skill link. Catalog-only preparation observes 139 named tools and closes its SDK/inspector with empty verified lineage. Private stage report SHA-256 `50d4d5282374f6d115f7eec53366fa5a3eba2f91bc9a125ff521ec4ce73ceed3`. Three sequential fresh-chat prompts and exact input/snapshot/artifact identities are handed to the user; no actual client discovery/use acceptance is inferred. The stage stays until transcript readback and owned-session closure. Ambient user configuration is unchanged.

An earlier preparation attempt dropped the context-owned launcher token when replacing its environment. The identity check refused it; private helper now preserves that owning context while adding only scoped configuration. Failed report `136a1d791bae8724e3b146de320bd01138cb9dfd3f8ff97b1ddb9d7449872b6d` remains immutable; exact failed temporary stage removal has a separate ownership/cleanup receipt after empty lineage. This helper correction changes no package/source/public verifier behavior.

P5-R0 requires affected existing native renewal after shared launch/lifecycle and preparation changes. Root is now renewing PSX import plus DOS/COM/host lanes against the frozen repaired source. Actual G5 transcripts, those G6 renewals and unavailable required Linux remain pending; no Phase 5 closure or delivery.

## Required existing native regression renewal

All four affected existing lanes pass on the frozen repaired macOS source with Ghidra 12.1.4/JDK 25. Root independently accepts the reports and verifies authored/runtime freeze `d8f6371e1f2e93f9b45116650c68699e1a8698080af657d53b2892b70313ea32` unchanged after the final host run.

- `npm run verify:ghidra:psx-import`: all nine independent imports across baseline, declared-register/fill and trailing-byte variants, plus four policy refusals pass. Private report `docs/psx-local/phase-5-regressions/r17-old-native-import/run-cAtTRb/report.json`, SHA-256 `668fd258a1631c7f88babe4ad807468aa3ea00c431c0a281371001f8ecaa145b`. Source/assets stay unchanged; workspace, direct sessions and roots are removed, cleanup errors are empty and lineage is verified empty.
- `npm run verify:ghidra:dos`: all three real entry/near/far CLI/MCP observations and source-integrity checks pass. Extracted final report `r17-old-native-dos/report.json`, SHA-256 `d634312dc9c75b21b7d91f1322713b3f039ca8638790c5210ffe4ff8f54c2745`. Native evidence is unmocked; cleanup is complete and lineage verified empty.
- `npm run verify:ghidra:com`: actual function, annotation, memory and truncation checks pass with unchanged source. Extracted final report `r17-old-native-com/report.json`, SHA-256 `4bcb2cdb405e45448e9f2e345efd3b416de102523cefed4405a941bfe57ae9a2`. Native evidence is unmocked; cleanup is complete and lineage verified empty.
- `npm run verify:ghidra`: all four host fixtures (debug, stripped, type-layout and jump-table), malformed-target refusal, public native API and real native-value CLI/stdio MCP boundaries pass. Extracted final report `r17-old-native-host-report.json`, SHA-256 `711a9a5969f3168610ec28d4e2530dfa6c2528f94eb1e09cd91c80ce4b20fcf7`. The real boundary lane records 272 successful and 52 rejected calls, source immutability, startup cancellation and private-socket cleanup. Fixture targets are absent; cleanup is complete and lineage verified empty. Its auxiliary Darwin-built ELF alias subcase remains separate from Linux host and Mach-O named non-entry-label coverage; PSX-010 stays deferred.

All report paths above are under ignored `docs/psx-local/phase-5-regressions`; exact original logs and captures are retained. Renewed complete load-image evidence was accepted earlier. These local regressions do not satisfy required Linux gates.

## Actual fresh-client G5 acceptance

The user supplied `transcript-recordings` from `/private/tmp/rea-psx-client-nWJKWT/project`. Root verifies supplied manifest/file/snapshot identities and reads the three live app chats without messaging them; the read-only test engineer independently compares actual recorded invocations and full immutable snapshots against the original fixture oracle. All three scenarios pass without reruns.

| Scenario                  | Chat ID                                | Snapshot SHA-256                                                   | Observed result                                                                                                                                                                                                                                                                                              |
| ------------------------- | -------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Broad static              | `01a12854-9ca4-7640-8975-da1432e9e6e0` | `9d0ce6ae87017c2abb7987cc9845c861d5f6c72c243c9fd896053fc2869d2876` | Source image verifies all 2048 payload bytes and entry; functions, pseudocode, calls and strings retain 15 complete Evidence records. Save/close and post-close `open:false` observed.                                                                                                                       |
| Direct call/delay slot    | `01a12857-552f-71d2-9529-12f273f33b47` | `19f6307b57b42e96eb80b45f8cfbda06006c99d87b151c24a7fd922d1dc8c2a3` | Actual JAL at `0x80010008` targets `0x80010080`; `0x8001000c` is an explicitly evidenced depth-one delay slot, `_li a0,0x7`. Four complete Evidence records retained; save/close and `open:false` observed.                                                                                                  |
| Negative snapshot/runtime | `01a12858-f9f0-7a43-9ae7-057dfac35ae4` | `573506180eba99e1ca348662015b3364f6b776233e2bd3f4d30e609357e5bb5f` | All 15 original broad records survive unchanged; unresolved computed call and runtime return address remain unknown. A 16-byte request beyond payload returns zero bytes, `complete:false`. Two source-bound unknowns retain supporting Evidence; 23 records saved, close and `session_open:false` observed. |

All 39 actual MCP calls use the staged `rea_psx_acceptance` server, complete successfully, and have no recorded MCP error. Every actual inspection call matches full retained Evidence by ID, operation and exact arguments. Source/session/export hashes, all 20 installed resource hashes, configuration/skill bindings and all 21 independent oracle words plus terminated string/sentinel match. The exact candidate remains `d4a7f8631fe85150f2ab20246d6a138f1bf475ce2e587cbeaf24aea01ed04acd`; original fixture remains `b2fb15c8af2b4f379e3421d7414ef66ea15c4cf7215e0569d4e3721cdba8a5a3`. Profiles consistently identify Ghidra 12.1.4/PsxLoader/default PSX language and expected loader/assets.

The three distinct chats each have one completed turn, correct isolated project and prompt, no recorded parent/fork, successful installed generated-skill reads, Codex Desktop originator, engine `0.162.0-alpha.17.2`, `gpt-6.1-sol` at high effort, and recorded macOS 27.0.1 arm64. They use normal ambient memory discovery. Desktop bundle version and trust transition remain unknown. Source-harness agent/planner discovery and actual trusted lifecycle were not observed; the direct chat's attempted `AGENTS.md` read correctly reported absence in the isolated installed project. These observations are separate from the three successful package scenarios.

Some native result wrappers preserve client-origin nested serialization failures and function-output truncation. Full snapshots and matching event/Evidence references establish the scenario claims; complete raw wire decoding, zero provider dispatch on replay and independently measured OS cleanup are not claimed. In particular the negative scenario performs a fresh native document query despite cached image evidence. User-facing answers preserve unknown runtime registers, runtime return address and overlay bytes; lack of overlay evidence does not establish overlay absence.

Root preserves 22 user evidence/configuration/report files as byte-identical private copies under `docs/psx-local/phase-5-client-runs/stage-OSRVHQ/received-evidence`, receipt SHA-256 `96796be786de50cdd7281dbcd48bf50cad03cefb7434cc337eb885e546e9a364`. Original user files and stage are intentionally retained. Closed binary projections do not prove app-owned MCP server exit; no process was signalled or user workspace deleted. Raw transcripts, snapshots, fixture and local payloads stay ignored and uncommitted.

Under subsequent user-approved P5-R18, Linux G2 and Linux installed G3 are optional and remain unverified. PSX-005 and Phase 5 stay in progress for concrete PR and approved verified merge delivery.

## Final local state checks

After the actual client review and native renewals, `npm run docs:check` passes all six tasks (4.804 seconds), and `npm run check` passes the configured static tasks and architecture guards. Git whitespace passes. Runtime, bridge, original fixtures, oracle and all authored source/test identities remain unchanged from the final native freeze; only the four state/results/guide documents change. All 22 preserved user files still match both original and copy digests. No repeated provider or focused-test run is required for these documentation-only edits; the existing final 185-test gate remains applicable. Local status is technically verified within the recorded macOS scope; required Linux acceptance and full phase delivery remain pending.

## P5-R18 completion scope and delivery readiness

The user explicitly removed Linux implementation/verification as a completion gate on 2026-10-10. Linux public G2 and Linux installed G3 are optional, unverified coverage; no Linux support is claimed. All required macOS G1/G3, selected patched-AC3 G4, three actual G5 scenarios and G6 controls/native regressions/bounded reviews pass. No source, package, provider, fixture or CI change follows from this scope amendment. Earlier Linux-blocked checkpoints are historical. Required final-content verification, commit/push/PR and user-approved verified merge remain G7; Phase 5/PSX-005 stay in-progress until delivery is satisfied.

## Concrete PR and user-requested project removal

Implementation commit `439f56c77e3fa9d85f2d668c3f9d625996ea077f` is pushed to `origin/codex/psx-phase-5`; [PR #5](https://github.com/Troll-Phace/rea/pull/5) is open and attached. No merge or automatic merge is authorized yet. PSX-005 stays in-progress until approved verified delivery.

Normal precommit formatting/lint hooks make one source representation change in `CliCleanupScope`: `Promise.allSettled([...record.pending])` becomes `Promise.allSettled(record.pending)`. The private built-in Set is enumerated synchronously in both expressions before any asynchronous continuation, with identical promise inputs and settlement behavior. All ten actual cleanup-scope controls pass after the edit, as do renewed six-task static checks, 1326 module boundaries and 1018 architecture guards. The 96-path staging check excludes binaries/local payloads; all other precommit identities remain unchanged. Existing native/cold-installed/fresh-client reports retain the exact earlier candidate/tarball hashes; no newly built artifact is claimed to have that installed acceptance. This equivalent iterable simplification does not add a lifecycle behavior or platform claim.

The user then explicitly asks to remove the temporary test project. Root rechecks the 22 preserved evidence files, archives the complete project privately (25 file/symlink entries with exact identities), and removes exactly `/private/tmp/rea-psx-client-nWJKWT/project`. Receipt `docs/psx-local/phase-5-client-runs/stage-OSRVHQ/project-removal-receipt.json` has SHA-256 `34c1f41ea063f27945e036f6d044c54e72229cf0fc8d57f526fdacc9a7847ad0`; original staging report and user records remain immutable in the private archive. The installed generated-skill symlink is preserved as a symlink. Process inspection observes app-owned MCP servers and recording workers; installed runtime/prefix/cache outside the requested project is retained. No process is signalled and complete OS process cleanup is not claimed. The earlier intentional-retention checkpoint is historical, superseded only for this requested project directory.

## Approved merge and final closure

User-approved [PR #5](https://github.com/Troll-Phace/rea/pull/5) merged at `1205e45502fe436ce05aff9601402da5b1951b00` on `2026-10-11T00:51:57Z` (2026-10-10 in the client timezone). Phase 5 and PSX-005 are complete under P5-R18 macOS scope; Linux remains optional/unverified. All five batch phases are complete; PSX-008/PSX-010 remain deferred nonblocking coverage items. No batch rollover or new phase is started.

The approved final PR head `23cd442dde2a7197af405e01fd128cd6621a3b6d` passes renewed full static/typecheck/lint/module/format checks and architecture guards, plus generated documentation. GitHub reports CLEAN/MERGEABLE and no advertised remote status checks. The user's explicit “go ahead and merge” authorizes the concrete PR; normal `--merge --match-head-commit` completes without bypass, force push or auto-merge. GitHub independently confirms MERGED and the exact commit/time; local main is fast-forwarded to the merge before documentation-only closure reconciliation. Earlier failed runs, prior pending statuses and exact measured tarball/source identities remain historical and unchanged.
