# PSX support architecture

## Existing system

The authoritative REA architecture is [architecture.mermaid](architecture.mermaid), with behavior documented in [ghidra-provider.md](ghidra-provider.md), [testing.md](testing.md), and [tool-design.md](tool-design.md). Dependency flow: domain/contracts -> application workflows -> provider and CLI/MCP composition at outer boundaries. This document records the PSX feature slice alongside those references.

BinaryTargetResolver reads a bounded header; domain/binaryTarget.ts classifies known formats. Phase 1 added the pure PS-X EXE parser and coherent `ps-x-exe`/`mips` identity without expanding ELF/PE architecture support. GhidraProvider.ts independently gates targets. GhidraAnalysisProfile.ts commits import semantics; GhidraLauncher.ts creates a private headless session. Java bridge returns observed data; evidence and snapshot schemas constrain transport/persistence. GhidraLoadImageAttest.ts dispatches independent DOS and PSX checks against the owned immutable snapshot. NativeAOT analysis extensions are not a general PSX loader interface.

## Phase 2 import slice

The [shared Phase 2 contract](active/phase-2-plan.md) assigns target-specific
loader inspection and source-layout admission to the Ghidra provider. Generic
installation availability remains independent of PSX support. Its discriminated
import configuration preserves automatic, DOS MZ and DOS COM modes and adds
explicit PSX selection with omitted RAM overrides. Static eligibility, supplied
commitments, advertised defaults and observed Program facts are separate values.

The production boundary hashes selected-installation code JARs/module
data and binds that inventory to the PSX profile. A packaged observer validates
import facts before analysis; the authenticated bridge observes them again after
analysis. Startup requires the target-bound analysis-completion report and
observer marker; Ghidra's final import report follows the serving postScript.
Source/asset disagreement fails the attempt through existing typed
errors and owned cleanup. The policy initially admits the KSEG0 2 MiB RAM bank
and preserves exact source declarations rather than normalizing aliases.

At the Phase 2 checkpoint only inventory observations were exposed and
load-image verification remained unsupported. PSX function/instruction operations were unavailable at that checkpoint.
The Phase 4 query slice below defines their current admission and verification gates. Empty FileBytes, missing SP and uninitialized
fill remain unknown or measured limitations. No producer provenance repair is
included at that checkpoint; Phase 3 resolves the adapted-provenance dependency below.

## Phase 3 static image evidence

The [shared Phase 3 contract](active/phase-3-plan.md), including its R1/R2
revisions, separates original loader observations, REA preparation and fresh
after-analysis observations. The installed loader has no FileBytes provenance.
`ReaGhidraPreparePsx` releases only its own script transaction before the
provenance helper opens a sole top-level transaction in REA's disposable
headless Program. The helper refuses another active transaction. It verifies
original payload content, creates genuine FileBytes from the complete immutable
snapshot and replaces only approved payload blocks with source-linked blocks.
Source executable bytes and third-party installations remain unchanged.

Preparation captures complete enumerated state, compares operational state
after restoration and checks actual final commit before publishing readiness.
Unsupported metadata makes preparation unavailable before mutation; cancellation
or failed validation requires complete original state, journal and source
restoration after final rollback. Neither process exit nor database cleanup
proves transaction completion. Public inspection reads current memory and exact
listing entry facts without another adaptation.

Removing memory deletes loader label history that public Ghidra APIs cannot
restore. The original complete journal is retained in a fixed authenticated
evidence record; preparation reports both journals and duplicate-preserving
differences. Success permits only measured ADD events recreated at restored
payload symbols/functions, with all other enumerated state equal. Original
journal retention is evidence preservation, not restoration of the live journal.
Rollback and unavailable outcomes permit no journal exception.

Strict version-3 startup agreement binds the fixed original record, source,
run, preparation digest and canonical profile. The profile includes provenance
method `rea-psx-filebytes-rebind-v2`, independent image interpretation and
`psx_preparation_transaction: exclusive-top-level-v1`. These semantic changes
invalidate prior PSX snapshot profiles while leaving non-PSX identities intact.
The provider owns record validation and engine interpretation; domain contracts
contain neutral values and shared CLI/MCP workflows preserve their Evidence.

The independent TypeScript verifier parses the snapshot separately, checks
complete payload coverage, actual source links/offsets/digests, unchanged mapped
bytes and the exact declared entry instruction. Contradictions yield `mismatch`;
missing required evidence yields `unsupported`. `verified` covers only the
enumerated adapted static payload. GP/SP and fill declarations remain separate
from observations, including explicit unknowns. Original-loader source lineage,
runtime correctness and MIPS query semantics are not established. Current
verification and preserved failures are in [Phase 3 results](active/phase-3-results.md).

## Phase 4 static query slice

The [shared Phase 4 contract](active/phase-4-plan.md), including R1, admits an
explicit provider-owned set of static instruction, call-target, function,
decompiler and reference queries. Annotation and native data-type queries are
refused before bridge dispatch. Source preparation and image interpretation are
unchanged. The neutral optional `delay_slots` contract preserves older captures;
new Ghidra responses report measured Listing slot membership, owned depth and
complete contiguous slot addresses, or explicit unknown coverage with limitations.

Flow kind prioritizes Listing calls, decoded p-code RETURN, Listing jumps,
terminal and fallthrough. Conditional/computed flags remain Listing FlowType
properties. A RETURN with computed false does not establish a known or direct
runtime return address. Classification evidence preserves both Listing and
p-code observations. Function bodies and tail-slot containment come from the
actual AddressSet and Listing; no body extension follows from arithmetic.

The provider checks both PSX scope `inventory-load-image-and-static-functions-v1`
and Ghidra flow interpretation `decoded-return-before-jump-and-delay-slots-v2`.
The latter intentionally invalidates older Ghidra semantic profiles, including
non-PSX targets. Other provider profiles remain unchanged; optional-field omission
alone does not invalidate their captures. Existing Evidence and snapshot workflows
preserve target/profile identity and reject mismatched reuse before query dispatch.
Snapshot document scope comes from each named input contract's actual `document`
field. Load-image inspection has a strict empty input and can therefore retain
and replay its query result without inventing a document argument. Existing
mutation, live/stateful, cursor and identity guards remain in effect.

[Phase 4 results](active/phase-4-results.md) separate deterministic adapter/schema
checks from bounded real synthetic macOS operations. The fixed decoder and full direct-provider operation gates pass. Final host
regressions pass with Mach-O host controls and an auxiliary ELF relocatable
entry-alias fixture; Mach-O named non-entry-label coverage remains unverified.
The single phase-close review and final configured checks pass; approved delivery
remains pending. Public real
CLI/MCP operation journeys, Linux, game inputs and installed-package/fresh-client
acceptance remain Phase 5. Static queries do not establish runtime reachability
or complete indirect targets.

## Later proposed analysis

Verify observed memory mappings and entry/register context against independently parsed header facts. Distinguish file bytes, uninitialized memory and hardware regions. Preserve exact source identity, reject contradictory measured data, and leave unobservable runtime values unknown. Do not make SDK signature names or decompiler output authoritative ground truth. Audit delay-slot semantics through public instruction/flow interfaces with a synthetic oracle.

Use existing cleanup/process ownership and cancellation infrastructure. Preserve temporary database behavior; live GUI project synchronization is excluded. Additive contracts must not imply all MIPS formats, hosts or providers are supported. Provider profiles and persisted snapshots must include new interpretation identities. Detailed file ownership and acceptance contracts live in PLAN.md.
