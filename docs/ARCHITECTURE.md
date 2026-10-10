# PSX support architecture

## Existing system

The authoritative REA architecture is [architecture.mermaid](architecture.mermaid), with behavior documented in [ghidra-provider.md](ghidra-provider.md), [testing.md](testing.md), and [tool-design.md](tool-design.md). Dependency flow: domain/contracts -> application workflows -> provider and CLI/MCP composition at outer boundaries. This document records the PSX feature slice alongside those references.

BinaryTargetResolver reads a bounded header; domain/binaryTarget.ts classifies known formats. Phase 1 added the pure PS-X EXE parser and coherent `ps-x-exe`/`mips` identity without expanding ELF/PE architecture support. GhidraProvider.ts independently gates targets. GhidraAnalysisProfile.ts commits import semantics; GhidraLauncher.ts creates a private headless session. Java bridge returns observed data; evidence and snapshot schemas constrain transport/persistence. GhidraLoadImageAttest.ts currently independently verifies DOS images only. NativeAOT analysis extensions are not a general PSX loader interface.

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

Phase 2 exposes inventory observations and keeps load-image verification
unsupported. PSX function/instruction operations remain unavailable until their
Phase 4 semantics are verified. Empty FileBytes, missing SP and uninitialized
fill remain unknown or measured limitations. No producer provenance repair is
included; PSX-007 stays a Phase 3 dependency.

## Later proposed evidence and analysis

Verify observed memory mappings and entry/register context against independently parsed header facts. Distinguish file bytes, uninitialized memory and hardware regions. Preserve exact source identity, reject contradictory measured data, and leave unobservable runtime values unknown. Do not make SDK signature names or decompiler output authoritative ground truth. Audit delay-slot semantics through public instruction/flow interfaces with a synthetic oracle.

Use existing cleanup/process ownership and cancellation infrastructure. Preserve temporary database behavior; live GUI project synchronization is excluded. Additive contracts must not imply all MIPS formats, hosts or providers are supported. Provider profiles and persisted snapshots must include new interpretation identities. Detailed file ownership and acceptance contracts live in PLAN.md.
