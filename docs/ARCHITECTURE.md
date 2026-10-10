# PSX support architecture

## Existing system

The authoritative REA architecture is [architecture.mermaid](architecture.mermaid), with behavior documented in [ghidra-provider.md](ghidra-provider.md), [testing.md](testing.md), and [tool-design.md](tool-design.md). Dependency flow: domain/contracts -> application workflows -> provider and CLI/MCP composition at outer boundaries. This document adds a proposed PSX feature slice without replacing those references.

BinaryTargetResolver reads a bounded header; domain/binaryTarget.ts classifies known formats. binaryTargetTypes.ts has x86/ARM architecture identities. GhidraProvider.ts independently gates targets. GhidraAnalysisProfile.ts commits import semantics; GhidraLauncher.ts creates a private headless session. Java bridge returns observed data; evidence and snapshot schemas constrain transport/persistence. GhidraLoadImageAttest.ts currently independently verifies DOS images only. NativeAOT analysis extensions are not a general PSX loader interface.

## Proposed feature

A format-aware PS-X EXE parser validates source header and ranges before provider admission. Explicit PSX format and CPU identity propagate through relevant domain, transport and snapshot contracts. Ghidra-specific loader availability, language, compiler spec and installed-loader identity belong to provider code. The PSX import profile commits all interpretation-affecting plugin resources; no raw-binary fallback on loader failure.

Verify observed memory mappings and entry/register context against independently parsed header facts. Distinguish file bytes, uninitialized memory and hardware regions. Preserve exact source identity, reject contradictory measured data, and leave unobservable runtime values unknown. Do not make SDK signature names or decompiler output authoritative ground truth. Audit delay-slot semantics through public instruction/flow interfaces with a synthetic oracle.

Use existing cleanup/process ownership and cancellation infrastructure. Preserve temporary database behavior; live GUI project synchronization is excluded. Additive contracts must not imply all MIPS formats, hosts or providers are supported. Provider profiles and persisted snapshots must include new interpretation identities. Detailed file ownership and acceptance contracts live in PLAN.md.
