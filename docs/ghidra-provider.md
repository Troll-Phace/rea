# Ghidra provider semantics

REA imports one target into an ephemeral Ghidra database. Linux/macOS support
read-only analysis and atomic function-name/entry-comment edits; Windows P0 is
read-only. GUI controls and persistent database mutation are unavailable.
Executable bytes remain unchanged.

Use [installation](installation.md#ghidra) for supported hosts, prerequisites,
configuration, startup deadlines, resource controls, and cleanup recovery.
[Windows P0](windows-ghidra-p0.md) has its own admission and lifecycle boundary;
[NativeAOT recovery](ghidra-nativeaot.md) is an optional, separately verified
extension. [PS-X EXE analysis](ghidra-psx.md) describes this fork's admitted
static workflow and separate real-provider acceptance gates. Check the
[release boundary](installation.md#released-package-and-main)
when using npm.

Provider selection and profile identity follow
[MCP contracts](mcp-contracts.md#identity-and-discovery). One deep
provider stays bound to the target; runtime failure never selects another
provider automatically. The contracts below describe Ghidra observations,
not equivalence with another engine's pseudocode or analysis database.

## Admitted inventory semantics

| Concern          | Ghidra contract                                                                                                                                                                                                                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Program identity | One `analyzeHeadless` import produces exactly one Program; `list_documents` therefore returns exactly one name.                                                                                                                                                                                 |
| Addresses        | Default memory uses lowercase `0x` hexadecimal. Non-default and external spaces use `<percent-encoded-space>:0x<hex>` and remain round-trippable. The handshake commits image base and default address-space name.                                                                              |
| Symbols          | `list_names` includes address-bearing memory and external symbols, including dynamic symbols, while excluding variable and no-address namespace records. Each item reports primary, dynamic, external, symbol type, and source facts.                                                           |
| Procedures       | Both non-external and external functions are listed. A local thunk remains distinct from its resolved target; exact and qualified name lookup fails on ambiguity rather than guessing.                                                                                                          |
| Strings          | Only Ghidra-defined string `Data` is observed. Items report charset, byte length, and whether a required null terminator is missing. The API cannot distinguish a present terminator from fixed/Pascal layouts when no terminator is missing, so that state is named `present_or_not_required`. |
| Memory           | Memory-block end addresses are exclusive. Read/write/execute, initialization, overlay, address space, and image base are direct Ghidra observations.                                                                                                                                            |
| Inventory        | Procedure, symbol, and string listings plus searches return the complete matching collection in one response; callers do not provide offsets or result-count limits.                                                                                                                            |
| Search           | Literal and Java-regex searches scan the complete immutable inventory and return all matching entries inline. Search waits for a reply or caller cancellation; there are no caller-supplied offsets or result-count limits.                                                                     |
| Analysis state   | The socket is exposed only after default auto-analysis completes. Established operations wait for their reply or caller cancellation; there is no fixed response-size ceiling.                                                                                                                  |

## PSX Phase 2 import boundary

The [shared execution contract](active/phase-2-plan.md) defines an initial
macOS/Linux implementation policy for PS-X EXE import. Admission requires a
nonempty aligned payload and complete entry instruction in the KSEG0 2 MiB RAM
bank, disjoint in-bank fill and zero separate-data declarations. Addresses and
raw GP/stack declarations remain unchanged. Layouts requiring RAM overrides are
unsupported because the installed loader's option transport fails.

The production configuration selects `PsxLoader`, `PSX:LE:32:default` and
compiler `default`, omitting both RAM arguments. Target-specific inspection is
separate from ordinary Ghidra availability. The profile binds installation
code/data fingerprints, policy and import semantics. A before-analysis observer
and authenticated after-analysis handshake must agree on source, selected
loader/assets, advertised defaults and effective Program facts. Startup also
requires a target-bound analysis-success report and correlated observer marker;
the terminal import report follows the serving postScript. The owned PSX
snapshot coordinate is canonicalized before transport. A zero process exit
alone cannot establish import success.

Phase 2 admitted inventory observations; function and instruction queries were
unavailable at that checkpoint. Phase 4 defines the static query slice below.
At that checkpoint `inspect_native_load_image` returned `unsupported` because
matching bytes could not establish original source offsets. Phase 3 adds the
adapted static-image evidence described below. Missing SP, uninitialized fill
and absent original-loader FileBytes remain explicit limitations.
The [Phase 2 results](active/phase-2-results.md) record nine real macOS imports
on Ghidra 12.1.4/Temurin 25.0.4.1 across three generated fixtures and four
pre-allocation policy refusals, with source/asset preservation and verified
cleanup. Linux remains unverified. PSX runtime behavior and complete
packaged-provider support remain later gates.

## PSX Phase 3 image evidence

`inspect_native_load_image` returns a PSX-specific `verified`, `mismatch` or
`unsupported` result with source declarations, measured mappings, named checks,
examined coverage and limitations. It independently reads the immutable snapshot
and checks the entire declared payload, genuine FileBytes/source offsets and
digests, mapped bytes, external entry and exact four-byte listing instruction at
the declared PC. A containing instruction is insufficient. Trailing source bytes
participate in source identity without becoming payload coverage. Optional
unobserved SP or fill content remains unknown; zero declarations are retained.

The installed PSX loader supplies no original FileBytes. During opening,
REA may rebind approved payload blocks to FileBytes in its disposable Program
under method `rea-psx-filebytes-rebind-v2`. It checks original content first and
preserves complete enumerated operational state. The wrapper releases only its
own script transaction, and preparation refuses any remaining active transaction.
Actual final commit and current source/state validation precede readiness;
failure requires complete original rollback. A preflight-unavailable adaptation
retains inventory with unsupported verification. Executable bytes, GUI databases
and installed loader files are unchanged.

Public Ghidra APIs cannot restore deleted loader label history. REA retains the
complete original journal in authenticated fixed-file evidence, reports the
adapted journal and exact duplicate-preserving differences, and discloses
restoration-generated payload ADD events. It does not claim to restore that live
journal. Unsupported and rollback outcomes require complete journal equality.
Fresh after-analysis journal facts are distinct from preparation journals.

Startup version 3 binds original evidence, preparation, source, run and profile
through the existing authenticated channel. Missing, forged or stale records
fail startup with owned cleanup. Semantic profile parameters identify the
provenance method, independent image checks and exclusive transaction policy;
old PSX snapshot profiles cannot silently reuse the new interpretation. DOS and
COM contracts retain their existing behavior.

Verified applies to the enumerated REA-adapted static image, not original-loader
lineage or runtime execution. Function/instruction semantics have their separate
Phase 4 verification gate below. See the [contract](active/phase-3-plan.md) and
[results](active/phase-3-results.md) for current measured coverage; direct
noanalysis feasibility, public auto-analysis acceptance and replay mutations are
separate evidence. Linux, game inputs and installed-package/fresh-client
acceptance remain unperformed.

## PSX Phase 4 static queries

The provider admits instruction and call-target inspection, function dossiers,
assembly, decompilation, instruction windows, callers/callees and references.
Annotation and native data-type inspection remain refused before bridge dispatch.
The [Phase 4 contract](active/phase-4-plan.md) requires real synthetic decoder and
operation checks; [results](active/phase-4-results.md) record their current status.

New Ghidra instruction results include measured `delay_slots`: Listing slot
membership, owned depth and complete contiguous addresses, or nulls when unknown.
Nondecoded addresses have all three slot values null. Ordinary instructions own
zero slots with an empty address list; a slot can itself own zero slots. Flow kind
uses decoded RETURN before jump. Conditional/computed are observed Listing flags;
computed false on a return does not establish a direct or known runtime target.
Static call targets preserve unresolved computed calls.

PSX profiles bind scope `inventory-load-image-and-static-functions-v1` and flow
semantics `decoded-return-before-jump-and-delay-slots-v2`; both are checked when
opening. All Ghidra profiles use the new flow version and older Ghidra profile
snapshots are intentionally stale. Optional omission of `delay_slots` remains
compatible for other providers. Linux, game/runtime analysis and full public
operation/package/fresh-client acceptance remain separate Phase 5 gates.

## Admitted function-analysis semantics

| Concern                 | Ghidra contract                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Decompiler lifetime     | One persistent `DecompInterface` is opened for the imported Program and disposed during bridge shutdown. Native decompilation has no fixed per-function deadline. External functions or functions without bodies return `null`; cancellation and native failure remain distinct.                                                                                                                                                                                                                                                                                                                                           |
| Serialization           | A FIFO sends one Program request at a time. Caller cancellation removes queued work promptly and is passed to active socket waits. This is an adapter safety commitment, not a claim that every Ghidra API is thread-safe.                                                                                                                                                                                                                                                                                                                                                                                                 |
| Function identity       | Every function result carries the entry address and Ghidra FunctionManager classification for external, thunk, and resolved thunk target. These are observations, not proof that unresolved targetless calls have been recovered.                                                                                                                                                                                                                                                                                                                                                                                          |
| Assembly and pseudocode | Assembly is complete Ghidra Listing text; pseudocode is Ghidra decompiler output. Neither is original source, and cross-provider comparison never treats Hopper and Ghidra text as equal or unequal semantic facts.                                                                                                                                                                                                                                                                                                                                                                                                        |
| Instruction fast path   | `read_function_instructions` returns every raw Listing instruction for the requested function without invoking the decompiler or whole-program name/string inventories.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Calls and references    | Callers/callees contain only resolved functions. Reference edges preserve exact ReferenceManager type and call/jump/data/read/write/indirect/computed/conditional/terminal/external facts. Targetless computed flow remains unknown. Synthetic entry-point references without actionable memory sources are omitted explicitly.                                                                                                                                                                                                                                                                                            |
| CFG                     | Dossiers use `BasicBlockModel` and retain only non-call successors inside the function body. CFG topology is address-normalized for comparison; provider-specific block construction remains a declared difference.                                                                                                                                                                                                                                                                                                                                                                                                        |
| P-code value flow       | Function dossiers include up to 3,000 high-p-code operations, at most 64 inputs per operation, and 12,000 def-use edges. Results identify memory reads/writes, branches, and calls by p-code opcode, and mark decompiler-dead operations. Large results report truncation, an omitted-operation lower bound, and known omitted-input/edge counts. The dossier is an intra-function graph; `trace_native_values` composes derived parameter/argument and return/output dependencies across resolved calls. It does not resolve memory aliasing, call side effects, runtime behavior, persistent state, or business meaning. |
| Result extent           | Function instruction scans and native API boundary observations remain complete. P-code flow is the explicit bounded exception; its count fields distinguish exact retained counts from lower-bound or known-omitted counts. Caller cancellation and provider failures remain distinct.                                                                                                                                                                                                                                                                                                                                    |

`npm run verify:ghidra` compiles the versioned C oracle into debug and stripped
host-native targets (x86-64/AArch64 ELF on Linux or Mach-O on macOS), plus a native
DWARF 4 type-layout object. It proves the admitted operations, external functions, resolved thunks, exports, stripped-name
behavior, direct and targetless indirect calls, typed references, strings/xrefs,
multi-block CFG, bounded p-code def-use/effect links, semantic enhanced workflows, cancellation, startup deadlines,
serialized concurrency, malformed-target rejection, profile identity, and
process/project cleanup against real Ghidra 12.1.4. Unit fixtures separately
cover startup deadlines, process exit, queued cancellation, and malformed wire
output.

`npm run verify:ghidra:cross-format` adds AArch64 ELF, x86-64 PE, and x86-64
Mach-O target coverage. It requires `clang`, LLD, and `lld-link`; set
`REA_CLANG`, `REA_LLD`, or `REA_LLD_LINK` to select them. The verifier checks
these tools before compilation. Keeping this matrix separate lets Linux
host/provider acceptance run with only the host compiler.

`npm run verify:ghidra:windows` and its `-- --x86` variant check the source-owned native x86 and x86-64 PE
fixture, all 25 read-only operations, target/snapshot/import SHA-256 linkage,
and project, endpoint, process, and runtime cleanup. The independent native
lane checks DACLs, handle admission, cancellation, and Job Object lifecycle.
`npm run verify:ghidra:windows:package` packs and installs REA into an isolated
prefix, then checks ordinary-user CLI/MCP operations against canonical contracts.
All lanes require matching native controls; package startup alone establishes
only package compatibility.
