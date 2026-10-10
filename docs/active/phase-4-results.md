# Phase 4 verification results

Execution contract: [phase-4-plan.md](phase-4-plan.md), P4-R0 with reviewed revisions through P4-R8, PSX-004. Historical attempts below retain their original revisions and outcomes.

## Current evidence

P4-R1 G1 passed through the real direct production provider on macOS.
Fresh P4-R5 G2 also passed: **79 recorded operations**, all 21 original words,
six transfers, both functions' meaningful pseudocode/dossiers, direct and
unresolved reference facts, selectors, readback equality and admission refusals.
The reports and failed predecessors remain immutable below. P4-21 simulated
CLI/MCP/schema/snapshot checks pass within their recorded scope, including
four-family zero-dispatch replay under R3.

Required native gates now pass within their recorded scopes: frozen full PSX
load-image, PSX import, DOS/COM, direct PSX G1/G2 and full host-native G4. R8's
auxiliary AArch64 ELF relocatable fixture passed independent compilation,
focused provider proof and every unchanged public alias/name/address/xrefs/
annotation check. Main host Mach-O controls passed separately. All failed
predecessors remain preserved below. Final configured checks and the single bounded close review passed; [PR #4](https://github.com/Troll-Phace/rea/pull/4)
is open; approved merge remains pending. Phase 4 delivery completion is not yet claimed.

This lane is real direct production-provider evidence on macOS. Real public
PSX CLI/stdio MCP operation journeys, Linux, installed-package/fresh-client
acceptance, patched AC3 and runtime execution remain separate Phase 5 gates.

`instruction-flow` is an original generated PS-X EXE with a 0x800-byte header,
0x800-byte payload, load/entry 0x80010000, explicit six-transfer/non-NOP-slot
oracle, computed unresolved call, two function tail slots and REA-PSX-P4 data.
The existing variants are checked against their original builder hashes:

| Variant                 | SHA-256                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| baseline                | be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a |
| declared-registers-fill | fb38aeaa649f3b90993bf6151dffc42da00cba2087344255bc6e60d9442ab3d1 |
| trailing-bytes          | 53fea47eea51911150080df66d2d1acc852d64a7fe39d3777cdcbcd54b155595 |

The runner accepts only `--stage decoder` or no arguments. It preflights the
explicit installation/JDK, loader and ignored capture path before owned
resources; opens one fresh canonical production session; captures each raw and
normalized result before independent assertions; attempts capture, source,
asset and code postchecks after a primary failure; retries owned close and
retains unresolved ownership. Reports default to ignored
`docs/psx-local/phase-4-operation-runs/run-*/report.json`.

## Historical initial deterministic checkpoint

`npm run test:focused -- tests/boundary/providers/ghidra/ghidraPsxOperationsVerifier.test.ts`
passed nine tests after the preflight and runner-wiring corrections. Capture/postcheck/primary failures remain distinct; unresolved
close retains exact resource/root ownership; a retry still records the initial
failure; every independent cleanup is attempted. First contradictory word stops
semantic checking after raw capture. Caller executable arguments fail preflight.
The three prior fixture hashes agree with `git show HEAD` builder outputs.

TypeScript `tsc --noEmit -p tsconfig.json`, targeted formatting, Git whitespace
and test discovery passed (all 709 files exactly once). Targeted oxlint returned
zero errors, with runner/helper size and complexity warnings. These tests use
real filesystem handles and exact paths with controlled failure seams; they do
not prove decoder or native-provider behavior. G1 must measure all original
oracle claims before G2 or public simulated evidence can support the phase.
Native mismatches remain blockers requiring a bounded contract revision.

## Initial preflight correction

The first G1 invocation stopped before workspace/provider allocation because
the verifier sliced ten bytes for the eleven-byte `REA-PSX-P4` plus NUL string.
The exact assertion was reproduced through exported read-only preflight:
actual `REA-PSX-P4`, expected `REA-PSX-P4\0`. No native decoder fact was
measured and no report directory was allocated. The code expectation violated
the original fixture specification; the generated source was correct.

Preflight now uses `Buffer.byteLength(expectedString, "ascii")` and independently
requires the NUL followed immediately by the saved sentinel. A deterministic
fixture boundary case checks the actual eleven bytes and rejects missing NUL
and shifted-sentinel mutations. The revised eight-test suite passed, TypeScript passed, and read-only decoder
preflight passed against the selected installed Ghidra/JDK without provider
allocation. Native G1 retry remains pending.

## First allocated native attempt and second verifier correction

Native decoder-stage attempt `run-jHW5AN/report.json` under
`docs/psx-local/phase-4-operation-runs/` has SHA-256
`1595f3dde4d7aaafd564d513cb9d019c0f12ce57ad36a157e9433422ae36dff6`.
Ghidra 12.1.4/Temurin 25.0.4.1 startup agreement and source-backed image
verification passed. Source, relevant code/bridge/dist fingerprints and 2,170
installed assets were unchanged; exact runtime/workspace paths were removed;
no unresolved session/retained root remained; process lineage was verified empty.

The primary `TypeError: Cannot read properties of undefined (reading 'map')`
occurred before the first instruction query: a positional runner call passed
the fixture validator into the oracle argument. This is a verifier code defect,
not a native decoder observation or failed native semantic oracle. The report
remains immutable. Decoder G1 remains pending.

The producing call now uses named `{call, oracle, stage}` arguments and the
runner exposes its actual operation-matrix call boundary. Deterministic coverage
invokes that same production caller, retains a deliberately contradictory raw
first instruction through the filesystem, and confirms first-instruction
dispatch and mismatch assertion rather than a wiring TypeError. A second case
proves invalid named stage reaches the helper's pre-dispatch check. Nine focused
tests passed. No positive simulated native lane was added.

The captured real load image was parsed against the named production
`psxLoadImageSchema`; its `status: verified` and `coverage.complete: true` fields
agree with the helper's dependent assertions. Read-only replay through the actual
runner caller reached `inspect_native_instruction(0x80010000)` before an intentional
stop. Named inventory/function/native-instruction/call-target contracts and Java
producer shapes were inspected for all dependent result accesses. Original
fixture and semantic expectations remain unchanged. After this second correction,
a further unsuccessful correction requires the bounded contract replan. Native
retry remains parent-owned and pending.

## Native decoder observation blocked on return oracle

The next native decoder-stage report `run-IWtgp1/report.json` under
`docs/psx-local/phase-4-operation-runs/` has SHA-256
`e8d6924a13aa324e2483a2d1a26f62f9acd184b3cf97e3c3ce135ae858709008`.
This attempt reached eighteen instruction queries, ending at `0x80010044`.
Earlier exact words, Listing flow classifications and delay-slot observations
passed their comparisons. Startup/source-backed image verification also passed.

At `0x80010044`, raw and normalized results both observed bytes `0800e003`,
Listing flow type `TERMINATOR`, p-code `RETURN`, kind `return`,
`conditional:false`, `computed:false`, empty direct destinations and
`delay_slots:{is_in_delay_slot:false,depth:1,addresses:["0x80010048"]}`.
The oracle asserted `computed:true`, so this native run failed its first
semantic mismatch there. The `computed` flag is a Ghidra Listing observation;
it must not be inferred from an architectural register operand or an assumed
runtime return target. RETURN evidence and the slot were actually observed;
this does not establish the unqueried tail/leaf/data/function/reference gates.

Original source SHA-256
`b2fb15c8af2b4f379e3421d7414ef66ea15c4cf7215e0569d4e3721cdba8a5a3`,
relevant source/bridge/dist fingerprints and installed asset inventory digest
`31db2c95632ade2fb2b15e3d7320f411125dc0e24fc26f65796aea7721fba869`
were unchanged. Exact runtime/workspace paths were removed, no session/root
ownership remained unresolved, cleanup errors were empty and process lineage
was verified empty. The immutable report remains retained.

At that failed attempt, G1 remained blocked. The bounded Astra revision was pending orchestrator readback;
no oracle, runtime, assertion or fixture change is made from this observation
before that reviewed revision. Later instructions at `0x80010048`,
`0x80010080` and `0x80010084`, call-target queries, nondecoded/data classifications,
procedure and reference/string gates were not reached in this run. G2 and
P4-21 dependent acceptance remain pending.

## Reviewed R1 and successful G1

The approved saved P4-R1 corrects only the two return expectations at
`0x80010044` and `0x80010080` to observed Listing `computed:false`; it retains
exact Listing `TERMINATOR`, decoded p-code `RETURN`, owned depth/slot and all
other oracle criteria. Register-target inference does not supply a Listing
flag. The computed call at `0x80010034` still requires `computed:true`.
No production/profile or generated executable changed. Fifteen focused
verifier tests passed, including literal partial return mutations and a
computed-call positive control; these do not simulate a complete native pass.

Actual decoder report `docs/psx-local/phase-4-operation-runs/run-6aUoxr/report.json`
has SHA-256 `203aa0c4451cd0eff4b736a9928db0e8e818c5d7db87082999cd20f797ab9cdd`.
The orchestrator independently reviewed its 52 successful real operations.
All 21 original instruction words, six transfer flows, owned non-NOP slots,
two return/slot function tails, exact selector behavior, direct/unresolved
call-target statuses, data/interior/outside-memory states and
strings/reference observations passed. The actual data reference originates
at `0x80010030`. Source/snapshot hashes, 2,170 installed assets and relevant
code fingerprints agree before/after; settlement failures and unresolved
owners are empty, exact runtime is absent, workspace removed and process
lineage verified empty. This is the required G1 evidence. Full decompiler/operation G2 was pending at
that checkpoint; the later R5 result below supplies its separate acceptance.

## Optional dossier correction and fresh G2 acceptance

Failed report `docs/psx-local/phase-4-operation-runs/run-oEckNl/report.json`,
SHA-256 `9aad3a560caef2281c1a8b29b07ecb09e14484d6d6219117c36615a815b2e767`,
retains 56 operations and the verifier's `TypeError` at
`dossier.unresolved_calls.some`. The named `functionDossierSchema` declares
that field optional; Ghidra legally omits it. The code expectation violated
the contract. Required `procedure_references.unresolved_calls` and static
call-target resolution already supply the actual site's coverage. This failed
run had unchanged source/private snapshot/assets/code, successful exact cleanup
and empty verified lineage; it did not establish G2 acceptance.

Reviewed R5 removes the unconditional optional-field access, preserves the
required unresolved reference at `0x80010034` and computed/empty-target
resolution, and checks the dossier's required uncertainty disclosure. The
focused verifier command recorded above passed **21 tests**. Six added cases
parse the self-contained captured dossier against its actual named schema,
parse the required reference contract, reach the exact next leaf query before
an intentional sentinel, and reject three targeted mutations at their intended
assertions. They preserve all prior oracle/lifecycle coverage and do not
simulate a full native pass. This is a separate rerun from the earlier combined
54-test public checkpoint; the later final 60-test rerun is recorded separately
below without adding these counts together.

Fresh report `docs/psx-local/phase-4-operation-runs/run-TqBh01/report.json`,
SHA-256 `e03ef660718ec01d5477a8bf7bd21a9e80a6298fd3b93910ff204d67139d827b`,
records `plan_revision:P4-R5`, `stage:operations`, `mocked:false`, `ok:true` and
**79 operations**. Independent readback verifies the 21-word/six-transfer
comparison, both meaningful decompilations and complete observed body ranges,
direct call/data reference flags and procedure identities, the required
unresolved call at `0x80010034`, callers/callees/xrefs, interior selectors,
unchanged post-read information/reference results and annotation/type refusals.
Dossiers omit optional `unresolved_calls` while retaining their uncertainty
limitations. The entry body includes its tail slot through `0x8001004b` and the
leaf body through `0x80010087`.

Original source, post-run source and private snapshot SHA-256 all equal
`b2fb15c8af2b4f379e3421d7414ef66ea15c4cf7215e0569d4e3721cdba8a5a3`.
Installed asset inventory digests agree for all 2,170 assets; relevant code
fingerprints agree before/after. Settlement failures and unresolved sessions,
cleanup errors and retained roots are empty. Exact runtime is absent, workspace
removed and lineage verified with no descendants. This completes the real
direct-production PSX G2 lane under R5; host-native fixture repair, full frozen
load-image regression and final review remain independent required gates.

## Public adapter and snapshot contracts (simulated providers)

The combined six-file focused command passed **54 tests**:

```text
npm run test:focused -- tests/boundary/mcp/ghidraPsxMcp.test.ts tests/boundary/cli/ghidraPsxCli.test.ts tests/boundary/providers/ghidra/ghidraPsxImport.test.ts tests/boundary/mcp/ghidraPsxImport.test.ts tests/boundary/cli/ghidraPsxImport.test.ts tests/boundary/providers/ghidra/ghidraPsxOperationsVerifier.test.ts
npm run test:local -- src/ghidra/GhidraSnapshotCache.test.ts
```

The source snapshot command passed **10 tests**; its combined rerun with
`src/application/binary/AnalysisSnapshotCache.test.ts` passed **47 tests** (10
provider snapshots and 37 application-cache cases). Actual registered CLI routes,
shared direct workflows and SDK InMemoryTransport MCP preserve equivalent
semantic results, source subject/digest, provider/profile, original selectors,
static unresolved targets and retained Evidence. Existing import tests now
admit function reads while preserving annotation/type refusal, verified/
mismatch/unsupported image evidence and cleanup coverage. Wrong provider,
malformed address/document, cancellation, provider errors and malformed outputs
do not create failed Evidence.

Ajv2020 validates the actual named SDK-converted instruction and call-target
output schemas under advertised draft2020-12. Decoded/nondecoded values,
unknown nulls, absent older optional fields, extra fields, wrong types and the
representable depth-zero/null-depth union constraints are exercised. Conversion
does **not** carry every Zod `superRefine` relationship: separate production
provider-boundary cases reject wrong depth/list length, duplicate slots,
nondecoded slot facts and noncanonical Ghidra slot addresses. No claim is made
that converted JSON Schema alone enforces those cross-field refinements.

Actual PSX session snapshot export/import now stores exactly four direct
entries with exact original parameters and replays instruction, call-target,
dossier and image queries with no new bridge query dispatch at identical
identity. Image is called with exactly `{}`; supplying `document` remains
rejected by its actual strict SDK input contract without query dispatch. All
Evidence is retained on import and after replay. An older capture omitting both `delay_slots`
and flow classification provenance also replays unchanged. Source, assets,
loader, options, provider identity, startup/provenance/transaction and obsolete
flow-v1 profiles reject at preview before dispatch while preserving prior
session/Evidence state. A separate non-Ghidra simulated session retains older
optional omission and replays without dispatch; old Ghidra profile rejection
is not a blanket rejection of older snapshots.

The required image replay first exposed a producing policy defect:
`AnalysisSnapshotCache` classified every official query except current-document/
list-documents as requiring an explicit document, while the image tool's named
schema accepts exactly `{}`. Historical partial tests retained image Evidence
but only three replayable query entries. Reviewed P4-R3 corrects this at the
backend-owned application boundary by deriving document scope from actual named
input fields. No public input/profile/snapshot-format change or fabricated image
entry was introduced. The final four-family test passed for current and older
optional-instruction captures; the separate cache tests preserve mutation,
permission, live-policy, cursor, document, capacity and other existing guards.

TypeScript passed; targeted lint has zero errors and only complexity/depth/
existing verifier-size warnings. Test discovery finds all **711 files exactly
once**. These deterministic simulated ports prove adapter/persistence and
failure semantics, not unqueried native facts. All new simulated instruction/
decompiler/dossier examples are explicitly labeled simulation.

## Reviewed R2 host-native fixture layout

The required host-native command failed an existing producer invariant:
entry alias and nominal interior label both compiled/imported at
`0x1000003c0`. Historical log
`docs/psx-local/phase-4-regressions/host-native.log` has SHA-256
`ff7415de94a592836eff52a22f4279cfe61893150e3563260423f68d6e5b2bf2`.
That aborted log has no final success/complete lineage attestation and does
not prove a production resolver failure.

Reviewed P4-R2 emits one `nop` immediately before the interior label in its
existing asm block, preserving every helper assertion and all other fixture
behavior. Independent `cc -O0 -g -fno-inline` compilation with Apple clang
21.0.0 (`clang-2100.3.34.2`), `nm -n` and `otool -tvV` proves entry, secondary
alias and bare-hex `dead` all at `0x1000003c0`; interior is `0x1000003c4`, at
`adrp` after `nop` and before `ldr`/`ret`. The executable was never run;
the exact temporary compilation workspace was removed.

Layout capture `docs/psx-local/phase-4-regressions/entry-aliases-r2-layout.json`
has SHA-256 `da689a3daeecf60d1a5ed2239084e7cb2d3e9c96c176c0f1780975560ac09054`.
Corrected source SHA-256 is
`8c4e92a3b2199734d605742a87e2c100021c52da157e3bd2943b61c7bb483718`;
compiled executable SHA-256 is
`b8b55f4511ef68497ee572aa77956dbc11fd47749064b2699395b685798f1bf3`.
This is independent layout proof on this macOS host, not full G4 acceptance
or another host's assembler/native verification.

The real R2 retry failed after passing distinct-address comparison because
`procedure_address` accepted `_rea_interior` where the unchanged helper requires
rejection. Preserved log `docs/psx-local/phase-4-regressions/host-native-r2.log`
has SHA-256 `c7ca7d653fa47e0725636e82deb452687d34108403126aa9b268b438d364c90c`;
the orchestrator verified 1,082 consumed production/fixture/build fingerprints
unchanged. No final success/complete lineage attestation was produced. The
accepted entry/body was not captured, so a separate FunctionManager entry at
the interior was then an unmeasured hypothesis. R2's compiled distinctness does
not prove native containment. Reviewed diagnostic-only R4 requests one canonical
production-provider ownership probe before any candidate repair; no additional
fixture, production selector or assertion weakening was authorized at that
checkpoint. The later R4/R6 measurements are recorded below.

## R4 ownership measurement and failed R6 local-symbol candidate

Baseline diagnostic `docs/psx-local/phase-4-entry-alias-runs/run-j2xC2j/report.json`,
SHA-256 `9a6c446c2b3c2c12c8b40b9d67a5dd3c7ffe74b79c780f920d1b17fbf2378259`,
records `diagnostic_complete:true` with 19 operations. `_rea_interior` at
`0x1000003c4` is an imported primary function symbol and actual FunctionManager
entry, with body `0x1000003c4..0x1000003cf`; canonical `dead` owns only
`0x1000003c0..0x1000003c3`. Interior-name selection therefore follows the
production entry-name contract. Compiled address distinctness did not prove
that the label belonged to the canonical function's observed body.

The baseline report remains `ok:false`: capture incorrectly assumed
`ownership.arguments`, which the launcher writes only for PSX imports.
Private snapshot hashing was not verified in that baseline. Source/executable,
code and installed assets were unchanged; all exact roots/workspace were
removed, no owners remained unresolved and process lineage was verified empty.
Successful cleanup does not turn its failed capture into acceptance.

Reviewed R6 removed only the interior `.globl` binding, retaining its ordinary
local name, prefix `nop`, all entry aliases and call/data behavior. Independent
compiler proof `docs/psx-local/phase-4-regressions/entry-aliases-r6-layout-reviewed.json`,
SHA-256 `6da20d507c0d05a9b6816876d34da0da2a47e6157959aa043209315eb9205af2`,
records Apple clang 21.0.0, exact `-O0 -g -fno-inline` flags, `nm -n` and
`otool -tvV`. The local `t _rea_interior` labels the actual instruction after
`nop`; all entry aliases share an address and main's displayed call alias
resolves that common entry. The first layout assertion's overly specific
`bl dead` display expectation remains preserved in a separate original capture;
the corrected proof resolves the observed label's address. The executable was
never run and its exact compilation workspace was removed. Eleven deterministic
compiler/collector/candidate checks passed without native allocations.

Fresh candidate `docs/psx-local/phase-4-entry-alias-runs/run-35UEBp/report.json`,
SHA-256 `04bd7ca6bee97bebf64d30fcdeded74a02e91fb73aa02af474758b71a4b9ee24`,
retains 26 operations, `diagnostic_complete:true`, `candidate_acceptance.accepted:false`
and `ok:false`. Despite the local compiled symbol, Ghidra again made the exact
interior name an imported primary function and actual entry at `0x1000003c4`.
Its body remains separate from `dead`'s one-instruction body; the focused gate
failed at `Interior must not be a FunctionManager entry`. Remaining candidate
assertions after that failure were not accepted. Recorded call/data/xrefs
responses do not substitute for the failed ownership criterion. No production
resolver, profile or full helper assertion changed.

R6 fixed capture through the actual `GhidraClient.readTargetSnapshot()` API;
snapshot/source-executable SHA-256 agree at
`3130846956d6bc8de73c5f2fcb75f22de91207e958b690e1b0ed1938d6d69185`.
The report explicitly distinguishes unavailable argv observation in non-PSX
ownership from source-backed read-only/delete-project/default-analysis policy.
Snapshot and runtime-lineage capture are independent settlement actions.
Source/executable, assets and code fingerprints remained stable. The only
settlement failure is the primary candidate assertion; capture/close/cleanup
completed, exact roots/workspace are absent and verified lineage is empty.
At that checkpoint, host-native G4 stayed blocked on a further reviewed bounded
decision. The R6 result accepted no additional candidate or full retry; later
R7/R8 evidence below preserves that distinction.

## Bounded regression/distribution checkpoint

The orchestrator reported successful unchanged-source DOS/COM production
regressions with complete cleanup and verified empty lineage:

| Captured log under `docs/psx-local/phase-4-regressions/` | SHA-256                                                            |
| -------------------------------------------------------- | ------------------------------------------------------------------ |
| `dos.log`                                                | `9335e23deb8cac9a6fbce6ca2e3b3b1fa4ed24685ad696eec69111c126a3db87` |
| `com.log`                                                | `8624c95be8c03ecb7312ffaf018843f722ac4e821e3000c1787857cc734867c1` |
| `package-retry.log`                                      | `4859510b67a96ac6c7999b58f09b82bff4dfda2d8731e69c014f42928e06532c` |
| `pack-dry-run-retry.log`                                 | `601fd02397804ea478838a0cbdf51b6da547b27b8684b5e5f8e5e790d16826a7` |

Package verification passed 139 tools/six prompts with verified empty lineage;
normal `npm pack --dry-run` with prepare hooks passed 1,062 files. Initial
unprivileged package/dry-run logs retain `.git/config` permission failures;
authorized normal-hook retries passed without disabling hooks. These establish
distribution integrity, not installed PSX or fresh-client acceptance.
Catalog generation/check, docs check and 78 local documentation links passed
at the orchestrator checkpoint. The earlier successful logs remain historical evidence. Post-R3 reruns and
remaining gates are recorded below; neither Phase 4 completion nor Phase 5
acceptance is claimed.

## Post-R3 public regressions and distribution

Independent log readback confirms the following integrated reruns. These are
separate from the direct PSX operation matrix and failed host fixture candidate.

| Captured log under `docs/psx-local/phase-4-regressions/` | SHA-256                                                            |
| -------------------------------------------------------- | ------------------------------------------------------------------ |
| `psx-import-post-r3.log`                                 | `4a0d8b5021dce4338c2e3c31c186072955a3e3fbe859d3af88c2f5d50886eb4e` |
| `dos-post-r3.log`                                        | `29dfda45aabded8f2f3fd630ee026e3e18d4ca18d9a116f4af5bac1f0afd90a1` |
| `com-post-r3.log`                                        | `8c20a467cc5e9c45c13d2daceb49a5c95d8663b689a28cd107879a49abc7a08e` |
| `package-post-r3.log`                                    | `25c4ee2c7627d70a3ee28ceec8a38f724d8b35fd7e45f49111a610f65c6ad6dc` |
| `pack-dry-run-post-r3.log`                               | `0b6ae1b3bd78258a945afe57831c5a4f9715846b797d63bbd1192a718dd7bf3b` |

PSX import passes nine imports across three original variants and four admission
negatives, with original-source identity, target-bound startup, CLI/stdio-MCP
and direct-provider observations, no allocation for rejected policy cases,
complete exact cleanup and verified empty lineage. DOS and COM reports each
record `ok:true`, unchanged original bytes, complete cleanup and empty verified
lineage. They exercise their existing public CLI/stdio MCP read-only workflows;
neither proves DOS execution or PSX operation parity.

Package verification passes 139 tools/six prompts and its existing CLI/MCP/setup/
Evidence checks with verified empty lineage. Normal `npm pack --dry-run` runs
prepack and prepare hooks and lists 1,062 files, excluding local PSX payloads,
test fixtures and `.agent-runtime`. These establish distribution integrity;
installed PSX/fresh-client acceptance remains a separate Phase 5 gate.

## Full load-image stability failure and frozen rerun

Preserved report `docs/psx-local/phase-4-final-load-image/run-xmt81j/report.json`,
SHA-256 `2efc8b257dc608923c1a9a81538d210e18fdfb07fdbf31b81758ff068fb2476c`,
records all nine imports and nine controlled captured-observation mutations
across the three original variants. Each case passed its native comparisons
and replay expectations. Overall `ok:false` is retained because the complete
tracked Git diff changed while the orchestrator wrote approval/progress docs.
Consumed code-file fingerprints and installed assets remained equal; the
failed postcheck names the differing full-diff hashes. This is a known writer
coordination failure, not a decoder, source mapping or production change.
No complete verified bundle was created. Cleanup removed the workspace and
all owned roots, with no unresolved session/evidence handle, no cleanup error
and empty verified lineage.

Fresh frozen report `docs/psx-local/phase-4-frozen-load-image/run-ytJDIh/report.json`,
SHA-256 `1db5ece6b716e680700db2cb4ec218af1bb0632477802f75af5bf8ffb8430a05`,
records `ok:true`, all nine imports and nine controlled replay mutations,
unchanged complete repository-code fingerprints and all 2,170 installed assets.
Exact runtime roots/workspace were removed; retained roots, unresolved sessions/
evidence handles and cleanup errors are empty; lineage is verified empty.
This successful frozen run is separate from the failed writer-coordination
attempt and retains its own pre-R8 auxiliary-verifier checkpoint fingerprints.
No failed report is overwritten or relabeled.

The native nondecoded PSX cases actually queried by G1/G2 are
`0x80010001` (`not-instruction-boundary`), `0x80010100` (`data`) and
`0x90000000` (`outside-memory`). Native undecodable status was not queried.
The deterministic SDK example at `0x80010104` exercises a simulated undecodable
value; it supplies contract coverage only, not a real decoder observation.

## R7 compiled metadata failure

The unchanged R6 metadata preflight
`docs/psx-local/phase-4-entry-alias-runs/preflight-r7-baseline-ygFv5e/report.json`,
SHA-256 `bf7fa88923c30a95176fcb351af6d4306508bcf5e61e2ad3853eef7e104b904d`,
proves both canonical entry and interior membership in actual linked
`LC_FUNCTION_STARTS`. The one approved Apple `.alt_entry` candidate in
`preflight-r7-candidate-gMiqYa/report.json` under the same root,
SHA-256 `daf239d85baac25af357dee91b357bebfb070f88028b6031f50673c7d0912385`,
has object `N_ALT_ENTRY` descriptor `0x0200`, but linked start bytes remain
`c007040c00000000`, including canonical `0x1000003c0`, interior
`0x1000003c4` and main `0x1000003d0`. Its compiled gate failed before any
native import. Source/object/executable metadata and disassembly are retained;
the exact temporary workspace was removed and no generated fixture was run.

Installed Ghidra's Mach-O function-start analyzer consumes this emitted
metadata and can create functions/split existing bodies at declared starts.
Changing symbol binding or the object alternate-entry descriptor did not remove
the interior from that representation. The fixture expectation that its named
label was non-entry did not match measured loader/analyzer ownership; no
production resolver exception or weakened negative assertion was introduced.
R8 changes only this auxiliary test producer's format to exercise the same
analyst selection question with a retained local non-function symbol.

## R8 independent ELF proof and focused native acceptance

Independent compiled proof
`docs/psx-local/phase-4-entry-alias-runs/preflight-r8-Y0dVwb/report.json`,
SHA-256 `f72e2cfa318c2bb7df668cf019d4bda1e0c5c4c264341dc5854e22d03c7397f3`,
records exact `cc --target=aarch64-linux-gnu -c -O0 -g -fno-inline SOURCE -o OUTPUT.o`
with Apple clang 21.0.0, source/object digests and installed LLVM inspection
output. Actual header is ELF64 little-endian `ET_REL`/`EM_AARCH64`; canonical
REA target parsing agrees on `kind:executable`, `format:elf`, `architecture:arm64`.
Target and main are defined function symbols; entry alias/`dead` share target
section/value; interior is retained local `STT_NOTYPE` at the instruction after
`nop`, inside the target's emitted extent. Main's `R_AARCH64_CALL26` points to
the common entry, and page/low data relocations point to the referenced data.
Section-relative values are not native Ghidra addresses. The exact temporary
workspace was removed, with no fixture execution or native import. Thirty
fresh compiled-metadata/parser/representation checks passed, including malformed
header/table/string/symbol/relocation boundaries and semantic mutations.

Focused native report
`docs/psx-local/phase-4-entry-alias-runs/run-P5XqPR/report.json`,
SHA-256 `d272637d4962fc3ed226085c907a57ab832fe10b6aa1ce59cf9708c943293855`,
records P4-R8, 25 operations, `diagnostic_complete:true` and accepted focused
candidate. Imported exact `rea_interior` is not a FunctionManager entry. Its
instruction at `0x100004` belongs to canonical `rea_alias_target`'s observed
body `0x100000..0x10000f`. Actual interior-name lookup projects provider
not-found as `AnalysisInputError`/`invalid_value`; explicit interior address
resolves `0x100000`. Secondary imported alias, `dead`, canonical and numeric
selectors agree; actual relocated main-call and referenced/unreferenced data
xrefs pass. Original/post-run source hashes agree, and object/private-snapshot
hashes agree; source, code and all 2,170 assets remain unchanged. Settlement failures/unresolved owners, cleanup
errors and retained roots are empty; exact roots/workspace are absent and
verified lineage is empty. This is focused direct-provider proof, separate from
the subsequent public helper acceptance.

## Full host-native acceptance and remaining scope

Full `npm run verify:ghidra` log
`docs/psx-local/phase-4-regressions/host-native-r8.log`,
SHA-256 `738180ef6b712484873c0f38221004f8c1a19500742aca08f0e893b624408d17`,
and its extracted `host-native-r8-result.json`,
SHA-256 `cdea4883d7bcda598b066604b5e1c33e872115bfc2abdff370658ebc51daf46d`,
record `ok:true`, complete cleanup and verified empty lineage. The actual
139-tool catalog produced 272 successful and 52 rejected boundary calls.
Mach-O debug/stripped/type-layout/jump-table controls and decoded p-code RETURN
CLI/stdio-MCP parity passed. The auxiliary alias subcase independently reports
`format:elf`, `architecture:arm64`, `relocatable:true` and its actual compiler
argv, symbols, observed addresses and completed assertions. Every original
public entry/alias/`dead`/numeric selector, dossier/pseudocode/info, interior-name
negative error, explicit containment, annotation, CLI name/address/xrefs form,
missing-name rejection and source-byte check passed; the original host target
was reopened.

The focused object, its owned private snapshot and full public helper object
share SHA-256
`4b93767f597ccd02f4532485e2e8987bae2d068689c42cfabaec370b91777f6e`;
source SHA-256 is
`9e18c19d387aaf4fcd50c40009b1488cb8f8dbe715d3d8dbcae2732677e838e5`.
Independent host before/after sidecars `host-native-r8-before.json` and
`host-native-r8-after.json` under the regression root are exactly equal at
SHA-256 `92894e0de7b7bc508794c23c5c2b470dc1dd8da2a38dd33bbacbb42a4889a726`,
covering 3,235 source/test/bridge/script/dist files and 2,170 installed assets.
These are the identities measured during the completed run; later documentation
reconciliation does not rewrite its historical repository-diff fingerprint.

This proves the auxiliary ELF-object public imported-entry/interior-name
question on macOS, alongside the separate Mach-O host controls. Mach-O named
non-entry rejection remains unverified and is tracked separately as PSX-010;
Linux native-host behavior also remains unverified.
Real public PSX operation journeys, installed-package/fresh-client discovery,
patched game acceptance and runtime correctness remain separate Phase 5 gates.
Fresh final public boundary rerun
`docs/psx-local/phase-4-regressions/boundaries-final.log`,
SHA-256 `02d83e55337a025a75b14e81c173d08d5826815c8a1d25df87ec6552adbae025`,
passed **60 tests across six files** in 6.93 seconds. This supersedes the earlier
combined 54-test checkpoint while retaining its historical result; the separate
21-test R5 focused run is not added again. The orchestrator reports the unchanged
136-test source and 117-test generic regression results remain valid.

Required Phase 4 native gates pass within these bounds. Final configured
static/docs checks and the single bounded close review pass. Reviewable
PR delivery is recorded below; approved merge remains pending; no delivery completion or Phase 5
acceptance claim is made.

## Final checks and bounded close review

Final `npm run check` passed six tasks (5.403s), resolved module boundaries in
1,324 source files and architecture guards across 1,016 files. Lint had zero
errors and existing warnings; this is not a zero-warning claim.
`npm run docs:check` passed six tasks (3.584s). Test discovery found all 711 files
exactly once. Configured framework validation, 53 local documentation links and
Git whitespace passed. These checks follow the unchanged source/runtime and
final R8 helper content; final state-only edits receive relevant rechecks before
commit. Post-R3 package and dry-run evidence above remains valid because R8
changes only unpackaged test helpers/fixture and authored phase documents.

One Sol 6.1/high read-only close review covered the complete intended diff, saved
R0–R8 contract and independently verified successful report/fingerprint digests.
It passed with no code findings or unconfirmed defect suspicions. The native
undecodable wording and auxiliary fixture coverage were corrected during final
documentation reconciliation. No extra code review or new native run is inferred.
PSX-009 meets its technical closure criteria and is closed; PSX-008 and PSX-010
remain deferred. Technical acceptance passed on 2026-10-10. Implementation commit
`d1947f50c7d6c9713b51dc76a3b9dca8db5ebfc5` was pushed with normal hooks and [PR #4](https://github.com/Troll-Phace/rea/pull/4)
is open and attached. Runtime/source/helper/test contents remain equal to the
measured native run; final documentation-only reconciliation does not revise its
historical fingerprints. Concrete approval and verified merge remain pending.
