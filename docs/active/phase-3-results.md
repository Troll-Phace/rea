# Phase 3 verification results

Contract: [Phase 3 execution plan](phase-3-plan.md). Local records: PSX-003,
PSX-007. Preparation baseline: `c498013fee5a61d4900a5edb7a9743f2a42b5c75`.

The revised nine-case feasibility gate, full nine-import public/direct matrix,
PSX import-policy regression, real DOS/COM source-runtime regressions and package
checks passed on macOS on 2026-10-10. The measured scope is generated synthetic
inputs on Ghidra 12.1.4/Temurin 25.0.4.1, using pinned Node 24.18.0/npm 11.16.0.
This document preserves the earlier failed attempts and distinguishes producer
pre-analysis evidence, public auto-analysis workflows, authenticated direct
sessions, controlled replay and distribution checks. R2 preparation retains
R1's version-3 commitments and method `rea-psx-filebytes-rebind-v2`; historic
version-2 attempts remain unchanged evidence for the original contract.

The revised nine-case feasibility matrix comprises baseline and declared-registers-fill
imports, split payload, journal multiplicity/order, unsupported data definition,
controlled transaction rollback, original-record tamper, active-transaction
refusal, and the actual production preparation preScript followed by a read-only
postScript observer. Required evidence
includes actual FileBytes source links, independent source-offset and digest
checks, exact operational-state comparisons, retained original and adapted raw
journals with independently recomputed deltas, unchanged source,
snapshot and installed assets, awaited process close, verified empty lineage,
and exact owned-root removal. Reports are retained under ignored
`docs/psx-local/phase-3-load-image-runs/`; failed runs remain failed evidence.

Early feasibility attempt 1 on 2026-10-10 failed before producer execution.
Ghidra 12.1.4/Temurin 25 exited zero while reporting probe compilation errors:
`cannot find symbol` for `ReaGhidraPsxImport` and
`ReaGhidraPsxProvenance`. The probe output was absent. The invocation supplied
the probe and default-package helper sources in separate script directories;
Ghidra compiled those directories as separate OSGi bundles. This is a verifier
launch-representation failure, not an adaptation result or an environmental
cause inferred from non-reproduction.

The historical report is
`docs/psx-local/phase-3-load-image-runs/run-ydmYGM/report.json`, SHA-256
`7308211599dbc533a0734b6a0b99febc7a536dc67397f7b05d6a322ed34ab2f3`.
It records unchanged baseline source and snapshot digests, removed owned
workspace, empty verified process lineage and no cleanup errors. The correction
materializes only the exact helper/probe Java source files in one owned script
directory, verifies original/copy hashes and retains script errors when an
ordinary zero exit produces no required probe output. The corrected rerun is
recorded below.

Early feasibility attempt 2 on 2026-10-10 reached production preparation and
reported unavailable baseline provenance with reason
`Affected label history cannot be restored exactly through public APIs`.
Original FileBytes remained empty, rebound ranges remained empty, and no rebind
was attempted. The measured original and final state fingerprints matched at
`9e480e53416fad7a3f24501b8e02ce6aa23aef9acb51b170b3c7f10e27df5712`.
The runner's requirement for applied baseline provenance failed; this is a
measured producer feasibility blocker under the saved contract, not a loader
startup failure or successful provenance proof.

The report is
`docs/psx-local/phase-3-load-image-runs/run-LW5dxy/report.json`, SHA-256
`b09e84b61b56d6f656555b11024050fe40e96932e33a0e1bade4c78781505775`.
The baseline source and owned snapshot both retained SHA-256
`be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a`;
the workspace was removed and verified lineage was empty with no cleanup errors.
Remaining matrix cases did not run under the original contract. The subsequently
reviewed R1 revision and its measured run are recorded below.

Attempts 1–2 captured initial installed-asset and code identities but did not
execute their post-failure asset/code/copy comparisons because an assertion
short-circuited those checks. No after-asset immutability claim is made for those
historical attempts. The runner now attempts those independent postchecks in its
outer cleanup path, preserving primary, postcheck and cleanup errors. Later
observations cannot retroactively establish old-attempt immutability.

R1 verification preparation follows the reviewed bounded revision in the saved
contract. Applied adaptation requires equal operational-state hashes, exact
producer operational-manifest comparison, independently checked journal delta
ordinals and affected-address scope, and exact-byte original-record linkage.
The runner captures only the fixed owned `psx-provenance-original.json` location,
retains its bytes separately from its parsed content, and distinguishes
pre-tamper bytes from the final tampered owned file. Failure probes require no
ready marker, no final before record, complete rollback fingerprints, raw journal
multiset equality and exact original memory/source observations. Probe protocol
version 2 also retains actual in-transaction observations at the injected fault;
the runner independently requires FileBytes and complete source-linked payload
coordinates, slice hashes and whole-source digests before accepting rollback.
The R1 matrix has now been attempted, with the failed gate recorded below;
public acceptance was still unperformed at that checkpoint.

R1 preparation checks: pinned Node 24.18.0/npm 11.16.0; source TypeScript
checking passed after fixture migration; seven independent runner-helper cases
passed for duplicate matching, reordered enumeration, null versus empty user,
ordinal continuity, signed-byte actions and canonical signed-Java-long dates.
These helper-only checks execute no provider. Five additional deterministic
helper assertions accepted a source-linked payload
and rejected missing FileBytes, missing linked rows, a wrong file offset and a
wrong original source digest; these also execute no provider. The orchestrator's serialized
build and focused SDK-converted schema suite passed all seven tests, including
canonical tools' declared dialect, input/output validity and nonrecursive
catalogs. Public profile/lifecycle boundary tests were unperformed at this preparation
checkpoint pending the revised real gate and P3-13 integration. Prepared examples are not acceptance
evidence.

Early feasibility attempt 3 on 2026-10-10 exercised the reviewed R1 contract
against actual Ghidra 12.1.4/Temurin 25, with auto-analysis disabled. Five cases
passed their independent runner assertions: baseline, declared-registers-fill,
split payload, journal multiplicity/order, and unsupported data definition.
The first four produced applied provenance with actual FileBytes links,
source offsets and digests, equal operational-state fingerprints, and retained
original/adapted journals whose independently recomputed deltas stayed within
the payload. Their full-state fingerprints differed as permitted for journal
recreation. Unsupported data produced unavailable provenance, no FileBytes,
an unchanged journal and equal full-state fingerprints. Exact original-record
bytes were retained for each of these five cases. These are direct synthetic
pre-analysis measurements, not canonical production-profile or public workflow
acceptance.

The sixth case, controlled rollback, reached the actual mutation path and
reported `CancelledException: Synthetic cancellation after payload block
removal/rebind`, with a suppressed `IllegalStateException: Rollback did not
restore original state and provenance`. Ghidra exited zero but produced no
required probe JSON. The runner correctly failed the overall gate; the seventh
case, original-record tamper, did not run. The report is
`docs/psx-local/phase-3-load-image-runs/run-dd9PJz/report.json`, SHA-256
`dc6602b3ed6d70b5d5026c944d5f6487c09b314e6e5ade8b562e5e03f7ff0d73`.
The retained command log is `.agent-runtime/phase-3-feasibility-attempt-3.log`.

The incomplete rollback probe emitted no raw failure observation, original
record bytes, original/restored journal arrays or comparison fingerprints.
That runner revision captured the fixed original file only after receiving probe
output; therefore it retained no rollback-case original-record copy before exact
workspace cleanup. The exception and stack trace establish the measured
failure, but do not identify which enumerated state or source observation
differed. Successful rollback and independent fault-time FileBytes verification
are not established by this attempt. This required the subsequently reviewed R2 revision before dependent integration
could continue.

All six executed cases retained unchanged executable-source and owned-snapshot
digests. Independent outer postchecks recorded the installed inventory's 2,170
assets unchanged, unchanged exact source/plan and compiled-runtime identities,
and unchanged script-bundle copies. Cleanup awaited process close, verified
empty descendant lineage, removed the exact owned workspace, retained no roots
and recorded no postcheck or cleanup errors. Reports from attempts 1–3 remain
immutable historical evidence; cleanup success does not resolve the rollback
gate failure.

R2 preparation follows the saved sole-transaction ownership revision. The direct
synthetic profile now includes `psx_preparation_transaction:
"exclusive-top-level-v1"`. Complete probe reports must explicitly have `ok:
true` and `evidence_complete: true`, measured script-wrapper release, completed
setup and no active adaptation transaction after final commit or rollback. The
active-transaction case instead retains both rejected-invocation active flags,
then independently checks the test's final owned close and exact unchanged
state, raw journal and source observations. The production-wrapper case invokes
the current production `ReaGhidraPreparePsx.java` preScript followed by the
test-only read-only `ReaPsxPreparationTransactionProbe.java` postScript; the
runner bundles these exact sources with the existing helpers/probe in one owned
script directory.

The R2 runner always attempts capture of the fixed original-evidence file in the
case's `finally`, even after absent/malformed/partial probe output. A no-follow
open verifies a bounded regular file and stable open-file identity before
retaining exact bytes, digest, stage and content status. Probe-retained original
bytes, when actually available, have their own pre-tamper/fault stage and digest;
current tampered bytes cannot substitute for them. Capture/reporting/source
postcheck errors remain separate from the primary case failure and owned cleanup
errors. Partial probe JSON cannot pass the gate. Sixteen deterministic helper
assertions passed for fixed-file capture, absent/partial/tampered evidence,
symlink/directory/capacity refusal, reporting failure, partial-report rejection
and required transaction observations; no provider was executed by those checks.
Five further helper assertions retained and hashed an actual probe-supplied
pre-tamper record, rejected contradictory digests, malformed base64 and excess
capture capacity, and preserved a reporting failure separately from valid bytes.
These checks also execute no provider.
The revised nine-case gate subsequently passed as recorded below.

Early feasibility attempt 4 on 2026-10-10 passed all nine revised R2 cases
against actual Ghidra 12.1.4/Temurin 25. The report is
`docs/psx-local/phase-3-load-image-runs/run-GSE38p/report.json`, SHA-256
`d1f19c48e804ee35202279c7a9d6e77acead0406087e39c894021a79b3adcdda`.
Baseline, declared-registers-fill, split, journal multiplicity and the production
preScript followed by its read-only observer committed with no active
transaction remaining. Unsupported data remained unavailable without mutation.
Cancellation and original-record tamper both fired after actual source-linked
FileBytes were observed, then completed rollback with identical complete
state, raw journal and source observations before readiness. The tamper record's
current bytes were retained as invalid and its distinct pre-tamper bytes as
validated original evidence. Active-transaction refusal retained the caller's
active transaction for the rejected invocation, published no original record,
and verified the test's own final close and unchanged complete state. Every case
actually observed and released its script wrapper; required setup transactions
were finalized before baseline capture.

All source/snapshot digests, 2,170 installed assets, exact source/plan and compiled
runtime identities, and script-bundle copies remained unchanged. All independent
postchecks passed; exact workspace removal and empty verified descendant lineage
were recorded with no retained roots or cleanup errors. This passes the direct
synthetic pre-analysis feasibility gate. It does not establish public workflow,
auto-analysis, authenticated production-client integration or release acceptance.
Attempts 1–3 remain unchanged failed historical evidence.

The full auto-analysis lane passed all nine distinct imports on 2026-10-10:
baseline, declared-registers-fill and trailing-bytes each used public stdio MCP,
public CLI and a separate authenticated direct provider session. The report is
`docs/psx-local/phase-3-load-image-runs/run-4LrkYH/report.json`, SHA-256
`d9e2e2ee7860e579440547b7877d7883b0e4bf473a22a8005f2fbe0890a9b75f`.
All nine run identities are distinct; each variant's three canonical production
profiles agree. Each result is `verified` for exactly 2,048 payload bytes at
`0x80010000`–`0x800107ff`, with actual FileBytes source links at file offset
2,048 and an exact four-byte instruction observed at the declared entry.
Complete original/modified source identity includes the header and trailing
bytes; neither enters payload coverage.

| Variant                 | Source bytes | Unchanged source/snapshot SHA-256                                  | Canonical profile digest                                           |
| ----------------------- | -----------: | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| baseline                |        4,096 | `be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a` | `607ea450d666b359508239c8b788eaa37c8969b6fc1524d0670884c43d45db19` |
| declared-registers-fill |        4,096 | `fb38aeaa649f3b90993bf6151dffc42da00cba2087344255bc6e60d9442ab3d1` | `36b099bd5501cf60cf56826064cf5281968d97744a1750ed67e311c1d14c9b39` |
| trailing-bytes          |        4,112 | `53fea47eea51911150080df66d2d1acc852d64a7fe39d3777cdcbcd54b155595` | `9b7592a1ecda904952e2f16445a3aa8a089b974e5cd201a638b306157ebb1f71` |

Public sessions retain complete Evidence and named SDK-converted MCP output
schema validation. Each session's fixed before record and original-evidence
record were captured as exact bytes and linked by source/run/profile and digest
to its own preparation provenance. CLI capture occurred during its owned
lifetime before automatic close, then correlated with final public Evidence.
Direct health and startup agreement belong only to their separate authenticated
sessions. The original/adapted preparation journals and independently recomputed
delta are retained separately from the fresh after-analysis journal; all nine
fresh observations contained 775 measured rows. Current journals were not
required to equal the retained preparation journal.

Baseline and trailing-byte results retain optional `entry.gp` and `entry.sp`
unknowns; zero GP declarations remain zero. Declared GP matched its observation;
declared SP remains unknown, and the 32-byte declared fill remains uninitialized
with unknown contents. The declared-fill classification does not prove zero
content. Function/instruction operations remain gated for Phase 4.

Nine controlled replays of actual authenticated observations produced the
required named mismatches: each variant independently changed a source offset,
original source digest and modified source digest while mapped memory hashes
remained unchanged. The offset mutation failed `mapping[24].file_offset`; digest
mutations failed `original_file_sha256` and `modified_file_sha256`, respectively.
These are production-attestor replay results, not live mutation of a Program or
source file.

All 38 exact source/plan/compiled-runtime fingerprints and source/snapshot hashes
were stable throughout the full run. The installed inventory's 2,170 assets
retained digest `31db2c95632ade2fb2b15e3d7320f411125dc0e24fc26f65796aea7721fba869`.
Every session's exact runtime root was absent after awaited close; the workspace
was removed, verified descendant lineage was empty, and no primary/postcheck/
cleanup errors, unresolved sessions, retained roots or evidence handles remained.
The bounded verifier cleanup correction also passed four deterministic exact
handle scenarios, including retained ownership after failed close and independent
read/close failures, and was independently accepted by the close reviewer.

The PSX defaults-only import regression passed three variants through distinct
public MCP, CLI and authenticated direct sessions, plus four pre-import refusals:
alternate bank, crossing RAM end, overlapping fill and nonzero data declaration.
Report: `docs/psx-local/phase-3-import-regression-runs/run-4cuGUQ/report.json`,
SHA-256 `af61f50d8ee7153e6daee166b07bc6fab30ba84c39ed119c08ddff5867519006`.
Admitted load images were verified; refusal sources remained unchanged and no
provider root was allocated. Installed assets were unchanged, exact workspace
cleanup passed and verified lineage was empty.

The real DOS MZ and DOS COM regressions passed against the source runtime with
verified load images, unchanged input bytes, completed cleanup and empty verified
lineage. DOS report: `.agent-runtime/phase-3-dos-proof.json`, SHA-256
`ace9a8f393f9038c6fe9d17be6454bbc7ef6892e343a63bf530287742516c35e`.
COM report: `.agent-runtime/phase-3-com-proof.json`, SHA-256
`ef99f54d9e127f9e0e8c6417f7abde477966896f7f27009e3ee9019686dbb026`.
COM explicitly records `packaged_artifact: false`; neither lane establishes DOS
runtime behavior or installed-package PSX acceptance.

Integrated source verification passed 328 tests, and the seven focused boundary
suites passed 130 tests with one Windows-only skip. After the bounded test-layout
lint corrections, the affected two boundary suites passed 93 tests. Before this results reconciliation, static
checking passed six tasks with 551 warnings and no errors, and generated
documentation checking passed six tasks. Final-content static/documentation
checks are recorded separately by the orchestrator. These checks supplement the real
provider lanes above; simulated boundary fixtures do not establish native
behavior.

Current package verification passed 139 tools, six prompts and four clients,
with empty verified lineage. Report: `.agent-runtime/phase-3-package-proof-final.json`,
SHA-256 `f4fb2641e92f61144f188f90874766aee2d72b0b3252213089a4a66732c60ca4`.
Normal `npm pack --dry-run --json` with prepare hooks enabled passed with 1,062
files, all three production PSX helpers included, and local runtime/payload and
test-only probe files excluded. Record:
`.agent-runtime/phase-3-package-dry-run-final.json`, SHA-256
`6580551f48239e926eb8651d531da53e3d30306de9a758fa1df15d4593de720c`.
Catalog generation/check also passed. These are distribution checks; they do not
establish real installed PSX or fresh-client operation.

Native reports retain their original code/plan/dirty-diff fingerprints. The
current full proof was captured after the declaration-only unused-alias removal;
subsequent plan/state/results wording reconciliation changes documentation only,
not the verified algorithms. Prior feasibility fingerprints describe their
historical revisions and are not relabeled as current-head evidence. Failed
reports remain immutable.

Original label history is retained as evidence. The adapted Program may contain
newly generated label-history events from REA restoration; its original journal
was not restored in place. Full Program-state preservation is required for
unavailable and rollback cases; it is not claimed for successful adaptation.

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec \
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home \
npm run verify:ghidra:psx-load-image -- --stage feasibility
```

The default command above without `--stage feasibility` runs the full public
auto-analysis matrix. Linux host evidence, patched AC3, MIPS instruction/delay-slot
semantics, installed-package/fresh-client acceptance and release readiness remain
separate unperformed gates. Adapted static payload
verification cannot establish the original loader's source lineage or runtime
correctness.
