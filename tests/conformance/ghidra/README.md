# Ghidra conformance corpus

These source-owned fixtures are compiled at verification time; generated
binaries and Ghidra projects are never committed.

- `inventory.c` produces separate x86-64 debug and stripped ELF executables.
  It covers imports, an external `puts` function, linker thunks, source symbols,
  direct calls, a targetless callback call, two referenced strings, and a
  multi-block branch.
- `entry-aliases.c` preserves secondary imported entry labels, a bare-hex
  alias, and an interior label. The native CLI/MCP lane verifies entry selection,
  annotation, interior-label rejection, and unchanged source bytes.
- `cross-format.c` is freestanding so the verifier can produce AArch64 ELF,
  x86-64 PE, and x86-64 Mach-O targets from the same semantics. It preserves an
  exported entry, direct and indirect calls, a volatile string reference, and a
  multi-block branch across loaders.

`scripts/verify-real-ghidra.mjs` uses `cc`, `clang`, and `lld-link` by default;
`REA_CC`, `REA_CLANG`, and `REA_LLD_LINK` can select alternate commands. The
verifier requires the verified bring-your-own Ghidra 12.1.4 installation through
`GHIDRA_INSTALL_DIR` and validates header classification before starting the
provider. Provider admission accepts the rest of the 12.1.x line; this lane does
not.

Conformance compares semantic facts: provider/profile identity, function
classification, resolved call edges, typed references, strings/xrefs, and CFG
topology. It only requires provider pseudocode and assembly to be non-empty,
bounded, and address-bearing; it never compares their text with Hopper. The
callback fixture also proves that an unresolved targetless flow is not silently
promoted to a direct callee. Every target runs in a separate owned project and
must leave no process, socket, project, or runtime root after close.

`psx-exe-fixture.mjs` creates an original 0x800-byte header and 0x800-byte
MIPS payload with known delay slots and distinctive data. Its three variants
cover baseline declarations, declared GP/SP/fill, and sixteen trailing bytes.
No fixture instructions are executed, and no game-derived inputs are accepted.

`scripts/probe-ghidra-psx-loader.mjs` is a development-only loader research
probe. First build the runtime with `npm run build:cached`, then select an
existing Ghidra installation and full JDK explicitly:

```bash
GHIDRA_INSTALL_DIR=/absolute/ghidra JAVA_HOME=/absolute/jdk \
  node scripts/probe-ghidra-psx-loader.mjs \
  --output-dir /absolute/ignored/loader-contract-runs
```

The probe creates a unique evidence directory and supervised disposable projects.
`--timeout-ms` selects a positive deadline per import (default 180,000 ms);
complete diagnostics are bounded to 4 MiB per command, with overflow reported as
failure. It observes automatic discovery and explicit `PsxLoader` imports,
both without analysis and with ordinary analysis, using
`ReaPsxLoaderContractProbe.java` before/after analysis. It binds import logs to
unique runtime class/resource/code-source identity and pre/post JAR digests,
rejects duplicate candidates, and never falls back to raw-binary import.

Evidence includes source hashes, argv, language/compiler, default and supplied
options, effective RAM state, analysis options, block/source ranges, FileBytes
provenance or explicit absence, bounded payload hashes, entry/register/fill
observations and trailing-byte uncertainty. Equal mapped bytes do not prove
source provenance. User settings/cache/temp are isolated; existing real user
extension roots are inventoried without changing or activating their extensions.
Every owned process must settle before exact-path filesystem cleanup. Cleanup
failure retains the owned root and fails the report. Ambient environment values
are not serialized. Reports and payloads belong in ignored local storage.

This lane measures the installed loader on its actual host. It does not establish
public REA PSX support, instruction-semantic acceptance, Linux behavior from a
macOS run, or source-backed attestation when FileBytes provenance is absent.

`scripts/verify-real-ghidra-psx-import.mjs` verifies the production defaults-only
PSX import policy using the same three generated variants. It accepts no binary
path. Build the runtime first and select the existing provider/JDK:

```bash
GHIDRA_INSTALL_DIR=/absolute/ghidra JAVA_HOME=/absolute/jdk \
  REA_PSX_IMPORT_PROOF_CAPTURE_DIR="$PWD/docs/psx-local/phase-2-import-runs" \
  npm run verify:ghidra:psx-import
```

The optional capture directory must be absolute and ignored by Git. Each run
records canonical source/profile identities, selected assets, safe exact argv,
private before-analysis observations and separately labeled authenticated
provider-boundary before/after observations. Public stdio MCP and CLI sessions
are distinct imports; their identical fixture/profile identities are checked,
and the provider-boundary health record is not attributed to a public session.
The public load-image result must verify source-backed adapted payload coverage
while retaining the original empty loader provenance. Function instructions remain gated. Four generated header-policy
negatives must fail before allocating a provider runtime.

Reports contain explicitly selected provider/JDK coordinates and selected
bounded startup report/marker lines;
transport credentials are redacted and ambient environment is not serialized.
The verifier requires unchanged source bytes, awaited owned-root cleanup and a
verified empty process lineage. Failed runs retain their diagnostic report;
cleanup failure retains ownership of the affected runtime. This lane establishes
production import on its measured host only. Linux, MIPS instruction semantics,
original-loader provenance, patched AC3, and installed-package/fresh-client
operation remain separate gates.

`scripts/verify-real-ghidra-psx-load-image.mjs --stage feasibility` checks
Phase 3 production preparation through the unshipped
`ReaPsxProvenanceContractProbe.java`. It accepts no caller binary path and uses
only the original generated baseline and declared-registers-fill inputs. The
test-only split, journal-multiplicity, unsupported-data, cancelled-transaction,
original-record-tamper, active-transaction refusal and actual production-wrapper
modes establish
producer-boundary preservation and rollback; they are not public CLI/MCP
positive evidence and introduce no fault flags into the packaged product.

```bash
GHIDRA_INSTALL_DIR=/absolute/ghidra JAVA_HOME=/absolute/temurin-25 \
  npm run verify:ghidra:psx-load-image -- --stage feasibility
```

This early stage uses `-noanalysis`. Its `after-analysis` metadata stage names
validate version-3 correlation only; they do not show auto-analysis ran. The
profile is a synthetic preparation commitment, separate from the canonical
production profile. Results distinguish actual FileBytes links and slice
digests, retained original empty provenance, exact operational-state fingerprints,
original and adapted journals, duplicate-preserving differences, complete
rollback, source/asset immutability and exact owned cleanup. The fixed original
record is captured as exact bytes with an independent digest; a tamper probe
retains separate original and final on-disk bytes. Applied adaptation may
recreate payload-address label-history events while retaining all original rows
as evidence. The original journal is not restored in place. Reports default to
ignored `docs/psx-local/phase-3-load-image-runs/`; the optional
`REA_PSX_LOAD_IMAGE_PROOF_CAPTURE_DIR` must select an absolute ignored directory.
The runner retains primary and cleanup failures and refuses success without
verified empty lineage and owned-root removal. Full public acceptance remains a
separate integration gate.

Default `npm run verify:ghidra:psx-load-image` is the full auto-analysis lane:
baseline, declared-registers-fill and trailing bytes each use public stdio MCP,
public CLI and a separately authenticated direct provider session. Nine distinct
run identities retain canonical profiles, exact owned source/snapshot and
fixed-record coordinates, whole/slice digests, current observations and complete
Evidence. The CLI's fixed records are captured during its owned lifetime before
its automatic close and correlated with the final public Evidence; direct health
records belong only to their separate authenticated session. Captured real
observations are replayed through the production attestor with independent
offset and source-digest mutations; replay is not actual live tampering. Public
unknown register/fill facets remain unknown. Every close, independent
source/code/asset postcheck and exact owned cleanup must pass.

The measured Phase 3 macOS runs on Ghidra 12.1.4/Temurin 25 passed the nine-case
R2 feasibility gate, nine full imports, nine controlled replay mismatches, and
PSX/DOS/COM regressions. Full report `run-4LrkYH/report.json` under the load-image
capture root has SHA-256
`d9e2e2ee7860e579440547b7877d7883b0e4bf473a22a8005f2fbe0890a9b75f`;
PSX policy regression `run-4cuGUQ/report.json` under
`docs/psx-local/phase-3-import-regression-runs/` has SHA-256
`af61f50d8ee7153e6daee166b07bc6fab30ba84c39ed119c08ddff5867519006`.
Both retained unchanged inputs/assets, exact owned cleanup and empty verified
lineage. The full report preserves nine distinct session identities and their
fixed original-record authentication; fresh after-analysis journal observations
remain separate from retained preparation journals. SP, zero-GP declaration
agreement and uninitialized fill contents retain their measured unknowns.

[Phase 3 results](../../../docs/active/phase-3-results.md) records the exact
source/profile/report identities, earlier failed attempts, current source-runtime
DOS/COM proofs and separate package checks. COM's native proof explicitly uses
the source runtime, not a packaged artifact. Distribution checks do not establish
real installed PSX/fresh-client behavior. Linux, patched game inputs, Phase 4
instruction/delay-slot semantics and runtime correctness remain unverified.
