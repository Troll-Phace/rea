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
The public load-image result must remain unsupported with empty source-file
provenance. Function instructions remain gated. Four generated header-policy
negatives must fail before allocating a provider runtime.

Reports contain explicitly selected provider/JDK coordinates and selected
bounded startup report/marker lines;
transport credentials are redacted and ambient environment is not serialized.
The verifier requires unchanged source bytes, awaited owned-root cleanup and a
verified empty process lineage. Failed runs retain their diagnostic report;
cleanup failure retains ownership of the affected runtime. This lane establishes
production import on its measured host only. Linux, MIPS instruction semantics,
source-backed provenance, patched AC3, and installed-package/fresh-client
operation remain separate gates.
