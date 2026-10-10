# P1-21R — bounded continuation using observed loader defaults

Batch: `psx-support-2026-10`. Astra/low replan supplement to [Phase 1](phase-1-plan.md), persisted by the orchestrator before resuming research. Local issues: PSX-001, PSX-002, PSX-003, PSX-006 and PSX-007.

This supplement supersedes P1-21's stop condition only for research measurements on the existing original fixtures. Production import remains blocked. Ownership remains with the test-engineer for the existing probe script, Java observer, conformance README and ignored evidence. The orchestrator owns shared state and ledger dispositions.

Approved integration extraction: test-engineer also owns `scripts/lib/psx-loader-observations.mjs` for existing log/observer normalization and attestation. The runner keeps process/project/resource ownership; the helper introduces no production interface. Finish extraction and reporting corrections before the final measurement matrix; preserve superseded raw evidence unchanged.

## Preserved failed experiment

Retain unchanged:

- `docs/psx-local/loader-contract-runs/run-2iooT6/report.json`
- `docs/psx-local/loader-contract-runs/run-2iooT6/1-baseline-explicit-noanalysis.log`

The explicit RAM override failed with:

```text
Value class does not match! Expected class psx.PsxBaseChooser,
but got class java.lang.String
```

The process returned exit code zero despite reporting import failure. Exit status alone cannot establish successful headless import.

Automatic baseline recorded defaults `0x80000000`/`0x200000`, image base `ram:80000000`, and the expected PSX language/compiler. Empty FileBytes is a measured provenance limitation, not successful source-backed attestation.

## Permitted continuation

Keep the fixture generator, payload, instruction oracle and declarations unchanged. Payload and PC remain `0x80010000`; payload size remains `0x800`. The loader's source-observed bank calculation for that PC yields `0x80000000`, matching the observed default. Do not move the payload to accommodate the loader.

Explicit research imports retain:

```text
-loader PsxLoader -processor PSX:LE:32:default -cspec default
```

Omit both `-loader-ramStart` and `-loader-ramSize`. Record omission as `optionMode: "loader-defaults"`; supplied RAM overrides are absent, distinct from observed defaults/effective program facts. This is a separate intentional research configuration; preserve the failed override run as its own experiment.

Run this exact matrix, each in a separately owned disposable project and a new unique evidence directory:

| Case | Fixture                 | Selection                                      | Analysis      |
| ---- | ----------------------- | ---------------------------------------------- | ------------- |
| 0    | baseline                | Automatic                                      | `-noanalysis` |
| 1    | baseline                | Explicit loader/language/compiler; default RAM | `-noanalysis` |
| 2    | baseline                | Explicit loader/language/compiler; default RAM | Enabled       |
| 3    | declared-registers-fill | Explicit loader/language/compiler; default RAM | `-noanalysis` |
| 4    | declared-registers-fill | Explicit loader/language/compiler; default RAM | Enabled       |
| 5    | trailing-bytes          | Explicit loader/language/compiler; default RAM | `-noanalysis` |
| 6    | trailing-bytes          | Explicit loader/language/compiler; default RAM | Enabled       |

No additional address variants, option experiments, extension edits, production adaptations or GUI work are included.

## Required case success

1. Owned execution settles successfully within its limits.
2. Logs contain expected loader/language selection and `REPORT: Import succeeded`.
3. Logs do not report import failure or probe exceptions.
4. Both observer completion markers and valid before/after JSON exist and match fixture, stage and program identity.
5. Loader selector/class/code-source/JAR facts agree with imported program and log evidence.
6. Source hashes before/after match for all generated fixtures, including on failure.
7. Required mapping, entry, register, fill, trailing-byte and provenance observations are present, with unavailable values explicit.
8. Cleanup is awaited and verified; unresolved resources are retained and recorded.

No-analysis cases still have before/after observer stages: label `analysis: false` so stage names do not imply analysis ran. Empty provenance or absent register context is a valid research measurement, never permission to promote that facet to verified.

Compare selected loader JAR digest with prior identity:

```text
481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c
```

A changed identity requires reconciliation before combining results.

## Analyzer selection evidence

Preserve the duplicate `MipsPreAnalyzer` warning. Existing logs say ClassSearcher selected standard `Ghidra/Processors/MIPS/lib/MIPS.jar` and ignored the extension definition. Record this selection and, where observable, runtime code source and selected JAR digest. Class selection does not prove analyzer execution. Do not remove, reorder or patch either asset.

## Downstream dispositions

- PSX-002/PSX-006: explicit RAM option transport is blocked by the measured class mismatch. Default-only research imports do not resolve deterministic production options/profile binding. Effective defaults, selected analyzer/resources and fingerprints require a subsequent authorized plan before production admission.
- PSX-003/PSX-007: absent FileBytes/original-file provenance blocks promised source-backed attestation. Equal mapped bytes cannot substitute for provenance; any producer-boundary adaptation needs its own plan and independent verification.
- PSX-001: may reach research measured/downstream blocked after this matrix, required observations and cleanup. It cannot claim deep PSX support, completed production profile or attestation. Review/delivery remain separate gates.

Stop and re-plan on unresolved loader identity, unexpected dialog/headless failure, changed source/assets, missing required observations or cleanup failure. Preserve evidence; do not broaden experiments. Linux, local AC3 and later application phases remain outside this continuation.
