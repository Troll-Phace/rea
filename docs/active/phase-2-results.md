# Phase 2 results — defaults-only production import

Batch `psx-support-2026-10`; issue PSX-002 and loader-policy finding PSX-006. Branch `codex/psx-phase-2`, baseline `3e36f98d`. The [saved execution contract](phase-2-plan.md) defines the narrow import scope. Review and delivery state live in [PROGRESS.md](../PROGRESS.md). These results contain sanitized conclusions; raw reports remain ignored local evidence.

## Deterministic integration

The new tests use original generated PS-X EXE bytes, real temporary files and JAR inventory, and explicitly simulated launch/bridge responses. Their evidence establishes REA boundary behavior, not installed-loader behavior.

- Filesystem admission: 15 tests cover renamed installation assets, duplicate/missing/incompatible resources, escaped symlinks, source/asset races, filename preservation including POSIX backslash/tab/newline, and six unsupported layout boundaries. Refusal precedes simulated provider allocation.
- Launcher: eight passing tests preserve DOS selectors and verify exact PSX selector/language/compiler, omitted RAM overrides, packaged preScript ordering, absolute descriptor arguments, read-only/delete-project flags, and caller path text. One Windows-only case is skipped on macOS.
- Owned-socket Client: 76 passing tests include authenticated producer-shaped PSX observations, one-field observation mutations with echoed commitments unchanged, completion-marker failures, zero-exit failure, target-bound diagnostic-report failures, URI/escaping/symlink identity and asset races. Existing cancellation, ownership, permission and target-identity cases remain covered. This suite requires local Unix-socket access on the current test host.
- Public adapter simulations: one MCP and one CLI integration test pass inventory/binding/open/close behavior, unsupported load-image observations with empty source provenance, and gated instruction/decompile/annotation calls before bridge dispatch.
- Snapshot: four tests pass, including same source/profile cache reuse and rejection after changed source bytes, selected assets or startup policy.

The final five focused boundary suites passed 101 tests with one Windows skip; the snapshot source suite passed four tests. The affected Client and SessionValues suites also passed 76 and 65 tests respectively (141 total), with the corrected runtime rebuilt. These results supersede the earlier startup expectations. A final static pass caught a readonly assignment in the simulated agreement helper; the helper now produces a new agreement object. Full TypeScript checking and the affected 76-test Client suite passed again after that test-only correction, with measured runtime/verifier content unchanged. Targeted lint has no errors. The new production verifier has one file-length warning. Dynamic PSX diagnostic-truncation rejection is unverified: the current supervisor retains complete output without a diagnostic byte budget, so this lane preserves the guard without inventing a budget or fake downstream snapshot. The orchestrator records this low-priority test gap as PSX-008. Test production dependencies were built by the focused runner. The package verifier now requires both Java helpers; actual package/static/regression gates are recorded by the orchestrator.

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
npm run test:local -- src/ghidra/GhidraSnapshotCache.test.ts
npm run test:focused -- \
  tests/boundary/providers/ghidra/ghidraClient.test.ts \
  tests/boundary/providers/ghidra/ghidraLauncher.test.ts \
  tests/boundary/providers/ghidra/ghidraPsxImport.test.ts \
  tests/boundary/mcp/ghidraPsxImport.test.ts \
  tests/boundary/cli/ghidraPsxImport.test.ts
npm run test:focused -- \
  tests/boundary/providers/ghidra/ghidraClient.test.ts \
  src/ghidra/GhidraSessionValues.test.ts
```

## Preserved first production failure

The first generated baseline reached `ReaGhidraPreparePsx.java`, emitted its correlated completion marker, completed ordinary analysis and entered `ReaGhidraBridge.java`. REA then rejected startup because the initial Client check required `REPORT: Import succeeded` while the postScript was still serving. Actual retained stdout contained `REPORT: Analysis succeeded for file:`; the terminal import report belongs to the later completed headless lifecycle. This is a reproduced lifecycle timing mismatch, not a provider installation or environment diagnosis.

The failed report is `docs/psx-local/phase-2-import-runs/run-5pBJ2X/report.json`. It records zero completed cases, unchanged generated input identity, no retained runtime roots, verified empty descendants and removed workspace. The failure and its raw diagnostics remain preserved. The saved contract corrects this timing rule. A second attempt, `docs/psx-local/phase-2-import-runs/run-S42RyB/report.json` (SHA-256 `1d881c341372e80d1d417611f8328f3512451b701b6dc3dcf797517e8f351742`), passed the output predicate but failed the authenticated handshake identity validator. Its runtime roots and descendant lineage were empty and its workspace was removed. The owning Client boundary now canonicalizes its immutable snapshot once before constructing the transport commitment; raw caller paths remain in diagnostics and the pure metadata parser stays strict. Boundary tests require that canonical launch coordinate and reject downstream alias repair; the backend real-file/symlink parser reproducer rejects the old alias commitment and accepts the canonical one. These failed attempts remain diagnostic evidence; the final successful matrix below supersedes them for acceptance without changing their failed status.

## Preserved verifier capture errors

`run-TmQMni/report.json` (SHA-256 `95ca9fdcaae427b50570a274be92ef20a2f46e76730d196598485bb6cd8815de`) reached successful public MCP startup and its limited inventory/load-image/gated-operation results, then failed because the verifier tried to read the already deleted credential descriptor. Its owned public runtime was removed and lineage was verified empty.

`run-2Feacs/report.json` (SHA-256 `2ec73736e0b9d867e2813d9567e55bd6e9be9c687a3362709cc589e7cce9edba`) reached successful baseline public MCP, CLI and separately authenticated provider health, then failed because the verifier searched the child-only runtime parent for the in-process Client. Its report established empty child runtime roots and verified empty lineage; it did **not** independently establish absence of the direct provider's exact root. This cleanup limitation is preserved. Both reports remain failed and their full paths are under `docs/psx-local/phase-2-import-runs/`.

The [bounded capture replan](phase-2-plan.md) moves preflight before disposable allocation, reads safe argv/profile/before-record evidence, and derives direct capture coordinates from authenticated snapshot identity. It registers exact candidates before capture assertions, awaits every close, records source hashes, checks exact direct-root absence and retains primary/cleanup failures. No credential-descriptor access, ambient temporary-directory scan or watcher is used. The final successful matrix below verifies this corrected capture contract.

## Final actual macOS matrix

Final report: `docs/psx-local/phase-2-import-runs/run-eIr3NI/report.json`, SHA-256 `68936261cfdc08b7cce99a1466aa85bb8e168ccf0ae1fce57926f3f0c6b97cd8`; verifier run `45230c21-be15-417b-97be-0719cbb5c051`. It records `ok: true`, `mocked: false`, repository HEAD `3e36f98d10d3a631ed134ae3b4ff4b2d05c1e168`, dirty file inventory and ten source/plan fingerprints. All fingerprints still matched at completion, including the frozen executed verifier. Final cleanup observation was `2026-10-10T04:01:36.074Z`.

Host: macOS/darwin arm64; pinned Node `24.18.0`, Ghidra `12.1.4` at `/opt/homebrew/Cellar/ghidra/12.1.4/libexec`, Temurin `25.0.4.1` at `/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home`. After the focused runner built the runtime, the exact final invocation was:

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec \
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home \
REA_PSX_IMPORT_PROOF_CAPTURE_DIR="$PWD/docs/psx-local/phase-2-import-runs" \
node scripts/verify-real-ghidra-psx-import.mjs
```

Each variant passed three independent production imports: public stdio MCP explicit Ghidra open/inventory/session/load-image/gated function/close; the established public CLI load-image command; and separately labeled production provider-boundary authenticated health. Identical source and canonical profile identities are required within each variant. The authenticated before/after metadata belongs to the separate direct session; it is not attributed to either public session. Public MCP and direct provider run IDs, argv, supplied profile commitments, private before records, their exact byte digests, target-bound analysis report lines and pre-analysis completion markers are retained separately.

| Variant                 | File bytes | Unchanged source SHA-256                                           | Common profile digest                                              |
| ----------------------- | ---------: | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| baseline                |       4096 | `be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a` | `1b89347dd30595b137fd6da63ef058c7f3de9b929f97ae292f4c499f9a8a562f` |
| declared-registers-fill |       4096 | `fb38aeaa649f3b90993bf6151dffc42da00cba2087344255bc6e60d9442ab3d1` | `41e81a678195e7c75fa47225b8dfd8b3561e95c156b1e6515d183c3384217ce3` |
| trailing-bytes          |       4112 | `53fea47eea51911150080df66d2d1acc852d64a7fe39d3777cdcbcd54b155595` | `87eca4494f0dcbe9d78292c743e86cb155caa4ee9f87acf57f50204b1159c761` |

Every live observed agreement selects `PsxLoader` / `psx.PsxLoader`, language `PSX:LE:32:default`, compiler `default`, image base `0x80000000`, RAM-size property `2097152` and the declared external entry. Exact argv omits both RAM overrides and includes read-only/delete-project and the packaged pre-analysis observer. Advertised defaults are separate `java.lang.String` observations, `0x80000000` / `0x200000`; supplied loader options are `{}`. The before record and authenticated after stage agree, and snapshot source digests agree before/after capture. The RAM-size property does not promise continuous initialized or mapped RAM coverage.

Observed loader and PSX analyzer code source is `Ghidra/Extensions/ghidra_psx_ldr/lib/ghidra_psx_ldr.jar`, SHA-256 `481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`. `psx.PsxAnalyzer` is observed enabled. Selected core MipsAddress/MipsPre/MipsSymbol analyzers use `Ghidra/Processors/MIPS/lib/MIPS.jar`, SHA-256 `905a4da889e7f69062f699b7dce48346f2b7a2ccd114ac189a974dfb72850080`; their enabled flags remain explicit unknowns. Selected class identity alone is not proof of analyzer execution or correct MIPS semantics.

The conservative installation inventory contains 2,170 assets. Whole-lane before/after inventory digest is unchanged: `31db2c95632ade2fb2b15e3d7320f411125dc0e24fc26f65796aea7721fba869`, algorithm `ghidra-code-data-v1`. Full canonical parameters and all selected asset/language/class digests are in the ignored report. No installed resource was patched or renamed.

All four generated policy-negative public opens passed expected refusal: alternate bank, RAM-end crossing, payload/fill overlap and nonzero data declaration. Each returned `execution_failure` with `psx-kseg0-2m-defaults-v1` diagnostics, kept the session closed, observed no analysis runtime root and left source bytes unchanged.

Each public MCP/CLI load-image result remains **unsupported** with an empty source-file collection and null source indices/file offsets on mappings. Instruction queries remain `capability_unavailable` with the Phase 4 gate. GP/SP/fill declarations are source expectations; this startup contract does not establish their effective register/content state. Uninitialized fill is not proof of zero content, and trailing-byte source mapping remains unknown. PSX-007 remains open: equality of mapped bytes is not source-backed provenance. Linux real-host import, MIPS instruction semantics, patched AC3 acceptance and installed-package/fresh-client discovery remain unperformed separate gates.

All three exact direct runtime paths were independently absent after awaited close. The dedicated child runtime directory was empty; no retained or unresolved provider roots, cleanup errors or live descendants remained. Native supervision closed, process lineage was verified empty and the owned workspace was removed. Reports contain source hashes and observations, no executable payloads, credential descriptors or ambient environment serialization. Earlier failures remain unchanged.

## Existing-format and package regressions

The orchestrator ran existing real macOS Ghidra DOS and COM lanes: both passed,
with source preservation, complete owned cleanup and verified empty descendant
lineage. DOS run `d1594e43-c62b-47b5-9af9-1d375e2e5f29` is retained in
`.agent-runtime/phase-2-dos-report.json` (parsed report SHA-256
`c78b39ad7cc129287a74385624fc533a685d4e40aa8717a3e43d86045d8b16ba`). COM run
`62b1f5ea-e55a-482e-abee-6847113ef2a7` is in
`.agent-runtime/phase-2-com-report.json` (parsed report SHA-256
`4d87f3f1bf1338ffc10810ba8cc1c8f57c86be3bbd497928d10e52a95d34b4f4`). These
lanes preserve existing loader configuration behavior; they do not establish PSX
semantics.

The initial package integrity lane passed 139 tools, six prompts and four
clients, with verified empty process lineage. The orchestrator's dry run listed
1,060 package files; both new Java helpers were required. This is package
integrity evidence, separate from real installed-package PSX acceptance. The orchestrator
reran seven provider source suites after both runtime corrections: 171 tests
passed, including 65 SessionValues and four snapshot tests. The unchanged
parser/load-image/DOS source regression set passed 75 tests earlier. Final package verification against the corrected runtime also passed 139 tools, six prompts and four clients, with verified empty lineage: `.agent-runtime/phase-2-final-package-report.json`, SHA-256 `72b5d2effcd06ab87c5d7d1131c751f2015f227ee7e9545aec3da8e1d1cf5c6a`, run `4d30ccd7-cbcf-4c78-9ab6-d85f2877ebde`. Final `npm run check` passed six tasks with 502 warnings and zero errors, including module-boundary and architecture guards; `npm run docs:check` passed six tasks. All 704 tests are discovered exactly once. The bounded close review below passed. Approved [PR #2](https://github.com/Troll-Phace/rea/pull/2) merged at `51a9f7311d631bbc06dd020f0f6a7cd30b9a8aa0` on 2026-10-10; PROGRESS.md records current-head checks and verified delivery.

## Bounded close review

One Sol6.1/high close reviewer found no new blocking or deferred source findings on 2026-10-10. It independently verified the final report and all ten source/plan fingerprints, separate public/direct evidence, nine imports, four policy negatives, the unchanged installation inventory, exact runtime-root absence and empty lineage, plus DOS/COM/package report digests. PSX-008 remains a nonblocking test-coverage gap. Final static and delivery status are recorded in PROGRESS.md.
