# Phase 1 results — format identity and installed-loader measurements

Batch: `psx-support-2026-10`; local issue PSX-001. Branch `codex/psx-phase-1`, baseline `7aa4d768`. Measured on 2026-10-09 America/New_York (final cleanup 2026-10-10T02:51:50.261Z). Technical outcome: identity implemented and loader research measured; downstream production work blocked. Review and PR/merge status are maintained in [PROGRESS.md](../PROGRESS.md).

Execution contracts: [shared Phase 1 plan](phase-1-plan.md) and [bounded defaults-only supplement](phase-1-loader-supplement.md). The original failed override experiment is retained separately. Raw reports, logs, generated executables and provider projects are local ignored evidence; this document contains no executable payloads.

## Implemented identity boundary

The pure Result parser reads the exact signature and fixed `0x800` header, preserves unsigned declarations, validates declared payload availability and checked payload/fill/stack arithmetic, and separates malformed structure from unsupported entry/payload policy. Raw data fields and trailing bytes remain distinct. An unspecified stack retains its offset with unknown SP.

Valid structural PSX identity is `ps-x-exe`/`mips` in resolution, artifact inventory, generic Evidence, snapshots and converted MCP schemas. Exact magic takes precedence over inferred filename artifact types and implicit Hopper documents; explicit caller target/format choices remain authoritative. Existing PE/ELF/Mach-O architecture support is unchanged.

Ghidra, Hopper and IDA reject explicit PSX deep analysis with `target_format_unsupported` before opening provider resources. Existing `auto` routing may open a neutral identity session with no selected deep provider or binding; deep analysis returns the existing typed unsupported selection error. Phase 1 enables recognition, not production PSX analysis.

## Host, invocation and evidence identity

- Host: macOS/darwin arm64; repository-local Node `24.18.0`, npm `11.16.0`.
- Ghidra: `12.1.4`, `/opt/homebrew/Cellar/ghidra/12.1.4/libexec`.
- Java: Temurin `25.0.4.1`, `/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home`.
- Actual loader: `psx.PsxLoader`, `PSX Executables Loader`; code source `Ghidra/Extensions/ghidra_psx_ldr/lib/ghidra_psx_ldr.jar`; SHA256 `481976bdf62759c1a83847f2394585205c20a3deb58fa9c48efe611dfafc530c`.
- Language/compiler: `PSX:LE:32:default` / `default`; image base `ram:80000000`.
- Final report: `docs/psx-local/loader-contract-runs/run-8keqyf/report.json`; SHA256 `692d534401d9fd7685025973614f2399c339a2bf7e36d77371ea6b2bef1628ff`.
- Verifier run ID: `0c9b5a7a-b812-4fa5-852c-52a6a6dcd402`.

After `npm run build:cached`, the final research invocation used:

```sh
export PATH="$PWD/.agent-runtime/toolchain/node_modules/.bin:$PATH"
GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.4/libexec \
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home \
node scripts/probe-ghidra-psx-loader.mjs \
  --output-dir "$PWD/docs/psx-local/loader-contract-runs"
```

Each case runs in a separately owned disposable project with `-readOnly`, before/after Java observers and `-deleteProject`. Explicit selection supplies `-loader PsxLoader -processor PSX:LE:32:default -cspec default`; both RAM overrides are omitted and metadata records `optionMode: loader-defaults`. The observer reports advertised defaults `0x80000000`/`0x200000`, distinct from supplied options. Exact per-case argv and observations are in the report. No fixture code is executed.

## Seven-case observations

All seven cases completed with expected selection, `REPORT: Import succeeded`, both observer markers, valid stage/program/fixture identities and settled owned execution. Before/after stage names do not imply analysis ran in `-noanalysis` cases.

| Case | Fixture                 | Selection            | Analysis | GP at entry | SP at entry | Fill sample          |
| ---- | ----------------------- | -------------------- | -------- | ----------- | ----------- | -------------------- |
| 0    | baseline                | automatic            | off      | `0`         | unknown     | uninitialized RAM    |
| 1    | baseline                | explicit/default RAM | off      | `0`         | unknown     | uninitialized RAM    |
| 2    | baseline                | explicit/default RAM | on       | `0`         | unknown     | uninitialized RAM    |
| 3    | declared-registers-fill | explicit/default RAM | off      | `80010800`  | unknown     | uninitialized `.bss` |
| 4    | declared-registers-fill | explicit/default RAM | on       | `80010800`  | unknown     | uninitialized `.bss` |
| 5    | trailing-bytes          | explicit/default RAM | off      | `0`         | unknown     | uninitialized RAM    |
| 6    | trailing-bytes          | explicit/default RAM | on       | `0`         | unknown     | uninitialized RAM    |

These sampled facts agree before and after each case. Every case has one initialized `CODE` block at `ram:80010000`, size `0x800`, matching the independently generated declared payload digest `a1778594b84b9e063a476315f75b73bdb8d8fb698fb78b9f63406bceaf6679ff`. The external entry is `ram:80010000`; the loader already creates an entry instruction before analysis. This is mapping-content evidence only.

Every before/after observation has an empty FileBytes collection and no original-file offsets for payload sources. Source-backed coverage is therefore **not established**. The declared stack would derive SP `0x801fff80`, but sampled SP context is absent. The declared fill at `0x80011000`, size `0x20`, is uninitialized `.bss`, so zero-filled content is not proven. In the declared variant, the sampled range immediately after payload (`0x80010800`, 16 bytes) is not covered; in baseline/trailing cases it is uninitialized RAM. Later policy must account for these actual mapping differences.

The trailing fixture has 16 additional file bytes while initialized payload extent and digest remain unchanged. There is no source-backed mapping found for file offsets `0x1000..0x100f`; global trailing-byte mapping status remains unknown without FileBytes provenance.

ClassSearcher selects `MipsPreAnalyzer` from standard `Ghidra/Processors/MIPS/lib/MIPS.jar` and ignores the duplicate extension definition. Runtime analyzer code-source evidence agrees; standard MIPS JAR SHA256 is `905a4da889e7f69062f699b7dce48346f2b7a2ccd114ac189a974dfb72850080`. Selected classes do not establish their execution. The enabled PsyQ analyzer and relevant extension assets are inventoried; analysis logs are retained locally. Production profile fingerprints need effective selected assets, not just the extension directory.

## Preservation and cleanup

All three generated fixture digests stayed unchanged after each import. The final before/after inventory contains 463 unchanged extension assets plus the unchanged selected MIPS JAR. Four probe source fingerprints match final source:

| Source                                                    | SHA256                                                             |
| --------------------------------------------------------- | ------------------------------------------------------------------ |
| `scripts/probe-ghidra-psx-loader.mjs`                     | `108ddf222fd7a38e417aaa0d9d1e53da676094eccba68072dcf0484531be2a5d` |
| `scripts/lib/psx-loader-observations.mjs`                 | `40d03051cf3b39083fd337a8ca1b6edb32bb73639b64b363ec21e6f78cd63854` |
| `tests/conformance/ghidra/psx-exe-fixture.mjs`            | `fe7c82f60196a9361da9f5a68c65e08a04ec001fa0ded4d27c034fd17e1c9174` |
| `tests/conformance/ghidra/ReaPsxLoaderContractProbe.java` | `37b2ab63213371543b6cc80e8dee30d977add00a924a4536017bdf09665d4086` |

Cleanup was awaited: native ownership inspector closed, exact disposable root removed, verifier lineage status verified with no descendants. User settings/cache/temp were isolated; real user extension roots were inventoried without loading them. No ambient environment was serialized, no installed asset patched, and no game input read. The earlier metadata-inconsistent `run-yYMXOX` is explicitly superseded; its raw report remains unchanged.

## Failed RAM override and downstream disposition

Preserved failed experiment: `docs/psx-local/loader-contract-runs/run-2iooT6/report.json`, SHA256 `70315521552048711c8f93538280b54e4073c2142d22f139a5a4c7339d0d213d`. Supplying `-loader-ramStart 0x80000000 -loader-ramSize 0x200000` failed with expected class `psx.PsxBaseChooser` versus actual `java.lang.String`; Ghidra nevertheless exited zero. The probe requires actual import and observer completion, not exit status alone.

- PSX-006 blocks PSX-002 production admission: explicitly replan a deterministic supported configuration, effective options and selected assets; refuse layouts requiring unsupported overrides. Defaults-only research does not resolve production profile identity.
- PSX-007 blocks PSX-003 source-backed attestation: plan a producer-boundary provenance adaptation and independently verify source offsets/coverage. Matching mapped hashes cannot substitute for provenance.
- Missing SP, uninitialized fill and changed surrounding coverage remain explicit limitations for later policy and attestation design; they are not runtime facts.

Phase 1 can finish its measured research outcome while these downstream gates stay open. Linux, actual public REA PSX import, local patched AC3, instruction/runtime semantics and package/client support remain unperformed later-phase gates.

## Validation

- Domain/provider local suites: 118 tests across nine files; installation/managed regression suites: 50 tests across two files. Focused filesystem: 57 tests; focused MCP/schema/error delivery: 11 tests. Follow-up test restructuring/schema boundary fixes passed their affected suites.
- `npm run build:cached`: three tasks passed.
- `npm run check`: six tasks and architecture guards passed; 487 existing warnings, zero errors.
- `npm run mcp-catalog:generate`, `npm run mcp-catalog:check`, `npm run docs:check`: passed.
- `npm run verify:test-discovery`: all 699 test files exactly once.
- Harness configured validator and 14 Python helper tests: passed. These are structural/simulated evidence; fresh-client agent/skill discovery and native hook lifecycle remain unverified.
- Actual seven-case macOS synthetic loader matrix: passed with the limitations and cleanup above.

The close review and final-content verification are recorded in PROGRESS.md before delivery. PSX-001 remains in progress until its required PR/merge delivery scope is satisfied.

Delivery: implementation commit `0a8b033ac7bbd2f6e6a5f8f48b55504463f3f000` pushed; [PR #1](https://github.com/Troll-Phace/rea/pull/1) open. Approved merge remains pending.
