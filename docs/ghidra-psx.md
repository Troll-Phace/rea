# PS-X EXE analysis with Ghidra

REA recognizes the exact `PS-X EXE` signature and can import admitted executables
through a caller-supplied Ghidra installation and compatible PSX loader. Source
bytes stay unchanged; REA owns a disposable headless Program. Use explicit
`ghidra` selection when you need the PSX static analysis workflow.

This fork's PSX work is not a claim about the published npm release. See the
[release boundary](installation.md#released-package-and-main),
[provider semantics](ghidra-provider.md), and the current
[Phase 5 results](active/phase-5-results.md) for acceptance status.

## Prerequisites and admission

Bring an existing Ghidra 12.1.4 installation, a PSX loader compatible with that
Ghidra version, and JDK 25. The measured macOS setup uses loader release
2026.10.03 and Temurin 25.0.4.1. REA does not install or upgrade these components.
Follow the loader's own installation instructions, then select the intended
installation and JDK through REA's
[Ghidra configuration](installation.md#ghidra). Keep a separately configured GUI
launcher separate from this headless provider.

PSX inspection checks the selected loader, language, code and analysis assets.
Missing, incompatible or ambiguous candidates are PSX-specific failures; they
do not disable ordinary Ghidra targets. No raw-binary fallback or provider switch
makes an unsupported PSX import usable. Startup must agree with the immutable
source and selected profile; a zero headless exit status alone proves nothing.

The current profile selects `PsxLoader` / `psx.PsxLoader`,
`PSX:LE:32:default`, compiler `default`, and omits RAM override arguments. It
admits a nonempty aligned payload and complete entry instruction in the KSEG0
2 MiB RAM bank, disjoint in-bank fill and zero separate-data declarations.
Structurally malformed headers differ from recognized layouts outside this
supported policy. Preserve the diagnostic and source declarations in either
case. Missing loader support, required RAM overrides or unsupported layout need
compatible resources or an explicitly revised implementation policy.

## Public static workflow

Use an absolute local input path. These CLI commands return Evidence as JSON:

```bash
rea inspect-native-load-image /absolute/path/to/boot.exe --provider ghidra --json
rea inspect-native-instruction /absolute/path/to/boot.exe 0x80010008 --provider ghidra --json
rea resolve-native-call-targets /absolute/path/to/boot.exe 0x80010008 --provider ghidra --json
rea instructions /absolute/path/to/boot.exe 0x80010000 --provider ghidra --json
rea decompile /absolute/path/to/boot.exe 0x80010000 --provider ghidra --json
rea function /absolute/path/to/boot.exe 0x80010000 --provider ghidra --json
rea xrefs /absolute/path/to/boot.exe 0x80010080 --provider ghidra --json
```

The example addresses belong to the original synthetic fixture; select the
actual observed address for another input. One-shot CLI commands own their
individual import and cleanup. Function, instruction-listing and decompile
routes support `--snapshot /absolute/path/to/analysis.json`. Load-image,
single-instruction and call-target CLI commands do not expose that option.

For MCP, open once with `open_binary({path, provider_id:"ghidra"})`, then use
`inspect_native_load_image({})`, `inspect_native_instruction({address})`,
`resolve_native_call_targets({address})`, `read_function_instructions({procedure})`,
`procedure_pseudo_code({procedure})`, `analyze_function({procedure})`, and
`procedure_references({procedure,direction:"outgoing"})` as the question requires.
`binary_session({})` reports actual target, provider, profile and availability.
Close with `close_binary({})`; supply `snapshot_path` only when saving the
session's immutable analysis snapshot. Load-image input is strictly empty.

## What the evidence establishes

`inspect_native_load_image` independently checks the immutable source header,
complete declared payload, genuine FileBytes offsets/digests, mapped bytes and
the exact declared entry instruction. `verified`, `mismatch` and `unsupported`
are distinct outcomes. Coverage and named limitations define the claim;
trailing bytes remain part of source identity without becoming payload coverage.

The installed loader lacks original FileBytes provenance. REA may replace
approved payload blocks with source-backed blocks in its disposable Program,
under an exclusive transaction with completed commit or rollback checks.
Verified therefore describes REA's adapted static payload. The complete original
label journal is retained as authenticated evidence and recreated payload ADD
events are disclosed; the original live journal is not claimed restored.
Bookmarks within approved payload blocks retain their exact database IDs, types,
categories, comments and original coordinates through checked temporary parking
and return in that same transaction. Unsupported metadata still prevents
adaptation; failed or cancelled preparation must restore the original state.

Addresses preserve the declared virtual values. Do not substitute a physical
alias or infer SP/GP state from a declaration alone. Unobserved SP and initialized
fill content remain unknown. Delay-slot fields describe measured Ghidra Listing
coverage and ownership. Decoded p-code RETURN can identify return flow while
Listing reports `computed:false`; that flag does not reveal a runtime return
address. Function bodies come from observed AddressSets rather than extending
ranges arithmetically. Decompiler text is recovered analysis, not original C.

Indirect calls can remain unresolved. Static image verification does not prove
runtime execution, runtime register state, complete indirect targets, overlay
availability or correctness of a reconstruction. PSX annotations and native
type inspection are refused under the current static query scope. Windows PSX,
arbitrary MIPS formats, automatic overlays, disc extraction, emulator control
and attached GUI database synchronization are outside this batch.

## Identity and snapshots

Snapshots bind source SHA-256 and the selected analysis profile, including
loader/assets, import policy, provenance method and flow interpretation. A change
to any binding can make an older snapshot stale. CLI and MCP retain Evidence,
unknowns and meaningful typed rejection rather than silently reusing results.
Never change installed loader files or original input bytes to test a negative.

`close_binary({snapshot_path})` retains eligible immutable query results;
`open_binary({path,provider_id:"ghidra",snapshot_path})` reopens with the same
identity. A rejected snapshot must not replace a previously usable session.
For instruction and call-target queries that you intend to cache, obtain the
actual Program name with `list_documents({})` and pass that exact value as
`document` alongside the address. Address-only Evidence is retained but does
not create those document-scoped cache entries. Image input stays `{}`;
function dossiers use their procedure selector without a document argument.
MCP replay reports its snapshot limitation. A supported CLI snapshot hit returns
the original persisted Evidence, retaining the execution that produced it.
Real replay and deterministic proof of zero provider dispatch are separate
claims. Existing Ghidra flow-version changes intentionally invalidate old
Ghidra semantic profiles, including non-PSX profiles.

## Acceptance lanes

Keep these rows separate. Prior successful reports cover their recorded source
and provider identities; they do not establish a new installed artifact.

| Lane                                                 | Current evidence boundary                                                                                                                                                                                              |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS arm64 source, Ghidra 12.1.4 / Temurin 25.0.4.1 | Complete renewed public CLI/MCP, snapshot, negative, cancellation and cleanup acceptance passed for the repaired source candidate.                                                                                     |
| Linux source                                         | Unverified; no Linux host is available. Linux verification is optional under the user-approved Phase 5 completion scope.                                                                                               |
| Installed local tarball                              | Complete macOS installed PSX acceptance passes for the exact cold-tested tarball, including public parity, snapshots, refusals, cancellation/recovery and cleanup.                                                     |
| Local Load Word patched AC3 Disc 1 boot image        | Complete fresh smoke passes source image/entry, five facets, snapshot and both CLI comparisons under the documented local journal limits. No retail, Disc 2 or overlay claim.                                          |
| Fresh Codex/client                                   | All three actual installed-package synthetic scenarios pass on recorded macOS Codex Desktop sessions. Trust transition, desktop bundle version, source-harness lifecycle and independent OS cleanup remain unobserved. |

For exact commands, immutable report identities, failures and cleanup outcomes,
see [testing](testing.md#psx-phase-5),
the [saved contract](active/phase-5-plan.md) and
[results](active/phase-5-results.md). Required macOS and actual client acceptance
pass. Linux remains unverified and is optional under P5-R18; approved PR delivery
is still required for full phase closure.

The local AC3 verifier authenticates each independent import against its own
captured startup and preparation records. It requires exact static image facts,
exact preparation/non-variable journal multisets and equal address-key sets.
It permits only a unique permutation of complete VARIABLE ADD-history groups,
preserving labels, users and duplicate counts. Its report retains the full
ordered inputs and every permitted difference. This comparison does not
establish equal event chronology, underlying variable storage, function
ownership or deterministic analyzer scheduling. Synthetic source and installed
package acceptance retain their existing stricter comparison.

## Fresh-client acceptance

Use the exact verified local tarball and an isolated project installation;
avoid resolving the published package or the source tree by accident. The
Phase 5 handoff supplies its digest, installed launcher, generated original
fixture path/digest and selected provider/JDK. Retain this separate client
workspace until the scenarios finish, then close owned sessions and remove it.
It is an intentional acceptance input, distinct from verifier cleanup failures.

In a new trusted project-rooted Codex session, connect the installed launcher as
a STDIO MCP server and expose that installed package's generated skill. Scoped
MCP configuration belongs in the isolated project's `.codex/config.toml`; local
skills can be discovered from `.agents/skills`, including symlinked folders.
These client mechanisms are documented in the official
[MCP configuration guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [skill discovery guide](https://learn.chatgpt.com/docs/build-skills).
Use a current supported client; the older `/usr/local/bin/codex` on the current
host lacks the modern MCP/configuration commands. No client upgrade is part of
this phase. Preserve existing user configuration and project trust choices.

Run each scenario in a fresh chat with the handoff's synthetic input path:

1. Broad: “Inspect this original PS-X EXE with REA. Explain its static support
   and evidence limits, cite the observations, and close the session.”
2. Direct: “Inspect the direct call and its delay slot, and verify the
   source-backed entry. Explain what is observed and what remains unknown;
   retain Evidence and close the session.”
3. Negative: “Can this static snapshot recover unobserved runtime registers
   or overlay bytes? Use the available evidence to assess that question and
   close the session.”

Record actual client/host/model/catalog identity, discovered skill, selected
tools and arguments, errors/retries, Evidence IDs and answers. The broad case
must actually discover and use the tools; the direct case must support its
claims with returned Evidence; the negative case must preserve unknowns and
unsupported boundaries. A successful launch or a catalog keyword match cannot
replace the transcript. Record phase-agent/skill discovery and trusted
SessionStart/SessionEnd observations separately; do not infer them from manual
helper invocation or stamp files. Review the returned transcripts against the
synthetic oracle before marking G5 accepted.
