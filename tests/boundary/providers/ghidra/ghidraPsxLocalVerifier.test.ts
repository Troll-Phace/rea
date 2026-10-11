import {
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { createAnalysisProfile } from "../../../../src/domain/analysisProfile.js";
import { createEvidence } from "../../../../src/domain/evidence.js";
import type { Evidence } from "../../../../src/domain/evidence.js";
import { ok } from "../../../../src/domain/result.js";
import { jsonValueSchema } from "../../../../src/domain/jsonValue.js";
import type {
  NativeLoadImageObservation,
  PsxLabelHistoryRow,
  PsxLoadImage,
} from "../../../../src/domain/native/nativeLoadImage.js";
import {
  psxImportObservationSchema,
  psxOriginalEvidenceRecordSchema,
} from "../../../../src/ghidra/GhidraImportConfiguration.js";
import { attestGhidraPsxLoadImage } from "../../../../src/ghidra/GhidraPsxLoadImageValues.js";
import {
  connectPsxOperationMcp,
  psxAppliedLoadImageObservation,
  psxFixtureAgreement,
  psxFixtureCommitment,
  psxFixtureOriginalRecord,
  psxFixtureSha256,
  psxImportBytes,
  psxInstructionFlowBytes,
  psxSimulatedOperation,
} from "../../../fixtures/ghidraPsxImport.js";

type LocalInput = {
  supplied_path: string;
  path: string;
  canonical_path: string;
  sha256: string;
  entry_address: string;
  entry_bytes: string;
  identity: string;
};
const local = (await import(
  new URL("../../../../scripts/verify-local-ghidra-psx.mjs", import.meta.url)
    .href
)) as {
  parseLocalPsxArguments(args: string[]): {
    supplied_path: string;
    path: string;
  };
  readLocalPsxInput(args: string[]): Promise<LocalInput>;
  localPsxFacet(
    name: string,
    parsed: unknown,
  ): { status: string; error?: unknown; reason?: string };
  verifyLocalPsx(input: unknown, target: LocalInput): Promise<unknown>;
  assertLocalPsxLiveParity(
    cli: JournalObservation,
    mcp: JournalObservation,
    binding: JournalBinding,
    bytes: Uint8Array,
  ): JournalComparison;
  localPsxBinding(
    input: LocalInput,
    selectedProfile: unknown,
    operation: string,
    parameters: Record<string, unknown>,
  ): Record<string, unknown>;
  localPsxSnapshotQueries(
    input: unknown,
    documents: unknown,
  ): [string, Record<string, unknown>][];
  settleLocalPsxOutcome(
    context: unknown,
    target: LocalInput,
    facets: unknown[],
  ): Promise<{
    ok: boolean;
    partial: boolean;
    facets: unknown[];
    fixtures: { after_sha256: string }[];
    settlement: {
      unresolved_owners: { identity: { id: string }; retry(): Promise<void> }[];
    };
    failures: { message: string }[];
  }>;
};
const publicHelper = (await import(
  new URL("../../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as {
  publicPsxDocumentIdentifier(documents: unknown, expected?: string): string;
  compilePublicPsxSchemas(catalog: unknown): Map<string, unknown>;
  capturePublicPsxReply(
    context: unknown,
    reply: unknown,
    operation: string,
    schema: unknown,
  ): Promise<{ value: unknown; evidence: Evidence }>;
  assertPublicPsxSnapshotEntries(
    snapshot: unknown,
    queries: [string, Record<string, unknown>][],
    observations: Evidence[],
    binding: unknown,
  ): unknown;
  validatePublicPsxEvidence(value: unknown, binding: unknown): unknown;
  validatePublicPsxImageImport(
    value: JournalObservation,
    binding: JournalBinding,
    bytes: Uint8Array,
  ): unknown;
  assertPublicPsxMcpReplay(
    replay: JournalObservation,
    original: JournalObservation,
    binding: JournalBinding,
  ): void;
  publicPsxSnapshotLimitation: string;
  publicPsxObservation(
    evidence: Evidence,
    binding: unknown,
    association: unknown,
  ): unknown;
  assertPublicPsxLiveParity(
    cli: unknown,
    mcp: unknown,
    binding: unknown,
    sourceBytes: Uint8Array,
  ): unknown;
  createPublicPsxContext(input: unknown): {
    fixtures: unknown[];
    primary?: Error;
    emit(event: unknown): Promise<void>;
    case(
      id: string,
      adapter: string,
      action: () => Promise<void>,
    ): Promise<void>;
    resources: {
      owner: string;
      identity: { kind: string; id: string };
      close(): Promise<void>;
    }[];
  };
};

const createLocalSdkSnapshotControl = async (identity: string) => {
  const declaredDocument = "Local generated Program 雪.v3";
  let discoveries = 0;
  const harness = await connectPsxOperationMcp(
    async (operation, parameters) => {
      if (operation === "list_documents") {
        discoveries += 1;
        return ok([
          identity === "changed" && discoveries > 1
            ? "Changed actual Program"
            : declaredDocument,
        ]);
      }
      if (operation === "inspect_native_load_image")
        return ok(
          jsonValueSchema.parse(
            psxAppliedLoadImageObservation(psxInstructionFlowBytes()),
          ),
        );
      if (parameters.document !== undefined && parameters.document !== null)
        expect(parameters.document).toBe(declaredDocument);
      const { document: _document, ...unscoped } = parameters;
      return ok(psxSimulatedOperation(operation, unscoped));
    },
  );
  const parent = await createTestTempDirectory("psx-local-sdk-snapshot-");
  const workspace = join(parent, "workspace");
  await mkdir(workspace);
  const log = join(parent, "events.jsonl");
  const input = {
    path: harness.fixture.source,
    supplied_path: harness.fixture.source,
    canonical_path: await realpath(harness.fixture.source),
    sha256: psxFixtureSha256(psxInstructionFlowBytes()),
    entry_address: "0x80010000",
    entry_bytes: psxInstructionFlowBytes()
      .subarray(0x800, 0x804)
      .toString("hex"),
    identity: "original generated PSX input",
    limitations: [],
  };
  const context = publicHelper.createPublicPsxContext({
    executable: process.execPath,
    prefixArgs: [],
    environment: { TMPDIR: workspace },
    workspace,
    record: async (event: unknown) => {
      await writeFile(log, `${JSON.stringify(event)}\n`, { flag: "a" });
    },
  });
  context.fixtures.push(input);
  context.resources.push({
    owner: "actual-sdk-local-generated-input",
    identity: { kind: "sdk-session", id: identity },
    close: () => harness.close(),
  });
  return { declaredDocument, harness, input, context, log };
};

describe("P5-R3 local Program discovery admission", () => {
  it.each([[], [""], ["A", "B"]].map((documents) => [documents]))(
    "rejects unusable local document discovery %j",
    (documents) => {
      expect(() =>
        local.localPsxSnapshotQueries(
          { entry_address: "0x801255ac" },
          documents,
        ),
      ).toThrow("exactly one observed nonempty Program");
    },
  );
});

describe("P5-R3 local generated-input SDK snapshot ownership", () => {
  it.each(["stable", "changed"])(
    "retains original unscoped Evidence and settles %s observed Program replay through actual SDK (simulated bridge)",
    async (identity) => {
      const { declaredDocument, harness, input, context, log } =
        await createLocalSdkSnapshotControl(identity);
      const facets = [
        local.localPsxFacet("instructions", {
          value: { retained: "generated partial observation" },
        }),
      ];
      try {
        await context.case("local-sdk-snapshot", "mcp", async () => {
          const catalog = await harness.mcp.listTools();
          const names = new Set([
            "list_documents",
            "inspect_native_load_image",
            "inspect_native_instruction",
          ]);
          const schemas = publicHelper.compilePublicPsxSchemas({
            tools: catalog.tools.filter(({ name }) => names.has(name)),
          });
          const request = async (
            operation: string,
            parameters: Record<string, unknown> = {},
          ) => {
            const raw = await harness.mcp.callTool({
              name: operation,
              arguments: parameters,
            });
            return publicHelper.capturePublicPsxReply(
              context,
              raw,
              operation,
              schemas.get(operation),
            );
          };
          const original = (
            await request("inspect_native_instruction", {
              address: input.entry_address,
            })
          ).evidence;
          const originalBytes = JSON.stringify(original);
          const documents = (await request("list_documents")).value;
          const queries = local.localPsxSnapshotQueries(input, documents);
          expect(queries).toEqual([
            ["inspect_native_load_image", {}],
            [
              "inspect_native_instruction",
              { address: input.entry_address, document: declaredDocument },
            ],
          ]);
          const scoped: Evidence[] = [];
          for (const [operation, parameters] of queries)
            scoped.push((await request(operation, parameters)).evidence);
          expect(scoped[1]?.normalized_result).toEqual(
            original.normalized_result,
          );
          expect(scoped[1]?.evidence_id).not.toBe(original.evidence_id);
          const saved = harness.session.exportAnalysisSnapshot();
          if (!saved.ok) throw saved.error;
          publicHelper.assertPublicPsxSnapshotEntries(
            saved.value,
            queries,
            scoped,
            {
              sourceDigest: input.sha256,
              selectedProfile: scoped[0]!.analysis_profile,
            },
          );
          expect(saved.value.entries).toHaveLength(2);
          expect(saved.value.evidence_bundle.records).toContainEqual(original);
          const closed = await harness.mcp.callTool({
            name: "close_binary",
            arguments: {},
          });
          if (closed.isError) throw new Error(JSON.stringify(closed));
          const imported = harness.session.importAnalysisSnapshot(saved.value);
          if (!imported.ok) throw imported.error;
          const opened = await harness.mcp.callTool({
            name: "open_binary",
            arguments: { path: input.path, provider_id: "ghidra" },
          });
          if (opened.isError) throw new Error(JSON.stringify(opened));
          const beforeDiscovery = harness.recording.queries.length;
          const reopenedDocuments = (await request("list_documents")).value;
          expect(harness.recording.queries.slice(beforeDiscovery)).toEqual([
            { operation: "list_documents", parameters: {} },
          ]);
          expect(JSON.stringify(original)).toBe(originalBytes);
          expect(harness.session.evidenceById(original.evidence_id)).toEqual(
            original,
          );
          publicHelper.publicPsxDocumentIdentifier(
            reopenedDocuments,
            declaredDocument,
          );
          const beforeReplay = structuredClone(harness.recording.queries);
          for (const [index, [operation, parameters]] of queries.entries()) {
            const replay = (await request(operation, parameters)).evidence;
            for (const field of [
              "normalized_result",
              "raw_result",
              "parameters",
              "subject",
              "provider",
              "analysis_profile",
            ] as const)
              expect(replay[field]).toEqual(scoped[index]![field]);
          }
          expect(harness.recording.queries).toEqual(beforeReplay);
        });
      } catch (cause) {
        context.primary = cause as Error;
        await context.emit({
          stage: "local-snapshot",
          kind: "failure",
          failure: { message: (cause as Error).message },
        });
      }
      const outcome = await local.settleLocalPsxOutcome(context, input, facets);
      expect(outcome.ok, JSON.stringify(outcome.failures)).toBe(
        identity === "stable",
      );
      expect(outcome.facets).toEqual(facets);
      expect(outcome.settlement.unresolved_owners).toEqual([]);
      expect(harness.recording.counts().closes).toBe(
        harness.recording.counts().clients,
      );
      const capture = await readFile(log, "utf8");
      expect(capture).toContain(declaredDocument);
      if (identity === "changed") {
        expect(capture).toContain("Changed actual Program");
        expect(outcome.failures).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              message: expect.stringContaining(
                "Snapshot Program identity changed",
              ),
            }),
          ]),
        );
      }
    },
  );
});

const generatedLocalShape = () => {
  // Original synthetic PS-X header/body only, never game bytes or an asserted
  // oracle for game code. The acceptance handoff header is deliberately explicit.
  const bytes = Buffer.alloc(0x75800);
  Buffer.from("PS-X EXE").copy(bytes);
  bytes.writeUInt32LE(0x801255ac, 0x10);
  bytes.writeUInt32LE(0x80120000, 0x18);
  bytes.writeUInt32LE(0x75000, 0x1c);
  Buffer.from("0800e003", "hex").copy(bytes, 0x800 + 0x55ac);
  return bytes;
};

describe("P5-R1 explicit local session binding handoff", () => {
  it("binds generated source/entry Evidence to the caller's observed profile and rejects an independent mismatch", async () => {
    const parent = await createTestTempDirectory("psx-local-binding-");
    const path = join(parent, "generated source 雪.exe");
    await writeFile(path, generatedLocalShape());
    const input = await local.readLocalPsxInput(["--binary", path]);
    const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
    const profile = createAnalysisProfile(provider, {
      psx_import: { source_sha256: input.sha256 },
      startup_agreement: "psx-observed-import-and-provenance-v3",
      psx_source_provenance: "rea-psx-filebytes-rebind-v2",
      psx_preparation_transaction: "exclusive-top-level-v1",
      instruction_flow_evidence:
        "decoded-return-before-jump-and-delay-slots-v2",
    });
    const value = createEvidence(
      { path, sha256: input.sha256, format: "ps-x-exe", architecture: "mips" },
      provider,
      {
        operation: "inspect_native_instruction",
        parameters: { address: input.entry_address },
        analysisProfile: profile,
        result: {
          address: input.entry_address,
          status: "decoded",
          procedure: null,
          architecture: "mips",
          mode: "default",
          bytes: input.entry_bytes,
          length: 4,
          mnemonic: "fixture",
          raw_disassembly: "fixture",
          operands: [],
          flow: {
            kind: "fallthrough",
            conditional: false,
            computed: false,
            direct_destinations: [],
          },
          references: [],
          limitations: [],
        },
      },
    );
    const before = JSON.stringify(value);
    const bind = (selected: unknown) =>
      local.localPsxBinding(input, selected, "inspect_native_instruction", {
        address: input.entry_address,
      });
    expect(
      publicHelper.validatePublicPsxEvidence(value, bind(profile)),
    ).toEqual(profile);
    const owner = (evidence: Evidence, runId: string) =>
      publicHelper.publicPsxObservation(evidence, bind(profile), {
        event_sequence: 1,
        run_id: runId,
        capture: {
          run_id: runId,
          runtime_root: parent,
          records: {},
          generated_control: true,
        },
      });
    const initial = owner(value, "generated-original");
    const fresh = owner(value, "generated-cli");
    expect(
      publicHelper.assertPublicPsxLiveParity(
        fresh,
        initial,
        bind(profile),
        generatedLocalShape(),
      ),
    ).toMatchObject({ mode: "native" });
    const marked = createEvidence(
      { path, sha256: input.sha256, format: "ps-x-exe", architecture: "mips" },
      provider,
      {
        operation: value.operation,
        parameters: value.parameters,
        analysisProfile: profile,
        result: value.normalized_result,
        limitations: [
          ...value.limitations,
          publicHelper.publicPsxSnapshotLimitation,
        ],
      },
    );
    expect(() =>
      publicHelper.assertPublicPsxLiveParity(
        fresh,
        owner(marked, "generated-cache"),
        bind(profile),
        generatedLocalShape(),
      ),
    ).toThrow();
    expect(value.parameters).toEqual({ address: input.entry_address });
    expect(() =>
      publicHelper.assertPublicPsxLiveParity(
        fresh,
        initial,
        local.localPsxBinding(input, profile, "inspect_native_instruction", {
          address: input.entry_address,
          document: "unselected",
        }),
        generatedLocalShape(),
      ),
    ).toThrow();
    expect(JSON.stringify(value)).toBe(before);
    expect(() =>
      publicHelper.validatePublicPsxEvidence(
        value,
        bind(
          createAnalysisProfile(provider, {
            ...profile.parameters,
            independent_revision: 2,
          }),
        ),
      ),
    ).toThrow();
    expect(() => bind(undefined)).toThrow("Actual local session profile");
    expect(await readFile(path)).toEqual(generatedLocalShape());
  });
});

describe("Phase 5 local verifier explicit-source admission (generated files only)", () => {
  it.each([
    [],
    ["--binary"],
    ["--unknown", "x"],
    ["--binary", "x", "--binary", "y"],
    ["--binary=x"],
    ["--binary", "--binary"],
  ])("rejects malformed/duplicate path options %j", (...args) => {
    expect(() => local.parseLocalPsxArguments(args)).toThrow("--binary PATH");
  });

  it("retains lexical caller choice alongside canonical identity and current header/hash", async () => {
    const parent = await createTestTempDirectory("psx-local-admission-");
    const path = join(parent, "generated source 雪.exe");
    const bytes = generatedLocalShape();
    await writeFile(path, bytes);
    const input = await local.readLocalPsxInput(["--binary", path]);
    expect(input).toMatchObject({
      supplied_path: path,
      path,
      canonical_path: path,
      entry_address: "0x801255ac",
      entry_bytes: "0800e003",
      identity: "Load Word translation-patched Disc 1 boot executable",
    });
    expect(input.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(await readFile(path)).toEqual(bytes);
    expect(await readdir(parent)).toEqual(["generated source 雪.exe"]);
  });

  it("stops mismatched declared AC3 layout before creating captures or clients", async () => {
    const parent = await createTestTempDirectory("psx-local-mismatch-");
    const path = join(parent, "original.exe");
    const bytes = generatedLocalShape();
    bytes.writeUInt32LE(0x80125600, 0x10);
    await writeFile(path, bytes);
    await expect(local.readLocalPsxInput(["--binary", path])).rejects.toThrow(
      "fixed AC3 assertions stopped before native allocation",
    );
    expect(await readdir(parent)).toEqual(["original.exe"]);
    expect(await readFile(path)).toEqual(bytes);
  });

  it("rejects malformed/truncated caller bytes and never scans another input", async () => {
    const parent = await createTestTempDirectory("psx-local-truncated-");
    const path = join(parent, "selected.exe");
    await writeFile(path, "PS-X EXE");
    await writeFile(join(parent, "unselected.exe"), generatedLocalShape());
    await expect(local.readLocalPsxInput(["--binary", path])).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe("PS-X EXE");
    expect(await readdir(parent)).toHaveLength(2);
  });

  it("retains typed unavailable facets as partial evidence", () => {
    const error = {
      code: "capability_unavailable",
      message: "Unavailable decompiler",
    };
    expect(local.localPsxFacet("decompile", { error })).toEqual({
      facet: "decompile",
      status: "inconclusive",
      error,
    });
    expect(
      local.localPsxFacet("containing-function", { value: { found: false } }),
    ).toMatchObject({
      status: "inconclusive",
      reason: "No observed containing function",
    });
    expect(local.localPsxFacet("decompile", { value: "" })).toMatchObject({
      status: "inconclusive",
    });
    expect(
      local.localPsxFacet("references", { value: { references: [] } }),
    ).toMatchObject({ status: "passed" });
  });

  it("rejects source replacement between admission and execution before client allocation", async () => {
    const parent = await createTestTempDirectory("psx-local-changed-");
    const path = join(parent, "selected.exe");
    await writeFile(path, generatedLocalShape());
    const input = await local.readLocalPsxInput(["--binary", path]);
    await writeFile(path, "replaced");
    await expect(local.verifyLocalPsx({}, input)).rejects.toThrow(
      "Local input changed after admission",
    );
    expect(await readdir(parent)).toEqual(["selected.exe"]);
  });

  it("retains generated local input, partial facet evidence and exact cleanup ownership after failed closes", async () => {
    const parent = await createTestTempDirectory("psx-local-cleanup-");
    const path = join(parent, "selected.exe");
    const bytes = generatedLocalShape();
    await writeFile(path, bytes);
    const input = await local.readLocalPsxInput(["--binary", path]);
    const workspace = join(parent, "workspace");
    await mkdir(workspace);
    const marker = join(workspace, "owned session resource");
    await writeFile(marker, "retained");
    const context = publicHelper.createPublicPsxContext({
      executable: process.execPath,
      prefixArgs: [],
      environment: { TMPDIR: workspace },
      workspace,
      record: async () => {},
    });
    context.fixtures.push(input);
    context.primary = new Error("controlled unavailable local facet");
    let release = false;
    context.resources.push({
      owner: "local-resource",
      identity: { kind: "generated-local-resource", id: marker },
      close: async () => {
        if (!release) throw new Error("local cleanup blocked");
        await rm(marker);
      },
    });
    const facets = [
      local.localPsxFacet("decompile", {
        error: {
          code: "capability_unavailable",
          message: "controlled unavailable",
        },
      }),
    ];
    const outcome = await local.settleLocalPsxOutcome(context, input, facets);
    expect(outcome.ok).toBe(false);
    expect(outcome.partial).toBe(true);
    expect(outcome.facets).toEqual(facets);
    expect(outcome.fixtures[0]?.after_sha256).toBe(input.sha256);
    expect(await readFile(path)).toEqual(bytes);
    const owner = outcome.settlement.unresolved_owners[0]!;
    expect(owner.identity.id).toBe(marker);
    expect(await readFile(marker, "utf8")).toBe("retained");
    release = true;
    await owner.retry();
    expect(outcome.ok).toBe(false);
  });
});

type JournalFact = Pick<
  PsxLabelHistoryRow,
  "address" | "label" | "action" | "user"
>;
type JournalBinding = {
  operation: string;
  parameters: Record<string, unknown>;
  sourceDigest: string;
  selectedProfile: ReturnType<typeof createAnalysisProfile>;
};
type JournalObservation = {
  mode: "native" | "mcp-cache";
  evidence: Evidence;
  binding: JournalBinding;
  event_sequence: number;
  run_id: string;
  capture: {
    run_id: string;
    runtime_root: string;
    snapshot: { path: string; sha256: string };
    records: Record<string, { path: string; text: string; sha256: string }>;
  };
};
type JournalRowReference = {
  run_id: string;
  event_sequence: number;
  evidence_id: string;
  index: number;
  ordinal: number;
  path: string;
};
type JournalComparison = {
  mode: string;
  policy: string;
  attestations: {
    run_id: string;
    original_record_sha256: string;
    startup_record_sha256: string;
  }[];
  inputEvidence: unknown;
  limitations: string[];
  journals: {
    path: string;
    cli_count: number;
    mcp_count: number;
    cli_multiplicities: (JournalFact & { count: number })[];
    mcp_multiplicities: (JournalFact & { count: number })[];
    row_mapping: { left: JournalRowReference; right: JournalRowReference }[];
  }[];
  variable_group_mappings: {
    cli_address: string;
    mcp_address: string;
    row_count: number;
    signature: {
      label: string | null;
      action: number;
      user: string | null;
      count: number;
    }[];
    cli_rows: JournalRowReference[];
    mcp_rows: JournalRowReference[];
  }[];
  differences: {
    path: string;
    left_path: string;
    right_path: string;
    left: unknown;
    right: unknown;
    own_runs: string[];
    event_sequences: number[];
    validated_by: string;
  }[];
};

const preparationFacts = (): JournalFact[] => [
  {
    address: "0x80000010",
    label: "outside synthetic seed",
    action: 127,
    user: null,
  },
  ...Array.from({ length: 3 }, () => ({
    address: "0x80010000",
    label: "original seed",
    action: 0,
    user: "synthetic author",
  })),
];
const variableGroups = () => [
  {
    address: "VARIABLE:0x23",
    label: "scratch α",
    user: "synthetic analyst",
    copies: 3,
  },
  { address: "VARIABLE:0x4b", label: "memo beta", user: null, copies: 5 },
  {
    address: "VARIABLE:0x7d",
    label: "pinned arbitrary name",
    user: "",
    copies: 2,
  },
];
const currentFacts = (swap = false): JournalFact[] => {
  const groups = variableGroups();
  return [
    ...preparationFacts(),
    {
      address: "0x80010004",
      label: "physical analysis",
      action: 0,
      user: "native fixture",
    },
    {
      address: "EXTERNAL:0x12",
      label: "external symbol",
      action: 0,
      user: null,
    },
    ...groups.flatMap((group, index) =>
      Array.from({ length: group.copies }, () => ({
        address: swap && index < 2 ? groups[1 - index]!.address : group.address,
        label: group.label,
        user: group.user,
        action: 0,
      })),
    ),
  ];
};
const clockedRows = (
  facts: JournalFact[],
  index: number,
): PsxLabelHistoryRow[] =>
  facts.map((fact, ordinal) => ({
    ...fact,
    ordinal,
    modification_time_ms:
      fact.user === null ? null : String(index * 10_000 + ordinal),
  }));

/** Each synthetic import is authenticated to its own independent retained bytes.
 * The real attestor computes its result; this fixture makes no native-provider claim. */
const journalImport = (
  index: number,
  facts = currentFacts(),
  mutate?: (observation: NativeLoadImageObservation) => void,
) => {
  const bytes = psxImportBytes();
  const sourceDigest = psxFixtureSha256(bytes);
  const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
  const profile = createAnalysisProfile(provider, {
    psx_import: { source_sha256: sourceDigest },
    startup_agreement: "psx-observed-import-and-provenance-v3",
    psx_source_provenance: "rea-psx-filebytes-rebind-v2",
    psx_preparation_transaction: "exclusive-top-level-v1",
    instruction_flow_evidence: "decoded-return-before-jump-and-delay-slots-v2",
  });
  const runId = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  const root = `/generated-independent-import/${runId}`;
  const snapshot = join(root, "immutable target 雪.exe");
  const measured = psxAppliedLoadImageObservation(bytes);
  const metadata = measured.psx!.provenance.metadata_preservation;
  const preparation =
    index % 2 === 0 ? preparationFacts().reverse() : preparationFacts();
  metadata.label_history.before = clockedRows(preparation, index);
  metadata.label_history.after = structuredClone(metadata.label_history.before);
  metadata.label_history.removed_before_ordinals = [];
  metadata.label_history.added_after_ordinals = [];
  metadata.label_history.program_journal = "unchanged";
  measured.psx!.current_label_history = clockedRows(
    index % 2 === 0 ? [...facts].reverse() : facts,
    index,
  );
  metadata.original_state_sha256 = psxFixtureSha256(
    Buffer.from(
      JSON.stringify({ runId, before: metadata.label_history.before }),
    ),
  );
  metadata.adapted_state_sha256 = metadata.original_state_sha256;
  mutate?.(measured);
  const original = psxOriginalEvidenceRecordSchema.parse(
    psxFixtureOriginalRecord(
      {
        run_id: runId,
        profile_digest: profile.digest,
        source_sha256: sourceDigest,
      },
      metadata,
    ),
  );
  const originalText = `${JSON.stringify(original)}\n`;
  metadata.original_record_sha256 = psxFixtureSha256(Buffer.from(originalText));
  const before = psxFixtureAgreement({
    commitment: psxFixtureCommitment(snapshot, bytes),
    runId,
    profileDigest: profile.digest,
    selectedClasses: [
      {
        class_name: "psx.PsxLoader",
        role: "loader",
        code_source_url: "file:/generated/psx.jar",
        code_source_relative: "Ghidra/Extensions/renamed-psx/lib/psx.jar",
        code_source_sha256: "b".repeat(64),
        class_resource_url: "jar:file:/generated/psx.jar!/psx/PsxLoader.class",
        enabled: null,
      },
    ],
    languageAssets: [
      {
        relative_path: "Ghidra/Processors/PSX/data/languages/psx.ldefs",
        sha256: "c".repeat(64),
      },
    ],
  }).before;
  before.provenance = structuredClone(measured.psx!.provenance);
  const beforeText = `${JSON.stringify(psxImportObservationSchema.parse(before))}\n`;
  const attested = attestGhidraPsxLoadImage(bytes, sourceDigest, measured);
  if (!attested.ok) throw new Error(attested.error);
  const evidence = createEvidence(
    {
      path: "/generated caller source 雪.exe",
      sha256: sourceDigest,
      format: "ps-x-exe",
      architecture: "mips",
    },
    provider,
    {
      operation: "inspect_native_load_image",
      parameters: {},
      analysisProfile: profile,
      rawResult: jsonValueSchema.parse(measured),
      result: jsonValueSchema.parse(attested.value),
    },
  );
  const binding: JournalBinding = {
    operation: evidence.operation,
    parameters: {},
    sourceDigest,
    selectedProfile: profile,
  };
  const association = {
    event_sequence: index * 7,
    run_id: runId,
    capture: {
      run_id: runId,
      runtime_root: root,
      snapshot: { path: snapshot, sha256: sourceDigest },
      records: Object.fromEntries(
        [
          ["psx-import-before.json", beforeText],
          ["psx-provenance-original.json", originalText],
        ].map(([name, text]) => [
          name!,
          {
            path: join(root, name!),
            text: text!,
            sha256: psxFixtureSha256(Buffer.from(text!)),
          },
        ]),
      ),
    },
  };
  const record = structuredClone(
    publicHelper.publicPsxObservation(evidence, binding, association),
  ) as JournalObservation;
  return { bytes, binding, record };
};
const journalImage = (record: JournalObservation): PsxLoadImage =>
  record.evidence.normalized_result as unknown as PsxLoadImage;
const journalPair = () => ({
  cli: journalImport(1),
  mcp: journalImport(2, currentFacts(true)),
});
const validateJournalPair = (pair: ReturnType<typeof journalPair>) => {
  for (const control of [pair.cli, pair.mcp])
    publicHelper.validatePublicPsxImageImport(
      control.record,
      pair.cli.binding,
      pair.cli.bytes,
    );
};
const compareJournalPair = (pair: ReturnType<typeof journalPair>) =>
  local.assertLocalPsxLiveParity(
    pair.cli.record,
    pair.mcp.record,
    pair.cli.binding,
    pair.cli.bytes,
  );
const rejectJournalPair = (pair: ReturnType<typeof journalPair>) => {
  const before = structuredClone(pair);
  expect(() => compareJournalPair(pair)).toThrow();
  expect(structuredClone(pair)).toEqual(before);
};

const remakeJournalEvidence = (
  original: Evidence,
  changes: Partial<Evidence> = {},
): Evidence => {
  const subject = changes.subject ?? original.subject;
  if (!subject)
    throw new Error("Synthetic journal requires its source subject");
  return createEvidence(
    {
      path: subject.local_path,
      sha256: subject.digest.sha256,
      format: subject.format,
      ...(subject.architecture === null
        ? {}
        : { architecture: subject.architecture }),
    },
    changes.provider ?? original.provider,
    {
      operation: changes.operation ?? original.operation,
      parameters: changes.parameters ?? original.parameters,
      predicateType: original.predicate_type,
      result: changes.normalized_result ?? original.normalized_result,
      rawResult: changes.raw_result ?? original.raw_result,
      analysisProfile: changes.analysis_profile ?? original.analysis_profile!,
      confidence: changes.confidence ?? original.confidence,
      authority: changes.authority ?? original.authority,
      environment: changes.environment ?? original.environment,
      limitations: changes.limitations ?? original.limitations,
      locations: changes.locations ?? original.locations,
      evidenceLinks: changes.evidence_links ?? original.evidence_links,
    },
  );
};
const retainedValue = (record: JournalObservation, path: string): unknown =>
  path
    .replaceAll(/\[(\d+)\]/gu, ".$1")
    .split(".")
    .reduce<unknown>((value, key) => {
      if (value === null || typeof value !== "object")
        throw new Error(`Missing retained path ${path}`);
      return (value as Record<string, unknown>)[key];
    }, journalImage(record));
const assertRowReference = (
  reference: JournalRowReference,
  record: JournalObservation,
  journalPath: string,
) => {
  expect(reference).toEqual({
    run_id: record.run_id,
    event_sequence: record.event_sequence,
    evidence_id: record.evidence.evidence_id,
    index: reference.index,
    ordinal: reference.ordinal,
    path: `${journalPath}[${reference.index}]`,
  });
  const row = retainedValue(record, reference.path) as PsxLabelHistoryRow;
  expect(row.ordinal).toBe(reference.ordinal);
};
const assertJournalReport = (
  report: JournalComparison,
  pair: ReturnType<typeof journalPair>,
) => {
  expect(report.journals).toHaveLength(3);
  for (const journal of report.journals) {
    const cliRows = retainedValue(
      pair.cli.record,
      journal.path,
    ) as PsxLabelHistoryRow[];
    const mcpRows = retainedValue(
      pair.mcp.record,
      journal.path,
    ) as PsxLabelHistoryRow[];
    expect(journal.cli_count).toBe(cliRows.length);
    expect(journal.mcp_count).toBe(mcpRows.length);
    expect(journal.row_mapping).toHaveLength(cliRows.length);
    expect(
      journal.row_mapping.map(({ left }) => left.index).sort((a, b) => a - b),
    ).toEqual(cliRows.map((_, index) => index));
    expect(
      journal.row_mapping.map(({ right }) => right.index).sort((a, b) => a - b),
    ).toEqual(mcpRows.map((_, index) => index));
    for (const { left, right } of journal.row_mapping) {
      assertRowReference(left, pair.cli.record, journal.path);
      assertRowReference(right, pair.mcp.record, journal.path);
      const leftRow = retainedValue(
        pair.cli.record,
        left.path,
      ) as PsxLabelHistoryRow;
      const rightRow = retainedValue(
        pair.mcp.record,
        right.path,
      ) as PsxLabelHistoryRow;
      for (const field of ["label", "action", "user"] as const)
        expect(leftRow[field]).toEqual(rightRow[field]);
      for (const field of [
        "address",
        "ordinal",
        "modification_time_ms",
      ] as const)
        if (leftRow[field] !== rightRow[field])
          expect(report.differences).toContainEqual(
            expect.objectContaining({
              left_path: `${left.path}.${field}`,
              right_path: `${right.path}.${field}`,
              left: leftRow[field],
              right: rightRow[field],
            }),
          );
    }
    for (const [rows, multiplicities] of [
      [cliRows, journal.cli_multiplicities],
      [mcpRows, journal.mcp_multiplicities],
    ] as const) {
      expect(multiplicities.reduce((sum, item) => sum + item.count, 0)).toBe(
        rows.length,
      );
      for (const item of multiplicities)
        expect(item.count).toBe(
          rows.filter(
            (row) =>
              row.address === item.address &&
              row.label === item.label &&
              row.action === item.action &&
              row.user === item.user,
          ).length,
        );
    }
    for (const [index, row] of cliRows.entries())
      for (const field of ["ordinal", "modification_time_ms"] as const)
        if (row[field] !== mcpRows[index]![field])
          expect(report.differences).toContainEqual(
            expect.objectContaining({
              left_path: `${journal.path}[${index}].${field}`,
              right_path: `${journal.path}[${index}].${field}`,
              left: row[field],
              right: mcpRows[index]![field],
            }),
          );
  }
  for (const difference of report.differences) {
    expect(difference.left).toEqual(
      retainedValue(pair.cli.record, difference.left_path),
    );
    expect(difference.right).toEqual(
      retainedValue(pair.mcp.record, difference.right_path),
    );
    expect(difference.own_runs).toEqual([
      pair.cli.record.run_id,
      pair.mcp.record.run_id,
    ]);
    expect(difference.event_sequences).toEqual([
      pair.cli.record.event_sequence,
      pair.mcp.record.event_sequence,
    ]);
    expect(difference.validated_by.length).toBeGreaterThan(0);
  }
};

describe("R17 independent import journal evidence", () => {
  it("authenticates whole ADD-group swaps and retains lossless rows, multiplicities and limitations", () => {
    const pair = journalPair();
    const before = structuredClone(pair);
    validateJournalPair(pair);
    const report = compareJournalPair(pair);
    expect(structuredClone(pair)).toEqual(before);
    expect(report.mode).toBe("local-independent-native-image");
    expect(report.policy).toBe("local-variable-add-journal-permutation-v1");
    expect(report.inputEvidence).toEqual([pair.cli.record, pair.mcp.record]);
    expect(report.attestations).toEqual(
      [pair.cli, pair.mcp].map(({ record }) => ({
        run_id: record.run_id,
        original_record_sha256:
          record.capture.records["psx-provenance-original.json"]!.sha256,
        startup_record_sha256:
          record.capture.records["psx-import-before.json"]!.sha256,
      })),
    );
    expect(report.limitations).toEqual([
      "Independent imports do not establish equal event chronology.",
      "VARIABLE addresses are per-import database keys; this comparison does not establish equal underlying variable storage or function ownership.",
      "Whole-group ADD-history permutation does not establish deterministic analyzer scheduling.",
      "Duplicate occurrence pairing is lossless comparison bookkeeping, not identification of corresponding native events.",
    ]);
    expect(report.variable_group_mappings).toHaveLength(2);
    for (const field of [
      "original_state_sha256",
      "adapted_state_sha256",
      "original_record_sha256",
    ])
      expect(report.differences).toContainEqual(
        expect.objectContaining({
          left_path: `observations.psx.provenance.metadata_preservation.${field}`,
          right_path: `observations.psx.provenance.metadata_preservation.${field}`,
        }),
      );
    for (const [index, group] of variableGroups().slice(0, 2).entries()) {
      const mapping = report.variable_group_mappings.find(
        (item) => item.cli_address === group.address,
      )!;
      expect(mapping).toEqual(
        expect.objectContaining({
          cli_address: group.address,
          mcp_address: variableGroups()[1 - index]!.address,
          row_count: group.copies,
          signature: [
            {
              label: group.label,
              action: 0,
              user: group.user,
              count: group.copies,
            },
          ],
        }),
      );
      for (const [references, record, address] of [
        [mapping.cli_rows, pair.cli.record, mapping.cli_address],
        [mapping.mcp_rows, pair.mcp.record, mapping.mcp_address],
      ] as const) {
        expect(references).toHaveLength(group.copies);
        for (const reference of references) {
          assertRowReference(
            reference,
            record,
            "observations.psx.current_label_history",
          );
          expect(retainedValue(record, `${reference.path}.address`)).toBe(
            address,
          );
        }
      }
    }
    assertJournalReport(report, pair);
    expect(() =>
      publicHelper.assertPublicPsxLiveParity(
        pair.cli.record,
        pair.mcp.record,
        pair.cli.binding,
        pair.cli.bytes,
      ),
    ).toThrow();
    expect(structuredClone(pair)).toEqual(before);
  });

  it("pins identical same-address groups before testing uniqueness of changed groups", () => {
    const pinned = ["VARIABLE:0x81", "VARIABLE:0x91"].flatMap((address) =>
      Array.from({ length: 2 }, () => ({
        address,
        label: null,
        action: 0,
        user: null,
      })),
    );
    const pair = {
      cli: journalImport(1, [...currentFacts(), ...pinned]),
      mcp: journalImport(2, [...currentFacts(true), ...pinned]),
    };
    validateJournalPair(pair);
    const report = compareJournalPair(pair);
    expect(report.variable_group_mappings).toHaveLength(2);
    expect(
      report.variable_group_mappings.some(({ cli_address }) =>
        pinned.some(({ address }) => cli_address === address),
      ),
    ).toBe(false);
    assertJournalReport(report, pair);
  });

  it("retains policy limits even when only clocks and enumeration differ", () => {
    const pair = { cli: journalImport(1), mcp: journalImport(2) };
    const before = structuredClone(pair);
    validateJournalPair(pair);
    const report = compareJournalPair(pair);
    expect(report.variable_group_mappings).toEqual([]);
    expect(report.limitations).toHaveLength(4);
    assertJournalReport(report, pair);
    expect(structuredClone(pair)).toEqual(before);
  });
});

type JournalFactsControl = {
  name: string;
  left?: () => JournalFact[];
  right: () => JournalFact[];
};
const changeFirstVariable = (changes: Partial<JournalFact>) => {
  const rows = currentFacts(true);
  const index = rows.findIndex(
    (row) => row.label === variableGroups()[0]!.label,
  );
  rows[index] = { ...rows[index]!, ...changes };
  return rows;
};
const mappedVariableKeys = (keys: string[], swap: boolean) =>
  currentFacts(swap).map((row) => ({
    ...row,
    address:
      keys[
        variableGroups().findIndex((group) => group.address === row.address)
      ] ?? row.address,
  }));
const ambiguousFacts = (swap: boolean): JournalFact[] =>
  ["VARIABLE:0xa1", "VARIABLE:0xa2", "VARIABLE:0xb1", "VARIABLE:0xb2"].flatMap(
    (address, index) =>
      Array.from({ length: 2 }, () => ({
        address,
        label:
          index < 2 !== swap
            ? "ambiguous left signature"
            : "ambiguous right signature",
        action: 0,
        user: null,
      })),
  );
const journalFactsControls: JournalFactsControl[] = [
  {
    name: "altered label",
    right: () => changeFirstVariable({ label: "altered original name" }),
  },
  { name: "altered action", right: () => changeFirstVariable({ action: 2 }) },
  {
    name: "altered user",
    right: () => changeFirstVariable({ user: "different analyst" }),
  },
  {
    name: "null becoming empty user",
    right: () => {
      const rows = currentFacts(true);
      const index = rows.findIndex(
        (row) => row.label === variableGroups()[1]!.label,
      );
      rows[index] = { ...rows[index]!, user: "" };
      return rows;
    },
  },
  {
    name: "added row",
    right: () => [...currentFacts(true), currentFacts(true).at(-1)!],
  },
  { name: "dropped row", right: () => currentFacts(true).slice(0, -1) },
  {
    name: "equal total rows but unequal duplicate counts",
    right: () => {
      const rows = currentFacts(true);
      const index = rows.findIndex(
        (row) => row.label === variableGroups()[0]!.label,
      );
      rows[index] = {
        ...rows.find((row) => row.label === variableGroups()[1]!.label)!,
      };
      return rows;
    },
  },
  {
    name: "label swap without the whole counted signature",
    right: () =>
      currentFacts().map((row) => {
        const index = variableGroups().findIndex(
          (group) => group.address === row.address,
        );
        return index < 0 || index > 1
          ? row
          : { ...row, label: variableGroups()[1 - index]!.label };
      }),
  },
  {
    name: "split group retaining every address key",
    right: () => changeFirstVariable({ address: variableGroups()[2]!.address }),
  },
  {
    name: "merged groups losing an address key",
    right: () =>
      currentFacts(true).map((row) => ({
        ...row,
        address:
          row.address === variableGroups()[0]!.address
            ? variableGroups()[1]!.address
            : row.address,
      })),
  },
  {
    name: "changed address key set",
    right: () => changeFirstVariable({ address: "VARIABLE:0xc3" }),
  },
  {
    name: "ambiguous remaining whole-group signatures",
    left: () => ambiguousFacts(false),
    right: () => ambiguousFacts(true),
  },
  {
    name: "matching mixed ADD and RENAME signatures",
    left: () =>
      currentFacts().map((row) => ({
        ...row,
        action: row.label === variableGroups()[0]!.label ? 2 : row.action,
      })),
    right: () =>
      currentFacts(true).map((row) => ({
        ...row,
        action: row.label === variableGroups()[0]!.label ? 2 : row.action,
      })),
  },
  ...[
    ["RAM", ["0x80011000", "0x80011004"]],
    ["external", ["EXTERNAL:0x21", "EXTERNAL:0x22"]],
    ["leading-zero VARIABLE", ["VARIABLE:0x023", "VARIABLE:0x04b"]],
    ["uppercase VARIABLE hex", ["VARIABLE:0xA3", "VARIABLE:0xB4"]],
    ["prefix-only VARIABLE", ["VARIABLE:0x23suffix", "VARIABLE:0x4bsuffix"]],
    ["missing VARIABLE hex prefix", ["VARIABLE:23", "VARIABLE:4b"]],
    [
      "oversized VARIABLE",
      ["VARIABLE:0x10000000000000000", "VARIABLE:0x20000000000000000"],
    ],
    ["trailing-newline VARIABLE", ["VARIABLE:0x23\n", "VARIABLE:0x4b\n"]],
  ].map(([name, keys]) => ({
    name: `${name} remapping`,
    left: () => mappedVariableKeys(keys as string[], false),
    right: () => mappedVariableKeys(keys as string[], true),
  })),
];

describe("R17 whole journal group refusal", () => {
  it.each(journalFactsControls)(
    "rejects $name after both real own-import validations",
    ({ left, right }) => {
      const pair = {
        cli: journalImport(1, left?.() ?? currentFacts()),
        mcp: journalImport(2, right()),
      };
      validateJournalPair(pair);
      rejectJournalPair(pair);
    },
  );

  it("rejects unequal preparation multiplicities even when each own before/after is valid", () => {
    const pair = journalPair();
    pair.mcp = journalImport(2, currentFacts(true), (measured) => {
      const journal =
        measured.psx!.provenance.metadata_preservation.label_history;
      journal.before[0]!.label = "different original preparation fact";
      journal.after = structuredClone(journal.before);
    });
    validateJournalPair(pair);
    rejectJournalPair(pair);
  });
});

const mutateJournalImage = (
  pair: ReturnType<typeof journalPair>,
  mutate: (image: PsxLoadImage) => void,
) => {
  const image = structuredClone(journalImage(pair.mcp.record));
  mutate(image);
  pair.mcp.record.evidence = remakeJournalEvidence(pair.mcp.record.evidence, {
    normalized_result: jsonValueSchema.parse(image),
  });
};
const journalIntegrityControls: {
  name: string;
  mutate: (image: PsxLoadImage) => void;
}[] = [
  {
    name: "negative current ordinal",
    mutate: (image) => {
      image.observations.psx!.current_label_history[0]!.ordinal = -1;
    },
  },
  {
    name: "duplicated current ordinal",
    mutate: (image) => {
      image.observations.psx!.current_label_history[1]!.ordinal = 0;
    },
  },
  {
    name: "invalid preparation ordinal",
    mutate: (image) => {
      image.observations.psx!.provenance.metadata_preservation.label_history.after[0]!.ordinal = 1;
    },
  },
  {
    name: "malformed clock",
    mutate: (image) => {
      image.observations.psx!.current_label_history[0]!.modification_time_ms =
        "not-a-clock";
    },
  },
  {
    name: "clock outside signed Java long",
    mutate: (image) => {
      image.observations.psx!.current_label_history[0]!.modification_time_ms =
        "9223372036854775808";
    },
  },
  {
    name: "tampered removed delta",
    mutate: (image) => {
      image.observations.psx!.provenance.metadata_preservation.label_history.removed_before_ordinals =
        [0];
    },
  },
  {
    name: "tampered added delta",
    mutate: (image) => {
      image.observations.psx!.provenance.metadata_preservation.label_history.added_after_ordinals =
        [1];
    },
  },
  {
    name: "tampered journal scope",
    mutate: (image) => {
      Object.assign(
        image.observations.psx!.provenance.metadata_preservation.label_history,
        { scope: "payload-only" },
      );
    },
  },
  {
    name: "static source digest",
    mutate: (image) => {
      image.observations.source_files[0]!.modified_sha256 = "f".repeat(64);
    },
  },
  {
    name: "static mapping source offset",
    mutate: (image) => {
      image.observations.mappings[0]!.file_offset = 2049;
    },
  },
  {
    name: "static mapping bytes",
    mutate: (image) => {
      image.observations.mappings[0]!.sha256 = "e".repeat(64);
    },
  },
  {
    name: "static entry",
    mutate: (image) => {
      image.entry.declared_pc = "0x80010004";
    },
  },
  {
    name: "coverage completeness",
    mutate: (image) => {
      image.coverage.complete = false;
    },
  },
  {
    name: "source provenance",
    mutate: (image) => {
      image.observations.psx!.provenance.source_sha256 = "d".repeat(64);
    },
  },
  {
    name: "operational state",
    mutate: (image) => {
      image.observations.psx!.provenance.metadata_preservation.adapted_operational_state_sha256 =
        "a".repeat(64);
    },
  },
  {
    name: "immutable declaration",
    mutate: (image) => {
      image.declarations.initial_gp = "0x1";
    },
  },
  {
    name: "unrecognized image field",
    mutate: (image) => {
      Object.assign(image, {
        unsupported_projection_field: "must remain visible",
      });
    },
  },
];
describe("R17 strict image integrity before journal projection", () => {
  it.each(journalIntegrityControls)(
    "rejects $name with freshly recomputed Evidence identity",
    ({ mutate }) => {
      const pair = journalPair();
      validateJournalPair(pair);
      mutateJournalImage(pair, mutate);
      expect(() =>
        publicHelper.validatePublicPsxImageImport(
          pair.mcp.record,
          pair.cli.binding,
          pair.cli.bytes,
        ),
      ).toThrow();
      rejectJournalPair(pair);
    },
  );

  it("rejects one otherwise valid immutable image difference after a valid group permutation", () => {
    const pair = journalPair();
    pair.mcp = journalImport(2, currentFacts(true), (measured) => {
      measured.source_files[0]!.name =
        "different synthetic FileBytes display name";
    });
    validateJournalPair(pair);
    rejectJournalPair(pair);
  });
});

const rehashCapturedRecord = (
  record: JournalObservation,
  name: string,
  mutate: (value: Record<string, unknown>) => void,
) => {
  const raw = record.capture.records[name]!;
  const value = JSON.parse(raw.text) as Record<string, unknown>;
  mutate(value);
  raw.text = `${JSON.stringify(value)}\n`;
  raw.sha256 = psxFixtureSha256(Buffer.from(raw.text));
};
type JournalCaptureControl = {
  name: string;
  mutate: (pair: ReturnType<typeof journalPair>) => void;
};
const journalCaptureControls: JournalCaptureControl[] = [
  {
    name: "missing original bytes",
    mutate: ({ mcp }) => {
      delete mcp.record.capture.records["psx-provenance-original.json"];
    },
  },
  {
    name: "missing startup bytes",
    mutate: ({ mcp }) => {
      delete mcp.record.capture.records["psx-import-before.json"];
    },
  },
  {
    name: "changed original raw bytes with old digest",
    mutate: ({ mcp }) => {
      mcp.record.capture.records["psx-provenance-original.json"]!.text += " ";
    },
  },
  {
    name: "changed startup raw bytes with old digest",
    mutate: ({ mcp }) => {
      mcp.record.capture.records["psx-import-before.json"]!.text += " ";
    },
  },
  {
    name: "wrong original digest",
    mutate: ({ mcp }) => {
      mcp.record.capture.records["psx-provenance-original.json"]!.sha256 =
        "a".repeat(64);
    },
  },
  {
    name: "wrong startup digest",
    mutate: ({ mcp }) => {
      mcp.record.capture.records["psx-import-before.json"]!.sha256 = "b".repeat(
        64,
      );
    },
  },
  {
    name: "captured record outside owned root",
    mutate: ({ mcp }) => {
      mcp.record.capture.records["psx-import-before.json"]!.path =
        "/different/psx-import-before.json";
    },
  },
  {
    name: "wrong capture run",
    mutate: ({ mcp }) => {
      mcp.record.capture.run_id = "00000000-0000-4000-8000-000000000099";
    },
  },
  {
    name: "wrong startup run with recomputed raw digest",
    mutate: ({ mcp }) =>
      rehashCapturedRecord(mcp.record, "psx-import-before.json", (value) => {
        (value.commitment as Record<string, unknown>).run_id =
          "00000000-0000-4000-8000-000000000099";
      }),
  },
  {
    name: "wrong original source with recomputed raw digest",
    mutate: ({ mcp }) =>
      rehashCapturedRecord(
        mcp.record,
        "psx-provenance-original.json",
        (value) => {
          (value.commitment as Record<string, unknown>).source_sha256 =
            "c".repeat(64);
        },
      ),
  },
  {
    name: "wrong startup profile with recomputed raw digest",
    mutate: ({ mcp }) =>
      rehashCapturedRecord(mcp.record, "psx-import-before.json", (value) => {
        (value.commitment as Record<string, unknown>).profile_digest =
          "d".repeat(64);
      }),
  },
  {
    name: "wrong snapshot source",
    mutate: ({ mcp }) => {
      mcp.record.capture.snapshot.sha256 = "e".repeat(64);
    },
  },
  {
    name: "wrong source bytes",
    mutate: ({ cli }) => {
      cli.bytes[2050] = cli.bytes[2050]! ^ 1;
    },
  },
  {
    name: "wrong source binding",
    mutate: ({ cli }) => {
      cli.binding.sourceDigest = "f".repeat(64);
    },
  },
  {
    name: "wrong selected profile",
    mutate: ({ cli }) => {
      cli.binding.selectedProfile = createAnalysisProfile(
        { id: "ghidra", name: "Ghidra", version: "12.1.4" },
        { wrong_profile: true },
      );
    },
  },
  {
    name: "cached mode",
    mutate: ({ mcp }) => {
      mcp.record.mode = "mcp-cache";
    },
  },
  {
    name: "cached Evidence marker",
    mutate: ({ mcp }) => {
      mcp.record.evidence = remakeJournalEvidence(mcp.record.evidence, {
        limitations: [
          ...mcp.record.evidence.limitations,
          publicHelper.publicPsxSnapshotLimitation,
        ],
      });
    },
  },
  {
    name: "absent native run association",
    mutate: ({ mcp }) => {
      mcp.record.run_id = "";
    },
  },
  {
    name: "missing retained event association",
    mutate: ({ mcp }) => {
      mcp.record.event_sequence = 0;
    },
  },
  {
    name: "nonintegral retained event association",
    mutate: ({ mcp }) => {
      mcp.record.event_sequence = 1.5;
    },
  },
];
describe("R17 own-run fixed-record authentication", () => {
  it.each(journalCaptureControls)(
    "rejects $name without changing inputs",
    ({ mutate }) => {
      const pair = journalPair();
      validateJournalPair(pair);
      mutate(pair);
      rejectJournalPair(pair);
    },
  );

  it("refuses independently valid captures that reuse the same native run", () => {
    const pair = {
      cli: journalImport(1),
      mcp: journalImport(1, currentFacts(true)),
    };
    validateJournalPair(pair);
    rejectJournalPair(pair);
  });

  it("keeps independently valid differing preparation delta ordinal arrays exact", () => {
    const recreate = (measured: NativeLoadImageObservation) => {
      const metadata = measured.psx!.provenance.metadata_preservation;
      const journal = metadata.label_history;
      const removed = journal.before.findLastIndex(
        (row) => row.label === "original seed",
      );
      journal.after = journal.before
        .filter((_, index) => index !== removed)
        .map((row, ordinal) => ({ ...row, ordinal }));
      journal.after.push({
        ordinal: journal.after.length,
        address: "0x80010000",
        label: "recreated synthetic seed",
        action: 0,
        user: "synthetic author",
        modification_time_ms: "45678",
      });
      journal.removed_before_ordinals = [removed];
      journal.added_after_ordinals = [journal.after.length - 1];
      journal.program_journal = "recreated-at-payload-addresses";
      metadata.adapted_state_sha256 = "f".repeat(64);
    };
    const pair = {
      cli: journalImport(1, currentFacts(), recreate),
      mcp: journalImport(2, currentFacts(true), recreate),
    };
    validateJournalPair(pair);
    const left = journalImage(pair.cli.record).observations.psx!.provenance
      .metadata_preservation.label_history;
    const right = journalImage(pair.mcp.record).observations.psx!.provenance
      .metadata_preservation.label_history;
    expect(left.removed_before_ordinals).not.toEqual(
      right.removed_before_ordinals,
    );
    rejectJournalPair(pair);
  });
});

const journalMetadataControls: {
  name: string;
  changes: (evidence: Evidence) => Partial<Evidence>;
}[] = [
  {
    name: "provider name",
    changes: (evidence) => {
      const profile = evidence.analysis_profile!;
      const provider = {
        ...profile.provider,
        name: "Different provider display",
      };
      return {
        provider,
        analysis_profile: createAnalysisProfile(provider, profile.parameters),
      };
    },
  },
  {
    name: "provider version",
    changes: (evidence) => {
      const profile = evidence.analysis_profile!;
      const provider = { ...profile.provider, version: "different version" };
      return {
        provider,
        analysis_profile: createAnalysisProfile(provider, profile.parameters),
      };
    },
  },
  {
    name: "subject path",
    changes: (evidence) => ({
      subject: {
        ...evidence.subject!,
        local_path: "/different caller source.exe",
      },
    }),
  },
  { name: "confidence", changes: () => ({ confidence: "derived" }) },
  { name: "authority", changes: () => ({ authority: "analyst-inference" }) },
  {
    name: "environment",
    changes: () => ({
      environment: {
        id: "controlled different environment",
        platform: "synthetic",
        architecture: "mips",
        isolation: "process",
      },
    }),
  },
  {
    name: "limitation",
    changes: (evidence) => ({
      limitations: [...evidence.limitations, "Additional differing limitation"],
    }),
  },
  {
    name: "location",
    changes: () => ({
      locations: [{ kind: "address", address: "0x80010004" }],
    }),
  },
  {
    name: "evidence link",
    changes: () => ({ evidence_links: ["ev_" + "a".repeat(64)] }),
  },
  {
    name: "operation",
    changes: () => ({ operation: "inspect_native_instruction" }),
  },
  { name: "parameters", changes: () => ({ parameters: { unexpected: true } }) },
];
describe("R17 immutable Evidence metadata and replay", () => {
  it.each(journalMetadataControls)(
    "rejects differing $name with valid Evidence content identity",
    ({ changes }) => {
      const pair = journalPair();
      validateJournalPair(pair);
      pair.mcp.record.evidence = remakeJournalEvidence(
        pair.mcp.record.evidence,
        changes(pair.mcp.record.evidence),
      );
      rejectJournalPair(pair);
    },
  );

  it("keeps snapshot replay strict for clocks, ordinals and VARIABLE keys", () => {
    const pair = journalPair();
    validateJournalPair(pair);
    const replay = structuredClone(pair.cli.record);
    replay.mode = "mcp-cache";
    replay.evidence = remakeJournalEvidence(replay.evidence, {
      limitations: [
        ...replay.evidence.limitations,
        publicHelper.publicPsxSnapshotLimitation,
      ],
    });
    publicHelper.assertPublicPsxMcpReplay(
      replay,
      pair.cli.record,
      pair.cli.binding,
    );
    for (const field of [
      "modification_time_ms",
      "ordinal",
      "address",
    ] as const) {
      const changed = structuredClone(replay);
      const image = journalImage(changed);
      const row = image.observations.psx!.current_label_history.find((item) =>
        item.address.startsWith("VARIABLE:"),
      )!;
      if (field === "ordinal") row.ordinal += 1;
      else if (field === "address") row.address = "VARIABLE:0xd4";
      else row.modification_time_ms = "99999";
      changed.evidence = remakeJournalEvidence(changed.evidence, {
        normalized_result: changed.evidence.normalized_result,
      });
      const before = structuredClone(changed);
      expect(() =>
        publicHelper.assertPublicPsxMcpReplay(
          changed,
          pair.cli.record,
          pair.cli.binding,
        ),
      ).toThrow();
      expect(changed).toEqual(before);
    }
  });

  it("delegates non-image entry parity to the unchanged exact public comparison", () => {
    const pair = { cli: journalImport(1), mcp: journalImport(2) };
    const parameters = { address: "0x80010000" };
    const instruction = psxSimulatedOperation(
      "inspect_native_instruction",
      parameters,
    );
    for (const control of [pair.cli, pair.mcp]) {
      control.record.evidence = remakeJournalEvidence(control.record.evidence, {
        operation: "inspect_native_instruction",
        parameters,
        normalized_result: jsonValueSchema.parse(instruction),
        raw_result: jsonValueSchema.parse(instruction),
      });
      control.binding.operation = "inspect_native_instruction";
      control.binding.parameters = parameters;
      control.record.binding = structuredClone(control.binding);
    }
    const before = structuredClone(pair);
    const expected = publicHelper.assertPublicPsxLiveParity(
      pair.cli.record,
      pair.mcp.record,
      pair.cli.binding,
      pair.cli.bytes,
    );
    expect(compareJournalPair(pair)).toEqual(expected);
    expect(structuredClone(pair)).toEqual(before);
    pair.mcp.record.evidence = remakeJournalEvidence(pair.mcp.record.evidence, {
      normalized_result: jsonValueSchema.parse({
        ...(instruction as Record<string, unknown>),
        mnemonic: "different instruction",
      }),
    });
    rejectJournalPair(pair);
  });
});
