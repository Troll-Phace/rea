import { Ajv2020 } from "ajv/dist/2020.js";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { parseEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { err, ok } from "../../../src/domain/result.js";
import { GhidraSessionError } from "../../../src/ghidra/GhidraSessionError.js";
import {
  connectPsxOperationMcp,
  psxAppliedLoadImageObservation,
  psxFixtureSha256,
  psxInstructionFlowBytes,
  psxSimulatedInstruction,
  psxSimulatedOperation,
} from "../../fixtures/ghidraPsxImport.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

type PublicBinding = {
  operation: string;
  parameters: Record<string, unknown>;
  sourceDigest: string;
  selectedProfile: unknown;
};
type PublicObservation = {
  mode: string;
  evidence: Evidence;
  event_sequence: number;
  run_id: string;
};
type LiveExpectations = {
  observe(
    evidence: Evidence,
    binding: PublicBinding,
    association: unknown,
  ): PublicObservation;
  live(binding: PublicBinding): PublicObservation;
  freeze(bindings: PublicBinding[]): unknown;
  observations(): PublicObservation[];
};
const publicVerifier = (await import(
  new URL("../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as {
  createPublicPsxLiveExpectations(): LiveExpectations;
  assertPublicPsxMcpReplay(
    replay: PublicObservation,
    original: PublicObservation,
    binding: PublicBinding,
  ): void;
  selectPublicPsxSnapshotEvidence(
    execution: unknown,
    binding: PublicBinding,
  ): Evidence;
  assertPublicPsxCliExecution(
    evidence: Evidence,
    binding: PublicBinding,
    execution: unknown,
    allocations: unknown[],
  ): unknown;
  publicPsxDigest(text: string): string;
  publicPsxSnapshotLimitation: string;
  publicPsxSnapshotQueries(
    documents: unknown,
  ): [string, Record<string, unknown>][];
  assertPublicPsxSnapshotEntries(
    snapshot: unknown,
    queries: [string, Record<string, unknown>][],
    observations: Evidence[],
    binding: { sourceDigest: string; selectedProfile: unknown },
  ): unknown;
  compilePublicPsxSchemas(catalog: unknown): Map<string, unknown>;
  createPublicPsxContext(input: unknown): unknown;
  capturePublicPsxReply(
    context: unknown,
    reply: unknown,
    operation: string,
    schema: unknown,
    options?: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  assertPublicPsxImageAdmissionRefusal(
    parsed: unknown,
    operation: string,
    parameters: unknown,
    schema: unknown,
  ): unknown;
};

/** Actual SDK/cache producers; the recording bridge is simulated, with no native-host claim. */
const createRetainedSdkEvidenceControl = async () => {
  const harness = await connectPsxOperationMcp();
  try {
    const state = async () =>
      toolContract("binary_session").outputSchema.parse(
        (await harness.mcp.callTool({ name: "binary_session", arguments: {} }))
          .structuredContent,
      ).result;
    const firstState = await state();
    const profile = firstState.analysis_provider_binding!.analysis_profile;
    const bindings = ["0x80010000", "0x80010080"].map((procedure) => ({
      operation: "analyze_function",
      parameters: { procedure },
      sourceDigest: psxFixtureSha256(psxInstructionFlowBytes()),
      selectedProfile: profile,
    }));
    const collection = publicVerifier.createPublicPsxLiveExpectations();
    let sequence = 0;
    const request = async (binding: PublicBinding) => {
      const reply = await harness.mcp.callTool({
        name: binding.operation,
        arguments: binding.parameters,
      });
      if (reply.isError) throw new Error(JSON.stringify(reply));
      const evidence = parseEvidence(reply.structuredContent);
      const current = await state();
      const runId = current.analysis_run!.run_id;
      return collection.observe(evidence, binding, {
        event_sequence: ++sequence,
        run_id: runId,
        capture: {
          run_id: runId,
          runtime_root: harness.fixture.root,
          records: {},
          simulated_bridge: true,
        },
      });
    };
    const first = [];
    for (const binding of bindings) first.push(await request(binding));
    collection.freeze(bindings);
    const beforeRepeat = structuredClone(harness.recording.queries);
    const repeated = [];
    for (const binding of bindings) repeated.push(await request(binding));
    expect(harness.recording.queries).toEqual(beforeRepeat);
    const saved = harness.session.exportAnalysisSnapshot();
    if (!saved.ok) throw saved.error;
    const closed = await harness.mcp.callTool({
      name: "close_binary",
      arguments: {},
    });
    if (closed.isError) throw new Error(JSON.stringify(closed));
    const imported = harness.session.importAnalysisSnapshot(saved.value);
    if (!imported.ok) throw imported.error;
    const opened = await harness.mcp.callTool({
      name: "open_binary",
      arguments: { path: harness.fixture.source, provider_id: "ghidra" },
    });
    if (opened.isError) throw new Error(JSON.stringify(opened));
    const beforeReplay = structuredClone(harness.recording.queries);
    const reopened = [];
    for (const binding of bindings) reopened.push(await request(binding));
    const refused = await harness.mcp.callTool({
      name: "inspect_native_load_image",
      arguments: { document: "forbidden" },
    });
    expect(refused.isError).toBe(true);
    const postNegative = [];
    for (const binding of bindings) postNegative.push(await request(binding));
    expect(harness.recording.queries).toEqual(beforeReplay);
    const text = JSON.stringify(saved.value);
    return {
      harness,
      bindings,
      collection,
      first,
      repeated,
      reopened,
      postNegative,
      saved: saved.value,
      execution: {
        mode: "snapshot-evidence",
        snapshot: {
          path: join(harness.fixture.root, "owned-sdk-snapshot.json"),
          text,
          sha256: publicVerifier.publicPsxDigest(text),
        },
        target: saved.value.target,
      },
    };
  } catch (error) {
    await harness.close();
    throw error;
  }
};

describe("P5-R4 actual SDK live ownership and persisted function Evidence", () => {
  it("retains first live records across real same-session cache, reopen and post-refusal observations without dispatch (simulated bridge)", async () => {
    const control = await createRetainedSdkEvidenceControl();
    try {
      const { bindings, collection, first, repeated, reopened, postNegative } =
        control;
      expect(collection.observations()).toHaveLength(8);
      for (const [index, binding] of bindings.entries()) {
        const original = first[index]!;
        expect(original.mode).toBe("native");
        expect(collection.live(binding)).toBe(original);
        expect(Object.isFrozen(original.evidence)).toBe(true);
        for (const records of [repeated, reopened, postNegative]) {
          const replay = records[index]!;
          expect(replay.mode).toBe("mcp-cache");
          publicVerifier.assertPublicPsxMcpReplay(replay, original, binding);
          const removed = structuredClone(replay);
          removed.evidence.limitations = removed.evidence.limitations.filter(
            (value) => value !== publicVerifier.publicPsxSnapshotLimitation,
          );
          expect(() =>
            publicVerifier.assertPublicPsxMcpReplay(removed, original, binding),
          ).toThrow();
        }
        expect(collection.live(binding).evidence).toEqual(original.evidence);
        expect(() =>
          collection.live({
            ...binding,
            parameters: { procedure: "0x80010004" },
          }),
        ).toThrow("Missing exact first live");
        expect(() =>
          collection.live({ ...binding, sourceDigest: "0".repeat(64) }),
        ).toThrow("Missing exact first live");
      }
    } finally {
      await control.harness.close();
    }
    expect(control.harness.recording.counts().closes).toBe(
      control.harness.recording.counts().clients,
    );
  });
});

describe("P5-R4 actual SDK unchanged persisted function hits", () => {
  it("selects both unchanged original function records through the production selector and admits zero-allocation CLI Evidence hits (simulated bridge)", async () => {
    const control = await createRetainedSdkEvidenceControl();
    try {
      for (const [index, binding] of control.bindings.entries()) {
        const execution = {
          ...control.execution,
          original: control.first[index]!,
        };
        const persisted = publicVerifier.selectPublicPsxSnapshotEvidence(
          execution,
          binding,
        );
        expect(persisted).toEqual(control.first[index]!.evidence);
        expect(persisted.limitations).not.toContain(
          publicVerifier.publicPsxSnapshotLimitation,
        );
        expect(
          publicVerifier.assertPublicPsxCliExecution(
            persisted,
            binding,
            execution,
            [],
          ),
        ).toMatchObject({
          mode: "snapshot-evidence",
          original_evidence_id: persisted.evidence_id,
        });
        expect(() =>
          publicVerifier.assertPublicPsxCliExecution(
            control.reopened[index]!.evidence,
            binding,
            execution,
            [],
          ),
        ).toThrow("exact original persisted Evidence");
        expect(() =>
          publicVerifier.assertPublicPsxCliExecution(
            persisted,
            binding,
            { ...execution, original: control.reopened[index]! },
            [],
          ),
        ).toThrow("original live owner");
        expect(() =>
          publicVerifier.assertPublicPsxCliExecution(
            persisted,
            binding,
            execution,
            [{ run_id: "unexpected-native" }],
          ),
        ).toThrow("unexpectedly allocated");
        expect(() =>
          publicVerifier.assertPublicPsxCliExecution(
            persisted,
            binding,
            { mode: "native" },
            [],
          ),
        ).toThrow("owned native runtime");
        expect(() =>
          publicVerifier.assertPublicPsxCliExecution(
            persisted,
            binding,
            undefined,
            [],
          ),
        ).toThrow("explicit execution mode");
      }
    } finally {
      await control.harness.close();
    }
  });
});

describe("P5-R4 actual SDK persisted function refusal controls", () => {
  it("denies persisted misses, changed bytes, query and selected profile without replacing retained Evidence (simulated bridge)", async () => {
    const control = await createRetainedSdkEvidenceControl();
    try {
      const binding = control.bindings[0]!;
      const original = control.first[0]!;
      const before = JSON.stringify(original);
      const execution = { ...control.execution, original };
      expect(() =>
        publicVerifier.selectPublicPsxSnapshotEvidence(
          {
            ...execution,
            snapshot: { ...execution.snapshot, sha256: "0".repeat(64) },
          },
          binding,
        ),
      ).toThrow();
      expect(() =>
        publicVerifier.selectPublicPsxSnapshotEvidence(execution, {
          ...binding,
          parameters: { procedure: "0x80010004" },
        }),
      ).toThrow("hit missing");
      expect(() =>
        publicVerifier.selectPublicPsxSnapshotEvidence(execution, {
          ...binding,
          sourceDigest: "0".repeat(64),
        }),
      ).toThrow();
      expect(() =>
        publicVerifier.selectPublicPsxSnapshotEvidence(execution, {
          ...binding,
          selectedProfile: control.saved.binding.analysis_profile && {
            ...control.saved.binding.analysis_profile,
            digest: "0".repeat(64),
          },
        }),
      ).toThrow();
      expect(JSON.stringify(original)).toBe(before);
      expect(control.collection.live(binding)).toBe(original);
    } finally {
      await control.harness.close();
    }
  });
});

const connectDeclaredProgramMcp = async (declaredDocument: string) => {
  return connectPsxOperationMcp(async (operation, parameters) => {
    if (operation === "list_documents") return ok([declaredDocument]);
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
  });
};

describe("P5-R3 actual SDK explicitly scoped snapshot population", () => {
  it("observes the declared Program, retains omitted selectors, and replays exact four scoped queries without dispatch (simulated bridge)", async () => {
    const declaredDocument = "Declared Program 雪.v2";
    const harness = await connectDeclaredProgramMcp(declaredDocument);
    const request = async (
      operation: string,
      parameters: Record<string, unknown> = {},
    ) => {
      const reply = await harness.mcp.callTool({
        name: operation,
        arguments: parameters,
      });
      if (reply.isError) throw new Error(JSON.stringify(reply));
      return parseEvidence(reply.structuredContent);
    };
    try {
      const omitted = [
        await request("inspect_native_instruction", { address: "0x80010008" }),
        await request("resolve_native_call_targets", { address: "0x80010034" }),
      ];
      const originalBytes = JSON.stringify(omitted);
      const initial = harness.session.exportAnalysisSnapshot();
      if (!initial.ok) throw initial.error;
      expect(initial.value.entries).toHaveLength(0);
      expect(initial.value.evidence_bundle.records).toEqual(
        expect.arrayContaining(omitted),
      );
      const discovery = await request("list_documents");
      expect(discovery.normalized_result).toEqual([declaredDocument]);
      const queries = publicVerifier.publicPsxSnapshotQueries(
        discovery.normalized_result,
      );
      const populated: Evidence[] = [];
      for (const [operation, parameters] of queries)
        populated.push(await request(operation, parameters));
      expect(populated[1]?.normalized_result).toEqual(
        omitted[0]?.normalized_result,
      );
      expect(populated[2]?.normalized_result).toEqual(
        omitted[1]?.normalized_result,
      );
      expect(populated[1]?.evidence_id).not.toBe(omitted[0]?.evidence_id);
      expect(populated[2]?.evidence_id).not.toBe(omitted[1]?.evidence_id);
      const saved = harness.session.exportAnalysisSnapshot();
      if (!saved.ok) throw saved.error;
      const binding = {
        sourceDigest: psxFixtureSha256(psxInstructionFlowBytes()),
        selectedProfile: populated[0]!.analysis_profile,
      };
      publicVerifier.assertPublicPsxSnapshotEntries(
        saved.value,
        queries,
        populated,
        binding,
      );
      expect(saved.value.entries).toHaveLength(4);
      expect(
        saved.value.entries.map(({ operation, parameters }) => [
          operation,
          parameters,
        ]),
      ).toEqual(expect.arrayContaining(queries));
      expect(saved.value.evidence_bundle.records).toEqual(
        expect.arrayContaining(omitted),
      );
      const wrongQueries = publicVerifier.publicPsxSnapshotQueries([
        "Unobserved Program",
      ]);
      expect(() =>
        publicVerifier.assertPublicPsxSnapshotEntries(
          saved.value,
          wrongQueries,
          populated,
          binding,
        ),
      ).toThrow();
      const omittedQueries = structuredClone(queries);
      omittedQueries[1]![1] = { address: "0x80010008" };
      const omittedObservation = [...populated];
      omittedObservation[1] = omitted[0]!;
      expect(() =>
        publicVerifier.assertPublicPsxSnapshotEntries(
          saved.value,
          omittedQueries,
          omittedObservation,
          binding,
        ),
      ).toThrow("exact query missing");
      const missing = structuredClone(saved.value);
      missing.entries = missing.entries.filter(
        ({ operation }) => operation !== "resolve_native_call_targets",
      );
      expect(() =>
        publicVerifier.assertPublicPsxSnapshotEntries(
          missing,
          queries,
          populated,
          binding,
        ),
      ).toThrow("exact query missing");
      const closed = await harness.mcp.callTool({
        name: "close_binary",
        arguments: {},
      });
      if (closed.isError) throw new Error(JSON.stringify(closed));
      const imported = harness.session.importAnalysisSnapshot(saved.value);
      if (!imported.ok) throw imported.error;
      const opened = await harness.mcp.callTool({
        name: "open_binary",
        arguments: { path: harness.fixture.source, provider_id: "ghidra" },
      });
      if (opened.isError) throw new Error(JSON.stringify(opened));
      const beforeDiscovery = harness.recording.queries.length;
      expect((await request("list_documents")).normalized_result).toEqual(
        discovery.normalized_result,
      );
      expect(harness.recording.queries.slice(beforeDiscovery)).toEqual([
        { operation: "list_documents", parameters: {} },
      ]);
      const beforeReplay = structuredClone(harness.recording.queries);
      for (const [index, [operation, parameters]] of queries.entries()) {
        const replay = await request(operation, parameters);
        for (const field of [
          "normalized_result",
          "raw_result",
          "parameters",
          "subject",
          "provider",
          "analysis_profile",
        ] as const)
          expect(replay[field]).toEqual(populated[index]![field]);
      }
      expect(harness.recording.queries).toEqual(beforeReplay);
      expect(JSON.stringify(omitted)).toBe(originalBytes);
      for (const record of omitted)
        expect(harness.session.evidenceById(record.evidence_id)).toEqual(
          record,
        );
    } finally {
      await harness.close();
    }
    expect(harness.recording.counts().closes).toBe(
      harness.recording.counts().clients,
    );
  });
});

describe("P5-R2 actual SDK and production named registration admission", () => {
  it("captures the strict image refusal without provider dispatch and then admits a valid query (simulated bridge)", async () => {
    const harness = await connectPsxOperationMcp();
    const parent = await createTestTempDirectory("psx-sdk-admission-");
    const workspace = join(parent, "workspace");
    await mkdir(workspace);
    const events: { kind: string; [key: string]: unknown }[] = [];
    const log = join(parent, "events.jsonl");
    const context = publicVerifier.createPublicPsxContext({
      executable: process.execPath,
      prefixArgs: [],
      environment: { TMPDIR: workspace },
      workspace,
      record: async (event: (typeof events)[number]) => {
        await writeFile(log, `${JSON.stringify(event)}\n`, { flag: "a" });
        events.push(event);
      },
    });
    try {
      const operation = "inspect_native_load_image";
      const parameters = { document: "not-admitted" };
      const catalog = await harness.mcp.listTools();
      const advertised = catalog.tools.find((tool) => tool.name === operation);
      if (!advertised) throw new Error("Missing named image schema");
      const schema = publicVerifier
        .compilePublicPsxSchemas({ tools: [advertised] })
        .get(operation);
      const before = structuredClone(harness.recording.queries);
      const evidenceBefore = harness.session.evidenceBundleForSerialization();
      const reply = await harness.mcp.callTool({
        name: operation,
        arguments: parameters,
      });
      const raw = JSON.stringify(reply);
      const parsed = await publicVerifier.capturePublicPsxReply(
        context,
        reply,
        operation,
        schema,
        { allowUnstructuredToolError: true },
      );
      expect(
        publicVerifier.assertPublicPsxImageAdmissionRefusal(
          parsed,
          operation,
          parameters,
          schema,
        ),
      ).toMatchObject({ category: "sdk-input-validation-refusal" });
      expect(harness.recording.queries).toEqual(before);
      expect(harness.session.evidenceBundleForSerialization()).toEqual(
        evidenceBefore,
      );
      expect(events.map((event) => event.kind)).toEqual([
        "raw_result",
        "observation",
      ]);
      expect(await readFile(log, "utf8")).toContain(raw);
      expect(JSON.stringify(reply)).toBe(raw);
      const valid = await harness.mcp.callTool({
        name: operation,
        arguments: {},
      });
      const success = await publicVerifier.capturePublicPsxReply(
        context,
        valid,
        operation,
        schema,
      );
      expect(success).not.toHaveProperty("tool_error");
      expect(success.observation_sequence).toBe(4);
      expect(parsed).not.toHaveProperty("observation_sequence");
      expect(success.value).toMatchObject({ status: "verified" });
      expect(harness.recording.queries.slice(before.length)).toContainEqual({
        operation,
        parameters: {},
      });
    } finally {
      await harness.close();
    }
    expect(harness.recording.counts().closes).toBe(
      harness.recording.counts().clients,
    );
  });
});

const cases = [
  [
    "inspect_native_instruction",
    { address: "0x80010008", document: "synthetic PSX" },
  ],
  ["resolve_native_call_targets", { address: "0x80010034" }],
  ["procedure_address", { procedure: "0x80010001" }],
  ["resolve_containing_procedure", { address: "0x80010048" }],
  ["procedure_info", { procedure: "0x8001000c" }],
  ["procedure_assembly", { procedure: "0x80010000" }],
  ["procedure_pseudo_code", { procedure: "0x80010080" }],
  ["read_function_instructions", { procedure: "0x80010084" }],
  ["procedure_callers", { procedure: "0x80010080" }],
  ["procedure_callees", { procedure: "0x80010000" }],
  ["procedure_references", { procedure: "0x80010000", direction: "outgoing" }],
  ["xrefs", { address: "0x80010080" }],
  ["analyze_function", { procedure: "0x80010000" }],
] as const;

describe("PSX static queries through SDK MCP (simulated bridge)", () => {
  it("routes every admitted family by name and retains subject/profile/Evidence and caller selectors", async () => {
    const harness = await connectPsxOperationMcp();
    try {
      for (const [name, parameters] of cases) {
        const reply = await harness.mcp.callTool({
          name,
          arguments: parameters,
        });
        if (reply.isError) throw new Error(JSON.stringify(reply));
        const evidence = parseEvidence(reply.structuredContent);
        expect(evidence.operation).toBe(name);
        expect(evidence.provider).toMatchObject({
          id: "ghidra",
          version: "12.1.4",
        });
        expect(evidence.subject).toMatchObject({
          format: "ps-x-exe",
          architecture: "mips",
          digest: { sha256: psxFixtureSha256(psxInstructionFlowBytes()) },
        });
        expect(evidence.analysis_profile?.parameters).toMatchObject({
          psx_operation_scope: "inventory-load-image-and-static-functions-v1",
          instruction_flow_evidence:
            "decoded-return-before-jump-and-delay-slots-v2",
        });
        expect(harness.session.evidenceById(evidence.evidence_id)).toEqual(
          evidence,
        );
        expect(harness.recording.queries).toContainEqual({
          operation: name,
          parameters: expect.objectContaining(parameters),
        });
      }
      const unresolved = parseEvidence(
        (
          await harness.mcp.callTool({
            name: "resolve_native_call_targets",
            arguments: { address: "0x80010034" },
          })
        ).structuredContent,
      );
      expect(unresolved.normalized_result).toMatchObject({
        call_site: "0x80010034",
        status: "unresolved",
        mechanism: "computed",
        targets: [],
      });
      const refs = parseEvidence(
        (
          await harness.mcp.callTool({
            name: "procedure_references",
            arguments: { procedure: "0x80010000", direction: "outgoing" },
          })
        ).structuredContent,
      );
      expect(refs.normalized_result).toMatchObject({
        references: [
          { source_address: "0x80010008", target_address: "0x80010080" },
        ],
        unresolved_calls: [{ address: "0x80010034" }],
      });
    } finally {
      await harness.close();
    }
    expect(harness.recording.counts().closes).toBe(
      harness.recording.counts().clients,
    );
  });
});

describe("PSX SDK converted output schemas (simulated bridge)", () => {
  it("validates actual advertised named schemas in draft2020-12 for decoded, nondecoded, call targets and old optional fields", async () => {
    const harness = await connectPsxOperationMcp();
    try {
      const advertised = new Map(
        (await harness.mcp.listTools()).tools.map((tool) => [tool.name, tool]),
      );
      for (const name of [
        "inspect_native_instruction",
        "resolve_native_call_targets",
      ] as const) {
        const schema: Record<string, unknown> | undefined =
          advertised.get(name)?.outputSchema;
        if (!schema) throw new Error(`Missing named ${name} output schema`);
        expect(schema.$schema).toBe(
          "https://json-schema.org/draft/2020-12/schema",
        );
        const validate = new Ajv2020({
          strict: false,
          validateFormats: false,
        }).compile(schema);
        for (const address of [
          "0x80010008",
          "0x8001000c",
          "0x80010034",
          "0x80010044",
          "0x80010001",
          "0x80010100",
          "0x80010104",
          "0x90000000",
        ]) {
          const reply = await harness.mcp.callTool({
            name,
            arguments: { address },
          });
          if (reply.isError) throw new Error(JSON.stringify(reply));
          const evidence = parseEvidence(reply.structuredContent);
          expect(
            validate(reply.structuredContent),
            JSON.stringify(validate.errors),
          ).toBe(true);
          if (name === "inspect_native_instruction") {
            const result = evidence.normalized_result as Record<
              string,
              unknown
            >;
            if (
              ["0x80010001", "0x80010100", "0x80010104", "0x90000000"].includes(
                address,
              )
            )
              expect(result.delay_slots).toEqual({
                is_in_delay_slot: null,
                depth: null,
                addresses: null,
              });
            const older = structuredClone(evidence);
            delete (older.normalized_result as Record<string, unknown>)
              .delay_slots;
            expect(validate(older)).toBe(true);
            const extra = structuredClone(evidence);
            (extra.normalized_result as Record<string, unknown>).unexpected =
              true;
            expect(validate(extra)).toBe(false);
            for (const delaySlots of [
              { is_in_delay_slot: false, depth: -1, addresses: [] },
              { is_in_delay_slot: false, depth: 0, addresses: ["0x8001000c"] },
              { is_in_delay_slot: null, depth: null, addresses: [] },
              { is_in_delay_slot: "false", depth: 0, addresses: [] },
            ]) {
              const malformed = structuredClone(evidence);
              (
                malformed.normalized_result as Record<string, unknown>
              ).delay_slots = delaySlots;
              expect(validate(malformed)).toBe(false);
            }
          } else {
            const malformed = structuredClone(evidence);
            (malformed.normalized_result as Record<string, unknown>).status =
              "invented-call";
            expect(validate(malformed)).toBe(false);
          }
        }
      }
    } finally {
      await harness.close();
    }
  });
});

describe("PSX MCP failure isolation (simulated bridge)", () => {
  it.each([
    "malformed output",
    "remote document error",
    "cancelled",
    "old omission",
  ] as const)(
    "preserves %s semantics without creating failed Evidence",
    async (scenario) => {
      const harness = await connectPsxOperationMcp(
        async (operation, parameters) => {
          if (scenario === "remote document error")
            return err(
              new GhidraSessionError(
                "remote",
                "Wrong explicit document",
                {},
                { remoteCode: "invalid_request" },
              ),
            );
          if (scenario === "cancelled")
            return err(
              new GhidraSessionError("cancelled", "Simulated cancellation"),
            );
          if (operation !== "inspect_native_instruction")
            throw new Error("Unmodeled command");
          const instruction = psxSimulatedInstruction(
            String(parameters.address),
          );
          if (scenario === "malformed output")
            instruction.delay_slots = {
              is_in_delay_slot: false,
              depth: 1,
              addresses: [],
            };
          if (scenario === "old omission") delete instruction.delay_slots;
          return ok(jsonValueSchema.parse(instruction));
        },
      );
      try {
        const before = harness.session.evidenceBundleForSerialization();
        const reply = await harness.mcp.callTool({
          name: "inspect_native_instruction",
          arguments: {
            address: "0x80010008",
            ...(scenario === "remote document error"
              ? { document: "caller document" }
              : {}),
          },
        });
        if (scenario === "old omission") {
          if (reply.isError) throw new Error(JSON.stringify(reply));
          const evidence = parseEvidence(reply.structuredContent);
          expect(evidence.normalized_result).not.toHaveProperty("delay_slots");
          expect(harness.session.evidenceById(evidence.evidence_id)).toEqual(
            evidence,
          );
        } else {
          expect(reply.isError).toBe(true);
          expect(parseMcpToolError(reply).error.code).toBe(
            scenario === "malformed output"
              ? "unreadable_output"
              : scenario === "cancelled"
                ? "cancelled"
                : "invalid_request",
          );
          expect(reply.structuredContent).toBeUndefined();
          expect(harness.session.evidenceBundleForSerialization()).toEqual(
            before,
          );
        }
      } finally {
        await harness.close();
      }
    },
  );

  it("rejects malformed addresses and PSX annotation/type requests before simulated bridge dispatch", async () => {
    const harness = await connectPsxOperationMcp();
    try {
      const before = harness.session.evidenceBundleForSerialization();
      for (const [name, arguments_] of [
        ["inspect_native_instruction", { address: "not an address" }],
        ["inspect_native_instruction", { address: "ram::0x100" }],
        [
          "annotate_native_function",
          { procedure: "0x80010000", name: "refused" },
        ],
        ["inspect_native_data_type", { address: "0x80010100" }],
      ] as const) {
        const reply = await harness.mcp.callTool({
          name,
          arguments: arguments_,
        });
        expect(reply.isError, name).toBe(true);
        expect(parseMcpToolError(reply)).not.toHaveProperty("evidence_id");
      }
      expect(harness.recording.calls).toEqual([]);
      expect(harness.session.evidenceBundleForSerialization()).toEqual(before);
    } finally {
      await harness.close();
    }
  });
});

describe("PSX provider cross-field validation through MCP", () => {
  it.each([
    "depth length",
    "duplicate slots",
    "nondecoded slots",
    "noncanonical slot",
    "invalid call target",
  ] as const)(
    "rejects %s at the production provider boundary without failed Evidence",
    async (mutation) => {
      const harness = await connectPsxOperationMcp(
        async (operation, parameters) => {
          if (mutation === "invalid call target") {
            const result = psxSimulatedOperation(operation, parameters);
            if (
              typeof result !== "object" ||
              result === null ||
              Array.isArray(result)
            )
              throw new Error("Expected target object");
            result.status = "invented-call";
            return ok(result);
          }
          const result = psxSimulatedInstruction(String(parameters.address));
          result.delay_slots =
            mutation === "depth length"
              ? { is_in_delay_slot: false, depth: 2, addresses: ["0x8001000c"] }
              : mutation === "duplicate slots"
                ? {
                    is_in_delay_slot: false,
                    depth: 2,
                    addresses: ["0x8001000c", "0x8001000c"],
                  }
                : mutation === "noncanonical slot"
                  ? {
                      is_in_delay_slot: false,
                      depth: 1,
                      addresses: ["0X8001000C"],
                    }
                  : { is_in_delay_slot: false, depth: 0, addresses: [] };
          return ok(jsonValueSchema.parse(result));
        },
      );
      try {
        const before = harness.session.evidenceBundleForSerialization();
        const reply = await harness.mcp.callTool({
          name:
            mutation === "invalid call target"
              ? "resolve_native_call_targets"
              : "inspect_native_instruction",
          arguments: {
            address:
              mutation === "nondecoded slots" ? "0x80010100" : "0x80010008",
          },
        });
        expect(reply.isError).toBe(true);
        expect(parseMcpToolError(reply).error.code).toBe("unreadable_output");
        expect(reply.structuredContent).toBeUndefined();
        expect(harness.session.evidenceBundleForSerialization()).toEqual(
          before,
        );
        expect(harness.recording.calls).toHaveLength(1);
      } finally {
        await harness.close();
      }
    },
  );
});

const replayQueries = [
  [
    "inspect_native_instruction",
    { address: "0x80010044", document: "synthetic PSX" },
  ],
  [
    "resolve_native_call_targets",
    { address: "0x80010034", document: "synthetic PSX" },
  ],
  ["analyze_function", { procedure: "0x80010000" }],
  ["inspect_native_load_image", {}],
] as const;

describe("PSX public session snapshot persistence (simulated bridge)", () => {
  it.each(["current", "older optional omission"] as const)(
    "replays %s instruction/target/dossier/image Evidence with zero bridge queries",
    async (capture) => {
      const harness = await connectPsxOperationMcp(
        async (operation, parameters) => {
          if (operation === "inspect_native_load_image")
            return ok(
              jsonValueSchema.parse(
                psxAppliedLoadImageObservation(psxInstructionFlowBytes()),
              ),
            );
          const result = psxSimulatedOperation(operation, parameters);
          if (
            capture === "older optional omission" &&
            operation === "inspect_native_instruction"
          ) {
            if (
              typeof result !== "object" ||
              result === null ||
              Array.isArray(result)
            )
              throw new Error("Expected instruction");
            delete result.delay_slots;
            const flow = result.flow;
            if (
              typeof flow !== "object" ||
              flow === null ||
              Array.isArray(flow)
            )
              throw new Error("Expected flow");
            delete flow.classification_evidence;
          }
          return ok(result);
        },
      );
      try {
        const original = [];
        for (const [name, parameters] of replayQueries) {
          const reply = await harness.mcp.callTool({
            name,
            arguments: parameters,
          });
          if (reply.isError) throw new Error(JSON.stringify(reply));
          original.push(parseEvidence(reply.structuredContent));
        }
        const exported = harness.session.exportAnalysisSnapshot();
        if (!exported.ok) throw exported.error;
        expect(exported.value.entries).toHaveLength(4);
        for (const [operation, parameters] of replayQueries) {
          const entry = exported.value.entries.find(
            (candidate) => candidate.operation === operation,
          );
          expect(entry?.parameters).toEqual(parameters);
        }
        expect(exported.value.evidence_bundle.records).toHaveLength(4);
        const closed = await harness.mcp.callTool({
          name: "close_binary",
          arguments: {},
        });
        if (closed.isError) throw new Error(JSON.stringify(closed));
        const imported = harness.session.importAnalysisSnapshot(exported.value);
        if (!imported.ok) throw imported.error;
        const opened = await harness.mcp.callTool({
          name: "open_binary",
          arguments: { path: harness.fixture.source, provider_id: "ghidra" },
        });
        if (opened.isError) throw new Error(JSON.stringify(opened));
        const queriesBefore = [...harness.recording.queries];
        expect(harness.session.evidenceById(original[3]!.evidence_id)).toEqual(
          original[3],
        );
        for (const [index, [name, parameters]] of replayQueries.entries()) {
          const reply = await harness.mcp.callTool({
            name,
            arguments: parameters,
          });
          if (reply.isError) throw new Error(JSON.stringify(reply));
          const evidence = parseEvidence(reply.structuredContent);
          expect(evidence.normalized_result).toEqual(
            original[index]?.normalized_result,
          );
          expect(evidence.subject).toEqual(original[index]?.subject);
          expect(evidence.provider).toEqual(original[index]?.provider);
          expect(evidence.analysis_profile).toEqual(
            original[index]?.analysis_profile,
          );
          expect(harness.session.evidenceById(evidence.evidence_id)).toEqual(
            evidence,
          );
          if (
            capture === "older optional omission" &&
            name === "inspect_native_instruction"
          ) {
            expect(evidence.normalized_result).not.toHaveProperty(
              "delay_slots",
            );
            expect(evidence.normalized_result).not.toHaveProperty(
              "flow.classification_evidence",
            );
          }
        }
        expect(harness.recording.queries).toEqual(queriesBefore);
        const invalidImage = await harness.mcp.callTool({
          name: "inspect_native_load_image",
          arguments: { document: "synthetic PSX" },
        });
        expect(invalidImage.isError).toBe(true);
        expect(invalidImage.structuredContent).toBeUndefined();
        expect(harness.recording.queries).toEqual(queriesBefore);
      } finally {
        await harness.close();
      }
      expect(harness.recording.counts().closes).toBe(
        harness.recording.counts().clients,
      );
    },
  );
});
