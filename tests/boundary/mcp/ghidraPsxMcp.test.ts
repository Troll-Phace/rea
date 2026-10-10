import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
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
