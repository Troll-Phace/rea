import { Cli } from "incur";
import { describe, expect, it } from "vitest";
import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { registerCoreAnalysisCommands } from "../../../src/cli/coreAnalysisCommands.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { err, ok } from "../../../src/domain/result.js";
import { GhidraSessionError } from "../../../src/ghidra/GhidraSessionError.js";
import { silentLogger } from "../../../src/logger.js";
import { connectPsxOperationMcp } from "../../fixtures/ghidraPsxImport.js";

const cliFor = (
  harness: Awaited<ReturnType<typeof connectPsxOperationMcp>>,
) => {
  const dependencies = {
    readConfiguration: () => ok(harness.recording.config),
    createBinarySession: () =>
      composeBinarySession(
        new AnalysisProviderRegistry([harness.recording.provider]),
      ),
    createManagedBinarySession: () => {
      throw new Error("Unmodeled managed target");
    },
  };
  const cli = Cli.create("simulated-psx-operation-parity", { sync: false });
  registerCoreAnalysisCommands(
    cli,
    silentLogger,
    runDirectAnalysis.bind(undefined, dependencies),
  );
  return async (args: string[], provider = "ghidra") => {
    const priorExitCode = process.exitCode;
    process.exitCode = undefined;
    let output = "";
    let exit = 0;
    try {
      await cli.serve([...args, "--provider", provider, "--json"], {
        stdout: (text) => {
          output += text;
        },
        exit: (code) => {
          exit = code;
        },
      });
      return {
        output: JSON.parse(output) as unknown,
        exit: process.exitCode ?? exit,
      };
    } finally {
      process.exitCode = priorExitCode;
    }
  };
};

const routes = [
  [
    "inspect-native-instruction",
    "inspect_native_instruction",
    "0x80010008",
    "address",
  ],
  [
    "inspect-native-instruction",
    "inspect_native_instruction",
    "0x8001000c",
    "address",
  ],
  [
    "inspect-native-instruction",
    "inspect_native_instruction",
    "0x80010001",
    "address",
  ],
  [
    "inspect-native-instruction",
    "inspect_native_instruction",
    "0x80010104",
    "address",
  ],
  [
    "resolve-native-call-targets",
    "resolve_native_call_targets",
    "0x80010008",
    "address",
  ],
  [
    "resolve-native-call-targets",
    "resolve_native_call_targets",
    "0x80010034",
    "address",
  ],
  ["instructions", "read_function_instructions", "0x80010084", "procedure"],
  ["decompile", "procedure_pseudo_code", "0x8001000c", "procedure"],
  ["function", "analyze_function", "0x80010000", "procedure"],
  ["xrefs", "xrefs", "0x80010080", "address"],
] as const;

describe("PSX CLI/MCP semantic parity (simulated Ghidra bridge)", () => {
  it("uses actual registered routes and preserves operation, selectors, subject, profile, unknowns and retained Evidence", async () => {
    const harness = await connectPsxOperationMcp();
    const run = cliFor(harness);
    try {
      for (const [command, operation, selector, key] of routes) {
        const direct = await run([command, harness.fixture.source, selector]);
        expect(direct.exit, JSON.stringify(direct.output)).toBe(0);
        const cliEvidence = parseEvidence(direct.output);
        const reply = await harness.mcp.callTool({
          name: operation,
          arguments: { [key]: selector },
        });
        if (reply.isError) throw new Error(JSON.stringify(reply));
        const mcpEvidence = parseEvidence(reply.structuredContent);
        expect(cliEvidence.operation).toBe(operation);
        expect(cliEvidence.normalized_result).toEqual(
          mcpEvidence.normalized_result,
        );
        expect(cliEvidence.provider).toEqual(mcpEvidence.provider);
        expect(cliEvidence.analysis_profile).toEqual(
          mcpEvidence.analysis_profile,
        );
        expect(cliEvidence.subject).toEqual(mcpEvidence.subject);
        expect(harness.session.evidenceById(mcpEvidence.evidence_id)).toEqual(
          mcpEvidence,
        );
        expect(harness.recording.queries).toContainEqual({
          operation,
          parameters: expect.objectContaining({ [key]: selector }),
        });
      }
    } finally {
      await harness.close();
    }
    expect(harness.recording.counts().closes).toBe(
      harness.recording.counts().clients,
    );
  });

  it("projects invalid address, wrong provider and observational refusals without Evidence or extra bridge dispatch", async () => {
    const harness = await connectPsxOperationMcp();
    const run = cliFor(harness);
    try {
      for (const args of [
        [
          "inspect-native-instruction",
          harness.fixture.source,
          "not an address",
        ],
        [
          "annotate-native-function",
          harness.fixture.source,
          "0x80010000",
          "--name",
          "forbidden",
        ],
        [
          "inspect-native-data-type",
          harness.fixture.source,
          "--address",
          "0x80010100",
        ],
      ]) {
        const response = await run(args);
        expect(response.exit).toBe(1);
        expect(response.output).not.toHaveProperty("evidence_id");
      }
      const wrongProvider = await run(
        ["inspect-native-instruction", harness.fixture.source, "0x80010008"],
        "hopper",
      );
      expect(wrongProvider.exit).toBe(1);
      expect(wrongProvider.output).not.toHaveProperty("evidence_id");
      expect(harness.recording.calls).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  it("preserves typed cancellation through the registered instruction command and closes its session", async () => {
    const harness = await connectPsxOperationMcp(async () =>
      err(
        new GhidraSessionError(
          "cancelled",
          "Simulated native request cancellation",
        ),
      ),
    );
    try {
      const result = await cliFor(harness)([
        "inspect-native-instruction",
        harness.fixture.source,
        "0x80010008",
      ]);
      expect(result.exit).toBe(1);
      expect(result.output).toMatchObject({ code: "cancelled" });
      expect(result.output).not.toHaveProperty("evidence_id");
      expect(harness.recording.calls).toEqual(["inspect_native_instruction"]);
    } finally {
      await harness.close();
    }
    expect(harness.recording.counts().closes).toBe(
      harness.recording.counts().clients,
    );
  });
});
