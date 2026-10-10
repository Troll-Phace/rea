import { Cli } from "incur";
import { expect, it } from "vitest";

import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { registerCoreAnalysisCommands } from "../../../src/cli/coreAnalysisCommands.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { silentLogger } from "../../../src/logger.js";
import {
  createPsxInstallationFixture,
  createPsxRecordingProvider,
  psxAppliedLoadImageObservation,
  psxUnavailableLoadImageObservation,
  psxFixtureSha256,
  psxImportBytes,
} from "../../fixtures/ghidraPsxImport.js";

it.each(["verified", "mismatch", "unsupported"] as const)(
  "projects synthetic PSX inventory, %s provenance, static reads and annotation refusal through actual CLI commands",
  async (status) => {
    const fixture = await createPsxInstallationFixture();
    const recording = createPsxRecordingProvider(fixture, {
      loadImage: (bytes) => {
        if (status === "unsupported")
          return psxUnavailableLoadImageObservation(bytes);
        const observation = psxAppliedLoadImageObservation(bytes);
        if (status === "mismatch") observation.mappings[0]!.file_offset = 0x801;
        return observation;
      },
    });
    const dependencies = {
      readConfiguration: () =>
        parseConfig({ GHIDRA_INSTALL_DIR: fixture.installationRoot }),
      createBinarySession: () =>
        composeBinarySession(
          new AnalysisProviderRegistry([recording.provider]),
        ),
      createManagedBinarySession: () => {
        throw new Error("Unexpected managed session for PSX CLI");
      },
    };
    const cli = Cli.create("rea-psx-cli-boundary", { sync: false });
    registerCoreAnalysisCommands(
      cli,
      silentLogger,
      runDirectAnalysis.bind(undefined, dependencies),
    );
    const previousExitCode = process.exitCode;
    const run = async (arguments_: readonly string[]) => {
      process.exitCode = undefined;
      let output = "";
      let exit = 0;
      await cli.serve([...arguments_, "--provider", "ghidra", "--json"], {
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
    };
    try {
      const bytes = await run([
        "read-bytes",
        fixture.source,
        "0x80010000",
        "--length",
        "4",
      ]);
      expect(bytes.exit).toBe(0);
      expect(bytes.output).toMatchObject({
        normalized_result: { address: "0x80010000", bytes_hex: "07000224" },
        provider: { id: "ghidra" },
        analysis_profile: {
          parameters: {
            psx_operation_scope: "inventory-load-image-and-static-functions-v1",
          },
        },
      });
      const loadImage = await run([
        "inspect-native-load-image",
        fixture.source,
      ]);
      expect(loadImage.exit).toBe(0);
      expect(loadImage.output).toMatchObject({
        normalized_result: {
          format: "ps-x-exe",
          status,
        },
      });
      const evidence = parseEvidence(loadImage.output);
      expect(evidence.subject?.digest.sha256).toBe(
        psxFixtureSha256(psxImportBytes()),
      );
      expect(evidence).toMatchObject({
        provider: { id: "ghidra" },
        subject: {
          format: "ps-x-exe",
          digest: { sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) },
        },
        analysis_profile: {
          parameters: {
            psx_operation_scope: "inventory-load-image-and-static-functions-v1",
          },
        },
      });
      if (status === "mismatch")
        expect(evidence.normalized_result).toMatchObject({
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: "mapping[0].file_offset",
              status: "mismatch",
            }),
          ]),
        });
      if (status === "unsupported")
        expect(evidence.normalized_result).toMatchObject({
          observations: {
            source_files: [],
            psx: { provenance: { status: "unavailable" } },
          },
          coverage: { complete: false },
        });
      for (const args of [
        ["instructions", fixture.source, "0x80010000"],
        ["decompile", fixture.source, "0x80010000"],
      ]) {
        const admitted = await run(args);
        expect(admitted.exit).toBe(0);
        expect(parseEvidence(admitted.output)).toMatchObject({
          provider: { id: "ghidra" },
          subject: { format: "ps-x-exe" },
        });
      }
      const rejected = await run([
        "annotate-native-function",
        fixture.source,
        "0x80010000",
        "--name",
        "renamed",
      ]);
      expect(rejected.exit).toBe(1);
      expect(rejected.output).toMatchObject({
        code: "capability_unavailable",
        details: { reason: expect.stringMatching(/PSX observational scope/u) },
      });
      expect(rejected.output).not.toHaveProperty("evidence_id");
      expect(recording.calls).toEqual([
        "read_bytes",
        "inspect_native_load_image",
        "read_function_instructions",
        "procedure_pseudo_code",
      ]);
      expect(recording.counts().closes).toBe(recording.counts().clients);
    } finally {
      process.exitCode = previousExitCode;
    }
  },
);
