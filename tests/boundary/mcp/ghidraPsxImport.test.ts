import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import {
  createPsxInstallationFixture,
  createPsxRecordingProvider,
  psxAppliedLoadImageObservation,
  psxUnavailableLoadImageObservation,
  psxFixtureSha256,
  psxImportBytes,
  psxFixtureMetadataPreservation,
} from "../../fixtures/ghidraPsxImport.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

it("binds a synthetic PSX session through MCP, preserves inventory and refuses function claims before dispatch", async () => {
  const fixture = await createPsxInstallationFixture();
  const recording = createPsxRecordingProvider(fixture);
  const session = composeBinarySession(
    new AnalysisProviderRegistry([recording.provider]),
  );
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger },
  );
  const mcp = new Client({
    name: "simulated-ghidra-psx-import",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await mcp.connect(clientTransport);
    const opened = await mcp.callTool({
      name: "open_binary",
      arguments: { path: fixture.source, provider_id: "ghidra" },
    });
    expect(opened.isError).not.toBe(true);
    const status = await mcp.callTool({
      name: "binary_session",
      arguments: {},
    });
    expect(status.structuredContent).toMatchObject({
      result: {
        open: true,
        analysis_provider_binding: {
          provider: { id: "ghidra", version: "12.1.4" },
          selection_source: "request",
          analysis_profile: {
            parameters: {
              psx_operation_scope: "inventory-and-load-image-v1",
            },
          },
        },
      },
    });
    const inventory = await mcp.callTool({
      name: "list_strings",
      arguments: {},
    });
    expect(inventory.isError).not.toBe(true);
    const evidence = parseEvidence(inventory.structuredContent);
    expect(evidence).toMatchObject({
      provider: { id: "ghidra" },
      subject: { digest: { sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) } },
      normalized_result: [
        { value: "synthetic inventory", address: "0x80010100" },
      ],
    });
    expect(session.evidenceById(evidence.evidence_id)).toEqual(evidence);
    const loadImage = await mcp.callTool({
      name: "inspect_native_load_image",
      arguments: {},
    });
    expect(loadImage.isError).not.toBe(true);
    expect(loadImage.structuredContent).toMatchObject({
      normalized_result: {
        status: "unsupported",
        observations: {
          source_files: [],
          mappings: [{ source_file_index: null, file_offset: null }],
          entry_context: [],
        },
      },
    });
    for (const [name, arguments_] of [
      ["read_function_instructions", { procedure: "0x80010000" }],
      ["procedure_pseudo_code", { procedure: "0x80010000" }],
      [
        "annotate_native_function",
        { procedure: "0x80010000", name: "renamed" },
      ],
    ] as const) {
      const rejected = await mcp.callTool({ name, arguments: arguments_ });
      expect(rejected.isError, name).toBe(true);
      expect(parseMcpToolError(rejected)).toMatchObject({
        error: {
          code: "capability_unavailable",
          details: { reason: expect.stringMatching(/PSX.*Phase 4/u) },
        },
      });
      expect(parseMcpToolError(rejected)).not.toHaveProperty("evidence_id");
    }
    expect(recording.calls).toEqual([
      "list_strings",
      "inspect_native_load_image",
    ]);
    const closed = await mcp.callTool({ name: "close_binary", arguments: {} });
    expect(closed.isError).not.toBe(true);
    expect(recording.counts().closes).toBe(1);
  } finally {
    await Promise.allSettled([mcp.close(), server.close()]);
    await session.close();
  }
});

it.each(["verified", "mismatch", "unsupported"] as const)(
  "projects %s PSX evidence through the named SDK-converted MCP schema (simulated bridge)",
  async (status) => {
    const fixture = await createPsxInstallationFixture();
    const recording = createPsxRecordingProvider(fixture, {
      loadImage: (bytes) => {
        if (status === "unsupported")
          return psxUnavailableLoadImageObservation(bytes);
        const observation = psxAppliedLoadImageObservation(bytes);
        if (status === "mismatch")
          observation.source_files[0]!.original_sha256 = "e".repeat(64);
        return observation;
      },
    });
    const session = composeBinarySession(
      new AnalysisProviderRegistry([recording.provider]),
    );
    const server = createServer(
      { kind: "session", session },
      { logger: silentLogger },
    );
    const mcp = new Client({ name: "psx-load-image-schema", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await mcp.connect(clientTransport);
      const opened = await mcp.callTool({
        name: "open_binary",
        arguments: { path: fixture.source, provider_id: "ghidra" },
      });
      expect(opened.isError).not.toBe(true);
      const advertised = (await mcp.listTools()).tools.find(
        (tool) => tool.name === "inspect_native_load_image",
      );
      if (advertised?.outputSchema === undefined)
        throw new Error("Named load-image output contract was not advertised");
      expect(advertised.outputSchema.$schema).toBe(
        "https://json-schema.org/draft/2020-12/schema",
      );
      const validate = new Ajv2020({
        strict: false,
        validateFormats: false,
      }).compile(advertised.outputSchema as Record<string, unknown>);
      const reply = await mcp.callTool({
        name: "inspect_native_load_image",
        arguments: {},
      });
      expect(reply.isError).not.toBe(true);
      expect(
        validate(reply.structuredContent),
        JSON.stringify(validate.errors),
      ).toBe(true);
      const evidence = parseEvidence(reply.structuredContent);
      expect(evidence).toMatchObject({
        provider: { id: "ghidra" },
        subject: {
          format: "ps-x-exe",
          digest: { sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) },
        },
        normalized_result: { format: "ps-x-exe", status },
      });
      expect(session.evidenceById(evidence.evidence_id)).toEqual(evidence);
      expect(evidence.subject?.digest.sha256).toBe(
        psxFixtureSha256(psxImportBytes()),
      );
      expect(evidence.analysis_profile).toBeDefined();
      if (status === "verified")
        expect(evidence.normalized_result).toMatchObject({
          observations: {
            psx: {
              schema_version: 2,
              provenance: {
                method: "rea-psx-filebytes-rebind-v2",
                metadata_preservation:
                  psxFixtureMetadataPreservation("applied"),
              },
              current_label_history:
                psxFixtureMetadataPreservation("applied").label_history.after,
            },
            entry_context: [
              {
                registers: [
                  { name: "gp", value_hex: "0x0" },
                  { name: "sp", value_hex: null },
                ],
              },
            ],
          },
          coverage: { complete: true, verified_payload_bytes: 2048 },
        });
      if (status === "unsupported")
        expect(evidence.normalized_result).toMatchObject({
          observations: {
            source_files: [],
            psx: {
              provenance: { status: "unavailable", reason: expect.any(String) },
            },
          },
          coverage: { complete: false },
        });
      expect(
        validate({
          ...evidence,
          normalized_result: {
            ...(evidence.normalized_result as object),
            unexpected: true,
          },
        }),
      ).toBe(false);
      expect(recording.calls).toEqual(["inspect_native_load_image"]);
    } finally {
      await Promise.allSettled([mcp.close(), server.close()]);
      const closed = await session.close();
      if (!closed.ok) throw closed.error;
    }
    expect(recording.counts().closes).toBe(1);
  },
);
