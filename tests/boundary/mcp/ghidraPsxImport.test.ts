import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import {
  createPsxInstallationFixture,
  createPsxRecordingProvider,
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
              psx_operation_scope: "inventory-observations-only-v1",
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
