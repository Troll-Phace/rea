import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { z } from "zod";

import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("delivers typed tool failures without violating the advertised success schema over stdio", async () => {
  const root = await createTestTempDirectory("rea-tool-error-schema-");
  const missing = join(root, "not-present.bin");
  const { client, call } = await connectLocalToolsMcp();
  const tools = (await client.listTools()).tools;
  const failures: string[] = [];
  const requests = [
    { name: "list_documents", arguments: {} },
    { name: "open_binary", arguments: { path: missing } },
    {
      name: "analyze_javascript_application",
      arguments: { input_path: missing },
    },
    { name: "inspect_artifact", arguments: {} },
  ];
  for (const request of requests) {
    const tool = tools.find(({ name }) => name === request.name);
    if (tool?.outputSchema === undefined)
      throw new Error(`${request.name} omitted its output schema`);
    const reply = await client.callTool(request);
    const diagnostic = parseMcpToolError(reply);
    expect(diagnostic.error.message, request.name).not.toBe("");
    if ("path" in request.arguments || "input_path" in request.arguments)
      expect(JSON.stringify(diagnostic), request.name).toContain(missing);
    if (reply.structuredContent !== undefined) {
      const validate = new Ajv2020({
        strict: false,
        validateFormats: false,
      }).compile(z.record(z.string(), z.unknown()).parse(tool.outputSchema));
      if (!validate(reply.structuredContent)) failures.push(request.name);
    }
  }
  expect(failures).toEqual([]);
  const successful = await call("get_evidence_bundle", {});
  expect(successful.isError).not.toBe(true);
  expect(successful.structuredContent).toBeDefined();
  await client.ping();
});

it("refuses PSX deep analysis over stdio while preserving unbound target identity", async () => {
  const root = await createTestTempDirectory("rea-psx-tool-error-");
  const path = join(root, "original.js");
  const bytes = Buffer.alloc(0x1000);
  Buffer.from([0x50, 0x53, 0x2d, 0x58, 0x20, 0x45, 0x58, 0x45]).copy(bytes);
  bytes.writeUInt32LE(0x80010000, 0x10);
  bytes.writeUInt32LE(0x80010000, 0x18);
  bytes.writeUInt32LE(0x800, 0x1c);
  await writeFile(path, bytes);
  const { client, call } = await connectLocalToolsMcp();
  for (const provider_id of ["ghidra", "hopper", "ida"]) {
    const reply = await call("open_binary", { path, provider_id });
    expect(reply.isError, JSON.stringify({ provider_id, reply })).toBe(true);
    const diagnostic = parseMcpToolError(reply);
    expect(diagnostic).toMatchObject({
      error: {
        details: {
          selection_reason: "target_unsupported",
          rejections: expect.arrayContaining([
            expect.objectContaining({
              provider_id,
              code: "target_format_unsupported",
            }),
          ]),
        },
      },
    });
    expect(reply.structuredContent).toBeUndefined();
    const session = await call("binary_session", {});
    expect(session.structuredContent).toMatchObject({
      result: { open: false, analysis_provider_binding: null },
    });
    expect(session.structuredContent).not.toMatchObject({ result: { path } });
  }
  const automatic = await call("open_binary", { path, provider_id: "auto" });
  expect(automatic.isError).not.toBe(true);
  expect(automatic.structuredContent).toMatchObject({
    result: {
      path,
      format: "ps-x-exe",
      architecture: "mips",
      kind: "executable",
    },
  });
  const unbound = await call("binary_session", {});
  expect(unbound.structuredContent).toMatchObject({
    result: {
      open: true,
      path,
      analysis_provider_binding: null,
      analysis_provider_candidates: ["ghidra", "hopper", "ida"].map((id) =>
          expect.objectContaining({
            provider: expect.objectContaining({ id }),
            selected: false,
            target_support: expect.objectContaining({
              status: "unsupported",
              code: "target_format_unsupported",
            }),
          }),
        ),
    },
  });
  const native = await call("analyze_function", { procedure: "main" });
  expect(parseMcpToolError(native)).toMatchObject({
    error: { details: { selection_reason: "target_unsupported" } },
  });
  expect(native.structuredContent).toBeUndefined();
  await call("close_binary", {});
  expect((await call("binary_session", {})).structuredContent).toMatchObject({
    result: { open: false },
  });
  expect(await readFile(path)).toEqual(bytes);
  await writeFile(path, bytes.subarray(0, 0x800));
  const malformed = await call("open_binary", { path });
  expect(parseMcpToolError(malformed).error.message).toContain(
    "malformed PS-X EXE",
  );
  expect(malformed.structuredContent).toBeUndefined();
  expect((await call("binary_session", {})).structuredContent).toMatchObject({
    result: { open: false },
  });
  await client.ping();
});
