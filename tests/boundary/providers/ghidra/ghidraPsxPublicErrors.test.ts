import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, onTestFinished } from "vitest";
import { createAnalysisProfile } from "../../../../src/domain/analysisProfile.js";
import {
  createEvidence,
  type Evidence,
} from "../../../../src/domain/evidence.js";
import { analysisErrorProjectionSchema } from "../../../../src/contracts/errorSchemas.js";
import {
  psxFixtureSha256,
  psxImportBytes,
} from "../../../fixtures/ghidraPsxImport.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

type Projection = ReturnType<typeof analysisErrorProjectionSchema.parse>;
type Parsed = {
  error?: Projection;
  cli_error_envelope?: Record<string, unknown>;
  evidence?: Evidence;
};
type Event = {
  sequence: number;
  stage: string;
  kind: string;
  adapter?: string;
  case_id?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  signal?: string | null;
  reply?: unknown;
  [key: string]: unknown;
};
type Context = {
  roots: Map<string, unknown>;
  sourceDigest?: string;
  case(
    id: string,
    adapter: string,
    action: () => Promise<unknown>,
  ): Promise<unknown>;
};
type Outcome = {
  ok: boolean;
  failures: unknown[];
  settlement: {
    verified_empty_lineage: boolean;
    remaining_roots: string[];
    unresolved_owners: unknown[];
  };
};
type Session = {
  call(
    operation: string,
    parameters?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<{ error?: Projection; value?: unknown }>;
  close(): Promise<void>;
};
const helper = (await import(
  new URL("../../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as {
  parsePublicPsxCliOutput(
    stdout: string,
    status: { exitCode?: unknown; signal?: unknown; allowError?: boolean },
  ): Parsed;
  assertPublicPsxErrorParity(cli: unknown, mcp: unknown): void;
  createPublicPsxContext(input: Record<string, unknown>): Context;
  invokePublicPsxCli(
    context: Context,
    argv: string[],
    options?: Record<string, unknown>,
  ): Promise<Parsed>;
  connectPublicPsxMcp(context: Context, caseId?: string): Promise<Session>;
  settlePublicPsxContext(context: Context): Promise<Outcome>;
};

const canonical = () => {
  const value = analysisErrorProjectionSchema.parse({
    code: "target_unavailable",
    category: "unavailable",
    message: "Original target cannot be read.",
    retryable: false,
    remediation: { action: "Provide the complete original file." },
    details: {
      path: "/caller secret folder/owned source 雪.exe",
      reason: "Original parser reason",
      retained: { token: "caller token text", offsets: [8, 16] },
    },
  });
  if (value.code !== "target_unavailable")
    throw new Error("Synthetic refusal must use target_unavailable");
  return value;
};
const flat = () => ({ error: "Analysis failed", ...canonical() });
const acceptedStatus = { exitCode: 1, signal: null, allowError: true };
const successEvidence = () => {
  const provider = {
    id: "ghidra",
    name: "Ghidra",
    version: "controlled-parser-record",
  };
  return createEvidence(
    {
      path: "/generated/parser source.exe",
      sha256: "a".repeat(64),
      format: "ps-x-exe",
      architecture: "mips",
    },
    provider,
    {
      operation: "list_documents",
      parameters: {},
      analysisProfile: createAnalysisProfile(provider, {}),
      result: ["synthetic parser record"],
    },
  );
};

const publicBoundary = async (script?: string) => {
  const parent = await createTestTempDirectory("psx-public-errors-");
  const workspace = join(parent, "workspace 雪");
  await mkdir(workspace);
  const dispatcher =
    script === undefined
      ? fileURLToPath(new URL("../../../../scripts/rea.mjs", import.meta.url))
      : join(parent, "controlled error CLI.mjs");
  if (script !== undefined) await writeFile(dispatcher, script);
  const events: Event[] = [];
  const context = helper.createPublicPsxContext({
    executable: process.execPath,
    prefixArgs: [dispatcher],
    workspace,
    environment: {
      PATH: process.env.PATH ?? "",
      HOME: parent,
      TMPDIR: workspace,
      REA_LOG_LEVEL: "silent",
    },
    record: async (event: Event) => {
      events.push(event);
      await writeFile(
        join(parent, "events.jsonl"),
        `${JSON.stringify(event)}\n`,
        { flag: "a" },
      );
    },
  });
  onTestFinished(async () => {
    const result = await helper.settlePublicPsxContext(context);
    expect(result.settlement.unresolved_owners).toEqual([]);
    expect(result.settlement.remaining_roots).toEqual([]);
  });
  return { parent, workspace, dispatcher, context, events };
};

describe("P5-R6 real compiled CLI and stdio SDK refusal parity (no Ghidra allocation)", () => {
  it("preserves complete canonical errors, actual source paths/raw records and exact cleanup for original malformed inputs", async () => {
    const f = await publicBoundary();
    const sdk = await helper.connectPublicPsxMcp(
      f.context,
      "actual-malformed-sdk",
    );
    try {
      await f.context.case(
        "actual-malformed-refusal-parity",
        "mcp",
        async () => {
          for (const [id, bytes] of [
            ["truncated", psxImportBytes().subarray(0, 0x40)],
            ["malformed", Buffer.from("PS-X EXE malformed")],
          ] as const) {
            const path = join(f.workspace, `${id} caller secret 雪.exe`);
            await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
            const digest = psxFixtureSha256(bytes);
            f.context.sourceDigest = digest;
            const mcp = await sdk.call(
              "open_binary",
              { path, provider_id: "ghidra" },
              { caseId: `mcp-${id}`, allowError: true },
            );
            expect(mcp.error?.code).toBe("target_unavailable");
            if (mcp.error?.code !== "target_unavailable")
              throw new Error(JSON.stringify(mcp));
            expect(mcp.error.details?.path).toBe(path);
            expect((await sdk.call("binary_session")).value).toMatchObject({
              open: false,
            });
            const cli = await helper.invokePublicPsxCli(
              f.context,
              ["inspect-native-load-image", path],
              { caseId: `cli-${id}`, sourceDigest: digest, allowError: true },
            );
            helper.assertPublicPsxErrorParity(cli.error, mcp.error);
            expect(cli.error).toEqual(mcp.error);
            expect(cli.cli_error_envelope?.error).toBe("Analysis failed");
            const raw = f.events.find(
              (event) =>
                event.case_id === `cli-${id}` &&
                typeof event.stdout === "string",
            )!;
            expect(raw).toMatchObject({ exit_code: 1, signal: null });
            expect(JSON.parse(raw.stdout!)).toEqual(cli.cli_error_envelope);
            expect(
              helper.parsePublicPsxCliOutput(raw.stdout!, acceptedStatus),
            ).toEqual(cli);
            const wire = f.events.find(
              (event) =>
                event.case_id === `mcp-${id}` &&
                event.kind === "raw_result" &&
                event.reply !== undefined,
            )!;
            expect(wire.reply).toMatchObject({
              isError: true,
              content: [{ type: "text" }],
            });
            const wireReply = wire.reply as {
              content: { type: string; text: string }[];
            };
            expect(JSON.parse(wireReply.content[0]!.text)).toEqual({
              error: mcp.error,
            });
            await expect(
              helper.invokePublicPsxCli(
                f.context,
                ["inspect-native-load-image", path],
                { caseId: `denied-${id}`, sourceDigest: digest },
              ),
            ).rejects.toThrow(JSON.stringify(cli.cli_error_envelope));
            expect(await readFile(path)).toEqual(bytes);
            expect(psxFixtureSha256(await readFile(path))).toBe(digest);
            expect(f.context.roots.size).toBe(0);
            expect(
              (await readdir(f.workspace)).some((name) =>
                name.startsWith("rea-ghidra-"),
              ),
            ).toBe(false);
          }
        },
      );
    } finally {
      await sdk.close();
    }
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(true);
    expect(settled.failures).toEqual([]);
    expect(settled.settlement.verified_empty_lineage).toBe(true);
    expect(f.events.some((event) => event.stage === "native-allocation")).toBe(
      false,
    );
    const persisted = (await readFile(join(f.parent, "events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(persisted).toEqual(f.events);
    expect(
      f.events.filter(
        (event) => event.adapter === "cli" && typeof event.stdout === "string",
      ),
    ).toHaveLength(4);
  });
});

describe("P5-R6 declared CLI envelope and optional diagnostic preservation", () => {
  it.each([
    {},
    {
      input_path: "caller-selected secret 雪/../source.json",
      input_reason: "invalid-json",
    },
    { input_path: "", input_reason: "read-failed" },
    { input_reason: "too-large" },
  ])(
    "retains valid declared diagnostics %j and denies the full validated record by default",
    (diagnostics) => {
      const envelope = { ...flat(), ...diagnostics };
      const stdout = JSON.stringify(envelope);
      const result = helper.parsePublicPsxCliOutput(stdout, acceptedStatus);
      expect(result).toEqual({
        error: canonical(),
        cli_error_envelope: envelope,
      });
      expect(JSON.stringify(result.cli_error_envelope)).toBe(stdout);
      expect(result.error).not.toHaveProperty("input_path");
      expect(result.error).not.toHaveProperty("input_reason");
      expect(() =>
        helper.parsePublicPsxCliOutput(stdout, { exitCode: 1, signal: null }),
      ).toThrow(stdout);
    },
  );

  it.each([
    "nested-error",
    "bare-label",
    "label-only",
    "missing-code",
    "unknown-code",
    "extra-field",
    "category",
    "retryable",
    "remediation",
    "details",
    "input-path-type",
    "input-reason-type",
    "input-reason-value",
  ])(
    "refuses invalid %s rather than manufacturing a canonical refusal",
    (kind) => {
      let value: unknown = flat();
      const changed = value as Record<string, unknown>;
      if (kind === "nested-error") value = { error: canonical() };
      if (kind === "bare-label") value = "Analysis failed";
      if (kind === "label-only") value = { error: "Analysis failed" };
      if (kind === "missing-code") delete changed.code;
      if (kind === "unknown-code") changed.code = "invented_error";
      if (kind === "extra-field")
        changed.unadvertised = "must survive rejection";
      if (kind === "category") changed.category = "invented_category";
      if (kind === "retryable") changed.retryable = "false";
      if (kind === "remediation")
        changed.remediation = { action: "", fallback: "extra" };
      if (kind === "details") changed.details = "invalid diagnostic carrier";
      if (kind === "input-path-type") changed.input_path = 42;
      if (kind === "input-reason-type")
        changed.input_reason = { reason: "invalid-json" };
      if (kind === "input-reason-value")
        changed.input_reason = "invented-reason";
      const bytes = JSON.stringify(value);
      expect(() =>
        helper.parsePublicPsxCliOutput(bytes, acceptedStatus),
      ).toThrow();
      expect(JSON.stringify(value)).toBe(bytes);
    },
  );

  it.each(["{", '{"error":', "not-json", ""])(
    "rejects malformed stdout %j",
    (stdout) => {
      expect(() =>
        helper.parsePublicPsxCliOutput(stdout, acceptedStatus),
      ).toThrow();
    },
  );
});

describe("P5-R6 exit/signal identity and strict complete canonical parity", () => {
  it.each([undefined, null, 0, 2, 1.5, "1"])(
    "refuses a declared error with invalid exit %j",
    (exitCode) => {
      expect(() =>
        helper.parsePublicPsxCliOutput(JSON.stringify(flat()), {
          exitCode,
          signal: null,
          allowError: true,
        }),
      ).toThrow();
    },
  );

  it.each([undefined, "SIGTERM", "SIGKILL"])(
    "refuses signaled or missing signal observation %j",
    (signal) => {
      expect(() =>
        helper.parsePublicPsxCliOutput(JSON.stringify(flat()), {
          exitCode: 1,
          signal,
          allowError: true,
        }),
      ).toThrow();
      expect(() =>
        helper.parsePublicPsxCliOutput(JSON.stringify(successEvidence()), {
          exitCode: 0,
          signal,
          allowError: true,
        }),
      ).toThrow();
    },
  );

  it("requires exit zero for successful Evidence even when allowError is enabled", () => {
    const evidence = successEvidence();
    const stdout = JSON.stringify(evidence);
    expect(
      helper.parsePublicPsxCliOutput(stdout, {
        exitCode: 0,
        signal: null,
        allowError: true,
      }),
    ).toEqual({ evidence });
    expect(() =>
      helper.parsePublicPsxCliOutput(stdout, acceptedStatus),
    ).toThrow();
  });

  it.each([
    "message",
    "path",
    "reason",
    "remediation",
    "nested-details",
    "missing-details",
  ])(
    "rejects a valid canonical %s disagreement with no diagnostic normalization",
    (kind) => {
      const left = canonical();
      const right = structuredClone(left);
      if (kind === "message") right.message = "Different producer reason";
      if (kind === "path") right.details!.path = "/different caller source.exe";
      if (kind === "reason") right.details!.reason = "Different input reason";
      if (kind === "remediation")
        right.remediation.action = "Different explicit action";
      if (kind === "nested-details")
        right.details!.retained = {
          token: "different caller token",
          offsets: [8, 17],
        };
      if (kind === "missing-details") delete right.details;
      const before = JSON.stringify([left, right]);
      helper.assertPublicPsxErrorParity(left, structuredClone(left));
      expect(() => helper.assertPublicPsxErrorParity(left, right)).toThrow();
      expect(JSON.stringify([left, right])).toBe(before);
    },
  );

  it("validates both parity operands instead of comparing malformed matching objects", () => {
    expect(() =>
      helper.assertPublicPsxErrorParity(
        { code: "target_unavailable" },
        { code: "target_unavailable" },
      ),
    ).toThrow();
  });
});

describe("P5-R6 invalid structured output retains supervised raw capture", () => {
  it("captures an undeclared nested CLI carrier before parser denial and settles the owned process", async () => {
    const stdout = JSON.stringify({ error: canonical() });
    const f = await publicBoundary(
      `process.stdout.write(${JSON.stringify(stdout)}); process.stderr.write('complete error diagnostics'); process.exitCode=1;`,
    );
    await expect(
      helper.invokePublicPsxCli(
        f.context,
        ["inspect-native-load-image", "unused owned malformed input"],
        { allowError: true },
      ),
    ).rejects.toThrow();
    const raw = f.events.find((event) => typeof event.stdout === "string");
    expect(raw).toMatchObject({
      stdout,
      stderr: "complete error diagnostics",
      exit_code: 1,
      signal: null,
    });
    expect(
      f.events.some(
        (event) => event.kind === "observation" && event.evidence !== undefined,
      ),
    ).toBe(false);
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.settlement.unresolved_owners).toEqual([]);
    expect(settled.settlement.verified_empty_lineage).toBe(true);
    expect(await readFile(join(f.parent, "events.jsonl"), "utf8")).toContain(
      stdout.replaceAll('"', '\\"'),
    );
  });
});
