import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SdkError, SdkErrorCode } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { createAnalysisProfile } from "../../../../src/domain/analysisProfile.js";
import { jsonValueSchema } from "../../../../src/domain/jsonValue.js";
import {
  createEvidence,
  type Evidence,
} from "../../../../src/domain/evidence.js";
import {
  type PsxLoadImage,
  type NativeLoadImageObservation,
} from "../../../../src/domain/native/nativeLoadImage.js";
import {
  psxImportObservationSchema,
  psxOriginalEvidenceRecordSchema,
} from "../../../../src/ghidra/GhidraImportConfiguration.js";
import { attestGhidraPsxLoadImage } from "../../../../src/ghidra/GhidraPsxLoadImageValues.js";
import {
  psxAppliedLoadImageObservation,
  psxFixtureAgreement,
  psxFixtureCommitment,
  psxFixtureOriginalRecord,
  psxFixtureSha256,
  psxImportBytes,
} from "../../../fixtures/ghidraPsxImport.js";

type Binding = {
  operation: string;
  parameters: Record<string, unknown>;
  sourceDigest: string;
  selectedProfile: unknown;
};

type Event = {
  sequence: number;
  kind: string;
  stage: string;
  [key: string]: unknown;
};
type Owner = {
  identity: Record<string, unknown>;
  close(): Promise<void>;
  retry(): Promise<void>;
};
type Outcome = {
  ok: boolean;
  failures: { stage: string; message: string }[];
  unpersisted_events: Event[];
  cases: { status: string }[];
  settlement: { unresolved_owners: Owner[]; remaining_roots: string[] };
};
type Context = {
  primary?: Error;
  resources: {
    owner: string;
    identity: Record<string, unknown>;
    close(): Promise<void>;
  }[];
  failures: unknown[];
  unpersisted_events: Event[];
  case(
    id: string,
    adapter: string,
    action: () => Promise<unknown>,
  ): Promise<unknown>;
};
type Session = {
  call(
    name: string,
    parameters?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  disconnect(): Promise<void>;
};
type Capture = {
  run_id: string;
  runtime_root: string;
  snapshot: { path: string; sha256: string };
  records: Record<string, { path: string; text: string; sha256: string }>;
};
type Association = { event_sequence: number; run_id: string; capture: Capture };
type Observation = Association & {
  mode: "native" | "mcp-cache";
  evidence: Evidence;
  binding: Binding;
};
type Route = {
  operation: string;
  parameters: Record<string, unknown>;
  argv: string[];
};
type Helper = {
  publicPsxSnapshotLimitation: string;
  publicPsxObservation(
    evidence: Evidence,
    binding: Binding,
    association: Association,
  ): Observation;
  createPublicPsxLiveExpectations(): {
    observe(
      evidence: Evidence,
      binding: Binding,
      association: Association,
    ): Observation;
    live(binding: Binding): Observation;
    missing(bindings: Binding[]): Binding[];
    freeze(bindings: Binding[]): Record<string, unknown>[];
    observations(): Observation[];
  };
  validatePublicPsxImageImport(
    record: Observation,
    binding: Binding,
    bytes: Buffer,
  ): unknown;
  assertPublicPsxLiveParity(
    cli: Observation,
    mcp: Observation,
    binding: Binding,
    bytes?: Buffer,
  ): {
    mode: string;
    differences: { path: string; own_runs: string[]; validated_by: string }[];
  };
  assertPublicPsxMcpReplay(
    replay: Observation,
    original: Observation,
    binding: Binding,
  ): void;
  assertPublicPsxCliExecution(
    evidence: Evidence,
    binding: Binding,
    execution: unknown,
    allocations: unknown[],
  ): unknown;
  qualifyPublicPsxRetainedCapture(
    allocation: unknown,
    components: unknown[],
  ): unknown;
  publicPsxSnapshotQueries(
    documents: unknown,
  ): [string, Record<string, unknown>][];
  compilePublicPsxSchemas(catalog: unknown): Map<string, unknown>;
  unwrapPublicPsxReply(
    reply: unknown,
    operation: string,
    schema: unknown,
    options?: Record<string, boolean>,
  ): Record<string, unknown>;
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
  validatePublicPsxEvidence(evidence: unknown, binding: Binding): unknown;
  assertPublicPsxStartupBinding(
    evidence: unknown,
    binding: Binding,
    commitment: unknown,
  ): unknown;
  assertPublicPsxParity(cli: unknown, mcp: unknown, binding: Binding): void;
  publicPsxFailure(cause: unknown): Record<string, unknown>;
  preflightPublicPsx(input: Record<string, unknown>): Promise<unknown>;
  createPublicPsxContext(input: Record<string, unknown>): Context;
  invokePublicPsxCli(
    context: Context,
    argv: string[],
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  settlePublicPsxContext(
    context: Context,
    postchecks?: (() => Promise<void>)[],
  ): Promise<Outcome>;
  connectPublicPsxMcp(context: Context): Promise<Session>;
  coordinatePublicPsxCancellation(
    input: Record<string, unknown>,
  ): Promise<{ status: string; allocated: unknown[] }>;
  assertPublicPsxCancellationOutcome(
    result: unknown,
    options: { mode: string; reason: Error; aborted: boolean },
  ): void;
  publicPsxSnapshotMutations(
    snapshot: unknown,
  ): { id: string; snapshot: unknown }[];
  redactPublicPsxEvent(event: unknown): Record<string, unknown>;
  publicPsxCliRoutes(source: string): Route[];
  publicPsxCliSnapshotRoutes(source: string, snapshot: string): Route[];
};
const helper = (await import(
  new URL("../../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as Helper;
const runner = (await import(
  new URL("../../../../scripts/verify-real-ghidra-psx.mjs", import.meta.url)
    .href
)) as {
  preflightPsxPublicRunner(
    args: string[],
    environment: Record<string, string>,
  ): Promise<unknown>;
};

const setup = async (
  script = "process.stdout.write('contradictory raw output');",
) => {
  const parent = await createTestTempDirectory("psx-public-verifier-");
  const workspace = join(parent, "workspace");
  await mkdir(workspace);
  const executableScript = join(parent, "owned launcher 雪.mjs");
  await writeFile(executableScript, script);
  const events: Event[] = [];
  const input = {
    executable: process.execPath,
    prefixArgs: [executableScript],
    environment: {
      PATH: process.env.PATH ?? "",
      TMPDIR: workspace,
      HOME: parent,
    },
    workspace,
    record: async (event: Event) => {
      events.push(event);
      await writeFile(
        join(parent, "events.jsonl"),
        `${JSON.stringify(event)}\n`,
        { flag: "a" },
      );
    },
  };
  return {
    parent,
    workspace,
    events,
    input,
    context: helper.createPublicPsxContext(input),
  };
};

describe("Phase 5 public verifier filesystem/process failure boundary (no native-provider claim)", () => {
  it.each([
    ["--binary", "private.exe"],
    ["--stage", "decoder"],
    ["--unknown"],
    ["--binary", "a", "--binary", "b"],
  ])(
    "rejects unsupported runner options %j before allocation",
    async (...args) => {
      await expect(runner.preflightPsxPublicRunner(args, {})).rejects.toThrow(
        "no target or stage",
      );
    },
  );

  it("requires an empty exact workspace before provider inspection", async () => {
    const test = await setup();
    await writeFile(join(test.workspace, "unrelated"), "preserve");
    await expect(helper.preflightPublicPsx(test.input)).rejects.toThrow(
      "Workspace must be empty",
    );
    expect(await readdir(test.workspace)).toEqual(["unrelated"]);
    expect(test.events).toEqual([]);
  });

  it("rejects a Ghidra dot-prefixed path component before native allocation", async () => {
    const parent = await createTestTempDirectory("psx-public-dotted-");
    const workspace = join(parent, ".cache", "workspace");
    await mkdir(workspace, { recursive: true });
    await expect(
      helper.preflightPublicPsx({
        executable: process.execPath,
        prefixArgs: [],
        environment: { TMPDIR: workspace },
        workspace,
        record: async () => {},
      }),
    ).rejects.toThrow("dot-prefixed");
    expect(await readdir(workspace)).toEqual([]);
  });

  it("records the explicit executable, separate argv and unrelated cwd before rejecting the first raw contradiction", async () => {
    const test = await setup();
    await expect(
      helper.invokePublicPsxCli(test.context, [
        "inspect-native-load-image",
        "caller path 雪.exe",
      ]),
    ).rejects.toThrow();
    expect(test.events[0]).toMatchObject({
      kind: "invocation",
      executable: process.execPath,
      argv: [
        test.input.prefixArgs[0],
        "inspect-native-load-image",
        "caller path 雪.exe",
        "--provider",
        "ghidra",
        "--json",
      ],
      cwd: test.workspace,
    });
    expect(
      test.events.find((event) => event.kind === "raw_result"),
    ).toMatchObject({ stdout: "contradictory raw output", exit_code: 0 });
    const settled = await helper.settlePublicPsxContext(test.context);
    expect(settled.settlement.unresolved_owners).toEqual([]);
    expect(await readFile(join(test.parent, "events.jsonl"), "utf8")).toContain(
      "contradictory raw output",
    );
  });

  it("retains complete streams beyond supervisor diagnostic retention", async () => {
    const test = await setup(
      "process.stdout.write('x'.repeat(1100000)); process.stderr.write('z'.repeat(1100000));",
    );
    await expect(
      helper.invokePublicPsxCli(test.context, ["inspect"]),
    ).rejects.toThrow();
    const raw = test.events.find((event) => event.kind === "raw_result");
    expect(typeof raw?.stdout === "string" ? raw.stdout.length : null).toBe(
      1100000,
    );
    expect(typeof raw?.stderr === "string" ? raw.stderr.length : null).toBe(
      1100000,
    );
    expect(
      typeof raw?.stdout === "string" ? new Set(raw.stdout).size : null,
    ).toBe(1);
    expect(
      typeof raw?.stderr === "string" ? new Set(raw.stderr).size : null,
    ).toBe(1);
    await helper.settlePublicPsxContext(test.context);
  });

  it("does not admit a valid CLI refusal when its durable raw capture failed", async () => {
    const envelope = {
      error: "Analysis failed",
      code: "target_unavailable",
      category: "unavailable",
      message: "Original source cannot be opened",
      retryable: false,
      remediation: { action: "Check the original source" },
      details: { path: "caller path 雪.exe", reason: "Original reason" },
    };
    const stdout = JSON.stringify(envelope);
    const test = await setup(
      `process.stdout.write(${JSON.stringify(stdout)}); process.exitCode=1;`,
    );
    test.context = helper.createPublicPsxContext({
      ...test.input,
      record: async (event: Event) => {
        if (event.adapter === "cli" && event.kind === "raw_result")
          throw Object.assign(new Error("raw refusal capture denied"), {
            code: "EACCES",
          });
        await test.input.record(event);
      },
    });
    await expect(
      helper.invokePublicPsxCli(test.context, ["inspect-native-load-image"], {
        allowError: true,
      }),
    ).rejects.toThrow("Durable public capture failed");
    expect(test.context.unpersisted_events).toContainEqual(
      expect.objectContaining({
        kind: "raw_result",
        stdout,
        exit_code: 1,
        signal: null,
      }),
    );
    const settled = await helper.settlePublicPsxContext(test.context);
    expect(settled.ok).toBe(false);
    expect(settled.settlement.unresolved_owners).toEqual([]);
    expect(settled.unpersisted_events).toContainEqual(
      expect.objectContaining({ stdout }),
    );
  });
});

const admissionReplyFixture = () => {
  const operation = "inspect_native_load_image";
  const schema = helper
    .compilePublicPsxSchemas({
      tools: [
        {
          name: operation,
          inputSchema: {
            $schema: "https://json-schema.org/draft/2020-12/schema",
            type: "object",
            properties: {},
            additionalProperties: false,
          },
          outputSchema: { type: "object" },
        },
      ],
    })
    .get(operation);
  const text =
    'Input validation error: Invalid arguments for tool inspect_native_load_image: Unrecognized key: "document"';
  const reply = { content: [{ type: "text", text }], isError: true };
  const projection = (code = "invalid_request") => ({
    code,
    category: "invalid_input",
    message: "Original application reason",
    retryable: true,
    remediation: { action: "Correct arguments" },
  });
  const typed = (code?: string) => ({
    content: [
      { type: "text", text: JSON.stringify({ error: projection(code) }) },
    ],
    isError: true,
  });
  return { operation, schema, reply, text, projection, typed };
};

describe("P5-R2 reply format and explicit admission controls", () => {
  it("exposes exact unstructured SDK content only in the intentional mode, preserving the original reply", () => {
    const f = admissionReplyFixture();
    const before = JSON.stringify(f.reply);
    for (const options of [
      {},
      { allowError: true },
      { allowInvalidInput: true },
    ])
      expect(() =>
        helper.unwrapPublicPsxReply(f.reply, f.operation, f.schema, options),
      ).toThrow("unstructured MCP tool error");
    const parsed = helper.unwrapPublicPsxReply(f.reply, f.operation, f.schema, {
      allowUnstructuredToolError: true,
    });
    expect(parsed).not.toHaveProperty("error");
    expect(parsed).not.toHaveProperty("evidence");
    expect(
      helper.assertPublicPsxImageAdmissionRefusal(
        parsed,
        f.operation,
        { document: "not-admitted" },
        f.schema,
      ),
    ).toMatchObject({
      category: "sdk-input-validation-refusal",
      content: f.reply.content,
    });
    expect(JSON.stringify(f.reply)).toBe(before);
  });

  it.each(["invalid_request", "capability_unavailable"])(
    "retains canonical REA %s code instead of classifying SDK text",
    (code) => {
      const f = admissionReplyFixture();
      const reply = f.typed(code);
      expect(
        helper.unwrapPublicPsxReply(reply, f.operation, f.schema, {
          allowError: true,
        }),
      ).toEqual({ error: f.projection(code) });
      expect(() =>
        helper.unwrapPublicPsxReply(reply, f.operation, f.schema, {
          allowUnstructuredToolError: true,
        }),
      ).toThrow("Original application reason");
      const consistent = {
        ...reply,
        structuredContent: { error: f.projection(code) },
      };
      expect(
        helper.unwrapPublicPsxReply(consistent, f.operation, f.schema, {
          allowError: true,
        }),
      ).toEqual({ error: f.projection(code) });
    },
  );

  it.each([
    "malformed-json",
    "invalid-projection",
    "conflicting-carriers",
    "plain-structured-conflict",
    "non-json-success",
    "missing-error-flag",
    "wrong-schema",
  ])("rejects %s without converting it into a refusal", (kind) => {
    const f = admissionReplyFixture();
    let reply: unknown = f.reply;
    let operation = f.operation;
    if (kind === "malformed-json")
      reply = { isError: true, content: [{ type: "text", text: '{"error":' }] };
    if (kind === "invalid-projection")
      reply = {
        isError: true,
        content: [
          { type: "text", text: '{"error":{"code":"invalid_request"}}' },
        ],
      };
    if (kind === "conflicting-carriers")
      reply = {
        ...f.typed(),
        structuredContent: { error: f.projection("capability_unavailable") },
      };
    if (kind === "plain-structured-conflict")
      reply = { ...f.reply, structuredContent: { error: f.projection() } };
    if (kind === "non-json-success") reply = { ...f.reply, isError: false };
    if (kind === "missing-error-flag") reply = { content: f.reply.content };
    if (kind === "wrong-schema") operation = "binary_session";
    expect(() =>
      helper.unwrapPublicPsxReply(reply, operation, f.schema, {
        allowError: true,
        allowUnstructuredToolError: true,
      }),
    ).toThrow();
  });
});

describe("P5-R2 literal producer expectation and capture ownership", () => {
  it.each([
    "wrong-tool",
    "wrong-field",
    "arbitrary-text",
    "wrong-arguments",
    "typed-error",
  ])("does not accept %s as strict-image admission proof", (kind) => {
    const f = admissionReplyFixture();
    let reply: unknown = f.reply;
    let parameters: unknown = { document: "not-admitted" };
    if (kind === "wrong-tool")
      reply = {
        isError: true,
        content: [
          {
            type: "text",
            text: f.text.replace("inspect_native_load_image", "binary_session"),
          },
        ],
      };
    if (kind === "wrong-field")
      reply = {
        isError: true,
        content: [
          { type: "text", text: f.text.replace('"document"', '"other"') },
        ],
      };
    if (kind === "arbitrary-text")
      reply = {
        isError: true,
        content: [{ type: "text", text: "Provider unavailable" }],
      };
    if (kind === "wrong-arguments") parameters = { other: "not-admitted" };
    if (kind === "typed-error") reply = f.typed();
    const parsed = helper.unwrapPublicPsxReply(reply, f.operation, f.schema, {
      allowError: true,
      allowUnstructuredToolError: true,
    });
    expect(() =>
      helper.assertPublicPsxImageAdmissionRefusal(
        parsed,
        f.operation,
        parameters,
        f.schema,
      ),
    ).toThrow();
  });

  it("persists the original raw refusal before default denial or malformed JSON parsing fails", async () => {
    const test = await setup();
    const f = admissionReplyFixture();
    for (const reply of [
      f.reply,
      { isError: true, content: [{ type: "text", text: '{"error":' }] },
    ]) {
      const before = test.events.length;
      await expect(
        helper.capturePublicPsxReply(
          test.context,
          reply,
          f.operation,
          f.schema,
          { allowError: true },
        ),
      ).rejects.toThrow();
      expect(test.events.slice(before)).toMatchObject([
        { kind: "raw_result", reply },
      ]);
      expect(
        await readFile(join(test.parent, "events.jsonl"), "utf8"),
      ).toContain(JSON.stringify(reply));
    }
  });

  it("keeps durable capture failure separate and never reaches refusal classification", async () => {
    const test = await setup();
    const f = admissionReplyFixture();
    const context = helper.createPublicPsxContext({
      ...test.input,
      record: async () => {
        throw new Error("capture denied");
      },
    });
    await expect(
      helper.capturePublicPsxReply(context, f.reply, f.operation, f.schema, {
        allowUnstructuredToolError: true,
      }),
    ).rejects.toThrow("Durable public capture failed");
    expect(context.unpersisted_events).toMatchObject([
      { kind: "raw_result", reply: f.reply },
    ]);
  });
});

const namedEvidenceFixture = () => {
  const sourceDigest = "a".repeat(64);
  const target = {
    path: "/generated source 雪.exe",
    sha256: sourceDigest,
    format: "ps-x-exe" as const,
    architecture: "mips" as const,
  };
  const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
  const workflow = {
    id: "rea-workflow",
    name: "REA composed investigation workflow",
    version: "1",
  };
  const profile = createAnalysisProfile(provider, {
    psx_import: { source_sha256: sourceDigest },
    startup_agreement: "psx-observed-import-and-provenance-v3",
    psx_source_provenance: "rea-psx-filebytes-rebind-v2",
    psx_preparation_transaction: "exclusive-top-level-v1",
    instruction_flow_evidence: "decoded-return-before-jump-and-delay-slots-v2",
  });
  const wrap = (upstream = profile, revision = 2) =>
    createAnalysisProfile(workflow, {
      upstream_analysis_profile: upstream,
      workflow_revision: revision,
    });
  const overview = createEvidence(target, workflow, {
    operation: "binary_overview",
    parameters: {},
    analysisProfile: wrap(),
    result: {
      document: "source",
      segments: [],
      segment_count: 0,
      procedure_count: 1,
      string_count: 0,
    },
    confidence: "derived",
    limitations: ["Derived by an REA composed workflow."],
  });
  const native = createEvidence(target, provider, {
    operation: "inspect_native_instruction",
    parameters: { address: "0x80010000" },
    analysisProfile: profile,
    rawResult: { retained: "native producer evidence" },
    result: {
      address: "0x80010000",
      status: "decoded",
      procedure: null,
      architecture: "mips",
      mode: "default",
      bytes: "00000000",
      length: 4,
      mnemonic: "nop",
      raw_disassembly: "nop",
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
  });
  const remake = (original: Evidence, changes: Partial<Evidence>) =>
    createEvidence(target, changes.provider ?? original.provider, {
      operation: changes.operation ?? original.operation,
      parameters: changes.parameters ?? original.parameters,
      result: changes.normalized_result ?? original.normalized_result,
      rawResult: original.raw_result,
      analysisProfile: changes.analysis_profile ?? original.analysis_profile!,
      confidence: changes.confidence ?? original.confidence,
      limitations: changes.limitations ?? original.limitations,
      authority: changes.authority ?? original.authority,
      environment: changes.environment ?? original.environment,
      locations: changes.locations ?? original.locations,
      evidenceLinks: changes.evidence_links ?? original.evidence_links,
    });
  const binding = (evidence: Evidence): Binding => ({
    operation: evidence.operation,
    parameters: evidence.parameters,
    sourceDigest,
    selectedProfile: profile,
  });
  return {
    profile,
    provider,
    workflow,
    overview,
    native,
    wrap,
    remake,
    binding,
  };
};

const association = (
  runId = "00000000-0000-4000-8000-000000000001",
  sequence = 1,
): Association => ({
  event_sequence: sequence,
  run_id: runId,
  capture: {
    run_id: runId,
    runtime_root: `/generated/${runId}`,
    snapshot: { path: `/generated/${runId}/target`, sha256: "a".repeat(64) },
    records: {},
  },
});

describe("P5-R4 immutable first live Evidence ownership", () => {
  it("keeps the first complete record through repeats, cache, later queries and freeze", () => {
    const f = namedEvidenceFixture();
    const binding = f.binding(f.native);
    const collection = helper.createPublicPsxLiveExpectations();
    const first = collection.observe(f.native, binding, association());
    const firstBytes = JSON.stringify(first);
    // Reproduce the old overwrite rule independently: last-write ownership loses
    // the original native observation when the cache observation arrives.
    const oldOwners = new Map([[JSON.stringify(binding), first]]);
    const cached = f.remake(f.native, {
      limitations: [
        ...f.native.limitations,
        helper.publicPsxSnapshotLimitation,
      ],
    });
    const replay = collection.observe(
      cached,
      binding,
      association(undefined, 2),
    );
    oldOwners.set(JSON.stringify(binding), replay);
    expect(oldOwners.get(JSON.stringify(binding))!.mode).toBe("mcp-cache");
    const repeated = f.remake(f.native, {});
    collection.observe(repeated, binding, association(undefined, 3));
    expect(collection.live(binding)).toBe(first);
    const manifest = collection.freeze([binding]);
    expect(manifest).toMatchObject([
      {
        evidence_id: f.native.evidence_id,
        event_sequence: 1,
        provenance_mode: "native",
      },
    ]);
    collection.observe(repeated, binding, association(undefined, 4));
    collection.observe(cached, binding, association(undefined, 5));
    collection.observe(
      f.overview,
      f.binding(f.overview),
      association(undefined, 6),
    );
    expect(collection.live(binding)).toBe(first);
    expect(collection.missing([f.binding(f.overview)])).toEqual([
      f.binding(f.overview),
    ]);
    expect(collection.observations()).toHaveLength(6);
    expect(() => {
      first.evidence.limitations.push("later mutation");
    }).toThrow();
    expect(() => {
      manifest[0]!.event_sequence = 99;
    }).toThrow();
    f.native.limitations.push("caller mutation after capture");
    const chronology = collection.observations();
    chronology.pop();
    expect(collection.observations()).toHaveLength(6);
    expect(JSON.stringify(first)).toBe(firstBytes);
    expect(() => collection.freeze([binding])).toThrow("already frozen");
  });

  it("cached Evidence cannot satisfy a missing live owner or its freeze", () => {
    const f = namedEvidenceFixture();
    const binding = f.binding(f.native);
    const cached = f.remake(f.native, {
      limitations: [helper.publicPsxSnapshotLimitation],
    });
    const collection = helper.createPublicPsxLiveExpectations();
    collection.observe(cached, binding, association());
    expect(collection.missing([binding])).toEqual([binding]);
    expect(() => collection.live(binding)).toThrow("Missing exact first live");
    expect(() => collection.freeze([binding])).toThrow(
      "Missing exact first live",
    );
    const first = collection.observe(
      f.native,
      binding,
      association(undefined, 2),
    );
    expect(collection.live(binding)).toBe(first);
  });

  it.each(["operation", "parameters", "source", "profile"])(
    "requires the exact %s live key",
    (kind) => {
      const f = namedEvidenceFixture();
      const binding = f.binding(f.native);
      const collection = helper.createPublicPsxLiveExpectations();
      collection.observe(f.native, binding, association());
      const changed = structuredClone(binding);
      if (kind === "operation")
        changed.operation = "resolve_native_call_targets";
      if (kind === "parameters") changed.parameters = { address: "0x80010004" };
      if (kind === "source") changed.sourceDigest = "b".repeat(64);
      if (kind === "profile")
        changed.selectedProfile = createAnalysisProfile(f.provider, {
          ...f.profile.parameters,
          independent_revision: 2,
        });
      expect(collection.missing([changed])).toEqual([changed]);
      expect(() => collection.live(changed)).toThrow(
        "Missing exact first live",
      );
      expect(() => collection.freeze([binding, changed])).toThrow();
    },
  );

  it("retains truthful cache provenance and full metadata disagreement", () => {
    const f = namedEvidenceFixture();
    const binding = f.binding(f.native);
    const first = helper.publicPsxObservation(f.native, binding, association());
    const cached = helper.publicPsxObservation(
      f.remake(f.native, { limitations: [helper.publicPsxSnapshotLimitation] }),
      binding,
      association(undefined, 2),
    );
    const bytes = JSON.stringify(cached);
    helper.assertPublicPsxMcpReplay(cached, first, binding);
    expect(() =>
      helper.assertPublicPsxLiveParity(first, cached, binding),
    ).toThrow("provenance mode mismatch");
    const removedMarker = structuredClone(cached);
    removedMarker.evidence = f.remake(f.native, { limitations: [] });
    expect(() =>
      helper.assertPublicPsxMcpReplay(removedMarker, first, binding),
    ).toThrow();
    expect(() =>
      helper.assertPublicPsxLiveParity(first, removedMarker, binding),
    ).toThrow();
    const metadataChanged = structuredClone(first);
    metadataChanged.evidence = f.remake(f.native, {
      evidence_links: [`ev_${"9".repeat(64)}`],
    });
    expect(() =>
      helper.assertPublicPsxLiveParity(first, metadataChanged, binding),
    ).toThrow();
    expect(JSON.stringify(cached)).toBe(bytes);
    expect(first.evidence.raw_result).toEqual(f.native.raw_result);
  });
});

/** Original generated bytes and separately committed simulated import records.
 * This proves verifier binding/checks; no native import or private state manifest
 * reconstruction is claimed by these producer-bound commitments. */
const imageImportFixture = (
  index: 1 | 2,
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
  const runId = `00000000-0000-4000-8000-00000000000${index}`;
  const owned = association(runId, index);
  owned.capture.snapshot.sha256 = sourceDigest;
  const measured = psxAppliedLoadImageObservation(bytes);
  const metadata = measured.psx!.provenance.metadata_preservation;
  for (const rows of [
    metadata.label_history.before,
    metadata.label_history.after,
    measured.psx!.current_label_history,
  ]) {
    for (const row of rows)
      if (row.modification_time_ms !== null)
        row.modification_time_ms = String(index * 1000 + row.ordinal);
  }
  // The preserved outside-payload row has the same clock within each import.
  metadata.label_history.after[0]!.modification_time_ms =
    metadata.label_history.before[2]!.modification_time_ms;
  measured.psx!.current_label_history = structuredClone(
    metadata.label_history.after,
  );
  mutate?.(measured);
  metadata.original_state_sha256 = psxFixtureSha256(
    Buffer.from(
      JSON.stringify({ runId, journal: metadata.label_history.before }),
    ),
  );
  metadata.adapted_state_sha256 = psxFixtureSha256(
    Buffer.from(
      JSON.stringify({ runId, journal: metadata.label_history.after }),
    ),
  );
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
  const baseline = psxFixtureAgreement({
    commitment: psxFixtureCommitment(owned.capture.snapshot.path, bytes),
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
  const before = {
    ...baseline,
    provenance: structuredClone(measured.psx!.provenance),
  };
  const beforeText = `${JSON.stringify(psxImportObservationSchema.parse(before))}\n`;
  for (const [name, text] of [
    ["psx-import-before.json", beforeText],
    ["psx-provenance-original.json", originalText],
  ]) {
    owned.capture.records[name!] = {
      path: join(owned.capture.runtime_root, name!),
      text: text!,
      sha256: psxFixtureSha256(Buffer.from(text!)),
    };
  }
  const attested = attestGhidraPsxLoadImage(bytes, sourceDigest, measured);
  if (!attested.ok) throw new Error(attested.error);
  const target = {
    path: "/generated source 雪.exe",
    sha256: sourceDigest,
    format: "ps-x-exe" as const,
    architecture: "mips" as const,
  };
  const evidence = createEvidence(target, provider, {
    operation: "inspect_native_load_image",
    parameters: {},
    analysisProfile: profile,
    rawResult: jsonValueSchema.parse(measured),
    result: jsonValueSchema.parse(attested.value),
  });
  const binding: Binding = {
    operation: evidence.operation,
    parameters: {},
    sourceDigest,
    selectedProfile: profile,
  };
  const remake = (changes: Partial<Evidence>) =>
    createEvidence(target, provider, {
      operation: evidence.operation,
      parameters: evidence.parameters,
      analysisProfile: profile,
      rawResult: evidence.raw_result,
      result: changes.normalized_result ?? evidence.normalized_result,
      predicateType: evidence.predicate_type,
      confidence: evidence.confidence,
      authority: evidence.authority,
      environment: evidence.environment,
      limitations: changes.limitations ?? evidence.limitations,
      locations: evidence.locations,
      evidenceLinks: evidence.evidence_links,
    });
  return {
    bytes,
    binding,
    remake,
    record: helper.publicPsxObservation(evidence, binding, owned),
  };
};

describe("P5-R4 independently bound image comparison (synthetic records only)", () => {
  it("accepts all six own-import difference families and retains the exact values/captures", () => {
    const left = imageImportFixture(1);
    const right = imageImportFixture(2);
    const before = JSON.stringify([left.record, right.record]);
    helper.validatePublicPsxImageImport(left.record, left.binding, left.bytes);
    helper.validatePublicPsxImageImport(
      right.record,
      right.binding,
      right.bytes,
    );
    const comparison = helper.assertPublicPsxLiveParity(
      left.record,
      right.record,
      left.binding,
      left.bytes,
    );
    expect(comparison.mode).toBe("independent-native-imports");
    const root = "observations.psx.provenance.metadata_preservation";
    expect(
      new Set(
        comparison.differences.map(({ path }) =>
          path.replace(/\[\d+\]/gu, "[*]"),
        ),
      ),
    ).toEqual(
      new Set([
        `${root}.original_state_sha256`,
        `${root}.adapted_state_sha256`,
        `${root}.original_record_sha256`,
        `${root}.label_history.before[*].modification_time_ms`,
        `${root}.label_history.after[*].modification_time_ms`,
        "observations.psx.current_label_history[*].modification_time_ms",
      ]),
    );
    for (const difference of comparison.differences) {
      expect(difference.own_runs).toEqual([
        left.record.run_id,
        right.record.run_id,
      ]);
      expect(difference.validated_by).not.toBe("");
    }
    expect(JSON.stringify([left.record, right.record])).toBe(before);
  });

  it.each([
    "run",
    "profile",
    "source",
    "raw-record-sha",
    "missing-capture",
    "original-state",
    "adapted-state",
    "before-journal",
    "after-journal",
    "current-journal",
  ])("rejects invalid own-import %s", (kind) => {
    const f = imageImportFixture(1);
    const changed = structuredClone(f.record);
    const image = changed.evidence.normalized_result as PsxLoadImage;
    const metadata = image.observations.psx!.provenance.metadata_preservation;
    if (kind === "run") changed.run_id = "00000000-0000-4000-8000-000000000099";
    if (kind === "profile" || kind === "source") {
      const raw = changed.capture.records["psx-provenance-original.json"]!;
      const original = JSON.parse(raw.text) as {
        commitment: { profile_digest: string; source_sha256: string };
      };
      if (kind === "profile")
        original.commitment.profile_digest = "9".repeat(64);
      else original.commitment.source_sha256 = "9".repeat(64);
      raw.text = `${JSON.stringify(original)}\n`;
      raw.sha256 = psxFixtureSha256(Buffer.from(raw.text));
    }
    if (kind === "raw-record-sha")
      changed.capture.records["psx-provenance-original.json"]!.text += " ";
    if (kind === "missing-capture")
      delete changed.capture.records["psx-import-before.json"];
    if (kind === "original-state")
      metadata.original_state_sha256 = "9".repeat(64);
    if (kind === "adapted-state")
      metadata.adapted_state_sha256 = "9".repeat(64);
    if (kind === "before-journal")
      metadata.label_history.before[0]!.modification_time_ms = "999";
    if (kind === "after-journal")
      metadata.label_history.after[1]!.modification_time_ms = "999";
    if (kind === "current-journal")
      image.observations.psx!.current_label_history[0]!.modification_time_ms =
        "9223372036854775808";
    changed.evidence = f.remake({
      normalized_result: changed.evidence.normalized_result,
    });
    expect(() =>
      helper.assertPublicPsxLiveParity(changed, f.record, f.binding, f.bytes),
    ).toThrow();
  });

  it.each(["non-time-label", "unlisted-source-name"])(
    "rejects a separately valid but differing %s field",
    (kind) => {
      const left = imageImportFixture(1);
      const right = imageImportFixture(2, (measured) => {
        if (kind === "non-time-label")
          measured.psx!.current_label_history[1]!.label = "different label";
        else measured.source_files[0]!.name = "different source display";
      });
      helper.validatePublicPsxImageImport(
        right.record,
        right.binding,
        right.bytes,
      );
      expect(() =>
        helper.assertPublicPsxLiveParity(
          left.record,
          right.record,
          left.binding,
          left.bytes,
        ),
      ).toThrow("Unlisted live image semantic difference");
    },
  );
});

describe("P5-R4 replay and native execution ownership", () => {
  it("requires complete same-run replay equality including all journal clocks and hashes", () => {
    const f = imageImportFixture(1);
    const replay = helper.publicPsxObservation(
      f.remake({
        limitations: [
          ...f.record.evidence.limitations,
          helper.publicPsxSnapshotLimitation,
        ],
      }),
      f.binding,
      { ...f.record, event_sequence: 3 },
    );
    helper.assertPublicPsxMcpReplay(replay, f.record, f.binding);
    const changed = structuredClone(replay);
    (
      changed.evidence.normalized_result as PsxLoadImage
    ).observations.psx!.current_label_history[1]!.modification_time_ms = "999";
    changed.evidence = f.remake({
      limitations: changed.evidence.limitations,
      normalized_result: changed.evidence.normalized_result,
    });
    expect(() =>
      helper.assertPublicPsxMcpReplay(changed, f.record, f.binding),
    ).toThrow("normalized_result disagreement");
    expect(() =>
      helper.assertPublicPsxLiveParity(f.record, replay, f.binding, f.bytes),
    ).toThrow("provenance mode mismatch");
  });

  it("native CLI requires its owned startup and rejects missing or replay execution modes", () => {
    const f = imageImportFixture(1);
    const caseId = "generated-native-binding";
    const capture = f.record.capture;
    const allocation = {
      sequence: 1,
      stage: "native-allocation",
      kind: "observation",
      adapter: "cli",
      case_id: caseId,
      runtime: {
        root: capture.runtime_root,
        run_id: capture.run_id,
        ownership: { run_id: capture.run_id },
        snapshot: capture.snapshot,
      },
    };
    const components = Object.entries(capture.records).map(
      ([name, record], index) => ({
        sequence: index + 2,
        stage: "runtime-capture",
        kind: "raw_result",
        adapter: "cli",
        case_id: caseId,
        runtime_root: capture.runtime_root,
        record_name: name,
        text: record.text,
        sha256: record.sha256,
      }),
    );
    const retained = helper.qualifyPublicPsxRetainedCapture(
      allocation,
      components,
    );
    expect(
      helper.assertPublicPsxCliExecution(
        f.record.evidence,
        f.binding,
        { mode: "native" },
        [retained],
      ),
    ).toMatchObject({ mode: "native", run_id: f.record.run_id });
    expect(() =>
      helper.assertPublicPsxCliExecution(
        f.record.evidence,
        f.binding,
        { mode: "native" },
        [],
      ),
    ).toThrow("exact owned native runtime");
    expect(() =>
      helper.assertPublicPsxCliExecution(
        f.record.evidence,
        f.binding,
        undefined,
        [f.record.capture],
      ),
    ).toThrow("explicit execution mode");
    const cached = f.remake({
      limitations: [
        ...f.record.evidence.limitations,
        helper.publicPsxSnapshotLimitation,
      ],
    });
    expect(() =>
      helper.assertPublicPsxCliExecution(
        cached,
        f.binding,
        { mode: "native" },
        [f.record.capture],
      ),
    ).toThrow("cached Evidence");
  });
});

describe("P5-R1 named Evidence ownership controls (generated records)", () => {
  it("accepts the workflow wrapper and native record without rewriting either observation", () => {
    const fixture = namedEvidenceFixture();
    for (const value of [fixture.overview, fixture.native]) {
      const before = JSON.stringify(value);
      expect(
        helper.validatePublicPsxEvidence(value, fixture.binding(value)),
      ).toEqual(fixture.profile);
      expect(JSON.stringify(value)).toBe(before);
    }
    expect(fixture.overview.analysis_profile).not.toEqual(fixture.profile);
    expect(fixture.overview.raw_result).toBeNull();
    expect(fixture.overview.confidence).toBe("derived");
  });

  it("rejects workflow ownership on a native operation and native ownership on the workflow", () => {
    const f = namedEvidenceFixture();
    const nativeWrapped = f.remake(f.native, {
      provider: f.workflow,
      analysis_profile: f.wrap(),
      confidence: "derived",
      limitations: f.overview.limitations,
    });
    const overviewRelabeled = f.remake(f.overview, {
      provider: f.provider,
      analysis_profile: f.profile,
    });
    expect(() =>
      helper.validatePublicPsxEvidence(nativeWrapped, f.binding(f.native)),
    ).toThrow();
    expect(() =>
      helper.validatePublicPsxEvidence(
        overviewRelabeled,
        f.binding(f.overview),
      ),
    ).toThrow();
  });

  it.each(["operation", "parameters", "source", "selected-profile"])(
    "rejects an independent mismatched %s invocation/session binding",
    (kind) => {
      const f = namedEvidenceFixture();
      const binding = f.binding(f.overview);
      if (kind === "operation")
        binding.operation = "inspect_native_instruction";
      if (kind === "parameters")
        binding.parameters = { document: "not admitted" };
      if (kind === "source") binding.sourceDigest = "b".repeat(64);
      if (kind === "selected-profile")
        binding.selectedProfile = createAnalysisProfile(f.provider, {
          ...f.profile.parameters,
          independent_revision: 2,
        });
      expect(() =>
        helper.validatePublicPsxEvidence(f.overview, binding),
      ).toThrow();
    },
  );
});

describe("P5-R1 committed upstream and derived provenance controls", () => {
  it.each([
    "absent",
    "malformed",
    "non-ghidra",
    "changed",
    "revision",
    "stale-upstream",
    "stale-outer",
  ])("rejects %s workflow commitment", (kind) => {
    const f = namedEvidenceFixture();
    let profile = f.wrap();
    if (kind === "absent")
      profile = createAnalysisProfile(f.workflow, { workflow_revision: 2 });
    if (kind === "malformed")
      profile = createAnalysisProfile(f.workflow, {
        upstream_analysis_profile: { provider: f.provider },
        workflow_revision: 2,
      });
    if (kind === "non-ghidra")
      profile = f.wrap(
        createAnalysisProfile(
          { ...f.provider, id: "hopper" },
          f.profile.parameters,
        ),
      );
    if (kind === "changed")
      profile = f.wrap(
        createAnalysisProfile(f.provider, {
          ...f.profile.parameters,
          independent_revision: 2,
        }),
      );
    if (kind === "revision") profile = f.wrap(f.profile, 1);
    let value = f.remake(f.overview, { analysis_profile: profile });
    if (kind === "stale-upstream") {
      const upstream = { ...f.profile, digest: "0".repeat(64) };
      value = f.remake(f.overview, { analysis_profile: f.wrap(upstream) });
    }
    if (kind === "stale-outer") {
      value = structuredClone(value);
      value.analysis_profile!.digest = "0".repeat(64);
    }
    expect(() =>
      helper.validatePublicPsxEvidence(value, f.binding(f.overview)),
    ).toThrow();
  });

  it.each(["confidence", "limitation", "provider"])(
    "rejects lost workflow %s ownership/provenance",
    (kind) => {
      const f = namedEvidenceFixture();
      const changes: Partial<Evidence> =
        kind === "confidence"
          ? { confidence: "observed" }
          : kind === "limitation"
            ? { limitations: [] }
            : {
                provider: { ...f.workflow, name: "Different owner" },
                analysis_profile: createAnalysisProfile(
                  { ...f.workflow, name: "Different owner" },
                  f.wrap().parameters,
                ),
              };
      expect(() =>
        helper.validatePublicPsxEvidence(
          f.remake(f.overview, changes),
          f.binding(f.overview),
        ),
      ).toThrow();
    },
  );
});

describe("P5-R1 startup identity and full outer parity", () => {
  it("binds workflow/native startup to execution digest and rejects the composed outer digest", () => {
    const f = namedEvidenceFixture();
    const commitment = {
      source_sha256: f.binding(f.overview).sourceDigest,
      profile_digest: f.profile.digest,
    };
    for (const value of [f.overview, f.native])
      expect(
        helper.assertPublicPsxStartupBinding(
          value,
          f.binding(value),
          commitment,
        ),
      ).toEqual(f.profile);
    expect(() =>
      helper.assertPublicPsxStartupBinding(f.overview, f.binding(f.overview), {
        ...commitment,
        profile_digest: f.overview.analysis_profile!.digest,
      }),
    ).toThrow();
    expect(() =>
      helper.assertPublicPsxStartupBinding(f.native, f.binding(f.native), {
        ...commitment,
        profile_digest: f.overview.analysis_profile!.digest,
      }),
    ).toThrow();
  });

  it("compares original workflow ownership, result and derived provenance", () => {
    const f = namedEvidenceFixture();
    const before = JSON.stringify(f.overview);
    helper.assertPublicPsxParity(
      f.overview,
      structuredClone(f.overview),
      f.binding(f.overview),
    );
    expect(JSON.stringify(f.overview)).toBe(before);
    for (const changed of [
      f.remake(f.overview, {
        limitations: [
          ...f.overview.limitations,
          "additional derived limitation",
        ],
      }),
      f.remake(f.overview, {
        normalized_result: {
          ...(f.overview.normalized_result as Record<string, never>),
          procedure_count: 2,
        },
      }),
      f.remake(f.overview, {
        analysis_profile: f.wrap(
          createAnalysisProfile(f.provider, {
            ...f.profile.parameters,
            independent_revision: 2,
          }),
        ),
      }),
      f.remake(f.overview, {
        provider: f.provider,
        analysis_profile: f.profile,
      }),
    ])
      expect(() =>
        helper.assertPublicPsxParity(
          changed,
          f.overview,
          f.binding(f.overview),
        ),
      ).toThrow();
    expect(() =>
      helper.assertPublicPsxParity(f.native, f.overview, f.binding(f.overview)),
    ).toThrow();
  });
});

describe("Phase 5 capture and retained ownership failures", () => {
  it("preserves a primary interruption and raw-capture failure independently", async () => {
    const test = await setup("setTimeout(() => {}, 10000);");
    const context = helper.createPublicPsxContext({
      ...test.input,
      record: async (event: Event) => {
        if (event.kind === "raw_result")
          throw Object.assign(new Error("capture disk failure"), {
            code: "EACCES",
          });
      },
    });
    const abort = new AbortController();
    abort.abort(new Error("test cancellation"));
    let caught: unknown;
    try {
      await helper.invokePublicPsxCli(context, ["inspect"], {
        signal: abort.signal,
      });
    } catch (cause) {
      caught = cause;
    }
    expect(caught).toBeInstanceOf(AggregateError);
    expect(
      (caught as AggregateError).errors.map((cause: Error) => cause.message),
    ).toEqual(["test cancellation", "Durable public capture failed"]);
    expect(helper.publicPsxFailure(caught)).toMatchObject({
      causes: [
        { message: "test cancellation" },
        {
          message: "Durable public capture failed",
          cause: { message: "capture disk failure", code: "EACCES" },
        },
      ],
    });
    expect(context.unpersisted_events).toHaveLength(1);
    const circular = new Error("owned cyclic failure");
    Object.assign(circular, { cause: circular });
    expect(
      JSON.parse(JSON.stringify(helper.publicPsxFailure(circular))),
    ).toMatchObject({
      message: "owned cyclic failure",
      cause: { name: "CircularCause" },
    });
    await helper.settlePublicPsxContext(context);
  });

  it("retains an exact failed-close handle and file, and an awaited retry never erases failure", async () => {
    const test = await setup();
    const marker = join(test.workspace, "owned resource");
    await writeFile(marker, "identity");
    let canClose = false,
      attempts = 0;
    test.context.primary = new Error("semantic contradiction");
    test.context.resources.push({
      owner: "owned-file",
      identity: { kind: "test-file", id: marker },
      close: async () => {
        attempts++;
        if (!canClose) throw new Error("close blocked");
        await rm(marker);
      },
    });
    const settled = await helper.settlePublicPsxContext(test.context);
    expect(settled.ok).toBe(false);
    expect(attempts).toBe(2);
    expect(await readFile(marker, "utf8")).toBe("identity");
    expect(settled.failures.map((item) => item.stage)).toEqual([
      "primary",
      "close",
      "close",
    ]);
    const owner = settled.settlement.unresolved_owners[0]!;
    expect(owner.identity.id).toBe(marker);
    canClose = true;
    await owner.retry();
    await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(settled.ok).toBe(false);
    expect(settled.failures).toHaveLength(3);
  });

  it("attempts independent postchecks and every close after a primary failure", async () => {
    const test = await setup();
    const marker = join(test.workspace, "source");
    await writeFile(marker, "mutated");
    let closed = false;
    test.context.primary = new Error("first contradiction");
    test.context.resources.push({
      owner: "another-file",
      identity: { kind: "test-resource", id: "resource" },
      close: async () => {
        closed = true;
      },
    });
    const settled = await helper.settlePublicPsxContext(test.context, [
      async () => {
        expect(await readFile(marker, "utf8")).toBe("original");
      },
    ]);
    expect(closed).toBe(true);
    expect(settled.failures.map((item) => item.stage)).toEqual([
      "primary",
      "postcheck",
    ]);
  });
});

describe("P5-R7 typed cancellation outcome boundary", () => {
  it("accepts the actual SDK abort/disconnect types and strict canonical cancellation after allocation", () => {
    const reason = new Error(
      "Owned SDK image cancelled after native allocation",
    );
    for (const [mode, cause] of [
      ["abort", new SdkError(SdkErrorCode.RequestTimeout, String(reason))],
      [
        "disconnect",
        new SdkError(SdkErrorCode.ConnectionClosed, "Connection closed"),
      ],
    ] as const)
      expect(() =>
        helper.assertPublicPsxCancellationOutcome(
          {
            status: "passed",
            allocated: [{ root: "controlled owner" }],
            outcome: { cause },
          },
          { mode, reason, aborted: mode === "abort" },
        ),
      ).not.toThrow();
    expect(() =>
      helper.assertPublicPsxCancellationOutcome(
        {
          status: "passed",
          allocated: [{ root: "controlled owner" }],
          outcome: {
            value: {
              error: {
                code: "cancelled",
                category: "cancelled",
                message: "Request cancelled",
                retryable: false,
                remediation: { action: "Retry deliberately" },
              },
            },
          },
        },
        { mode: "abort", reason, aborted: true },
      ),
    ).not.toThrow();
  });

  it.each([
    "ordinary-error",
    "unrelated-sdk-timeout",
    "wrong-sdk-code",
    "not-aborted",
    "missing-allocation",
    "completed-success",
  ])("rejects %s as native cancellation proof", (kind) => {
    const reason = new Error(
      "Owned SDK image cancelled after native allocation",
    );
    const cause =
      kind === "ordinary-error"
        ? new Error("cancel-looking unrelated failure")
        : kind === "unrelated-sdk-timeout"
          ? new SdkError(SdkErrorCode.RequestTimeout, "cancel-looking timeout")
          : kind === "wrong-sdk-code"
            ? new SdkError(SdkErrorCode.ConnectionClosed, "Connection closed")
            : new SdkError(SdkErrorCode.RequestTimeout, String(reason));
    const result = {
      status: kind === "completed-success" ? "inconclusive" : "passed",
      allocated:
        kind === "missing-allocation" ? [] : [{ root: "controlled owner" }],
      outcome:
        kind === "completed-success" ? { value: { evidence: {} } } : { cause },
    };
    expect(() =>
      helper.assertPublicPsxCancellationOutcome(result, {
        mode: "abort",
        reason,
        aborted: kind !== "not-aborted",
      }),
    ).toThrow();
  });
});

describe("Phase 5 actual SDK and cancellation coordination", () => {
  it("captures a real SDK reply before rejecting the wrong named output shape", async () => {
    const script = `import readline from 'node:readline';
for await (const line of readline.createInterface({input:process.stdin})) {
 const request=JSON.parse(line); if (!Object.hasOwn(request,'id')) continue;
 let result;
 if(request.method==='initialize') result={protocolVersion:request.params.protocolVersion,capabilities:{tools:{}},serverInfo:{name:'controlled-failure-fixture',version:'1'}};
 else if(request.method==='tools/list') result={tools:[{name:'binary_session',inputSchema:{type:'object',additionalProperties:false},outputSchema:{type:'object',properties:{result:{type:'string'}},required:['result'],additionalProperties:false}}]};
 else if(request.method==='tools/call') result={content:[{type:'text',text:JSON.stringify({result:42})}],structuredContent:{result:42}};
 else throw new Error('Unmodeled protocol method '+request.method);
 process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,result})+'\\n');
}`;
    const test = await setup(script);
    const session = await helper.connectPublicPsxMcp(test.context);
    try {
      for (const [operation, parameters, options] of [
        ["inspect_native_load_image", {}, { observeAllocations: false }],
        [
          "inspect_native_load_image",
          {},
          {
            observeAllocations: false,
            allocationObserver: {
              kind: "cancellation-coordinator",
              case_id: "other request",
            },
          },
        ],
        [
          "inspect_native_load_image",
          { document: "not admitted" },
          {
            observeAllocations: false,
            allocationObserver: {
              kind: "cancellation-coordinator",
              case_id: "inspect_native_load_image",
            },
          },
        ],
        [
          "binary_session",
          {},
          {
            observeAllocations: false,
            allocationObserver: {
              kind: "cancellation-coordinator",
              case_id: "binary_session",
            },
          },
        ],
        ["binary_session", {}, { observeAllocations: null }],
      ] as const)
        await expect(
          session.call(operation, parameters, options),
        ).rejects.toThrow();
      expect(
        test.events.filter(
          (event) => event.stage === "operation" && event.kind === "invocation",
        ),
      ).toEqual([]);
      await expect(session.call("binary_session")).rejects.toThrow(
        "Structured content does not match the tool's output schema",
      );
      expect(
        test.events.some(
          (event) =>
            event.kind === "raw_result" &&
            JSON.stringify(event.reply ?? null).includes('"result":42'),
        ),
      ).toBe(true);
    } finally {
      await session.disconnect();
    }
    const settled = await helper.settlePublicPsxContext(test.context);
    expect(settled.settlement.unresolved_owners).toEqual([]);
  });

  it("keeps a completed-open race inconclusive and does not send cancellation", async () => {
    let cancelled = false;
    const result = await helper.coordinatePublicPsxCancellation({
      pending: Promise.resolve({ value: "already complete" }),
      observe: async () => [],
      cancel: async () => {
        cancelled = true;
      },
    });
    expect(result.status).toBe("inconclusive");
    expect(cancelled).toBe(false);
  });

  it("coordinates cancellation on an observed allocation before the controlled request rejects", async () => {
    let reject: (cause: Error) => void = () => {
      throw new Error("uninitialized");
    };
    const pending = new Promise((_, rejectPromise) => {
      reject = rejectPromise;
    });
    const order: string[] = [];
    const result = await helper.coordinatePublicPsxCancellation({
      pending,
      observe: async () => {
        order.push("observed-owner");
        return [{ root: "owned-test-root" }];
      },
      cancel: async () => {
        order.push("cancel");
        reject(new Error("controlled abort"));
      },
    });
    expect(order).toEqual(["observed-owner", "cancel"]);
    expect(result.status).toBe("passed");
  });
});

describe("Phase 5 snapshot routes and credential capture", () => {
  it.each(
    [null, {}, [], [""], [1], ["Program A", "Program B"]].map((documents) => [
      documents,
    ]),
  )(
    "rejects unusable observed Program discovery %j before producing snapshot requests",
    (documents) => {
      expect(() => helper.publicPsxSnapshotQueries(documents)).toThrow(
        "exactly one observed nonempty Program identity",
      );
    },
  );

  it("binds the four immutable queries to the exact observed Program and leaves CLI omission intact", () => {
    const documents = [" caller-selected Program 雪.v2 "];
    const before = JSON.stringify(documents);
    expect(helper.publicPsxSnapshotQueries(documents)).toEqual([
      ["inspect_native_load_image", {}],
      [
        "inspect_native_instruction",
        { address: "0x80010008", document: documents[0] },
      ],
      [
        "resolve_native_call_targets",
        { address: "0x80010034", document: documents[0] },
      ],
      ["analyze_function", { procedure: "0x80010000" }],
    ]);
    expect(JSON.stringify(documents)).toBe(before);
    for (const route of helper.publicPsxCliRoutes("source")) {
      expect(route.parameters).not.toHaveProperty("document");
      expect(route.argv).not.toContain("--document");
    }
  });

  it("creates separate persisted snapshot contradictions without changing the original", async () => {
    const test = await setup();
    const original = {
      target: { sha256: "a".repeat(64) },
      binding: {
        analysis_profile: {
          parameters: {
            psx_asset_inventory: [{ sha256: "b".repeat(64) }],
            psx_import: { supplied_loader_options: {} },
            instruction_flow_evidence: "original",
          },
        },
      },
    };
    const bytes = JSON.stringify(original);
    const path = join(test.workspace, "original snapshot.json");
    await writeFile(path, bytes);
    const mutations = helper.publicPsxSnapshotMutations(original);
    expect(mutations.map((item) => item.id)).toEqual([
      "source-digest",
      "loader-assets",
      "import-options",
      "interpretation",
    ]);
    for (const mutation of mutations)
      await writeFile(
        join(test.workspace, `${mutation.id}.json`),
        JSON.stringify(mutation.snapshot),
      );
    expect(JSON.stringify(original)).toBe(bytes);
    expect(await readFile(path, "utf8")).toBe(bytes);
    expect(
      new Set(mutations.map((item) => JSON.stringify(item.snapshot))).size,
    ).toBe(4);
  });
});

describe("P5-R4 complete fresh CLI routes and capture fidelity", () => {
  it("retains every fresh route and separates the two supported function snapshot routes", () => {
    const source = "source 雪.exe";
    const routes = helper.publicPsxCliRoutes(source);
    expect(routes).toHaveLength(45);
    const expected: [string, Record<string, unknown>][] = [
      ["inspect_native_load_image", {}],
      ...[
        0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72,
        128, 132,
      ].map((offset): [string, Record<string, unknown>] => [
        "inspect_native_instruction",
        { address: `0x${(0x80010000 + offset).toString(16)}` },
      ]),
      ...["0x80010001", "0x80010100", "0x90000000"].map(
        (address): [string, Record<string, unknown>] => [
          "inspect_native_instruction",
          { address },
        ],
      ),
      ...[
        "0x80010008",
        "0x80010034",
        "0x80010010",
        "0x80010018",
        "0x80010044",
        "0x80010080",
        "0x80010001",
        "0x80010100",
        "0x90000000",
      ].map((address): [string, Record<string, unknown>] => [
        "resolve_native_call_targets",
        { address },
      ]),
      ...["0x80010000", "0x80010080"].flatMap((procedure) =>
        [
          "read_function_instructions",
          "procedure_pseudo_code",
          "analyze_function",
        ].map((operation): [string, Record<string, unknown>] => [
          operation,
          { procedure },
        ]),
      ),
      ["binary_overview", {}],
      [
        "search_procedures",
        { pattern: ".*", mode: "regex", case_sensitive: false },
      ],
      [
        "search_strings",
        { pattern: "REA-PSX-P4", mode: "literal", case_sensitive: false },
      ],
      ["xrefs", { address: "0x80010080" }],
      ["xrefs", { address: "0x80010100" }],
    ];
    expect(
      routes.map(({ operation, parameters }) => [operation, parameters]),
    ).toEqual(expected);
    for (const route of routes) {
      expect(route.argv[1]).toBe(source);
      expect(route.argv).not.toContain("--snapshot");
      expect(route.argv).not.toContain("--document");
    }
    expect(helper.publicPsxCliSnapshotRoutes(source, "snapshot.json")).toEqual(
      ["0x80010000", "0x80010080"].map((procedure) => ({
        operation: "analyze_function",
        parameters: { procedure },
        argv: ["function", source, procedure, "--snapshot", "snapshot.json"],
      })),
    );
    expect(
      routes.filter(
        (route) => route.operation === "inspect_native_instruction",
      ),
    ).toHaveLength(24);
    for (const route of routes.filter((row) =>
      [
        "inspect_native_load_image",
        "inspect_native_instruction",
        "resolve_native_call_targets",
      ].includes(row.operation),
    ))
      expect(route.argv).not.toContain("--snapshot");
    expect(routes.some((row) => row.operation === "procedure_references")).toBe(
      false,
    );
    expect(
      routes.filter((row) => row.operation === "analyze_function"),
    ).toHaveLength(2);
  });

  it("redacts recognized transport credentials and explicit markings before persistence while retaining source values", async () => {
    const test = await setup();
    const captured = helper.redactPublicPsxEvent({
      transport: {
        token: "auth-value",
        endpoint_path: "/owned/endpoint",
        transport: "socket",
        run_id: "run",
      },
      source: {
        token: "caller token text",
        name: "private.exe",
        path: "/caller/secret/file",
      },
      marked: { _rea_sensitive: true, value: "explicit secret" },
    });
    await writeFile(
      join(test.parent, "redacted.json"),
      JSON.stringify(captured),
    );
    const bytes = await readFile(join(test.parent, "redacted.json"), "utf8");
    expect(bytes).not.toContain("auth-value");
    expect(bytes).not.toContain("explicit secret");
    expect(bytes).toContain("REA REDACTED");
    expect(bytes).toContain("caller token text");
    expect(bytes).toContain("/caller/secret/file");
  });
});
