import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import {
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  Client,
  SdkError,
  SdkErrorCode,
  specTypeSchemas,
} from "@modelcontextprotocol/client";
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from "@modelcontextprotocol/client/stdio";
import Ajv from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseEvidence } from "../../dist/domain/evidence.js";
import {
  analysisProfileSchema,
  createAnalysisProfile,
} from "../../dist/domain/analysisProfile.js";
import { toolContract } from "../../dist/contracts/toolContracts.js";
import {
  analysisCliErrorEnvelopeSchema,
  analysisErrorProjectionSchema,
} from "../../dist/contracts/errorSchemas.js";
import {
  analysisQueryId,
  parseAnalysisSnapshot,
  snapshotEvidenceForQuery,
} from "../../dist/domain/analysisSnapshot.js";
import { psxLoadImageSchema } from "../../dist/domain/native/nativeLoadImage.js";
import {
  psxImportObservationSchema,
  psxOriginalEvidenceRecordSchema,
} from "../../dist/ghidra/GhidraImportConfiguration.js";
import {
  attestGhidraPsxLoadImage,
  validateGhidraPsxPreparation,
} from "../../dist/ghidra/GhidraPsxLoadImageValues.js";
import { inspectGhidraInstallation } from "../../dist/ghidra/GhidraInstallation.js";
import { inspectGhidraPsxLoader } from "../../dist/ghidra/GhidraPsxLoader.js";
import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
} from "../../dist/process/ProviderProcess.js";
import {
  cleanupOwnedProcessGroup,
  readProcessRunId,
} from "../../dist/process/ProcessOwnership.js";
import {
  observeProcessStartIdentity,
  signalProcessWithStartIdentity,
  systemProcessOwnershipHost,
} from "../../dist/process/ProcessOwnershipObservation.js";
import {
  ProviderStartupDeadline,
  waitForAbortableDelay,
} from "../../dist/process/ProviderDeadline.js";
import { buildPsxExeFixture } from "../../tests/conformance/ghidra/psx-exe-fixture.mjs";
import {
  assertPsxInstructionFlowFixture,
  psxInstructionFlowOracle,
  settlePsxVerification,
  verifyPsxInstructionFlow,
} from "./real-ghidra-psx-instruction-flow.mjs";
import { completeVerifierRun, createVerifierRun } from "./verifier-run.mjs";

export const publicPsxDigest = (value) =>
  createHash("sha256").update(value).digest("hex");
export function publicPsxFailure(cause) {
  const ancestors = new Set();
  const project = (error) => {
    if (ancestors.has(error))
      return { name: "CircularCause", message: "[REA circular error cause]" };
    const ownedObject = error !== null && typeof error === "object";
    if (ownedObject) ancestors.add(error);
    try {
      const code = error?.code;
      return {
        name: String(error?.name ?? typeof error),
        message: String(error?.message ?? error),
        ...(typeof error?._tag === "string" ? { tag: error._tag } : {}),
        ...(typeof code === "string" ||
        (typeof code === "number" && Number.isFinite(code))
          ? { code }
          : {}),
        ...(ownedObject && Object.hasOwn(error, "cause")
          ? { cause: project(error.cause) }
          : {}),
        ...(error instanceof AggregateError
          ? { causes: [...error.errors].map((item) => project(item)) }
          : {}),
      };
    } finally {
      if (ownedObject) ancestors.delete(error);
    }
  };
  return redactPublicPsxEvent(project(cause));
}
const absent = async (path) => {
  try {
    await stat(path);
    return false;
  } catch (cause) {
    if (cause.code === "ENOENT") return true;
    throw cause;
  }
};
const childOf = (parent, child) => {
  const path = relative(parent, child);
  return (
    path !== "" &&
    path !== ".." &&
    !path.startsWith(`..${sep}`) &&
    !isAbsolute(path)
  );
};

/** Only recognized transport credential representations or explicit markings are secret.
 * Source names, hashes, arbitrary `token` fields and ordinary Evidence remain intact.
 * The private Ghidra credential descriptor is never opened by this verifier.
 */
export function redactPublicPsxEvent(event) {
  const redactions = [];
  const visit = (value, path) => {
    if (Array.isArray(value))
      return value.map((item, index) => visit(item, `${path}/${index}`));
    if (value && typeof value === "object") {
      const descriptor =
        typeof value.token === "string" &&
        typeof value.endpoint_path === "string" &&
        typeof value.transport === "string" &&
        typeof value.run_id === "string";
      const authenticatedRequest =
        typeof value.token === "string" &&
        typeof value.method === "string" &&
        Object.hasOwn(value, "params") &&
        Object.hasOwn(value, "id");
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => {
          if (
            (key === "token" && (descriptor || authenticatedRequest)) ||
            (key === "value" && value._rea_sensitive === true)
          ) {
            redactions.push(`${path}/${key}`);
            return [
              key,
              "[REA REDACTED: transport credential or explicitly sensitive value]",
            ];
          }
          return [key, visit(item, `${path}/${key}`)];
        }),
      );
    }
    if (typeof value === "string") {
      // Recognize complete serialized JSON transport envelopes, not name/text patterns.
      try {
        const decoded = JSON.parse(value);
        if (decoded && typeof decoded === "object") {
          const previous = redactions.length;
          const sanitized = visit(decoded, path);
          if (redactions.length > previous) return JSON.stringify(sanitized);
        }
      } catch {
        /* ordinary complete text remains untouched */
      }
    }
    return value;
  };
  const sanitized = visit(event, "");
  return redactions.length
    ? {
        ...sanitized,
        redactions: redactions.map((path) => ({
          path,
          reason: "transport-authentication-or-explicit-marking",
        })),
      }
    : sanitized;
}

/** Read-only admission; invalid arguments cannot create reports, files, or processes. */
export async function preflightPublicPsx({
  executable,
  prefixArgs,
  environment,
  workspace,
  record,
}) {
  assert.ok(
    isAbsolute(executable ?? ""),
    "Absolute public executable is required",
  );
  assert.ok(
    Array.isArray(prefixArgs) &&
      prefixArgs.every((value) => typeof value === "string"),
    "prefixArgs must be a string array",
  );
  assert.ok(
    environment &&
      Object.values(environment).every((value) => typeof value === "string"),
    "Complete string-valued environment is required",
  );
  assert.equal(
    typeof record,
    "function",
    "Durable record callback is required",
  );
  assert.ok(
    isAbsolute(workspace ?? ""),
    "Absolute empty owned workspace is required",
  );
  assert.equal(
    await realpath(workspace),
    resolve(workspace),
    "Workspace must be canonical",
  );
  assert.deepEqual(await readdir(workspace), [], "Workspace must be empty");
  assert.equal(
    resolve(environment.TMPDIR ?? ""),
    workspace,
    "TMPDIR must be the exact owned workspace",
  );
  assert.ok(
    !workspace.split(sep).some((element) => element.startsWith(".")),
    "Ghidra workspace must have no dot-prefixed path elements",
  );
  assert.ok(
    ["darwin", "linux"].includes(process.platform),
    "Public PSX lane requires macOS or Linux",
  );
  for (const key of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
    assert.ok(
      isAbsolute(environment[key] ?? ""),
      `Explicit absolute ${key} is required`,
    );
  await stat(executable);
  const installation = inspectGhidraInstallation({
    installDir: environment.GHIDRA_INSTALL_DIR,
    javaHome: environment.JAVA_HOME,
    environment,
  });
  assert.equal(
    installation.status,
    "available",
    `Ghidra prerequisite failed: ${JSON.stringify(installation)}`,
  );
  assert.equal(installation.providerVersion, "12.1.4");
  assert.match(installation.javaVersion, /^25(?:\.|$)/u);
  const assets = await inspectGhidraPsxLoader(
    installation.installDir,
    installation.providerVersion,
  );
  assert.equal(
    assets.status,
    "available",
    `PSX assets prerequisite failed: ${JSON.stringify(assets)}`,
  );
  const fixture = buildPsxExeFixture({ variant: "instruction-flow" });
  assertPsxInstructionFlowFixture(fixture.bytes);
  return { installation, assets, fixture };
}

/** Event/owner boundary shared by synthetic and explicitly bounded local workflows. */
export function createPublicPsxContext({
  executable,
  prefixArgs,
  environment,
  workspace,
  record,
  captureFilesystem = {},
}) {
  const context = {
    executable,
    prefixArgs: [...prefixArgs],
    environment: { ...environment },
    workspace,
    record,
    run: createVerifierRun(),
    sequence: 0,
    cases: [],
    failures: [],
    captureErrors: new WeakSet(),
    unpersisted_events: [],
    resources: [],
    roots: new Map(),
    captureFilesystem: {
      readFile,
      realpath,
      readdir,
      stat,
      rm,
      ...captureFilesystem,
    },
    identities: [],
    fixtures: [],
    primary: undefined,
  };
  // Prevent SDK default inheritance from introducing values omitted by the caller.
  context.environment = {
    ...Object.fromEntries(DEFAULT_INHERITED_ENV_VARS.map((key) => [key, ""])),
    ...context.environment,
    REA_PROCESS_RUN_ID: context.run.run_id,
  };
  context.emit = async (event) => {
    const complete = redactPublicPsxEvent({
      sequence: ++context.sequence,
      ...event,
    });
    try {
      await record(structuredClone(complete));
    } catch (cause) {
      context.unpersisted_events.push(complete);
      const failure = new Error("Durable public capture failed", { cause });
      context.captureErrors.add(failure);
      context.failures.push({
        stage: "capture",
        event_sequence: complete.sequence,
        event_stage: complete.stage,
        ...publicPsxFailure(failure),
      });
      throw failure;
    }
    return complete.sequence;
  };
  context.case = async (id, adapter, action) => {
    const start = context.sequence + 1;
    try {
      const result = await action();
      await context.emit({
        stage: "assertion",
        case_id: id,
        adapter,
        kind: "assertion",
        criterion: id,
        outcome: "passed",
      });
      context.cases.push({
        id,
        adapter,
        status: "passed",
        evidence_sequences: Array.from(
          { length: context.sequence - start + 1 },
          (_, index) => start + index,
        ),
      });
      return result;
    } catch (cause) {
      context.cases.push({
        id,
        adapter,
        status: cause?.inconclusive ? "inconclusive" : "failed",
        evidence_sequences: Array.from(
          { length: context.sequence - start + 1 },
          (_, index) => start + index,
        ),
      });
      throw cause;
    }
  };
  return context;
}

const requiredPublicPsxCapture = [
  "snapshot",
  "psx-import-before.json",
  "psx-provenance-original.json",
];

function publicPsxCaptureMissing(observed) {
  return requiredPublicPsxCapture.filter(
    (name) => !observed.capture_state.components[name],
  );
}

function parsePublicPsxFixedRecord(observed, name, raw) {
  assert.equal(
    dirname(raw.path),
    observed.root,
    `Captured ${name} root mismatch`,
  );
  assert.equal(
    publicPsxDigest(raw.text),
    raw.sha256,
    `Captured ${name} digest mismatch`,
  );
  const schema =
    name === "psx-import-before.json"
      ? psxImportObservationSchema
      : psxOriginalEvidenceRecordSchema;
  const value = schema.parse(JSON.parse(raw.text));
  assert.equal(
    value.commitment.run_id,
    observed.run_id,
    `Captured ${name} run mismatch`,
  );
  assert.equal(
    value.commitment.source_sha256,
    observed.snapshot.sha256,
    `Captured ${name} source mismatch`,
  );
  if (name === "psx-import-before.json") {
    assert.equal(value.stage, "before-analysis");
    assert.equal(value.observed.source.snapshot_path, observed.snapshot.path);
    assert.equal(value.observed.source.sha256, observed.snapshot.sha256);
    if (observed.snapshot.byte_length !== undefined)
      assert.equal(
        value.observed.source.file_bytes,
        observed.snapshot.byte_length,
      );
  }
  return value;
}

function validatePublicPsxCaptureComponents(
  observed,
  sourceDigest,
  profileDigest,
) {
  assert.equal(
    observed.snapshot.sha256,
    sourceDigest,
    "Retained native source mismatch",
  );
  assert.equal(dirname(observed.snapshot.path), observed.root);
  assert.equal(observed.ownership.run_id, observed.run_id);
  const before = parsePublicPsxFixedRecord(
    observed,
    "psx-import-before.json",
    observed.records["psx-import-before.json"],
  );
  const original = parsePublicPsxFixedRecord(
    observed,
    "psx-provenance-original.json",
    observed.records["psx-provenance-original.json"],
  );
  assert.equal(
    before.commitment.profile_digest,
    original.commitment.profile_digest,
    "Retained native profile mismatch",
  );
  if (profileDigest !== undefined)
    assert.equal(
      before.commitment.profile_digest,
      profileDigest,
      "Retained native selected profile mismatch",
    );
  const metadata = before.provenance.metadata_preservation;
  assert.equal(
    metadata.original_record_sha256,
    observed.records["psx-provenance-original.json"].sha256,
  );
  assert.equal(metadata.original_state_sha256, original.state_sha256);
  assert.equal(
    metadata.original_operational_state_sha256,
    original.operational_state_sha256,
  );
  assert.deepEqual(metadata.label_history.before, original.label_history);
  return before.commitment;
}

/** Native binding uses durably retained proof, never a promise that historical paths exist. */
export function assertPublicPsxRetainedCapture(
  observed,
  { sourceDigest, profileDigest } = {},
) {
  assert.ok(observed?.capture_state, "Native allocation omitted capture state");
  assert.ok(
    Number.isSafeInteger(observed.allocation_event_sequence) &&
      observed.allocation_event_sequence > 0,
    "Native allocation omitted durable ownership sequence",
  );
  const missing = publicPsxCaptureMissing(observed);
  assert.deepEqual(
    missing,
    [],
    `Native capture incomplete: ${missing.join(", ")}`,
  );
  assert.equal(
    observed.capture_state.status,
    "complete",
    "Native capture is not complete",
  );
  for (const name of requiredPublicPsxCapture) {
    const component = observed.capture_state.components[name];
    assert.ok(
      Number.isSafeInteger(component.event_sequence) &&
        component.event_sequence > 0,
      `Native ${name} omitted durable component sequence`,
    );
    const retained =
      name === "snapshot" ? observed.snapshot : observed.records[name];
    assert.equal(retained.event_sequence, component.event_sequence);
  }
  return validatePublicPsxCaptureComponents(
    observed,
    sourceDigest ?? observed.snapshot.sha256,
    profileDigest,
  );
}

/** Explicitly qualify historical durable events for offline replay; no expected hash or filesystem fallback. */
export function qualifyPublicPsxRetainedCapture(
  allocationEvent,
  componentEvents,
) {
  assert.equal(allocationEvent.stage, "native-allocation");
  assert.equal(allocationEvent.kind, "observation");
  assert.ok(
    Number.isSafeInteger(allocationEvent.sequence) &&
      allocationEvent.sequence > 0,
  );
  const observed = structuredClone(allocationEvent.runtime);
  assert.ok(
    isAbsolute(observed.root) && observed.run_id === observed.ownership.run_id,
  );
  observed.records = {};
  observed.allocation_event_sequence = allocationEvent.sequence;
  observed.capture_state = {
    status: "incomplete",
    missing: [...requiredPublicPsxCapture],
    components: {},
  };
  if (typeof observed.snapshot.sha256 === "string") {
    observed.snapshot.event_sequence = allocationEvent.sequence;
    observed.snapshot.captured_at = allocationEvent.captured_at ?? null;
    observed.capture_state.components.snapshot = {
      event_sequence: allocationEvent.sequence,
      captured_at: observed.snapshot.captured_at,
    };
  }
  for (const event of componentEvents) {
    assert.equal(event.runtime_root, observed.root);
    assert.equal(event.case_id, allocationEvent.case_id);
    assert.equal(event.adapter, allocationEvent.adapter);
    assert.ok(
      Number.isSafeInteger(event.sequence) &&
        event.sequence > allocationEvent.sequence,
    );
    if (event.stage === "snapshot-capture") {
      assert.equal(event.kind, "observation");
      assert.equal(event.snapshot.path, observed.snapshot.path);
      observed.snapshot = {
        ...structuredClone(event.snapshot),
        event_sequence: event.sequence,
        captured_at: event.captured_at ?? null,
      };
      observed.capture_state.components.snapshot = {
        event_sequence: event.sequence,
        captured_at: observed.snapshot.captured_at,
      };
    } else {
      assert.equal(event.stage, "runtime-capture");
      assert.equal(event.kind, "raw_result");
      assert.notEqual(
        event.component_status,
        "rejected",
        "Rejected component cannot qualify retained capture",
      );
      const name = event.record_name;
      assert.ok(requiredPublicPsxCapture.includes(name) && name !== "snapshot");
      const raw = {
        path: join(observed.root, name),
        text: event.text,
        sha256: event.sha256,
        event_sequence: event.sequence,
        captured_at: event.captured_at ?? null,
      };
      parsePublicPsxFixedRecord(observed, name, raw);
      if (observed.records[name])
        assert.deepEqual(
          observed.records[name],
          raw,
          "Conflicting durable fixed-record events",
        );
      observed.records[name] = raw;
      observed.capture_state.components[name] = {
        event_sequence: event.sequence,
        captured_at: raw.captured_at,
      };
    }
  }
  observed.capture_state.missing = publicPsxCaptureMissing(observed);
  assert.deepEqual(
    observed.capture_state.missing,
    [],
    `Native capture incomplete: ${observed.capture_state.missing.join(", ")}`,
  );
  const commitment = validatePublicPsxCaptureComponents(
    observed,
    observed.snapshot.sha256,
  );
  observed.capture_state.status = "complete";
  observed.capture_state.profile_digest = commitment.profile_digest;
  return immutablePublicRecord(observed);
}

async function observePublicPsxRetirement(context, observed, component) {
  observed.lifetime ??= { status: "observed", missing: [] };
  if (observed.lifetime.missing.includes(component)) return;
  await context.emit({
    stage: "native-lifetime",
    case_id: observed.case_id,
    adapter: observed.adapter,
    kind: "observation",
    runtime_root: observed.root,
    run_id: observed.run_id,
    component,
    observation:
      observed.capture_state.components[component] ||
      component === "root" ||
      component === "ownership.json"
        ? "absent-after-observation"
        : "absent-not-yet-produced",
    capture_status: observed.capture_state.status,
  });
  observed.lifetime.missing.push(component);
}

/** Compile the exact advertised named schemas, never selecting by catalog order. */
export function compilePublicPsxSchemas(catalog) {
  const schemas = new Map();
  for (const tool of catalog.tools) {
    assert.ok(!schemas.has(tool.name), `Duplicate tool ${tool.name}`);
    const compile = (schema) => {
      assert.ok(
        schema && typeof schema === "object",
        `${tool.name} omitted schema`,
      );
      const dialect =
        schema.$schema ?? "http://json-schema.org/draft-07/schema#";
      assert.ok(
        [
          "https://json-schema.org/draft/2020-12/schema",
          "http://json-schema.org/draft-07/schema#",
        ].includes(dialect),
        `Unsupported advertised dialect ${dialect}`,
      );
      const ajv = dialect.includes("2020-12")
        ? new Ajv2020({ strict: false, allErrors: true })
        : new Ajv({ strict: false, allErrors: true });
      addFormats(ajv);
      assert.equal(
        ajv.validateSchema(schema),
        true,
        `${tool.name} invalid advertised schema`,
      );
      return ajv.compile(schema);
    };
    schemas.set(tool.name, {
      input: compile(tool.inputSchema),
      output: tool.outputSchema ? compile(tool.outputSchema) : null,
      tool,
      sha256: publicPsxDigest(JSON.stringify(tool)),
    });
  }
  return schemas;
}

export function unwrapPublicPsxReply(
  reply,
  operation,
  schema,
  { allowError = false, allowUnstructuredToolError = false } = {},
) {
  assert.equal(
    schema?.tool.name,
    operation,
    `${operation} received wrong named schema`,
  );
  const envelope = specTypeSchemas.CallToolResult["~standard"].validate(reply);
  assert.ok(
    Object.hasOwn(envelope, "value"),
    `${operation} invalid SDK CallToolResult: ${JSON.stringify(envelope.issues)}`,
  );
  const texts = reply.content.filter((item) => item.type === "text");
  const text = texts[0]?.text;
  let textValue;
  let unstructured = false;
  if (text !== undefined) {
    try {
      textValue = JSON.parse(text);
    } catch (cause) {
      // A malformed JSON envelope is not an unstructured SDK diagnostic.
      if (reply.isError !== true || ["{", "["].includes(text.trimStart()[0]))
        throw cause;
      unstructured = true;
    }
  }
  if (reply.structuredContent !== undefined && text !== undefined) {
    assert.equal(
      unstructured,
      false,
      "Contradictory structured/non-JSON text carriers",
    );
    assert.equal(texts.length, 1, "Ambiguous MCP JSON text carriers");
    assert.deepEqual(
      reply.structuredContent,
      textValue,
      "Conflicting MCP structured/text carriers",
    );
  }
  const value =
    reply.structuredContent !== undefined ? reply.structuredContent : textValue;
  if (reply.isError === true) {
    if (unstructured && reply.structuredContent === undefined) {
      if (!allowUnstructuredToolError)
        throw new Error(`${operation} returned an unstructured MCP tool error`);
      return {
        tool_error: {
          kind: "unstructured-mcp-tool-error",
          content: reply.content,
          raw_reply: reply,
        },
      };
    }
    assert.ok(
      value && typeof value === "object" && !Array.isArray(value),
      "REA error omitted JSON envelope",
    );
    assert.deepEqual(
      Object.keys(value),
      ["error"],
      "Invalid REA JSON error envelope",
    );
    assert.equal(texts.length <= 1, true, "Ambiguous REA error text carriers");
    const error = analysisErrorProjectionSchema.parse(value.error);
    if (schema.output?.schema?.properties?.error)
      assert.ok(schema.output(value), JSON.stringify(schema.output.errors));
    if (!allowError)
      throw new Error(`${operation} failed: ${JSON.stringify(error)}`);
    return { error };
  }
  assert.ok(
    schema.output && schema.output(value),
    `${operation} advertised output mismatch: ${JSON.stringify(schema.output?.errors)}`,
  );
  if (Object.hasOwn(value, "normalized_result")) {
    const evidence = parseEvidence(value);
    assert.equal(evidence.operation, operation);
    return { value: evidence.normalized_result, evidence };
  }
  assert.ok(
    Object.hasOwn(value, "result"),
    `${operation} omitted named lifecycle result`,
  );
  return { value: value.result };
}

/** Durable SDK reply capture owns decoding order, including intentional refusal probes. */
export async function capturePublicPsxReply(
  context,
  reply,
  operation,
  schema,
  {
    caseId = operation,
    allowError = false,
    allowUnstructuredToolError = false,
  } = {},
) {
  await context.emit({
    stage: "operation",
    case_id: caseId,
    adapter: "mcp",
    kind: "raw_result",
    reply,
    transport_status: "complete",
  });
  const parsed = unwrapPublicPsxReply(reply, operation, schema, {
    allowError,
    allowUnstructuredToolError,
  });
  const observationSequence = await context.emit({
    stage: "operation",
    case_id: caseId,
    adapter: "mcp",
    kind: "observation",
    ...parsed,
  });
  return parsed.evidence
    ? { ...parsed, observation_sequence: observationSequence }
    : parsed;
}

/** Exact pinned SDK producer expectation, independently bound to the advertised strict input. */
export function assertPublicPsxImageAdmissionRefusal(
  parsed,
  operation,
  parameters,
  schema,
) {
  assert.equal(operation, "inspect_native_load_image");
  assert.equal(schema?.tool.name, operation);
  assert.deepEqual(parameters, { document: "not-admitted" });
  assert.equal(
    schema.input({}),
    true,
    "Image schema refused valid empty input",
  );
  assert.equal(
    schema.input(parameters),
    false,
    "Image schema accepted forbidden document",
  );
  const errors = structuredClone(schema.input.errors);
  assert.ok(
    errors.some(
      (error) =>
        error.keyword === "additionalProperties" &&
        error.params.additionalProperty === "document",
    ),
    "Named input schema omitted forbidden document proof",
  );
  assert.deepEqual(Object.keys(parsed), ["tool_error"]);
  assert.equal(parsed.tool_error.kind, "unstructured-mcp-tool-error");
  const reply = parsed.tool_error.raw_reply;
  assert.equal(reply.isError, true);
  assert.equal(reply.structuredContent, undefined);
  const content = [
    {
      type: "text",
      text: 'Input validation error: Invalid arguments for tool inspect_native_load_image: Unrecognized key: "document"',
    },
  ];
  assert.deepEqual(reply.content, content);
  assert.deepEqual(parsed.tool_error.content, content);
  return {
    category: "sdk-input-validation-refusal",
    operation,
    parameters,
    content: reply.content,
    raw_reply: reply,
    input_schema_sha256: publicPsxDigest(
      JSON.stringify(schema.tool.inputSchema),
    ),
    input_validation_errors: errors,
  };
}

/** SDK close is followed by independent native exit and complete stderr observation.
 * Its SDK object stays the primary close handle. Retry signaling additionally
 * requires the original native start identity and current run token.
 */
async function settleSdkChild(session) {
  if (session.pid === null) return;
  const deadline = new ProviderStartupDeadline(5000);
  try {
    while (true) {
      const current = await observeProcessStartIdentity(session.pid);
      if (
        current === undefined &&
        session.transport.stderr?.readableEnded !== false
      )
        return;
      deadline.signal.throwIfAborted();
      await deadline.wait(10);
    }
  } catch (cause) {
    throw new Error(
      "SDK launcher exit or complete stderr settlement remains unresolved",
      { cause },
    );
  } finally {
    deadline.dispose();
  }
}

/** Actual SDK transport. Full protocol messages and stderr are durably captured. */
export async function connectPublicPsxMcp(context, caseId = "mcp-session") {
  const args = [...context.prefixArgs, "mcp"];
  await context.emit({
    stage: "transport",
    case_id: caseId,
    adapter: "mcp",
    kind: "invocation",
    executable: context.executable,
    argv: args,
    cwd: context.workspace,
    owned_identity: { verifier_run_id: context.run.run_id },
  });
  const transport = new StdioClientTransport({
    command: context.executable,
    args,
    env: context.environment,
    cwd: context.workspace,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-public-psx-verifier", version: "1" });
  const stderr = [];
  transport.stderr?.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
  const session = {
    client,
    transport,
    schemas: undefined,
    pid: null,
    closed: false,
    wire: Promise.resolve(),
    wireFailure: undefined,
    captureAbort: new AbortController(),
    closeAttempt: 0,
    disconnected: false,
    startIdentity: undefined,
  };
  const clientClosed = client.onclose;
  client.onclose = () => {
    session.disconnected = true;
    clientClosed?.();
  };
  // Chain SDK message capture ahead of parsing without using SDK private process fields.
  const start = transport.start.bind(transport);
  transport.start = async () => {
    await start();
    session.pid = transport.pid;
    assert.ok(
      Number.isSafeInteger(session.pid),
      "SDK omitted owned launcher PID",
    );
    session.startIdentity = await observeProcessStartIdentity(session.pid);
    assert.equal(
      session.startIdentity?.state,
      "readable",
      "SDK launcher start identity is unavailable",
    );
    assert.equal(
      await readProcessRunId(session.pid),
      context.run.run_id,
      "SDK launcher run token differs",
    );
    Object.assign(resource.identity, {
      pid: session.pid,
      start_identity: session.startIdentity.identity,
      verifier_run_id: context.run.run_id,
    });
    await context.emit({
      stage: "transport",
      case_id: caseId,
      adapter: "mcp",
      kind: "observation",
      owned_identity: resource.identity,
    });
    const receive = transport.onmessage;
    transport.onmessage = (message, ...rest) => {
      session.wire = session.wire
        .then(async () => {
          await context.emit({
            stage: "protocol",
            case_id: caseId,
            adapter: "mcp",
            kind: "raw_result",
            reply: message,
            transport_status: "received",
            pid: session.pid,
          });
          receive?.(message, ...rest);
        })
        .catch((cause) => {
          session.wireFailure = cause;
          session.captureAbort.abort(cause);
          transport.onerror?.(cause);
        });
    };
  };
  const resource = {
    owner: `mcp:${caseId}`,
    identity: { kind: "sdk-stdio", id: caseId },
    close: async () => {
      if (!session.closed) {
        if (
          session.closeAttempt++ > 0 &&
          session.startIdentity?.state === "readable"
        ) {
          const current = await observeProcessStartIdentity(session.pid);
          if (current !== undefined) {
            assert.equal(
              await readProcessRunId(session.pid),
              context.run.run_id,
              "SDK retry ownership token differs",
            );
            const signaled = await signalProcessWithStartIdentity(
              session.pid,
              session.startIdentity.identity,
              "SIGTERM",
            );
            assert.ok(
              ["signaled", "gone"].includes(signaled),
              `SDK retry signaling refused: ${signaled}`,
            );
          }
        }
        const activeTransport = client.transport;
        assert.ok(
          activeTransport === undefined || activeTransport === transport,
          "Owned SDK transport changed",
        );
        if (activeTransport === undefined || transport.pid === null)
          session.disconnected = true;
        if (
          session.schemas &&
          !session.disconnected &&
          context.unpersisted_events.length === 0
        ) {
          const state = await session.call(
            "binary_session",
            {},
            { caseId: "settlement-state" },
          );
          if (state.value?.open)
            await session.call(
              "close_binary",
              {},
              { caseId: "settlement-close" },
            );
        }
        await client.close();
        await transport.close();
        session.disconnected = true;
        await settleSdkChild(session);
        session.closed = true;
      }
      await session.wire;
      try {
        await context.emit({
          stage: "transport",
          case_id: caseId,
          adapter: "mcp",
          kind: "raw_result",
          stderr: Buffer.concat(stderr).toString("utf8"),
          pid: session.pid,
          transport_status: "closed",
        });
      } catch (cause) {
        if (!context.captureErrors.has(cause))
          context.failures.push({
            stage: "capture",
            owner: resource.owner,
            ...publicPsxFailure(cause),
          });
      }
    },
  };
  context.resources.push(resource);
  await client.connect(transport, {
    timeout: 180000,
    signal: session.captureAbort.signal,
  });
  const catalog = await client.listTools();
  await context.emit({
    stage: "schemas",
    case_id: caseId,
    adapter: "mcp",
    kind: "raw_result",
    catalog,
  });
  session.schemas = compilePublicPsxSchemas(catalog);
  session.call = async (
    operation,
    parameters = {},
    {
      allowError = false,
      caseId: id = operation,
      signal,
      allowInvalidInput = false,
      allowUnstructuredToolError = false,
      observeAllocations = true,
      allocationObserver,
    } = {},
  ) => {
    assert.equal(typeof observeAllocations, "boolean");
    if (!observeAllocations) {
      assert.equal(operation, "inspect_native_load_image");
      assert.deepEqual(parameters, {});
      assert.deepEqual(allocationObserver, {
        kind: "cancellation-coordinator",
        case_id: id,
      });
    }
    const schema = session.schemas.get(operation);
    assert.ok(schema, `Named public tool missing: ${operation}`);
    if (!allowInvalidInput)
      assert.ok(
        schema.input(parameters),
        `${operation} invalid input: ${JSON.stringify(schema.input.errors)}`,
      );
    await context.emit({
      stage: "operation",
      case_id: id,
      adapter: "mcp",
      kind: "invocation",
      operation,
      parameters,
      pid: session.pid,
      schema_sha256: schema.sha256,
    });
    let reply;
    try {
      let complete = false;
      const pending = client
        .callTool(
          { name: operation, arguments: parameters },
          {
            timeout: 180000,
            signal: signal
              ? AbortSignal.any([signal, session.captureAbort.signal])
              : session.captureAbort.signal,
          },
        )
        .finally(() => {
          complete = true;
        });
      // Attach rejection immediately while allocation capture is in progress.
      const result = pending.then(
        (value) => ({ value }),
        (cause) => ({ cause }),
      );
      while (!complete) {
        if (observeAllocations && context.sourceDigest)
          await observePublicPsxAllocations(
            context,
            session.pid,
            id,
            "mcp",
            context.sourceDigest,
          );
        await waitForAbortableDelay(10);
      }
      const received = await result;
      if (received.cause) throw received.cause;
      reply = received.value;
    } catch (cause) {
      await context.emit({
        stage: "operation",
        case_id: id,
        adapter: "mcp",
        kind: "raw_result",
        transport_status: "failed",
        failure: publicPsxFailure(cause),
      });
      throw cause;
    }
    await session.wire;
    if (session.wireFailure) throw session.wireFailure;
    return capturePublicPsxReply(context, reply, operation, schema, {
      caseId: id,
      allowError,
      allowUnstructuredToolError,
    });
  };
  session.close = resource.close;
  session.disconnect = async () => {
    session.disconnected = true;
    await transport.close();
    await client.close();
    await settleSdkChild(session);
    session.closed = true;
  };
  return session;
}

/** Read only manifests inside this invocation's canonical private TMPDIR. */
export async function observePublicPsxAllocations(
  context,
  parentPid,
  caseId,
  adapter,
  sourceDigest,
) {
  const filesystem = context.captureFilesystem;
  for (const entry of await filesystem.readdir(context.workspace, {
    withFileTypes: true,
  })) {
    if (!entry.isDirectory() || !entry.name.startsWith("rea-ghidra-")) continue;
    const root = join(context.workspace, entry.name);
    let ownership;
    try {
      ownership = JSON.parse(
        await filesystem.readFile(join(root, "ownership.json"), "utf8"),
      );
    } catch (cause) {
      if (cause.code === "ENOENT") {
        const old = context.roots.get(root);
        if (old && old.ownership.parent_pid === parentPid)
          await observePublicPsxRetirement(context, old, "ownership.json");
        continue;
      }
      throw cause;
    }
    const old = context.roots.get(root);
    if (old)
      assert.deepEqual(old.ownership, ownership, "Runtime ownership changed");
    if (ownership.parent_pid !== parentPid) continue;
    if (await absent(root)) continue;
    try {
      assert.equal(await filesystem.realpath(root), root);
    } catch (cause) {
      if (cause.code === "ENOENT" && old) {
        await observePublicPsxRetirement(context, old, "root");
        continue;
      }
      throw cause;
    }
    assert.ok(childOf(context.workspace, root));
    assert.equal(ownership.ownership_kind, "posix-process-group");
    assert.ok(
      typeof ownership.run_id === "string" &&
        Number.isSafeInteger(ownership.pid),
    );
    const argv = ownership.arguments;
    assert.ok(Array.isArray(argv));
    const snapshot = argv[argv.indexOf("-import") + 1];
    assert.equal(dirname(snapshot), root);
    if (!old) {
      const observation = {
        root,
        ownership: immutablePublicRecord(structuredClone(ownership)),
        case_id: caseId,
        adapter,
        snapshot: { path: snapshot },
        records: {},
        run_id: ownership.run_id,
        source_digest: sourceDigest,
        capture_state: {
          status: "incomplete",
          missing: [...requiredPublicPsxCapture],
          components: {},
        },
        lifetime: { status: "observed", missing: [] },
      };
      context.roots.set(root, observation);
      context.resources.push({
        owner: `native-runtime:${ownership.run_id}`,
        identity: {
          kind: "native-runtime",
          id: ownership.run_id,
          root,
          ...ownership,
        },
        close: () => closePublicPsxNativeRoot(context, observation),
      });
    }
    const observed = context.roots.get(root);
    assert.equal(
      observed.source_digest,
      sourceDigest,
      "Runtime source selection changed",
    );
    assert.equal(
      observed.snapshot.path,
      snapshot,
      "Runtime snapshot coordinate changed",
    );
    if (!observed.allocation_event_sequence) {
      observed.allocation_event_sequence = await context.emit({
        stage: "native-allocation",
        case_id: caseId,
        adapter,
        kind: "observation",
        runtime: observed,
      });
    }
    let currentRootStat;
    try {
      currentRootStat = await filesystem.stat(root);
    } catch (cause) {
      if (cause.code === "ENOENT") {
        await observePublicPsxRetirement(context, observed, "root");
        continue;
      }
      throw cause;
    }
    const currentIdentity = {
      device: currentRootStat.dev,
      inode: currentRootStat.ino,
    };
    if (observed.root_identity)
      assert.deepEqual(
        observed.root_identity,
        currentIdentity,
        "Runtime directory identity changed",
      );
    else observed.root_identity = immutablePublicRecord(currentIdentity);
    if (observed.capture_state.status !== "complete") {
      try {
        const bytes = await filesystem.readFile(snapshot);
        const sha256 = publicPsxDigest(bytes);
        assert.equal(sha256, sourceDigest, "Owned snapshot digest mismatch");
        if (observed.snapshot.sha256)
          assert.equal(
            sha256,
            observed.snapshot.sha256,
            "Captured snapshot changed",
          );
        else {
          const captured_at = new Date().toISOString();
          const measured = {
            path: snapshot,
            sha256,
            byte_length: bytes.length,
            captured_at,
          };
          const event_sequence = await context.emit({
            stage: "snapshot-capture",
            case_id: observed.case_id,
            adapter: observed.adapter,
            kind: "observation",
            runtime_root: root,
            run_id: observed.run_id,
            captured_at,
            snapshot: measured,
          });
          observed.snapshot = immutablePublicRecord({
            ...measured,
            event_sequence,
          });
          observed.capture_state.components.snapshot = {
            event_sequence,
            captured_at,
          };
          observed.capture_state.missing = publicPsxCaptureMissing(observed);
        }
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
        await observePublicPsxRetirement(context, observed, "snapshot");
      }
    }
    await capturePublicPsxRuntime(context, root);
  }
  for (const observed of context.roots.values())
    if (
      observed.ownership.parent_pid === parentPid &&
      (await absent(observed.root))
    )
      await observePublicPsxRetirement(context, observed, "root");
  return [...context.roots.values()].filter(
    (root) =>
      root.ownership.parent_pid === parentPid &&
      root.case_id === caseId &&
      root.capture_state.components.snapshot,
  );
}

export async function capturePublicPsxRuntime(context, root) {
  const observation = context.roots.get(root);
  assert.ok(observation, "Cannot capture an unobserved native owner");
  for (const name of [
    "psx-import-before.json",
    "psx-provenance-original.json",
    "ghidra.log",
    "script.log",
  ]) {
    try {
      const text = await context.captureFilesystem.readFile(
        join(root, name),
        "utf8",
      );
      const sha256 = publicPsxDigest(text);
      const fixed = requiredPublicPsxCapture.includes(name);
      const old = observation.records[name];
      const raw = redactPublicPsxEvent({
        path: join(root, name),
        sha256,
        text,
      });
      if (fixed) {
        if (!observation.capture_state.components.snapshot) continue;
        try {
          if (old)
            assert.equal(
              sha256,
              old.sha256,
              `Immutable captured ${name} changed`,
            );
          parsePublicPsxFixedRecord(observation, name, raw);
          const other =
            name === "psx-import-before.json"
              ? "psx-provenance-original.json"
              : "psx-import-before.json";
          if (observation.records[other]) {
            const peer = parsePublicPsxFixedRecord(
              observation,
              other,
              observation.records[other],
            );
            assert.equal(
              JSON.parse(text).commitment.profile_digest,
              peer.commitment.profile_digest,
              "Fixed capture profile changed",
            );
            validatePublicPsxCaptureComponents(
              {
                ...observation,
                records: { ...observation.records, [name]: raw },
              },
              observation.source_digest,
            );
          }
        } catch (cause) {
          try {
            await context.emit({
              stage: "runtime-capture",
              case_id: observation.case_id,
              adapter: observation.adapter,
              kind: "raw_result",
              runtime_root: root,
              record_name: name,
              text,
              sha256,
              component_status: "rejected",
              failure: publicPsxFailure(cause),
            });
          } catch (capture) {
            throw new AggregateError(
              [cause, capture],
              "Invalid fixed record and durable capture failed",
            );
          }
          throw cause;
        }
      }
      if (old?.sha256 === sha256) continue;
      const captured_at = new Date().toISOString();
      const event_sequence = await context.emit({
        stage: "runtime-capture",
        case_id: observation.case_id,
        adapter: observation.adapter,
        kind: "raw_result",
        runtime_root: root,
        record_name: name,
        sha256,
        text,
        captured_at,
      });
      observation.records[name] = immutablePublicRecord({
        ...raw,
        event_sequence,
        captured_at,
      });
      if (fixed)
        observation.capture_state.components[name] = {
          event_sequence,
          captured_at,
        };
      observation.capture_state.missing = publicPsxCaptureMissing(observation);
    } catch (cause) {
      if (cause.code !== "ENOENT") throw cause;
      await observePublicPsxRetirement(context, observation, name);
    }
  }
  observation.capture_state.missing = publicPsxCaptureMissing(observation);
  if (!observation.capture_state.missing.length) {
    const commitment = validatePublicPsxCaptureComponents(
      observation,
      observation.source_digest,
    );
    if (observation.capture_state.status !== "complete") {
      observation.capture_state.completion_event_sequence = await context.emit({
        stage: "native-capture-complete",
        case_id: observation.case_id,
        adapter: observation.adapter,
        kind: "observation",
        runtime_root: root,
        run_id: observation.run_id,
        source_sha256: observation.snapshot.sha256,
        profile_digest: commitment.profile_digest,
        component_sequences: Object.fromEntries(
          Object.entries(observation.capture_state.components).map(
            ([name, component]) => [name, component.event_sequence],
          ),
        ),
      });
    }
    observation.capture_state.profile_digest = commitment.profile_digest;
    observation.capture_state.status = "complete";
  }
}

/** Complete-stream CLI collection; supervisor diagnostics are not the raw capture. */
async function assertCurrentPublicPsxRoot(context, observed) {
  assert.equal(
    await context.captureFilesystem.realpath(observed.root),
    observed.root,
  );
  assert.ok(childOf(context.workspace, observed.root));
  const current = await context.captureFilesystem.stat(observed.root);
  assert.deepEqual(
    observed.root_identity,
    { device: current.dev, inode: current.ino },
    "Native cleanup directory identity changed",
  );
  try {
    const ownership = JSON.parse(
      await context.captureFilesystem.readFile(
        join(observed.root, "ownership.json"),
        "utf8",
      ),
    );
    assert.deepEqual(
      ownership,
      observed.ownership,
      "Native cleanup ownership changed",
    );
  } catch (cause) {
    if (cause.code !== "ENOENT") throw cause;
    await observePublicPsxRetirement(context, observed, "ownership.json");
  }
}

/** Independent source remains caller-owned after the private import copy retires. */
async function verifyPublicPsxOriginalSource(context, observed) {
  const sources = context.fixtures.filter(
    (fixture) =>
      (fixture.before_sha256 ?? fixture.sha256) === observed.source_digest,
  );
  assert.ok(
    sources.length > 0,
    "Native cleanup omitted independent original source",
  );
  for (const fixture of sources)
    assert.equal(
      publicPsxDigest(await readFile(fixture.canonical_path ?? fixture.path)),
      observed.source_digest,
      "Original source changed during native cleanup",
    );
}

/** Retained native retry never reacquires the private source after process settlement. */
async function closePublicPsxNativeRoot(context, observed) {
  if (observed.capture_state.status === "complete")
    try {
      assertPublicPsxRetainedCapture(observed, {
        sourceDigest: observed.source_digest,
      });
    } catch (cause) {
      context.failures.push({
        stage: "capture",
        owner: observed.run_id,
        ...publicPsxFailure(cause),
      });
    }
  if (!(await absent(observed.root)))
    await assertCurrentPublicPsxRoot(context, observed);
  const cleaned = await cleanupOwnedProcessGroup({
    runId: observed.ownership.run_id,
    leaderPid: observed.ownership.pid,
    processGroupId: observed.ownership.process_group_id,
    expectedParentPid: observed.ownership.parent_pid,
    expectedCommand: observed.ownership.launcher,
  });
  assert.equal(cleaned.cleaned, true, JSON.stringify(cleaned));
  await verifyPublicPsxOriginalSource(context, observed);
  if (!(await absent(observed.root))) {
    await assertCurrentPublicPsxRoot(context, observed);
    try {
      await context.captureFilesystem.rm(observed.root, { recursive: true });
    } catch (cause) {
      if (cause.code !== "ENOENT" || !(await absent(observed.root)))
        throw cause;
    }
  }
  assert.ok(await absent(observed.root));
  observed.lifetime.status = "retired";
}

export function parsePublicPsxCliOutput(
  stdout,
  { exitCode, signal, allowError = false },
) {
  const output = JSON.parse(stdout);
  const refusal = analysisCliErrorEnvelopeSchema.safeParse(output);
  assert.equal(signal, null, "CLI output terminated by signal");
  if (refusal.success) {
    const envelope = output;
    const {
      error: _label,
      input_path: _path,
      input_reason: _reason,
      ...fields
    } = envelope;
    const error = analysisErrorProjectionSchema.parse(fields);
    assert.equal(exitCode, 1, "CLI refusal requires exit 1");
    if (!allowError) throw new Error(`CLI failed: ${JSON.stringify(envelope)}`);
    return { error, cli_error_envelope: envelope };
  }
  const evidence = parseEvidence(output);
  assert.equal(exitCode, 0, "CLI Evidence requires exit 0");
  return { evidence };
}

export function assertPublicPsxErrorParity(cli, mcp) {
  assert.deepEqual(
    analysisErrorProjectionSchema.parse(cli),
    analysisErrorProjectionSchema.parse(mcp),
    "CLI/MCP canonical refusal disagreement",
  );
}

export async function invokePublicPsxCli(
  context,
  argv,
  {
    caseId = argv[0],
    sourceDigest,
    allowError = false,
    signal,
    afterAllocation,
    binding,
    execution,
  } = {},
) {
  if (execution?.mode === "snapshot-evidence") {
    assert.ok(
      childOf(context.workspace, execution.snapshot.path),
      "Snapshot CLI input must be owned by this workspace",
    );
    assert.equal(
      await realpath(execution.snapshot.path),
      execution.snapshot.path,
    );
    assert.equal(
      await readFile(execution.snapshot.path, "utf8"),
      execution.snapshot.text,
    );
    assert.ok(
      argv.includes("--snapshot") &&
        argv[argv.indexOf("--snapshot") + 1] === execution.snapshot.path,
    );
    selectPublicPsxSnapshotEvidence(execution, binding);
  }
  const args = [
    ...context.prefixArgs,
    ...argv,
    "--provider",
    "ghidra",
    "--json",
  ];
  await context.emit({
    stage: "operation",
    case_id: caseId,
    adapter: "cli",
    kind: "invocation",
    executable: context.executable,
    argv: args,
    cwd: context.workspace,
  });
  const runId = randomUUID();
  const stdout = [],
    stderr = [];
  const launched = await spawnOwnedProviderProcess({
    command: context.executable,
    arguments: args,
    cwd: context.workspace,
    env: context.environment,
    hostEnvironment: {},
    runId,
    expectedCommand: null,
    observation: { captureStdout: false },
    onAcquired: (child) => {
      child.stdout?.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
      child.stderr?.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    },
  });
  const supervisor = new ProviderProcessSupervisor(
    {
      ...launched,
      ownsProcessLifetime: true,
      cleanup: () => cleanupOwnedProcessGroup(launched.ownership),
    },
    { captureStdout: false },
  );
  const resource = {
    owner: `cli:${runId}`,
    identity: { kind: "owned-cli", id: runId, ...launched.ownership },
    close: async () => {
      const stopped = await supervisor.stop();
      assert.notEqual(stopped.status, "incomplete", JSON.stringify(stopped));
      supervisor.dispose();
    },
  };
  context.resources.push(resource);
  const deadline = new ProviderStartupDeadline(180000, signal);
  let primary,
    allocated = false;
  try {
    while (!(await supervisor.waitForOutputClose(10))) {
      if (sourceDigest) {
        const roots = await observePublicPsxAllocations(
          context,
          launched.process.pid,
          caseId,
          "cli",
          sourceDigest,
        );
        if (!allocated && roots.length) {
          allocated = true;
          await afterAllocation?.(roots, resource);
        }
      }
      deadline.signal.throwIfAborted();
      await deadline.wait(10);
    }
  } catch (cause) {
    primary = cause;
  } finally {
    deadline.dispose();
    try {
      await resource.close();
    } catch (cause) {
      if (primary)
        primary = new AggregateError(
          [primary, cause],
          "CLI execution and cleanup failed",
        );
      else primary = cause;
    }
    await supervisor.waitForOutputClose(1000);
    const status = supervisor.snapshot();
    try {
      await context.emit({
        stage: "operation",
        case_id: caseId,
        adapter: "cli",
        kind: "raw_result",
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exit_code: status.exitCode ?? null,
        signal: status.signal ?? null,
        owned_identity: launched.ownership,
      });
    } catch (capture) {
      primary = primary
        ? new AggregateError(
            [primary, capture],
            "CLI primary and raw capture failed",
          )
        : capture;
    }
  }
  if (primary) throw primary;
  const status = supervisor.snapshot();
  const parsed = parsePublicPsxCliOutput(
    Buffer.concat(stdout).toString("utf8"),
    {
      exitCode: status.exitCode,
      signal: status.signal ?? null,
      allowError,
    },
  );
  if (Object.hasOwn(parsed, "error")) return parsed;
  const evidence = parsed.evidence;
  if (sourceDigest) {
    assert.equal(
      binding?.sourceDigest,
      sourceDigest,
      "CLI omitted explicit source binding",
    );
    validatePublicPsxEvidence(evidence, binding);
  }
  let executionProof;
  if (sourceDigest) {
    const roots = [...context.roots.values()].filter(
      (root) =>
        root.ownership.parent_pid === launched.process.pid &&
        root.case_id === caseId,
    );
    executionProof = assertPublicPsxCliExecution(
      evidence,
      binding,
      execution,
      roots,
    );
    for (const root of roots) {
      root.capture_outcome = {
        status: "native-result",
        evidence_id: evidence.evidence_id,
      };
      root.lifetime.status = "invocation-settled";
    }
    if (execution.mode === "snapshot-evidence") {
      const resulting = await readFile(execution.snapshot.path, "utf8");
      assert.equal(
        resulting,
        execution.snapshot.text,
        "Exact-hit snapshot input changed",
      );
      await context.emit({
        stage: "snapshot-cli",
        case_id: caseId,
        adapter: "cli",
        kind: "raw_result",
        imported: execution.snapshot,
        resulting: {
          path: execution.snapshot.path,
          text: resulting,
          sha256: publicPsxDigest(resulting),
        },
        invocation_identity: launched.ownership,
        original_run_id: execution.original.run_id,
      });
    } else {
      const root = roots[0];
      context.identities.push({
        run_id: root.run_id,
        evidence_profile: evidence.analysis_profile,
        execution_profile: binding.selectedProfile,
        source_sha256: sourceDigest,
        runtime_root: root.root,
        adapter: "cli",
      });
    }
  }
  const eventSequence = await context.emit({
    stage: "operation",
    case_id: caseId,
    adapter: "cli",
    kind: "observation",
    evidence,
  });
  const observation =
    executionProof?.mode === "native"
      ? publicPsxObservation(evidence, binding, {
          event_sequence: eventSequence,
          run_id: executionProof.run_id,
          capture: publicPsxCaptureForRun(context, executionProof.run_id),
          invocation_identity: launched.ownership,
        })
      : executionProof
        ? immutablePublicRecord(
            structuredClone({
              ...executionProof,
              evidence,
              event_sequence: eventSequence,
              invocation_identity: launched.ownership,
              original_run_id: execution.original.run_id,
            }),
          )
        : undefined;
  return { value: evidence.normalized_result, evidence, observation };
}

/** Preserve every failed attempt even when an awaited retry later succeeds. */
export async function settlePublicPsxContext(context, postchecks = []) {
  const settled = await settlePsxVerification({
    primary: context.primary,
    postchecks,
    resources: context.resources,
    capture: [...context.roots.keys()].map((root) => async () => {
      if (!(await absent(root))) await capturePublicPsxRuntime(context, root);
      const observed = context.roots.get(root);
      if (observed.capture_outcome?.status !== "cancelled")
        assertPublicPsxRetainedCapture(observed, {
          sourceDigest: observed.source_digest,
        });
    }),
    cleanup: [...context.roots.keys()].map((root) => async () => {
      assert.ok(await absent(root), `Owned runtime remains: ${root}`);
    }),
  });
  context.failures.push(
    ...settled.failures.map(({ stage, owner, attempt, error }) => ({
      stage,
      ...(owner ? { owner, attempt } : {}),
      ...publicPsxFailure(error),
    })),
  );
  const unresolvedOwners = context.resources
    .filter((resource) => settled.unresolved.includes(resource.owner))
    .map((resource) => ({
      identity: resource.identity,
      close: resource.close,
      retry: resource.close,
    }));
  const remainingRoots = [];
  for (const entry of await readdir(context.workspace, {
    withFileTypes: true,
  })) {
    if (
      !entry.isDirectory() ||
      !entry.name.startsWith("rea-ghidra-") ||
      context.roots.has(join(context.workspace, entry.name))
    )
      continue;
    const root = join(context.workspace, entry.name);
    remainingRoots.push(root);
    const retry = async () => {
      assert.ok(
        await absent(root),
        "Unobserved native root still lacks verified cleanup authority",
      );
    };
    unresolvedOwners.push({
      identity: { kind: "unobserved-native-root", id: root, root },
      close: retry,
      retry,
    });
    context.failures.push({
      stage: "cleanup",
      message: `Unobserved native allocation retained: ${root}`,
    });
  }
  for (const [root, observed] of context.roots) {
    if (await absent(root)) continue;
    remainingRoots.push(root);
    // A disconnected public launcher can leave its native root. Retain exact identity
    // and a retry handle; never infer ownership from an executable/PID pair alone.
    if (
      unresolvedOwners.some(
        (owner) =>
          owner.identity.kind === "native-runtime" &&
          owner.identity.root === root,
      )
    )
      continue;
    const close = () => closePublicPsxNativeRoot(context, observed);
    unresolvedOwners.push({
      identity: {
        kind: "native-runtime",
        id: observed.run_id,
        root,
        ...observed.ownership,
      },
      close,
      retry: close,
    });
  }
  const pendingRetries = new Set(unresolvedOwners);
  for (const owner of unresolvedOwners) {
    const close = owner.close;
    owner.close = owner.retry = async () => {
      await close();
      pendingRetries.delete(owner);
    };
  }
  const releaseInspector = async () => {
    assert.equal(
      pendingRetries.size,
      0,
      "Process inspector is retained for unresolved cleanup owners",
    );
    await systemProcessOwnershipHost.close?.();
  };
  if (context.releaseInspector && pendingRetries.size > 0)
    unresolvedOwners.push({
      identity: { kind: "process-inspector", id: context.run.run_id },
      close: releaseInspector,
      retry: releaseInspector,
    });
  else if (context.releaseInspector)
    try {
      await releaseInspector();
    } catch (cause) {
      context.failures.push({
        stage: "inspector-close",
        ...publicPsxFailure(cause),
      });
      unresolvedOwners.push({
        identity: { kind: "process-inspector", id: context.run.run_id },
        close: releaseInspector,
        retry: releaseInspector,
      });
    }
  let lineage;
  try {
    lineage = await completeVerifierRun(context.run);
    assert.equal(lineage.process_lineage.status, "verified");
    assert.deepEqual(lineage.process_lineage.descendants, []);
  } catch (cause) {
    context.failures.push({ stage: "lineage", ...publicPsxFailure(cause) });
  }
  const settlement = {
    verified_empty_lineage:
      lineage?.process_lineage.status === "verified" &&
      lineage.process_lineage.descendants.length === 0,
    remaining_roots: remainingRoots,
    unresolved_owners: unresolvedOwners,
    lineage,
  };
  try {
    await context.emit({
      stage: "settlement",
      case_id: "settlement",
      kind: "settlement",
      settlement: {
        ...settlement,
        unresolved_owners: unresolvedOwners.map((owner) => owner.identity),
      },
    });
  } catch (cause) {
    context.failures.push({ stage: "capture", ...publicPsxFailure(cause) });
  }
  return {
    ok:
      context.cases.length > 0 &&
      context.cases.every((item) => item.status === "passed") &&
      context.failures.length === 0 &&
      context.unpersisted_events.length === 0 &&
      settlement.verified_empty_lineage &&
      remainingRoots.length === 0 &&
      unresolvedOwners.length === 0,
    cases: context.cases,
    fixtures: context.fixtures,
    identities: context.identities,
    owned_runtime_inventory: [...context.roots.values()],
    failures: context.failures,
    unpersisted_events: context.unpersisted_events,
    settlement,
  };
}

/** Frozen C1 argv mapping; genuine MCP-only primitives deliberately have no mapping. */
export function publicPsxCliRoutes(source) {
  const oracle = psxInstructionFlowOracle;
  return [
    {
      operation: "inspect_native_load_image",
      parameters: {},
      argv: ["inspect-native-load-image", source],
    },
    ...[
      ...oracle.words.map(([address]) => address),
      "0x80010001",
      oracle.data,
      "0x90000000",
    ].map((address) => ({
      operation: "inspect_native_instruction",
      parameters: { address },
      argv: ["inspect-native-instruction", source, address],
    })),
    ...[
      "0x80010008",
      "0x80010034",
      "0x80010010",
      "0x80010018",
      "0x80010044",
      "0x80010080",
      "0x80010001",
      oracle.data,
      "0x90000000",
    ].map((address) => ({
      operation: "resolve_native_call_targets",
      parameters: { address },
      argv: ["resolve-native-call-targets", source, address],
    })),
    ...[oracle.entry, oracle.leaf].flatMap((procedure) =>
      [
        ["read_function_instructions", "instructions"],
        ["procedure_pseudo_code", "decompile"],
        ["analyze_function", "function"],
      ].map(([operation, command]) => ({
        operation,
        parameters: { procedure },
        argv: [command, source, procedure],
      })),
    ),
    {
      operation: "binary_overview",
      parameters: {},
      argv: ["inspect", source],
    },
    {
      operation: "search_procedures",
      parameters: { pattern: ".*", mode: "regex", case_sensitive: false },
      argv: ["search", source, ".*", "--kind", "procedures", "--mode", "regex"],
    },
    {
      operation: "search_strings",
      parameters: {
        pattern: "REA-PSX-P4",
        mode: "literal",
        case_sensitive: false,
      },
      argv: [
        "search",
        source,
        "REA-PSX-P4",
        "--kind",
        "strings",
        "--mode",
        "literal",
      ],
    },
    ...[oracle.leaf, oracle.data].map((address) => ({
      operation: "xrefs",
      parameters: { address },
      argv: ["xrefs", source, address],
    })),
  ];
}

const psxWorkflowProvider = {
  id: "rea-workflow",
  name: "REA composed investigation workflow",
  version: "1",
};

/** Interpret only the saved named workflow, retaining the original Evidence unchanged. */
export function validatePublicPsxEvidence(value, binding) {
  assert.ok(binding, "Evidence omitted explicit invocation/session binding");
  const { operation, parameters, sourceDigest, selectedProfile } = binding;
  const evidence = parseEvidence(value);
  assert.equal(
    evidence.operation,
    operation,
    "Evidence operation differs from invocation",
  );
  const contract = toolContract(operation);
  contract.outputSchema.parse(evidence);
  assert.deepEqual(evidence.parameters, contract.inputSchema.parse(parameters));
  assert.equal(evidence.subject?.digest.sha256, sourceDigest);
  assert.equal(evidence.subject?.format, "ps-x-exe");
  assert.equal(evidence.subject?.architecture, "mips");
  const selected = analysisProfileSchema.parse(selectedProfile);
  assert.equal(selected.provider.id, "ghidra");
  assert.equal(selected.parameters.psx_import.source_sha256, sourceDigest);
  for (const [name, expected] of [
    ["startup_agreement", "psx-observed-import-and-provenance-v3"],
    ["psx_source_provenance", "rea-psx-filebytes-rebind-v2"],
    ["psx_preparation_transaction", "exclusive-top-level-v1"],
    [
      "instruction_flow_evidence",
      "decoded-return-before-jump-and-delay-slots-v2",
    ],
  ])
    assert.equal(selected.parameters[name], expected);
  const outer = analysisProfileSchema.parse(evidence.analysis_profile);
  let execution = outer;
  if (operation === "binary_overview") {
    assert.deepEqual(evidence.provider, psxWorkflowProvider);
    assert.deepEqual(outer.provider, psxWorkflowProvider);
    assert.equal(outer.parameters.workflow_revision, 2);
    assert.equal(evidence.confidence, "derived");
    assert.ok(
      evidence.limitations.includes("Derived by an REA composed workflow."),
    );
    execution = analysisProfileSchema.parse(
      outer.parameters.upstream_analysis_profile,
    );
    assert.deepEqual(
      outer,
      createAnalysisProfile(psxWorkflowProvider, {
        upstream_analysis_profile: execution,
        workflow_revision: 2,
      }),
    );
  } else assert.equal(evidence.provider.id, "ghidra");
  assert.equal(execution.provider.id, "ghidra");
  assert.deepEqual(
    execution,
    selected,
    "Evidence execution differs from selected session profile",
  );
  return execution;
}

/** Native startup commits execution ownership rather than a composed outer observation. */
export function assertPublicPsxStartupBinding(evidence, binding, commitment) {
  const execution = validatePublicPsxEvidence(evidence, binding);
  assert.equal(commitment.source_sha256, binding.sourceDigest);
  assert.equal(commitment.profile_digest, execution.digest);
  return execution;
}

function assertPublicPsxMetadata(cli, mcp, binding) {
  validatePublicPsxEvidence(cli, binding);
  validatePublicPsxEvidence(mcp, binding);
  assert.equal(cli.operation, mcp.operation);
  assert.deepEqual(cli.subject, mcp.subject);
  assert.deepEqual(cli.provider, mcp.provider);
  assert.deepEqual(cli.analysis_profile, mcp.analysis_profile);
  for (const field of [
    "parameters",
    "confidence",
    "authority",
    "environment",
    "limitations",
    "locations",
    "evidence_links",
  ])
    assert.deepEqual(
      cli[field],
      mcp[field],
      `${binding.operation} ${field} disagreement`,
    );
}

export function assertPublicPsxParity(cli, mcp, binding) {
  assertPublicPsxMetadata(cli, mcp, binding);
  assert.deepEqual(
    cli.normalized_result,
    mcp.normalized_result,
    `${cli.operation} CLI/MCP semantic disagreement`,
  );
}

export const publicPsxSnapshotLimitation =
  "Loaded from a local REA analysis snapshot; this call did not re-run the provider.";
const immutablePublicRecord = (value) => {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) immutablePublicRecord(child);
    Object.freeze(value);
  }
  return value;
};
const liveExpectationKey = (binding) => {
  const profile = analysisProfileSchema.parse(binding.selectedProfile);
  return JSON.stringify([
    binding.operation,
    toolContract(binding.operation).inputSchema.parse(binding.parameters),
    binding.sourceDigest,
    profile.digest,
  ]);
};

/** Retain one chronological observation with its explicit execution/capture association. */
export function publicPsxObservation(evidence, binding, association) {
  validatePublicPsxEvidence(evidence, binding);
  assert.ok(
    Number.isSafeInteger(association.event_sequence) &&
      association.event_sequence > 0,
  );
  assert.equal(typeof association.run_id, "string");
  assert.ok(association.run_id.length > 0 && association.capture);
  assert.equal(association.capture.run_id, association.run_id);
  return immutablePublicRecord(
    structuredClone({
      ...association,
      mode: evidence.limitations.includes(publicPsxSnapshotLimitation)
        ? "mcp-cache"
        : "native",
      evidence,
      binding,
    }),
  );
}

/** Chronology never replaces the first live, exact source/profile/query owner. */
export function createPublicPsxLiveExpectations() {
  const live = new Map();
  const observations = [];
  let frozen = false;
  return {
    observe(evidence, binding, association) {
      const record = publicPsxObservation(evidence, binding, association);
      observations.push(record);
      const key = liveExpectationKey(binding);
      if (!frozen && record.mode === "native" && !live.has(key))
        live.set(key, record);
      return record;
    },
    missing(bindings) {
      return bindings.filter(
        (binding) => !live.has(liveExpectationKey(binding)),
      );
    },
    live(binding) {
      const record = live.get(liveExpectationKey(binding));
      assert.ok(
        record && record.mode === "native",
        "Missing exact first live expectation",
      );
      validatePublicPsxEvidence(record.evidence, binding);
      return record;
    },
    freeze(bindings) {
      assert.equal(frozen, false, "Live collection already frozen");
      const manifest = bindings.map((binding) => {
        const record = this.live(binding);
        return {
          operation: binding.operation,
          parameters: binding.parameters,
          source_sha256: binding.sourceDigest,
          profile: binding.selectedProfile,
          evidence_id: record.evidence.evidence_id,
          event_sequence: record.event_sequence,
          run_id: record.run_id,
          runtime_root: record.capture.runtime_root,
          provenance_mode: record.mode,
        };
      });
      frozen = true;
      return immutablePublicRecord(structuredClone(manifest));
    },
    observations() {
      return [...observations];
    },
  };
}

/** Capture association contains only already observed owned startup/original records. */
export function publicPsxCaptureForRun(context, runId) {
  const matches = [...context.roots.values()].filter(
    (root) => root.run_id === runId,
  );
  assert.equal(
    matches.length,
    1,
    "Missing exact native run capture association",
  );
  const root = matches[0];
  assertPublicPsxRetainedCapture(root, { sourceDigest: root.source_digest });
  return structuredClone({
    run_id: root.run_id,
    runtime_root: root.root,
    parent_pid: root.ownership.parent_pid,
    snapshot: root.snapshot,
    records: Object.fromEntries(
      ["psx-import-before.json", "psx-provenance-original.json"].map((name) => [
        name,
        root.records[name],
      ]),
    ),
  });
}

/** Validate image facts against their own source and independently captured fixed-record bytes. */
export function validatePublicPsxImageImport(record, binding, sourceBytes) {
  assert.equal(
    record.mode,
    "native",
    "Image import requires native observation",
  );
  assert.equal(
    record.evidence.limitations.includes(publicPsxSnapshotLimitation),
    false,
    "Cached Evidence cannot be a live expectation",
  );
  const profile = validatePublicPsxEvidence(record.evidence, binding);
  const image = psxLoadImageSchema.parse(record.evidence.normalized_result);
  assert.equal(image.status, "verified");
  assert.equal(image.coverage.complete, true);
  const capture = record.capture;
  assert.ok(
    capture && capture.records,
    "Image import omitted required own-run capture",
  );
  assert.equal(capture.run_id, record.run_id);
  assert.equal(capture.snapshot.sha256, binding.sourceDigest);
  assert.equal(publicPsxDigest(sourceBytes), binding.sourceDigest);
  const readCaptured = (name, schema) => {
    const raw = capture.records[name];
    assert.ok(raw && typeof raw.text === "string", `Image omitted ${name}`);
    assert.equal(dirname(raw.path), capture.runtime_root);
    assert.equal(
      publicPsxDigest(raw.text),
      raw.sha256,
      `Captured ${name} digest mismatch`,
    );
    return schema.parse(JSON.parse(raw.text));
  };
  const before = readCaptured(
    "psx-import-before.json",
    psxImportObservationSchema,
  );
  const original = readCaptured(
    "psx-provenance-original.json",
    psxOriginalEvidenceRecordSchema,
  );
  assert.equal(before.stage, "before-analysis");
  assertPublicPsxStartupBinding(record.evidence, binding, before.commitment);
  for (const item of [before, original]) {
    assert.equal(item.commitment.run_id, record.run_id);
    assert.equal(item.commitment.profile_digest, profile.digest);
    assert.equal(item.commitment.source_sha256, binding.sourceDigest);
  }
  assert.equal(before.observed.source.snapshot_path, capture.snapshot.path);
  assert.equal(before.observed.source.sha256, binding.sourceDigest);
  assert.equal(before.observed.source.file_bytes, sourceBytes.length);
  const provenance = image.observations.psx.provenance;
  assert.deepEqual(
    provenance,
    before.provenance,
    "Image preparation differs from own startup capture",
  );
  const metadata = provenance.metadata_preservation;
  assert.equal(
    capture.records["psx-provenance-original.json"].sha256,
    metadata.original_record_sha256,
  );
  assert.equal(original.state_sha256, metadata.original_state_sha256);
  assert.equal(
    original.operational_state_sha256,
    metadata.original_operational_state_sha256,
  );
  assert.deepEqual(original.label_history, metadata.label_history.before);
  const preparation = validateGhidraPsxPreparation(provenance, {
    sourceSha256: binding.sourceDigest,
    sourceFileBytes: sourceBytes.length,
    payloadStart: Number.parseInt(image.payload.start.slice(2), 16),
    payloadBytes: image.payload_bytes,
  });
  assert.ok(preparation.ok, preparation.error);
  const attested = attestGhidraPsxLoadImage(
    sourceBytes,
    binding.sourceDigest,
    image.observations,
  );
  assert.ok(attested.ok, attested.error);
  assert.deepEqual(
    image,
    attested.value,
    "Image differs from independent strict source/journal checks",
  );
  return {
    run_id: record.run_id,
    original_record_sha256: metadata.original_record_sha256,
    startup_record_sha256: capture.records["psx-import-before.json"].sha256,
  };
}

function stablePublicPsxImage(image) {
  const { observations, ...imageFacts } = image;
  const { psx, ...observationFacts } = observations;
  const { provenance, current_label_history, ...psxFacts } = psx;
  const { metadata_preservation, ...provenanceFacts } = provenance;
  const {
    original_state_sha256: _originalStateSha256,
    adapted_state_sha256: _adaptedStateSha256,
    original_record_sha256: _originalRecordSha256,
    label_history,
    ...metadataFacts
  } = metadata_preservation;
  const { before, after, ...journalFacts } = label_history;
  const rowFacts = (rows) =>
    rows.map(
      ({ modification_time_ms: _modificationTimeMs, ...facts }) => facts,
    );
  return {
    imageFacts,
    observationFacts,
    psxFacts,
    provenanceFacts,
    metadataFacts,
    journalFacts,
    before: rowFacts(before),
    after: rowFacts(after),
    current: rowFacts(current_label_history),
  };
}

/** Independent imports retain per-run journal clocks/commitments; all other facts remain exact. */
export function assertPublicPsxLiveParity(cli, mcp, binding, sourceBytes) {
  for (const record of [cli, mcp]) {
    assert.equal(
      record.mode,
      "native",
      "Fresh/replay provenance mode mismatch",
    );
    assert.equal(
      record.evidence.limitations.includes(publicPsxSnapshotLimitation),
      false,
      "Cached Evidence cannot be a live expectation",
    );
  }
  assertPublicPsxMetadata(cli.evidence, mcp.evidence, binding);
  if (binding.operation !== "inspect_native_load_image") {
    assert.deepEqual(
      cli.evidence.normalized_result,
      mcp.evidence.normalized_result,
    );
    return { mode: "native", differences: [] };
  }
  const attestations = [cli, mcp].map((record) =>
    validatePublicPsxImageImport(record, binding, sourceBytes),
  );
  const [left, right] = [cli, mcp].map(
    (record) => record.evidence.normalized_result,
  );
  assert.deepEqual(
    stablePublicPsxImage(left),
    stablePublicPsxImage(right),
    "Unlisted live image semantic difference",
  );
  const differences = [];
  const root = "observations.psx.provenance.metadata_preservation";
  const note = (path, leftValue, rightValue, check) => {
    if (leftValue !== rightValue)
      differences.push({
        path,
        left: leftValue,
        right: rightValue,
        own_runs: attestations.map(({ run_id }) => run_id),
        validated_by: check,
      });
  };
  for (const field of [
    "original_state_sha256",
    "adapted_state_sha256",
    "original_record_sha256",
  ])
    note(
      `${root}.${field}`,
      left.observations.psx.provenance.metadata_preservation[field],
      right.observations.psx.provenance.metadata_preservation[field],
      "own fixed-record bytes and authenticated preparation capture",
    );
  for (const [path, leftRows, rightRows] of [
    [
      `${root}.label_history.before`,
      left.observations.psx.provenance.metadata_preservation.label_history
        .before,
      right.observations.psx.provenance.metadata_preservation.label_history
        .before,
    ],
    [
      `${root}.label_history.after`,
      left.observations.psx.provenance.metadata_preservation.label_history
        .after,
      right.observations.psx.provenance.metadata_preservation.label_history
        .after,
    ],
    [
      "observations.psx.current_label_history",
      left.observations.psx.current_label_history,
      right.observations.psx.current_label_history,
    ],
  ])
    for (const [index, row] of leftRows.entries())
      note(
        `${path}[${index}].modification_time_ms`,
        row.modification_time_ms,
        rightRows[index].modification_time_ms,
        "strict Java-long, ordinal, delta, scope and own preparation/image checks",
      );
  return { mode: "independent-native-imports", attestations, differences };
}

/** MCP replay owns its truthful extra cache provenance and preserves all original facts. */
export function assertPublicPsxMcpReplay(replay, original, binding) {
  validatePublicPsxEvidence(replay.evidence, binding);
  validatePublicPsxEvidence(original.evidence, binding);
  assert.equal(
    replay.mode,
    "mcp-cache",
    "MCP replay omitted cache provenance mode",
  );
  const originalLimitations = original.evidence.limitations;
  const expectedLimitations =
    original.mode === "mcp-cache"
      ? originalLimitations
      : [...originalLimitations, publicPsxSnapshotLimitation];
  assert.deepEqual(replay.evidence.limitations, expectedLimitations);
  assert.equal(
    replay.evidence.limitations.filter(
      (item) => item === publicPsxSnapshotLimitation,
    ).length,
    1,
  );
  for (const field of [
    "subject",
    "provider",
    "analysis_profile",
    "parameters",
    "confidence",
    "authority",
    "environment",
    "locations",
    "evidence_links",
    "normalized_result",
    "raw_result",
  ])
    assert.deepEqual(
      replay.evidence[field],
      original.evidence[field],
      `${binding.operation} MCP replay ${field} disagreement`,
    );
}

export function publicPsxCliSnapshotRoutes(source, snapshot) {
  return ["0x80010000", "0x80010080"].map((procedure) => ({
    operation: "analyze_function",
    parameters: { procedure },
    argv: ["function", source, procedure, "--snapshot", snapshot],
  }));
}

/** Exact production selector owns persisted CLI expectations, never MCP cache observations. */
export function selectPublicPsxSnapshotEvidence(execution, binding) {
  assert.equal(execution.mode, "snapshot-evidence");
  assert.equal(binding.operation, "analyze_function");
  assert.ok(execution.snapshot && isAbsolute(execution.snapshot.path));
  assert.equal(
    publicPsxDigest(execution.snapshot.text),
    execution.snapshot.sha256,
  );
  const snapshot = parseAnalysisSnapshot(JSON.parse(execution.snapshot.text));
  const profile = analysisProfileSchema.parse(binding.selectedProfile);
  assert.equal(execution.target.sha256, binding.sourceDigest);
  assert.equal(snapshot.target.sha256, binding.sourceDigest);
  assert.deepEqual(snapshot.binding.analysis_profile, profile);
  const evidence = snapshotEvidenceForQuery(snapshot, {
    target: execution.target,
    bindingProfile: profile,
    operation: binding.operation,
    parameters: binding.parameters,
    provider: profile.provider,
    evidenceProfile: profile,
  });
  assert.ok(evidence, "Required exact persisted CLI Evidence hit missing");
  validatePublicPsxEvidence(evidence, binding);
  return evidence;
}

/** Positive CLI execution has an explicit native or exact persisted-Evidence owner. */
export function assertPublicPsxCliExecution(
  evidence,
  binding,
  execution,
  allocations,
) {
  assert.ok(execution, "CLI omitted explicit execution mode");
  validatePublicPsxEvidence(evidence, binding);
  if (execution.mode === "snapshot-evidence") {
    assert.equal(
      allocations.length,
      0,
      "Snapshot Evidence hit unexpectedly allocated a native runtime",
    );
    const expected = selectPublicPsxSnapshotEvidence(execution, binding);
    assert.ok(
      execution.original && execution.original.mode === "native",
      "Persisted Evidence omitted original live owner",
    );
    validatePublicPsxEvidence(execution.original.evidence, binding);
    assert.deepEqual(
      expected,
      execution.original.evidence,
      "Persisted Evidence differs from original live owner",
    );
    assert.deepEqual(
      evidence,
      expected,
      "CLI differs from exact original persisted Evidence",
    );
    return {
      mode: "snapshot-evidence",
      original_evidence_id: expected.evidence_id,
      snapshot_sha256: execution.snapshot.sha256,
    };
  }
  assert.equal(execution.mode, "native");
  assert.equal(
    evidence.limitations.includes(publicPsxSnapshotLimitation),
    false,
    "Native CLI returned cached Evidence",
  );
  assert.equal(
    allocations.length,
    1,
    "Live CLI omitted its exact owned native runtime capture",
  );
  const root = allocations[0];
  const commitment = assertPublicPsxRetainedCapture(root, {
    sourceDigest: binding.sourceDigest,
    profileDigest: binding.selectedProfile.digest,
  });
  assertPublicPsxStartupBinding(evidence, binding, commitment);
  return { mode: "native", run_id: root.run_id };
}

/** Preserve the single public Program identity and reject changed observations on reopen. */
export function publicPsxDocumentIdentifier(documents, expected) {
  assert.ok(
    Array.isArray(documents) &&
      documents.length === 1 &&
      typeof documents[0] === "string" &&
      documents[0].length > 0,
    "Snapshot requires exactly one observed nonempty Program identity",
  );
  const document = documents[0];
  if (expected !== undefined)
    assert.equal(document, expected, "Snapshot Program identity changed");
  return document;
}

/** Bind immutable queries to the exact Program identity observed through list_documents. */
export function publicPsxSnapshotQueries(documents) {
  const document = publicPsxDocumentIdentifier(documents);
  return [
    ["inspect_native_load_image", {}],
    ["inspect_native_instruction", { address: "0x80010008", document }],
    ["resolve_native_call_targets", { address: "0x80010034", document }],
    ["analyze_function", { procedure: "0x80010000" }],
  ];
}

/** Require exact cache keys and their actually retained, profile-bound public observations. */
export function assertPublicPsxSnapshotEntries(
  value,
  queries,
  observations,
  { sourceDigest, selectedProfile },
) {
  const snapshot = parseAnalysisSnapshot(value);
  assert.equal(snapshot.target.sha256, sourceDigest);
  assert.deepEqual(snapshot.binding.analysis_profile, selectedProfile);
  assert.equal(observations.length, queries.length);
  for (const [index, [operation, parameters]] of queries.entries()) {
    const observation = observations[index];
    validatePublicPsxEvidence(observation, {
      operation,
      parameters,
      sourceDigest,
      selectedProfile,
    });
    const queryId = analysisQueryId(
      snapshot.target,
      snapshot.binding,
      operation,
      parameters,
    );
    const entry = snapshot.entries.find((item) => item.query_id === queryId);
    assert.ok(entry, `${operation} exact query missing from real saved cache`);
    assert.equal(entry.operation, operation);
    assert.deepEqual(entry.parameters, parameters);
    assert.deepEqual(entry.execution.result, observation.normalized_result);
    assert.deepEqual(entry.execution.raw_result, observation.raw_result);
    assert.deepEqual(entry.execution.provider, observation.provider);
    assert.deepEqual(
      snapshot.evidence_bundle.records.find(
        (record) => record.evidence_id === observation.evidence_id,
      ),
      observation,
    );
  }
  return snapshot;
}

/** Independent copies retain distinct contradictions, never altering provider assets. */
export function publicPsxSnapshotMutations(snapshot) {
  return [
    [
      "source-digest",
      (copy) => {
        copy.target.sha256 = "0".repeat(64);
      },
    ],
    [
      "loader-assets",
      (copy) => {
        copy.binding.analysis_profile.parameters.psx_asset_inventory[0].sha256 =
          "0".repeat(64);
      },
    ],
    [
      "import-options",
      (copy) => {
        copy.binding.analysis_profile.parameters.psx_import.supplied_loader_options =
          { ramStart: "0x90000000" };
      },
    ],
    [
      "interpretation",
      (copy) => {
        copy.binding.analysis_profile.parameters.instruction_flow_evidence =
          "contradictory-interpretation";
      },
    ],
  ].map(([id, mutate]) => {
    const copy = structuredClone(snapshot);
    mutate(copy);
    return { id, snapshot: copy };
  });
}

/** Observe allocated native ownership, not elapsed time, before invoking cancellation. */
export async function coordinatePublicPsxCancellation({
  pending,
  observe,
  cancel,
  deadlineMs = 180000,
}) {
  let complete = false;
  const result = pending.then(
    (value) => {
      complete = true;
      return { value };
    },
    (cause) => {
      complete = true;
      return { cause };
    },
  );
  const deadline = new ProviderStartupDeadline(deadlineMs);
  try {
    while (!complete) {
      const allocated = await observe();
      if (allocated.length) {
        if (complete) break;
        await cancel(allocated);
        const outcome = await result;
        return {
          status:
            outcome.cause || outcome.value?.error?.code === "cancelled"
              ? "passed"
              : "inconclusive",
          allocated,
          outcome,
        };
      }
      deadline.signal.throwIfAborted();
      await deadline.wait(10);
    }
    return { status: "inconclusive", allocated: [], outcome: await result };
  } finally {
    deadline.dispose();
  }
}

function requireCancellation(result) {
  if (result.status !== "passed") {
    const error = new Error(
      "Request completed before cancellation established an in-flight refusal",
    );
    error.inconclusive = true;
    throw error;
  }
  if (result.outcome.cause)
    assert.match(
      result.outcome.cause.message ?? "",
      /cancel|abort|disconnect|closed/iu,
      "Unrelated request failure cannot prove cancellation",
    );
}

async function retainPublicPsxCancellation(context, result) {
  requireCancellation(result);
  for (const observed of result.allocated) {
    assert.equal(
      context.roots.get(observed.root),
      observed,
      "Cancellation omitted its exact observed owner",
    );
    assert.ok(
      observed.capture_state.components.snapshot,
      "Cancellation lacks observed source component",
    );
    assert.equal(observed.snapshot.sha256, observed.source_digest);
    const event_sequence = await context.emit({
      stage: "cancellation",
      case_id: observed.case_id,
      adapter: observed.adapter,
      kind: "assertion",
      criterion: "observed-in-flight-cancellation",
      outcome: "passed",
      runtime_root: observed.root,
      run_id: observed.run_id,
      capture_status: observed.capture_state.status,
      missing_capture_components: publicPsxCaptureMissing(observed),
      error: result.outcome.cause
        ? publicPsxFailure(result.outcome.cause)
        : result.outcome.value.error,
    });
    observed.capture_outcome = { status: "cancelled", event_sequence };
  }
}

function publicPsxCancellationBinding(state, source, sourceDigest) {
  assert.equal(state.open, true, "Cancellation target is not admitted");
  assert.equal(state.path, source, "Cancellation target path changed");
  assert.equal(
    state.sha256,
    sourceDigest,
    "Cancellation target source changed",
  );
  assert.equal(state.analysis_provider_binding.provider.id, "ghidra");
  const selectedProfile = analysisProfileSchema.parse(
    state.analysis_provider_binding.analysis_profile,
  );
  assert.equal(selectedProfile.provider.id, "ghidra");
  assert.equal(typeof state.analysis_run.run_id, "string");
  return {
    operation: "inspect_native_load_image",
    parameters: {},
    sourceDigest,
    selectedProfile,
  };
}

function bindPublicPsxCancellationSource(context, sourceDigest) {
  if (context.sourceDigest === undefined) context.sourceDigest = sourceDigest;
  assert.equal(
    context.sourceDigest,
    sourceDigest,
    "Cancellation context source changed",
  );
}

export function assertPublicPsxCancellationOutcome(
  cancellation,
  { mode, reason, aborted },
) {
  assert.ok(["abort", "disconnect"].includes(mode));
  requireCancellation(cancellation);
  assert.ok(
    cancellation.allocated.length > 0,
    "Cancellation omitted allocation",
  );
  if (mode === "abort") assert.equal(aborted, true);
  if (cancellation.outcome.cause) {
    const cause = cancellation.outcome.cause;
    assert.ok(
      SdkError.isInstance(cause),
      "Non-SDK failure cannot prove cancellation",
    );
    assert.equal(
      cause.code,
      mode === "abort"
        ? SdkErrorCode.RequestTimeout
        : SdkErrorCode.ConnectionClosed,
      "Unrelated SDK failure cannot prove cancellation",
    );
    if (mode === "abort") assert.equal(cause.message, String(reason));
  } else {
    assert.equal(
      analysisErrorProjectionSchema.parse(cancellation.outcome.value.error)
        .code,
      "cancelled",
    );
  }
}

/** Cancellation belongs to the first deep request after lazy admission. */
export async function cancelPublicPsxNativeRequest(
  context,
  session,
  { source, sourceDigest, caseId, mode, deadlineMs = 180000 },
) {
  assert.ok(["abort", "disconnect"].includes(mode));
  await session.call("close_binary", {}, { caseId: `${caseId}-prior-close` });
  await observePublicPsxAllocations(
    context,
    session.pid,
    `${caseId}-baseline`,
    "mcp",
    sourceDigest,
  );
  for (const root of context.roots.values())
    if (root.ownership.parent_pid === session.pid)
      assert.ok(
        await absent(root.root),
        "Prior target retained a native runtime",
      );
  const baseline = new Set(context.roots.keys());
  await session.call(
    "open_binary",
    { path: source, provider_id: "ghidra" },
    { caseId: `${caseId}-admission` },
  );
  const admission = (
    await session.call("binary_session", {}, { caseId: `${caseId}-binding` })
  ).value;
  const binding = publicPsxCancellationBinding(admission, source, sourceDigest);
  bindPublicPsxCancellationSource(context, sourceDigest);
  await observePublicPsxAllocations(
    context,
    session.pid,
    `${caseId}-admission`,
    "mcp",
    sourceDigest,
  );
  assert.equal(
    admission.analysis_run.process_lineage.status,
    "not_observed",
    "Lazy admission already observed native startup",
  );
  assert.equal(
    [...context.roots.values()].filter(
      (root) =>
        root.ownership.parent_pid === session.pid && !baseline.has(root.root),
    ).length,
    0,
    "Lazy admission allocated a native runtime",
  );
  await context.emit({
    stage: "cancellation",
    case_id: caseId,
    adapter: "mcp",
    kind: "observation",
    admission,
    native_allocations: [],
    operation: binding.operation,
    parameters: binding.parameters,
  });
  const abort = new AbortController();
  const reason = new Error("Owned SDK image cancelled after native allocation");
  const pending = session.call(binding.operation, binding.parameters, {
    caseId,
    ...(mode === "abort" ? { signal: abort.signal } : {}),
    allowError: true,
    observeAllocations: false,
    allocationObserver: { kind: "cancellation-coordinator", case_id: caseId },
  });
  let cancellation;
  try {
    cancellation = await coordinatePublicPsxCancellation({
      pending,
      deadlineMs,
      observe: async () => {
        const allocated = await observePublicPsxAllocations(
          context,
          session.pid,
          caseId,
          "mcp",
          sourceDigest,
        );
        return allocated.filter((root) => {
          if (baseline.has(root.root)) return false;
          if (root.lifetime.status === "retired") return false;
          assert.equal(root.ownership.parent_pid, session.pid);
          assert.equal(root.run_id, admission.analysis_run.run_id);
          assert.equal(root.ownership.run_id, root.run_id);
          assert.equal(root.case_id, caseId);
          assert.equal(root.snapshot.sha256, sourceDigest);
          if (root.records["psx-import-before.json"])
            assert.equal(
              JSON.parse(root.records["psx-import-before.json"].text).commitment
                .profile_digest,
              binding.selectedProfile.digest,
            );
          return true;
        });
      },
      cancel: async (allocated) => {
        await context.emit({
          stage: "cancellation",
          case_id: caseId,
          adapter: "mcp",
          kind: "observation",
          action:
            mode === "abort"
              ? "SDK request abort"
              : "owned SDK transport disconnect",
          operation: binding.operation,
          parameters: binding.parameters,
          allocated: allocated.map(({ root, run_id, ownership, snapshot }) => ({
            root,
            run_id,
            ownership,
            source_sha256: snapshot.sha256,
          })),
        });
        if (mode === "abort") abort.abort(reason);
        else await session.disconnect();
      },
    });
  } catch (primary) {
    const interruption = new Error(
      "Owned SDK cancellation coordination failed",
    );
    try {
      if (mode === "abort") abort.abort(interruption);
      else await session.disconnect();
      try {
        await pending;
      } catch (cause) {
        const expected =
          SdkError.isInstance(cause) &&
          (mode === "abort"
            ? cause.code === SdkErrorCode.RequestTimeout &&
              cause.message === String(interruption)
            : cause.code === SdkErrorCode.ConnectionClosed);
        if (!expected && cause !== primary) throw cause;
      }
    } catch (cleanup) {
      throw new AggregateError(
        [primary, cleanup],
        "Cancellation coordination and request cleanup failed",
      );
    }
    throw primary;
  }
  assertPublicPsxCancellationOutcome(cancellation, {
    mode,
    reason,
    aborted: abort.signal.aborted,
  });
  await retainPublicPsxCancellation(context, cancellation);
  for (const root of cancellation.allocated) {
    await closePublicPsxNativeRoot(context, root);
    await context.emit({
      stage: "cancellation",
      case_id: caseId,
      adapter: "mcp",
      kind: "assertion",
      criterion: "exact-cancelled-native-owner-settled",
      outcome: "passed",
      runtime_root: root.root,
      run_id: root.run_id,
    });
  }
  return {
    cancellation,
    admission,
    binding,
    run_id: admission.analysis_run.run_id,
  };
}

export async function verifyPublicPsxCancellationRecovery(
  context,
  session,
  { source, sourceDigest, caseId },
) {
  const state = (
    await session.call("binary_session", {}, { caseId: `${caseId}-binding` })
  ).value;
  const binding = publicPsxCancellationBinding(state, source, sourceDigest);
  bindPublicPsxCancellationSource(context, sourceDigest);
  const baseline = new Set(context.roots.keys());
  const parsed = await session.call(
    "inspect_native_load_image",
    {},
    { caseId },
  );
  const evidence = parseEvidence(parsed.evidence);
  validatePublicPsxEvidence(evidence, binding);
  assert.equal(evidence.normalized_result.status, "verified");
  const allocated = [...context.roots.values()].filter(
    (root) =>
      root.ownership.parent_pid === session.pid &&
      root.case_id === caseId &&
      !baseline.has(root.root),
  );
  assert.equal(
    allocated.length,
    1,
    "Recovery omitted its new exact native allocation",
  );
  const root = allocated[0];
  assert.equal(root.run_id, state.analysis_run.run_id);
  const commitment = assertPublicPsxRetainedCapture(root, {
    sourceDigest,
    profileDigest: binding.selectedProfile.digest,
  });
  assertPublicPsxStartupBinding(evidence, binding, commitment);
  root.capture_outcome = {
    status: "native-result",
    evidence_id: evidence.evidence_id,
  };
  await context.emit({
    stage: "cancellation-recovery",
    case_id: caseId,
    adapter: "mcp",
    kind: "assertion",
    criterion: "new-bound-native-recovery",
    outcome: "passed",
    runtime_root: root.root,
    run_id: root.run_id,
    evidence_id: evidence.evidence_id,
  });
}

function verifyRuntimeBinding(context, state, sourceDigest) {
  const run = state.analysis_run.run_id;
  const profile = state.analysis_provider_binding.analysis_profile;
  assert.equal(profile.provider.id, "ghidra");
  assert.equal(
    profile.parameters.startup_agreement,
    "psx-observed-import-and-provenance-v3",
  );
  assert.equal(
    profile.parameters.psx_source_provenance,
    "rea-psx-filebytes-rebind-v2",
  );
  assert.equal(
    profile.parameters.instruction_flow_evidence,
    "decoded-return-before-jump-and-delay-slots-v2",
  );
  const root = [...context.roots.values()].find((item) => item.run_id === run);
  assert.ok(root, "Public run omitted exact native ownership capture");
  assert.ok(
    root.ownership.arguments.includes("-readOnly") &&
      root.ownership.arguments.includes("-deleteProject"),
  );
  assert.ok(!root.ownership.arguments.includes("-noanalysis"));
  assert.equal(
    root.ownership.arguments[root.ownership.arguments.indexOf("-loader") + 1],
    "PsxLoader",
  );
  assert.ok(
    !root.ownership.arguments.some((argument) =>
      /^-loader-ram(?:Start|Size)/u.test(argument),
    ),
  );
  const before = JSON.parse(root.records["psx-import-before.json"].text);
  const provenance = JSON.parse(
    root.records["psx-provenance-original.json"].text,
  );
  assert.equal(before.commitment.run_id, run);
  assert.equal(before.commitment.profile_digest, profile.digest);
  assert.equal(before.commitment.source_sha256, sourceDigest);
  // Keep original record independent; structural capture does not relabel it as
  // adapted loader lineage or infer unknown register/fill facts.
  assert.ok(provenance && root.snapshot.sha256 === sourceDigest);
  context.identities.push({
    run_id: run,
    profile,
    runtime_root: root.root,
    source_sha256: sourceDigest,
  });
}

async function acquirePublicPsxLiveExpectation(
  context,
  collection,
  source,
  binding,
) {
  const fresh = await connectPublicPsxMcp(
    context,
    `fresh-owner-${binding.operation}`,
  );
  let primary;
  try {
    await fresh.call("open_binary", { path: source, provider_id: "ghidra" });
    const state = (await fresh.call("binary_session")).value;
    assert.deepEqual(
      state.analysis_provider_binding.analysis_profile,
      binding.selectedProfile,
    );
    const result = await fresh.call(binding.operation, binding.parameters);
    collection.observe(result.evidence, binding, {
      event_sequence: result.observation_sequence,
      run_id: state.analysis_run.run_id,
      capture: publicPsxCaptureForRun(context, state.analysis_run.run_id),
    });
    collection.live(binding);
    await fresh.call("close_binary");
  } catch (cause) {
    primary = cause;
  }
  try {
    await fresh.close();
  } catch (cleanup) {
    primary = primary
      ? new AggregateError(
          [primary, cleanup],
          "Fresh expectation and cleanup failed",
        )
      : cleanup;
  }
  if (primary) throw primary;
}

/** Same complete public matrix for repository and installed executable callers. */
export async function verifyPublicPsx(arguments_) {
  const preflight = await preflightPublicPsx(arguments_);
  const context = createPublicPsxContext(arguments_);
  context.releaseInspector = true;
  const source = join(context.workspace, "original synthetic PSX flow 雪.exe");
  const sourceDigest = publicPsxDigest(preflight.fixture.bytes);
  context.sourceDigest = sourceDigest;
  let session;
  let selectedProfile;
  let currentRunId;
  let lastObservation;
  let target;
  const liveExpectations = createPublicPsxLiveExpectations();
  const bindingFor = (operation, parameters) => ({
    operation,
    parameters,
    sourceDigest,
    selectedProfile,
  });
  const call = async (operation, parameters = {}) => {
    const parsed = await session.call(operation, parameters);
    if (operation === "open_binary" && !parsed.error) {
      const state = (await session.call("binary_session")).value;
      selectedProfile = analysisProfileSchema.parse(
        state.analysis_provider_binding.analysis_profile,
      );
      currentRunId = state.analysis_run.run_id;
    }
    if (parsed.evidence) {
      lastObservation = liveExpectations.observe(
        parsed.evidence,
        bindingFor(operation, parameters),
        {
          event_sequence: parsed.observation_sequence,
          run_id: currentRunId,
          capture: publicPsxCaptureForRun(context, currentRunId),
        },
      );
    }
    return parsed.value;
  };
  try {
    await context.emit({
      stage: "preflight",
      case_id: "prerequisites",
      kind: "observation",
      installation: preflight.installation,
      assets: preflight.assets.candidate,
      fixture: preflight.fixture.expected,
    });
    await writeFile(source, preflight.fixture.bytes, {
      mode: 0o600,
      flag: "wx",
    });
    context.fixtures.push({
      path: source,
      canonical_path: await realpath(source),
      sha256: sourceDigest,
      expected: preflight.fixture.expected,
    });
    session = await connectPublicPsxMcp(context);
    await context.case("mcp-complete-independent-oracle", "mcp", async () => {
      target = await call("open_binary", {
        path: source,
        provider_id: "ghidra",
      });
      assert.equal(target.sha256, sourceDigest);
      assert.equal(target.format, "ps-x-exe");
      await verifyPsxInstructionFlow({
        call,
        oracle: psxInstructionFlowOracle,
        stage: "operations",
      });
      const routes = publicPsxCliRoutes(source);
      for (const route of routes)
        if (
          liveExpectations.missing([
            bindingFor(route.operation, route.parameters),
          ]).length
        )
          await call(route.operation, route.parameters);
      for (const missing of liveExpectations.missing(
        routes.map((route) => bindingFor(route.operation, route.parameters)),
      ))
        await acquirePublicPsxLiveExpectation(
          context,
          liveExpectations,
          source,
          missing,
        );
      verifyRuntimeBinding(context, await call("binary_session"), sourceDigest);
      await context.emit({
        stage: "live-expectations",
        case_id: "complete-base-route-owners",
        adapter: "mcp",
        kind: "observation",
        manifest: liveExpectations.freeze(
          routes.map((route) => bindingFor(route.operation, route.parameters)),
        ),
      });
    });
    await context.case(
      "mcp-selector-and-capability-refusals",
      "mcp",
      async () => {
        for (const [operation, parameters, code] of [
          [
            "annotate_native_function",
            { procedure: psxInstructionFlowOracle.entry, name: "forbidden" },
            "capability_unavailable",
          ],
          [
            "inspect_native_data_type",
            { address: psxInstructionFlowOracle.data },
            "capability_unavailable",
          ],
          [
            "procedure_address",
            { procedure: "nonexistent_function" },
            "invalid_request",
          ],
        ]) {
          const refused = await session.call(operation, parameters, {
            allowError: true,
          });
          assert.equal(refused.error?.code, code);
        }
        const operation = "inspect_native_load_image";
        const parameters = { document: "not-admitted" };
        const schema = session.schemas.get(operation);
        const beforeRefusal = await call("binary_session");
        assert.equal(schema.input({}), true);
        assert.equal(schema.input(parameters), false);
        const refused = await session.call(operation, parameters, {
          allowInvalidInput: true,
          allowUnstructuredToolError: true,
        });
        await context.emit({
          stage: "admission-refusal",
          case_id: "strict-image-document",
          adapter: "mcp",
          kind: "observation",
          ...assertPublicPsxImageAdmissionRefusal(
            refused,
            operation,
            parameters,
            schema,
          ),
        });
        const afterRefusal = await call("binary_session");
        assert.equal(afterRefusal.open, true);
        assert.equal(afterRefusal.sha256, sourceDigest);
        assert.equal(
          afterRefusal.analysis_run.run_id,
          beforeRefusal.analysis_run.run_id,
        );
        assert.deepEqual(
          afterRefusal.analysis_provider_binding.analysis_profile,
          selectedProfile,
        );
        assert.equal((await call(operation)).status, "verified");
      },
    );
    const snapshotPath = join(context.workspace, "public snapshot.json");
    let snapshot;
    let snapshotText;
    let snapshotEventSequence;
    let snapshotRunId;
    await context.case("mcp-four-family-snapshot", "mcp", async () => {
      const documents = await call("list_documents");
      const queries = publicPsxSnapshotQueries(documents);
      const scopedEvidence = [];
      const scopedObservations = [];
      for (const [operation, parameters] of queries) {
        const original = Object.hasOwn(parameters, "document")
          ? liveExpectations.live(
              bindingFor(operation, { address: parameters.address }),
            ).evidence
          : undefined;
        const result = await call(operation, parameters);
        if (Object.hasOwn(parameters, "document")) {
          assert.ok(original, `${operation} omitted-document oracle missing`);
          assert.deepEqual(result, original.normalized_result);
        }
        scopedEvidence.push(lastObservation.evidence);
        scopedObservations.push(lastObservation);
      }
      snapshotRunId = currentRunId;
      await call("close_binary", { snapshot_path: snapshotPath });
      const raw = await readFile(snapshotPath, "utf8");
      snapshotText = raw;
      snapshotEventSequence = await context.emit({
        stage: "snapshot",
        case_id: "snapshot-save",
        adapter: "mcp",
        kind: "raw_result",
        path: snapshotPath,
        sha256: publicPsxDigest(raw),
        text: raw,
      });
      snapshot = assertPublicPsxSnapshotEntries(
        JSON.parse(raw),
        queries,
        scopedEvidence,
        { sourceDigest, selectedProfile },
      );
      await call("open_binary", {
        path: source,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      assert.deepEqual(selectedProfile, snapshot.binding.analysis_profile);
      publicPsxDocumentIdentifier(await call("list_documents"), documents[0]);
      for (const [index, [operation, parameters]] of queries.entries()) {
        const previous = scopedEvidence[index];
        const replay = await session.call(operation, parameters);
        const replayOwner = liveExpectations.observe(
          replay.evidence,
          bindingFor(operation, parameters),
          {
            event_sequence: replay.observation_sequence,
            run_id: currentRunId,
            capture: publicPsxCaptureForRun(context, currentRunId),
          },
        );
        assertPublicPsxMcpReplay(
          replayOwner,
          scopedObservations[index],
          bindingFor(operation, parameters),
        );
        assert.deepEqual(replay.value, previous.normalized_result);
        assert.deepEqual(
          replay.evidence.analysis_profile,
          previous.analysis_profile,
        );
        assert.deepEqual(replay.evidence.raw_result, previous.raw_result);
        assert.deepEqual(replay.evidence.provider, previous.provider);
        assert.deepEqual(replay.evidence.subject, previous.subject);
        assert.deepEqual(replay.evidence.parameters, previous.parameters);
      }
    });
    await context.case("mcp-atomic-snapshot-rejections", "mcp", async () => {
      const previousState = await call("binary_session");
      for (const mutation of publicPsxSnapshotMutations(snapshot)) {
        const path = join(
          context.workspace,
          `contradictory-${mutation.id}.json`,
        );
        const bytes = JSON.stringify(mutation.snapshot);
        await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
        const rejected = await session.call(
          "open_binary",
          { path: source, provider_id: "ghidra", snapshot_path: path },
          { allowError: true },
        );
        assert.equal(rejected.error?.code, "evidence_integrity_mismatch");
        assert.equal(
          (await call("binary_session")).analysis_run.run_id,
          previousState.analysis_run.run_id,
        );
        assert.equal(await readFile(path, "utf8"), bytes);
        assert.equal(
          (await call("inspect_native_load_image")).status,
          "verified",
        );
      }
    });
    await context.case("cli-complete-parity", "cli", async () => {
      for (const [index, route] of publicPsxCliRoutes(source).entries()) {
        const binding = bindingFor(route.operation, route.parameters);
        const result = await invokePublicPsxCli(context, route.argv, {
          caseId: `cli-${index}-${route.operation}`,
          sourceDigest,
          binding,
          execution: { mode: "native" },
        });
        const comparison = assertPublicPsxLiveParity(
          result.observation,
          liveExpectations.live(binding),
          binding,
          preflight.fixture.bytes,
        );
        await context.emit({
          stage: "live-parity",
          case_id: `cli-${index}-${route.operation}`,
          adapter: "cli",
          kind: "assertion",
          criterion: "exact-live-operation-facts-and-own-import-provenance",
          outcome: "passed",
          comparison,
        });
        if (route.operation === "search_procedures")
          for (const address of [
            psxInstructionFlowOracle.entry,
            psxInstructionFlowOracle.leaf,
          ])
            assert.ok(
              JSON.stringify(result.value).includes(address),
              `Procedure search omitted ${address}`,
            );
        if (route.operation === "search_strings")
          assert.ok(JSON.stringify(result.value).includes("REA-PSX-P4"));
      }
    });
    await context.case(
      "cli-exact-persisted-function-evidence",
      "cli",
      async () => {
        for (const [index, route] of publicPsxCliSnapshotRoutes(
          source,
          snapshotPath,
        ).entries()) {
          const path = join(
            context.workspace,
            `owned-cli-function-snapshot-${index}.json`,
          );
          await writeFile(path, snapshotText, { mode: 0o600, flag: "wx" });
          const binding = bindingFor(route.operation, route.parameters);
          const execution = {
            mode: "snapshot-evidence",
            snapshot: {
              path,
              text: snapshotText,
              sha256: publicPsxDigest(snapshotText),
            },
            target,
          };
          const original = selectPublicPsxSnapshotEvidence(execution, binding);
          execution.original = publicPsxObservation(original, binding, {
            event_sequence: snapshotEventSequence,
            run_id: snapshotRunId,
            capture: publicPsxCaptureForRun(context, snapshotRunId),
          });
          const argv = publicPsxCliSnapshotRoutes(source, path)[index].argv;
          await invokePublicPsxCli(context, argv, {
            caseId: `cli-persisted-function-${index}`,
            sourceDigest,
            binding,
            execution,
          });
        }
      },
    );
    await call("close_binary");
    await context.case("public-malformed-policy-refusals", "mcp", async () => {
      const original = preflight.fixture.bytes;
      const unsupported = Buffer.from(original);
      unsupported.writeUInt32LE(0xa0010000, 0x18);
      unsupported.writeUInt32LE(0xa0010000, 0x10);
      for (const [id, bytes] of [
        ["truncated", original.subarray(0, 0x40)],
        ["malformed", Buffer.from("PS-X EXE malformed")],
        ["unsupported-layout", unsupported],
      ]) {
        const path = join(context.workspace, `${id}.exe`);
        await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
        const before = context.roots.size;
        const rejected = await session.call(
          "open_binary",
          { path, provider_id: "ghidra" },
          { allowError: true },
        );
        assert.equal(
          rejected.error?.code,
          id === "unsupported-layout"
            ? "execution_failure"
            : "target_unavailable",
          JSON.stringify(rejected),
        );
        if (id === "unsupported-layout")
          assert.equal(
            rejected.error.details.diagnostics.psx_import_policy.policy,
            "psx-kseg0-2m-defaults-v1",
          );
        assert.equal((await call("binary_session")).open, false);
        assert.equal(
          context.roots.size,
          before,
          "Rejected input allocated native runtime",
        );
        assert.deepEqual(await readFile(path), bytes);
        const cli = await invokePublicPsxCli(
          context,
          ["inspect-native-load-image", path],
          { caseId: `cli-${id}`, allowError: true },
        );
        assertPublicPsxErrorParity(cli.error, rejected.error);
      }
    });
    await context.case("sdk-in-flight-image-cancellation", "mcp", async () => {
      const id = "sdk-cancel-image";
      await cancelPublicPsxNativeRequest(context, session, {
        source,
        sourceDigest,
        caseId: id,
        mode: "abort",
      });
      const state = (
        await session.call(
          "binary_session",
          {},
          { caseId: `${id}-after-cancel` },
        )
      ).value;
      await context.emit({
        stage: "cancellation",
        case_id: id,
        adapter: "mcp",
        kind: "observation",
        public_session_after_cancel: state,
      });
      if (state.open) {
        await verifyPublicPsxCancellationRecovery(context, session, {
          source,
          sourceDigest,
          caseId: `${id}-same-session-recovery`,
        });
        await session.call("close_binary");
      }
      await session.call("open_binary", {
        path: source,
        provider_id: "ghidra",
      });
      await verifyPublicPsxCancellationRecovery(context, session, {
        source,
        sourceDigest,
        caseId: `${id}-reopened-recovery`,
      });
      await session.call("close_binary");
    });
    await context.case("owned-mcp-native-disconnect", "mcp", async () => {
      const disconnected = await connectPublicPsxMcp(
        context,
        "disconnect-session",
      );
      const id = "disconnect-image";
      await cancelPublicPsxNativeRequest(context, disconnected, {
        source,
        sourceDigest,
        caseId: id,
        mode: "disconnect",
      });
      await disconnected.close();
      const recovered = await connectPublicPsxMcp(
        context,
        `${id}-recovery-session`,
      );
      await recovered.call("open_binary", {
        path: source,
        provider_id: "ghidra",
      });
      await verifyPublicPsxCancellationRecovery(context, recovered, {
        source,
        sourceDigest,
        caseId: `${id}-fresh-connection-recovery`,
      });
      await recovered.call("close_binary");
      await recovered.close();
    });
  } catch (cause) {
    context.primary = cause;
    try {
      await context.emit({
        stage: "primary",
        case_id: context.cases.at(-1)?.id ?? "public-workflow",
        kind: "failure",
        failure: publicPsxFailure(cause),
      });
    } catch (capture) {
      context.failures.push({ stage: "capture", ...publicPsxFailure(capture) });
    }
  }
  return settlePublicPsxContext(context, [
    async () => {
      if (context.fixtures.length) {
        const after = publicPsxDigest(await readFile(source));
        context.fixtures[0].after_sha256 = after;
        assert.equal(after, sourceDigest, "Source changed");
      }
    },
    async () => {
      const after = await inspectGhidraPsxLoader(
        preflight.installation.installDir,
        preflight.installation.providerVersion,
      );
      assert.equal(after.status, "available");
      assert.deepEqual(
        after.candidate.assets,
        preflight.assets.candidate.assets,
        "Installed assets changed",
      );
    },
  ]);
}
