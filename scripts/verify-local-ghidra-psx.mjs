#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePsxExeHeader } from "../dist/domain/psxExe.js";
import {
  assertPublicPsxLiveParity,
  assertPublicPsxSnapshotEntries,
  connectPublicPsxMcp,
  createPublicPsxContext,
  invokePublicPsxCli,
  publicPsxDigest,
  publicPsxDocumentIdentifier,
  publicPsxFailure,
  publicPsxCaptureForRun,
  publicPsxObservation,
  settlePublicPsxContext,
  validatePublicPsxEvidence,
  validatePublicPsxImageImport,
} from "./lib/real-ghidra-psx-public.mjs";
import {
  preflightPsxPublicRunner,
  runCapturedPsxPublic,
} from "./verify-real-ghidra-psx.mjs";

export const localPsxExpectedHeader = Object.freeze({
  payloadAddress: 0x80120000,
  payloadBytes: 0x75000,
  initialPc: 0x801255ac,
});

/** Exactly one caller-selected source; no discovery, manifests, or directory search. */
export function parseLocalPsxArguments(args) {
  assert.ok(
    args.length === 2 &&
      args[0] === "--binary" &&
      typeof args[1] === "string" &&
      args[1].length > 0 &&
      !args[1].startsWith("--"),
    "Usage: node scripts/verify-local-ghidra-psx.mjs --binary PATH",
  );
  return { supplied_path: args[1], path: resolve(args[1]) };
}

export async function readLocalPsxInput(args) {
  const input = parseLocalPsxArguments(args);
  assert.ok(isAbsolute(input.path));
  const canonicalPath = await realpath(input.path);
  const bytes = await readFile(input.path);
  const parsed = parsePsxExeHeader(bytes);
  if (!parsed.ok) throw parsed.error;
  for (const [key, expected] of Object.entries(localPsxExpectedHeader))
    assert.equal(
      parsed.value[key],
      expected,
      `Local patched-AC3 header mismatch: ${key}; fixed AC3 assertions stopped before native allocation`,
    );
  const offset = 0x800 + parsed.value.initialPc - parsed.value.payloadAddress;
  return {
    ...input,
    canonical_path: canonicalPath,
    sha256: publicPsxDigest(bytes),
    header: parsed.value,
    entry_address: `0x${parsed.value.initialPc.toString(16)}`,
    entry_bytes: bytes.subarray(offset, offset + 4).toString("hex"),
    identity: "Load Word translation-patched Disc 1 boot executable",
    limitations: ["No retail, Disc 2, overlays, or runtime coverage"],
  };
}

/** Typed unavailable results remain explicit partial facets, never manufactured success. */
export function localPsxFacet(name, parsed) {
  if (parsed.error)
    return { facet: name, status: "inconclusive", error: parsed.error };
  const value = parsed.value;
  if (name === "containing-function" && value?.found !== true)
    return {
      facet: name,
      status: "inconclusive",
      observation: value,
      reason: "No observed containing function",
    };
  if (
    name === "decompile" &&
    !(typeof value === "string" && /\{[\s\S]*\}/u.test(value))
  )
    return {
      facet: name,
      status: "inconclusive",
      observation: value,
      reason: "Decompiler returned no meaningful function body",
    };
  if (name === "references" && !Array.isArray(value?.references))
    return {
      facet: name,
      status: "inconclusive",
      observation: value,
      reason: "No typed outgoing references observed",
    };
  return { facet: name, status: "passed", observation: value };
}

/** Local ownership boundary retains partial observations and independent source checks. */
export async function settleLocalPsxOutcome(context, input, facets) {
  const outcome = await settlePublicPsxContext(context, [
    async () => {
      const after = publicPsxDigest(await readFile(input.path));
      context.fixtures[0].after_sha256 = after;
      assert.equal(after, input.sha256, "Caller source changed");
      assert.equal(
        await realpath(input.path),
        input.canonical_path,
        "Caller source identity changed",
      );
    },
  ]);
  return {
    ...outcome,
    facets,
    partial: facets.some((item) => item.status !== "passed"),
    limitations: input.limitations,
  };
}

/** Carry caller input and the observed session profile into shared named validation. */
export function localPsxBinding(input, selectedProfile, operation, parameters) {
  assert.ok(selectedProfile, "Actual local session profile is required");
  return { operation, parameters, sourceDigest: input.sha256, selectedProfile };
}

const localPsxJournalPolicy = "local-variable-add-journal-permutation-v1";
const localPsxJournalLimits = [
  "Independent imports do not establish equal event chronology.",
  "VARIABLE addresses are per-import database keys; this comparison does not establish equal underlying variable storage or function ownership.",
  "Whole-group ADD-history permutation does not establish deterministic analyzer scheduling.",
  "Duplicate occurrence pairing is lossless comparison bookkeeping, not identification of corresponding native events.",
];
const journalFacts = (row, withAddress) =>
  withAddress
    ? [row.address, row.label, row.action, row.user]
    : [row.label, row.action, row.user];

function journalMultiplicity(rows, withAddress) {
  const counts = new Map();
  for (const { row } of rows) {
    const key = JSON.stringify(journalFacts(row, withAddress));
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function journalGroups(rows) {
  const groups = new Map();
  for (const [index, row] of rows.entries()) {
    const group = groups.get(row.address) ?? [];
    group.push({ row, index });
    groups.set(row.address, group);
  }
  return groups;
}

function canonicalVariableAddress(address) {
  // The producer emits an encoded space name and unsigned Java-long hex.
  // Match the entire coordinate; a prefix or a coerced numeric value is not identity.
  const parsed = /^VARIABLE:(0x(?:0|[1-9a-f][0-9a-f]{0,15}))$/u.exec(address);
  return parsed !== null && parsed[0] === address;
}

/** Independently authenticate both raw imports before applying the local journal policy. */
export function assertLocalPsxLiveParity(cli, mcp, binding, sourceBytes) {
  if (binding.operation !== "inspect_native_load_image")
    return assertPublicPsxLiveParity(cli, mcp, binding, sourceBytes);
  const inputs = [cli, mcp];
  const attestations = inputs.map((record) =>
    validatePublicPsxImageImport(record, binding, sourceBytes),
  );
  for (const record of inputs) {
    assert.ok(typeof record.run_id === "string" && record.run_id.length > 0);
    assert.ok(
      Number.isSafeInteger(record.event_sequence) && record.event_sequence > 0,
      "Local import requires its retained observation event",
    );
    validatePublicPsxEvidence(record.evidence, binding);
  }
  assert.notEqual(
    cli.run_id,
    mcp.run_id,
    "Local imports must have distinct run IDs",
  );
  for (const field of [
    "operation",
    "subject",
    "provider",
    "analysis_profile",
    "parameters",
    "confidence",
    "authority",
    "environment",
    "limitations",
    "locations",
    "evidence_links",
  ])
    assert.deepEqual(
      cli.evidence[field],
      mcp.evidence[field],
      `${field} disagreement`,
    );

  const images = inputs.map((record) => record.evidence.normalized_result);
  const root = "observations.psx.provenance.metadata_preservation";
  const metadata = images.map(
    (image) => image.observations.psx.provenance.metadata_preservation,
  );
  const digestFields = [
    "original_state_sha256",
    "adapted_state_sha256",
    "original_record_sha256",
  ];
  const projection = (image) => {
    const copy = structuredClone(image);
    delete copy.observations.psx.current_label_history;
    const preserved = copy.observations.psx.provenance.metadata_preservation;
    for (const field of digestFields) delete preserved[field];
    delete preserved.label_history.before;
    delete preserved.label_history.after;
    return copy;
  };
  assert.deepEqual(
    projection(images[0]),
    projection(images[1]),
    "Unlisted local image semantic difference",
  );

  const differences = [];
  const differenceKeys = new Set();
  const note = (leftPath, rightPath, left, right, validatedBy) => {
    const key = JSON.stringify([leftPath, rightPath, left, right]);
    if (left !== right && !differenceKeys.has(key)) {
      differenceKeys.add(key);
      differences.push({
        path: leftPath,
        left_path: leftPath,
        right_path: rightPath,
        left,
        right,
        own_runs: inputs.map((record) => record.run_id),
        event_sequences: inputs.map((record) => record.event_sequence),
        validated_by: validatedBy,
      });
    }
  };
  for (const field of digestFields)
    note(
      `${root}.${field}`,
      `${root}.${field}`,
      metadata[0][field],
      metadata[1][field],
      "own fixed-record bytes and authenticated preparation capture",
    );
  const reference = (record, path, item) => ({
    run_id: record.run_id,
    event_sequence: record.event_sequence,
    evidence_id: record.evidence.evidence_id,
    index: item.index,
    ordinal: item.row.ordinal,
    path: `${path}[${item.index}]`,
  });
  const pairRows = (leftRows, rightRows, path, withAddress, policy) => {
    assert.deepEqual(
      journalMultiplicity(leftRows, withAddress),
      journalMultiplicity(rightRows, withAddress),
      `${path} counted journal facts disagreement`,
    );
    const available = new Map();
    for (const item of rightRows) {
      const key = JSON.stringify(journalFacts(item.row, withAddress));
      const matches = available.get(key) ?? [];
      matches.push(item);
      available.set(key, matches);
    }
    return leftRows.map((leftItem) => {
      const key = JSON.stringify(journalFacts(leftItem.row, withAddress));
      const rightItem = available.get(key).shift();
      const left = reference(cli, path, leftItem),
        right = reference(mcp, path, rightItem);
      for (const field of ["address", "ordinal", "modification_time_ms"])
        note(
          `${left.path}.${field}`,
          `${right.path}.${field}`,
          leftItem.row[field],
          rightItem.row[field],
          policy,
        );
      return { left, right };
    });
  };
  const journals = [];
  const retainJournal = (path, leftRows, rightRows, rowMapping) => {
    // Report all changed original indexed clocks as well as matched-occurrence
    // clock/ordinal paths. The row mapping supplies the permitted fact relation.
    assert.equal(leftRows.length, rightRows.length);
    for (const [index, row] of leftRows.entries())
      for (const field of ["ordinal", "modification_time_ms"])
        note(
          `${path}[${index}].${field}`,
          `${path}[${index}].${field}`,
          row[field],
          rightRows[index][field],
          "authenticated original indexed clocks/ordinals with counted journal row mapping",
        );
    const items = (rows) => rows.map((row, index) => ({ row, index }));
    const multiplicities = (rows) =>
      journalMultiplicity(items(rows), true).map(([key, count]) => {
        const [address, label, action, user] = JSON.parse(key);
        return { address, label, action, user, count };
      });
    journals.push({
      path,
      cli_count: leftRows.length,
      mcp_count: rightRows.length,
      cli_multiplicities: multiplicities(leftRows),
      mcp_multiplicities: multiplicities(rightRows),
      row_mapping: rowMapping,
    });
  };
  for (const field of ["before", "after"]) {
    const path = `${root}.label_history.${field}`;
    const [leftRows, rightRows] = metadata.map(
      (value) => value.label_history[field],
    );
    const items = (rows) => rows.map((row, index) => ({ row, index }));
    retainJournal(
      path,
      leftRows,
      rightRows,
      pairRows(
        items(leftRows),
        items(rightRows),
        path,
        true,
        "exact preparation multiset except clock and ordinal",
      ),
    );
  }

  const currentPath = "observations.psx.current_label_history";
  const [leftRows, rightRows] = images.map(
    (image) => image.observations.psx.current_label_history,
  );
  const [leftGroups, rightGroups] = [leftRows, rightRows].map(journalGroups);
  assert.deepEqual(
    [...leftGroups.keys()].sort(),
    [...rightGroups.keys()].sort(),
    "Current journal address-key set disagreement",
  );
  const pinned = [],
    changed = [];
  for (const [address, rows] of leftGroups) {
    const right = rightGroups.get(address);
    if (
      JSON.stringify(journalMultiplicity(rows, false)) ===
      JSON.stringify(journalMultiplicity(right, false))
    )
      pinned.push(address);
    else {
      assert.ok(
        canonicalVariableAddress(address),
        "Changed noncanonical or non-VARIABLE journal group",
      );
      assert.ok(
        [...rows, ...right].every(({ row }) => row.action === 0),
        "Changed VARIABLE journal groups must contain ADD actions only",
      );
      changed.push(address);
    }
  }
  const signatures = (groups) => {
    const bySignature = new Map();
    for (const address of changed) {
      const signature = JSON.stringify(
        journalMultiplicity(groups.get(address), false),
      );
      assert.ok(
        !bySignature.has(signature),
        "Ambiguous VARIABLE group signature",
      );
      bySignature.set(signature, address);
    }
    return bySignature;
  };
  const [leftSignatures, rightSignatures] = [leftGroups, rightGroups].map(
    signatures,
  );
  assert.deepEqual(
    [...leftSignatures.keys()].sort(),
    [...rightSignatures.keys()].sort(),
    "Unmatched whole VARIABLE group signature",
  );
  assert.equal(
    changed.reduce(
      (count, address) => count + leftGroups.get(address).length,
      0,
    ),
    changed.reduce(
      (count, address) => count + rightGroups.get(address).length,
      0,
    ),
    "VARIABLE group row totals disagree",
  );
  const variableMappings = [];
  const rowMapping = pinned.flatMap((address) =>
    pairRows(
      leftGroups.get(address),
      rightGroups.get(address),
      currentPath,
      true,
      "exact pinned address-group multiset except clock and ordinal",
    ),
  );
  for (const [key, cliAddress] of leftSignatures) {
    const mcpAddress = rightSignatures.get(key);
    const left = leftGroups.get(cliAddress),
      right = rightGroups.get(mcpAddress);
    assert.equal(
      left.length,
      right.length,
      "VARIABLE group cardinality disagreement",
    );
    rowMapping.push(
      ...pairRows(left, right, currentPath, false, localPsxJournalPolicy),
    );
    variableMappings.push({
      cli_address: cliAddress,
      mcp_address: mcpAddress,
      row_count: left.length,
      signature: JSON.parse(key).map(([facts, count]) => {
        const [label, action, user] = JSON.parse(facts);
        return { label, action, user, count };
      }),
      cli_rows: left.map((item) => reference(cli, currentPath, item)),
      mcp_rows: right.map((item) => reference(mcp, currentPath, item)),
    });
  }
  rowMapping.sort((left, right) => left.left.index - right.left.index);
  retainJournal(currentPath, leftRows, rightRows, rowMapping);
  return {
    mode: "local-independent-native-image",
    policy: localPsxJournalPolicy,
    attestations,
    inputEvidence: inputs.map((record) => structuredClone(record)),
    limitations: [...localPsxJournalLimits],
    journals,
    variable_group_mappings: variableMappings,
    differences,
  };
}

/** Two immutable local queries use only the observed caller entry and Program identity. */
export function localPsxSnapshotQueries(input, documents) {
  assert.ok(
    typeof input.entry_address === "string" && input.entry_address.length > 0,
  );
  const document = publicPsxDocumentIdentifier(documents);
  return [
    ["inspect_native_load_image", {}],
    ["inspect_native_instruction", { address: input.entry_address, document }],
  ];
}

/** Explicit bounded game sequence; no synthetic fixed oracle is used on this input. */
export async function verifyLocalPsx(arguments_, input) {
  assert.ok(
    input && isAbsolute(input.path),
    "Explicit admitted input is required",
  );
  assert.equal(
    publicPsxDigest(await readFile(input.path)),
    input.sha256,
    "Local input changed after admission",
  );
  const context = createPublicPsxContext(arguments_);
  context.releaseInspector = true;
  context.sourceDigest = input.sha256;
  context.fixtures.push({ ...input });
  let session;
  let selectedProfile;
  const facets = [];
  const originalEvidence = new Map();
  const originalSequences = new Map();
  const originalOwners = new Map();
  const call = async (operation, parameters = {}, options) => {
    const parsed = await session.call(operation, parameters, options);
    if (parsed.evidence) {
      assert.equal(parsed.evidence.subject.digest.sha256, input.sha256);
      if (selectedProfile)
        validatePublicPsxEvidence(
          parsed.evidence,
          localPsxBinding(input, selectedProfile, operation, parameters),
        );
      if (!originalEvidence.has(operation)) {
        originalEvidence.set(operation, parsed.evidence);
        originalSequences.set(operation, parsed.observation_sequence);
      }
    }
    return parsed;
  };
  const facet = async (name, operation, parameters) => {
    const sequence = context.sequence + 1;
    const parsed = await call(operation, parameters, {
      allowError: true,
      caseId: `local-${name}`,
    });
    const result = localPsxFacet(name, parsed);
    facets.push(result);
    context.cases.push({
      id: `local-${name}`,
      adapter: "mcp",
      status: result.status,
      evidence_sequences: Array.from(
        { length: context.sequence - sequence + 1 },
        (_, index) => sequence + index,
      ),
    });
    await context.emit({
      stage: "local-facet",
      case_id: `local-${name}`,
      adapter: "mcp",
      kind: "assertion",
      criterion: name,
      outcome: result.status,
      facet: result,
    });
    return parsed.value;
  };
  try {
    await context.emit({
      stage: "preflight",
      case_id: "local-explicit-input",
      kind: "observation",
      input,
    });
    session = await connectPublicPsxMcp(context, "local-mcp");
    await context.case("local-source-image-entry", "mcp", async () => {
      const target = (
        await call("open_binary", { path: input.path, provider_id: "ghidra" })
      ).value;
      assert.equal(target.sha256, input.sha256);
      assert.equal(target.format, "ps-x-exe");
      const image = (await call("inspect_native_load_image")).value;
      assert.equal(image.status, "verified");
      assert.equal(image.coverage.complete, true);
      assert.ok(image.observations.entry_points.includes(input.entry_address));
      const instruction = (
        await call("inspect_native_instruction", {
          address: input.entry_address,
        })
      ).value;
      assert.equal(instruction.address, input.entry_address);
      assert.equal(instruction.status, "decoded");
      assert.equal(instruction.bytes, input.entry_bytes);
      const state = (await call("binary_session")).value;
      selectedProfile = state.analysis_provider_binding.analysis_profile;
      for (const [operation, parameters] of [
        ["inspect_native_load_image", {}],
        ["inspect_native_instruction", { address: input.entry_address }],
      ]) {
        const binding = localPsxBinding(
          input,
          selectedProfile,
          operation,
          parameters,
        );
        validatePublicPsxEvidence(originalEvidence.get(operation), binding);
        const owner = publicPsxObservation(
          originalEvidence.get(operation),
          binding,
          {
            event_sequence: originalSequences.get(operation),
            run_id: state.analysis_run.run_id,
            capture: publicPsxCaptureForRun(context, state.analysis_run.run_id),
          },
        );
        assert.equal(
          owner.mode,
          "native",
          "Local initial Evidence is already cached",
        );
        originalOwners.set(operation, owner);
      }
      context.identities.push({
        run_id: state.analysis_run.run_id,
        profile: state.analysis_provider_binding.analysis_profile,
        source_sha256: input.sha256,
      });
      assert.ok(
        [...context.roots.values()].some(
          (root) => root.run_id === state.analysis_run.run_id,
        ),
        "Local public run has no captured runtime identity",
      );
    });
    const containing = await facet(
      "containing-function",
      "resolve_containing_procedure",
      { address: input.entry_address },
    );
    if (containing?.found === true) {
      const procedure = containing.procedure.address;
      await facet("instructions", "read_function_instructions", { procedure });
      await facet("assembly", "procedure_assembly", { procedure });
      await facet("decompile", "procedure_pseudo_code", { procedure });
      await facet("references", "procedure_references", {
        procedure,
        direction: "outgoing",
      });
    } else
      for (const name of [
        "instructions",
        "assembly",
        "decompile",
        "references",
      ]) {
        facets.push({
          facet: name,
          status: "inconclusive",
          reason: "No observed containing function",
        });
        context.cases.push({
          id: `local-${name}`,
          adapter: "mcp",
          status: "inconclusive",
          evidence_sequences: [],
        });
      }
    const snapshotPath = join(context.workspace, "local private snapshot.json");
    await context.case("local-snapshot-roundtrip", "mcp", async () => {
      const originalInstruction = originalEvidence.get(
        "inspect_native_instruction",
      );
      const documents = (await call("list_documents")).value;
      const queries = localPsxSnapshotQueries(input, documents);
      const scopedEvidence = [];
      for (const [operation, parameters] of queries) {
        const parsed = await call(operation, parameters);
        if (operation === "inspect_native_instruction")
          assert.deepEqual(parsed.value, originalInstruction.normalized_result);
        scopedEvidence.push(parsed.evidence);
      }
      await call("close_binary", { snapshot_path: snapshotPath });
      const text = await readFile(snapshotPath, "utf8");
      await context.emit({
        stage: "snapshot",
        case_id: "local-snapshot",
        adapter: "mcp",
        kind: "raw_result",
        path: snapshotPath,
        text,
        sha256: publicPsxDigest(text),
      });
      const snapshot = assertPublicPsxSnapshotEntries(
        JSON.parse(text),
        queries,
        scopedEvidence,
        {
          sourceDigest: input.sha256,
          selectedProfile,
        },
      );
      await call("open_binary", {
        path: input.path,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      const reopened = (await call("binary_session")).value;
      assert.deepEqual(
        reopened.analysis_provider_binding.analysis_profile,
        snapshot.binding.analysis_profile,
      );
      assert.equal(reopened.sha256, input.sha256);
      publicPsxDocumentIdentifier(
        (await call("list_documents")).value,
        documents[0],
      );
      for (const [index, [operation, parameters]] of queries.entries()) {
        const replay = await call(operation, parameters);
        const previous = scopedEvidence[index];
        assert.deepEqual(replay.value, previous.normalized_result);
        for (const field of [
          "raw_result",
          "analysis_profile",
          "subject",
          "provider",
          "parameters",
        ])
          assert.deepEqual(replay.evidence[field], previous[field]);
      }
      await call("close_binary");
    });
    await context.case("local-cli-image-entry", "cli", async () => {
      for (const [operation, argv] of [
        [
          "inspect_native_load_image",
          ["inspect-native-load-image", input.path],
        ],
        [
          "inspect_native_instruction",
          ["inspect-native-instruction", input.path, input.entry_address],
        ],
      ]) {
        const binding = localPsxBinding(
          input,
          selectedProfile,
          operation,
          operation === "inspect_native_instruction"
            ? { address: input.entry_address }
            : {},
        );
        const cli = await invokePublicPsxCli(context, argv, {
          caseId: `local-cli-${operation}`,
          sourceDigest: input.sha256,
          binding,
          execution: { mode: "native" },
        });
        const comparison = assertLocalPsxLiveParity(
          cli.observation,
          originalOwners.get(operation),
          binding,
          await readFile(input.path),
        );
        await context.emit({
          stage: "local-cli-parity",
          case_id: `local-cli-${operation}`,
          adapter: "cli",
          kind: "assertion",
          operation,
          comparison,
        });
      }
    });
  } catch (cause) {
    context.primary = cause;
    try {
      await context.emit({
        stage: "primary",
        case_id: "local-smoke",
        kind: "failure",
        failure: publicPsxFailure(cause),
      });
    } catch (capture) {
      context.failures.push({ stage: "capture", ...publicPsxFailure(capture) });
    }
  }
  return settleLocalPsxOutcome(context, input, facets);
}

export async function main(args = process.argv.slice(2)) {
  // Header/source admission completes before any capture or native allocation.
  const input = await readLocalPsxInput(args);
  const preflight = await preflightPsxPublicRunner([], process.env, "local");
  const result = await runCapturedPsxPublic({
    preflight,
    lane: "local",
    execute: verifyLocalPsx,
    input,
  });
  if (!result.ok) process.exitCode = 1;
  return result;
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  await main();
