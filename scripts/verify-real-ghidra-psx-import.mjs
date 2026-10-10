#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseConfig } from "../dist/config/parseConfig.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { inspectGhidraPsxLoader } from "../dist/ghidra/GhidraPsxLoader.js";
import { GhidraProvider } from "../dist/ghidra/GhidraProvider.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { silentLogger } from "../dist/logger.js";
import { systemProcessOwnershipHost } from "../dist/process/ProcessOwnershipObservation.js";
import { buildPsxExeFixture } from "../tests/conformance/ghidra/psx-exe-fixture.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import {
  requireMcpOperationResult,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";

// Original generated inputs only: no input path, game seed or provider installation.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-psx-import.mjs");
assert.ok(
  ["darwin", "linux"].includes(process.platform),
  "PSX import verification requires macOS/Linux",
);
assert.ok(
  isAbsolute(process.env.GHIDRA_INSTALL_DIR ?? ""),
  "Select an absolute existing GHIDRA_INSTALL_DIR",
);
const exec = promisify(execFile);
const repository = fileURLToPath(new URL("..", import.meta.url));
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
assert.equal(installation.status, "available", JSON.stringify(installation));
const initialAssets = await inspectGhidraPsxLoader(
  installation.installDir,
  installation.providerVersion,
);
assert.equal(initialAssets.status, "available", JSON.stringify(initialAssets));
const run = createVerifierRun();
const capture = await captureRoot();
const code = await codeIdentity();
let workspace;
let runtime;
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const report = {
  schema_version: 1,
  lane: "ghidra-psx-production-import",
  mocked: false,
  host: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    ghidra: installation.providerVersion,
    java: { home: installation.javaHome, version: installation.javaVersion },
  },
  code,
  installed_assets: {
    before_inventory_digest: initialAssets.candidate.asset_inventory_digest,
    inventory_version: "ghidra-code-data-v1",
    asset_count: initialAssets.candidate.assets.length,
  },
  selected_environment: {
    GHIDRA_INSTALL_DIR: env.GHIDRA_INSTALL_DIR,
    JAVA_HOME: env.JAVA_HOME ?? null,
  },
  cases: [],
  policy_negatives: [],
  unperformed: [
    process.platform === "darwin"
      ? "Linux real-host import"
      : "macOS real-host import",
    "patched AC3 acceptance",
    "PSX MIPS instruction semantics",
    "source-backed PSX provenance",
    "installed package and fresh-client discovery",
  ],
};
const directRuntimeRoots = new Set();
const unresolvedDirectSessions = [];
let failure;
try {
  workspace = await mkdtemp(join(tmpdir(), "rea-psx-import-proof-"));
  runtime = join(workspace, "runtime");
  env.TMPDIR = runtime;
  await mkdir(runtime);
  for (const variant of [
    "baseline",
    "declared-registers-fill",
    "trailing-bytes",
  ]) {
    process.stderr.write(`PSX production case: ${variant}\n`);
    const fixture = buildPsxExeFixture({ variant });
    const path = join(workspace, `${variant} source 雪.exe`);
    await writeFile(path, fixture.bytes, { mode: 0o600 });
    const sha256 = digest(fixture.bytes);
    const mcp = await verifyMcp(path, sha256, fixture.expected);
    const cli = await verifyCli(path, sha256);
    const startup = await observeStartup(path, sha256, fixture.expected);
    assert.equal(mcp.profile.digest, cli.profile.digest);
    assert.equal(mcp.profile.digest, startup.profile.digest);
    assert.deepEqual(mcp.profile.parameters, cli.profile.parameters);
    assert.deepEqual(mcp.profile.parameters, startup.profile.parameters);
    assert.equal(
      digest(await readFile(path)),
      sha256,
      "Source changed after all production imports",
    );
    const measured = {
      variant,
      source: { sha256, file_bytes: fixture.bytes.length, unchanged: true },
      expected_declarations: fixture.expected,
      mcp,
      cli,
      startup,
    };
    report.cases.push(measured);
    if (capture !== undefined)
      await writeJson(join(capture, `${variant}.json`), measured);
  }
  report.policy_negatives = await verifyPolicyNegatives();
  const finalAssets = await inspectGhidraPsxLoader(
    installation.installDir,
    installation.providerVersion,
  );
  assert.equal(finalAssets.status, "available", JSON.stringify(finalAssets));
  report.installed_assets.after_inventory_digest =
    finalAssets.candidate.asset_inventory_digest;
  assert.deepEqual(
    finalAssets.candidate.assets,
    initialAssets.candidate.assets,
  );
  assert.equal(
    finalAssets.candidate.asset_inventory_digest,
    initialAssets.candidate.asset_inventory_digest,
  );
  report.installed_assets.unchanged = true;
} catch (cause) {
  failure = cause;
} finally {
  const cleanupErrors = await attemptAll([
    () => systemProcessOwnershipHost.close?.(),
  ]);
  const leftovers = [];
  if (runtime !== undefined) {
    try {
      leftovers.push(
        ...(await readdir(runtime)).map((name) => join(runtime, name)),
      );
    } catch (cause) {
      if (cause.code !== "ENOENT") cleanupErrors.push(cause);
    }
  }
  for (const path of directRuntimeRoots) {
    try {
      await stat(path);
      leftovers.push(path);
    } catch (cause) {
      if (cause.code !== "ENOENT") {
        leftovers.push(path);
        cleanupErrors.push(cause);
      }
    }
  }
  const lineage = await completeVerifierRun(run);
  report.verifier_run = lineage;
  report.cleanup = {
    retained_roots: leftovers,
    unresolved_direct_sessions: unresolvedDirectSessions,
    process_lineage: lineage.process_lineage,
    workspace_allocated: workspace !== undefined,
    workspace_removed: false,
  };
  if (
    leftovers.length === 0 &&
    cleanupErrors.length === 0 &&
    unresolvedDirectSessions.length === 0 &&
    lineage.process_lineage.status === "verified" &&
    lineage.process_lineage.descendants.length === 0
  ) {
    if (workspace !== undefined) {
      try {
        await rm(workspace, { recursive: true, force: true });
        report.cleanup.workspace_removed = true;
      } catch (cause) {
        leftovers.push(workspace);
        cleanupErrors.push(cause);
      }
    }
  } else
    cleanupErrors.push(
      new Error("Owned runtime or verified lineage cleanup did not complete"),
    );
  report.cleanup.errors = cleanupErrors.map(projectFailure);
  if (cleanupErrors.length !== 0)
    failure = new AggregateError(
      [failure, ...cleanupErrors].filter(Boolean),
      "Verification/cleanup failed",
    );
  report.ok = failure === undefined;
  if (failure !== undefined) report.failure = projectFailure(failure);
  if (capture !== undefined) {
    try {
      await writeJson(join(capture, "report.json"), report);
    } catch (cause) {
      report.ok = false;
      report.capture_write_error = projectFailure(cause);
      failure = new AggregateError(
        [failure, cause].filter(Boolean),
        "Verification/report writing failed",
      );
    }
  }
}
process.stdout.write(`${JSON.stringify(report)}\n`);
if (failure !== undefined) throw failure;

function projectFailure(cause) {
  return {
    name: cause instanceof Error ? cause.name : "Unknown",
    message: cause instanceof Error ? cause.message : String(cause),
    ...(cause instanceof AggregateError
      ? { errors: cause.errors.map(projectFailure) }
      : {}),
  };
}
async function attemptAll(actions) {
  const failures = [];
  for (const action of actions) {
    try {
      await action();
    } catch (cause) {
      failures.push(cause);
    }
  }
  return failures;
}
function requireSettled(primary, cleanupErrors) {
  if (cleanupErrors.length !== 0)
    throw new AggregateError(
      [primary, ...cleanupErrors].filter(Boolean),
      "Operation/cleanup failed",
    );
  if (primary !== undefined) throw primary;
}
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
async function captureRoot() {
  const selected = process.env.REA_PSX_IMPORT_PROOF_CAPTURE_DIR;
  if (selected === undefined) return undefined;
  assert.ok(
    isAbsolute(selected),
    "REA_PSX_IMPORT_PROOF_CAPTURE_DIR must be absolute",
  );
  await exec(
    "git",
    ["check-ignore", "--quiet", join(resolve(selected), "report.json")],
    { cwd: repository },
  );
  await mkdir(selected, { recursive: true, mode: 0o700 });
  return mkdtemp(join(selected, "run-"));
}
async function codeIdentity() {
  const paths = [
    "scripts/verify-real-ghidra-psx-import.mjs",
    "tests/conformance/ghidra/psx-exe-fixture.mjs",
    "bridge/ghidra/ReaGhidraBridge.java",
    "bridge/ghidra/ReaGhidraPsxImport.java",
    "bridge/ghidra/ReaGhidraPreparePsx.java",
    "src/ghidra/GhidraPsxLoader.ts",
    "src/ghidra/GhidraClient.ts",
    "src/ghidra/GhidraSessionValues.ts",
    "src/ghidra/GhidraImportConfiguration.ts",
    "docs/active/phase-2-plan.md",
  ];
  const head = (
    await exec("git", ["rev-parse", "HEAD"], { cwd: repository })
  ).stdout.trim();
  const dirty = (
    await exec("git", ["status", "--short"], { cwd: repository })
  ).stdout
    .trim()
    .split("\n")
    .filter(Boolean);
  const files = [];
  for (const path of paths)
    files.push({
      path,
      sha256: digest(await readFile(join(repository, path))),
    });
  return { head, dirty, files };
}
async function roots() {
  return (await readdir(runtime)).filter((name) =>
    name.startsWith("rea-ghidra-"),
  );
}
async function publicCall(client, name, arguments_ = {}) {
  return requireMcpOperationResult(
    await client.callTool({ name, arguments: arguments_ }, { timeout: 240000 }),
    name,
  );
}
function assertUnsupported(image) {
  assert.equal(image.status, "unsupported");
  assert.deepEqual(image.observations.source_files, []);
  assert.ok(
    image.observations.mappings.every(
      (mapping) =>
        mapping.source_file_index === null && mapping.file_offset === null,
    ),
  );
}
async function verifyMcp(path, sha256, expected) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-psx-import", version: "1" });
  let opened = false;
  let observation;
  let primary;
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  try {
    await client.connect(transport);
    const target = await publicCall(client, "open_binary", {
      path,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(target.format, "ps-x-exe");
    assert.equal(target.architecture, "mips");
    assert.equal(target.sha256, sha256);
    const documents = await publicCall(client, "list_documents");
    assert.equal(documents.length, 1);
    const image = await publicCall(client, "inspect_native_load_image");
    assertUnsupported(image);
    assert.ok(
      image.observations.entry_points.includes(
        `0x${expected.initialPc.toString(16)}`,
      ),
    );
    const status = await publicCall(client, "binary_session");
    assert.equal(status.analysis_provider_binding.provider.id, "ghidra");
    assert.equal(status.analysis_provider_binding.selection_source, "request");
    assert.equal(
      status.analysis_provider_binding.analysis_profile.parameters
        .psx_operation_scope,
      "inventory-observations-only-v1",
    );
    const gated = await client.callTool({
      name: "read_function_instructions",
      arguments: { procedure: `0x${expected.initialPc.toString(16)}` },
    });
    const rejected = requireMcpToolError(gated);
    assert.equal(rejected.code, "capability_unavailable");
    assert.match(rejected.details.reason, /PSX.*Phase 4/u);
    const runtimeObservation = await captureLiveRuntime(
      status.analysis_run.run_id,
      sha256,
      status.analysis_provider_binding.analysis_profile,
    );
    await publicCall(client, "close_binary");
    opened = false;
    assert.equal((await publicCall(client, "binary_session")).open, false);
    observation = {
      public_stdio: true,
      documents,
      profile: status.analysis_provider_binding.analysis_profile,
      run: status.analysis_run,
      load_image: image,
      gated_operation: rejected,
      runtime: runtimeObservation,
    };
  } catch (cause) {
    if (stderr.trim()) process.stderr.write(`${stderr}\n`);
    primary = cause;
  }
  const cleanupErrors = await attemptAll([
    async () => {
      if (opened) await publicCall(client, "close_binary");
    },
    () => client.close(),
    () => transport.close(),
    async () =>
      assert.deepEqual(await roots(), [], "MCP owned runtime survived close"),
    async () => assert.equal(digest(await readFile(path)), sha256),
  ]);
  requireSettled(primary, cleanupErrors);
  return observation;
}
async function verifyCli(path, sha256) {
  const { stdout } = await exec(
    process.execPath,
    [
      entrypoint,
      "inspect-native-load-image",
      path,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.provider.id, "ghidra");
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.subject.format, "ps-x-exe");
  assertUnsupported(evidence.normalized_result);
  assert.equal(digest(await readFile(path)), sha256);
  assert.deepEqual(await roots(), [], "CLI owned runtime survived exit");
  return {
    public_cli: true,
    profile: evidence.analysis_profile,
    load_image: evidence.normalized_result,
    source_unchanged: true,
  };
}
async function captureLiveRuntime(runId, sha256, profile, ownedRoot) {
  let root = ownedRoot;
  if (root === undefined) {
    const ownedRoots = await roots();
    assert.equal(ownedRoots.length, 1, "Expected one owned provider runtime");
    root = join(runtime, ownedRoots[0]);
  }
  assert.ok(isAbsolute(root));
  const ownership = JSON.parse(
    await readFile(join(root, "ownership.json"), "utf8"),
  );
  assert.equal(ownership.run_id, runId);
  assert.ok(
    Array.isArray(ownership.arguments),
    "Exact launch argv not retained",
  );
  assert.equal(
    ownership.arguments[ownership.arguments.indexOf("-loader") + 1],
    "PsxLoader",
  );
  assert.ok(ownership.arguments.includes("-readOnly"));
  assert.ok(ownership.arguments.includes("-deleteProject"));
  assert.ok(
    !ownership.arguments.some((value) =>
      /^-loader-ram(?:Start|Size)/u.test(value),
    ),
  );
  const snapshotPath =
    ownership.arguments[ownership.arguments.indexOf("-import") + 1];
  assert.ok(
    isAbsolute(snapshotPath),
    "Owned argv omitted absolute snapshot path",
  );
  const beforeBytes = await readFile(join(root, "psx-import-before.json"));

  const logs = {};
  for (const name of ["ghidra.log", "script.log"]) {
    assert.ok(
      (await stat(join(root, name))).size < 4 * 1024 * 1024,
      "Unbounded retained startup diagnostics",
    );
    // The credential descriptor is deleted after loading. Retain only the
    // producer's target-bound report and fixed marker, never arbitrary log text.
    logs[name] = (await readFile(join(root, name), "utf8"))
      .split("\n")
      .filter((line) =>
        /REPORT: Analysis succeeded for file:|REA_PSX_IMPORT_BEFORE_COMPLETE/u.test(
          line,
        ),
      )
      .join("\n");
  }
  assert.match(logs["ghidra.log"], /REPORT: Analysis succeeded for file:/u);
  const before = JSON.parse(beforeBytes.toString("utf8"));
  const recordSha256 = digest(beforeBytes);
  assert.match(
    logs["script.log"] + logs["ghidra.log"],
    new RegExp(`REA_PSX_IMPORT_BEFORE_COMPLETE ${runId} ${recordSha256}`, "u"),
  );
  assert.equal(before.commitment.run_id, runId);
  assert.equal(before.commitment.profile_digest, profile.digest);
  assert.equal(before.commitment.source_sha256, sha256);
  assert.equal(dirname(snapshotPath), await realpath(root));
  assert.equal(before.observed.source.sha256, sha256);
  assert.equal(before.observed.source.snapshot_path, snapshotPath);
  const snapshotSha256 = digest(await readFile(snapshotPath));
  assert.equal(snapshotSha256, sha256);
  return {
    owned_runtime_root: root,
    ownership,
    supplied: {
      ...profile.parameters.psx_import,
      source_snapshot_path: snapshotPath,
    },
    before_record_sha256: recordSha256,
    before,
    source_snapshot_unchanged: true,
    snapshot_source_hashes: {
      before: before.observed.source.sha256,
      after: snapshotSha256,
    },
    logs,
  };
}
function assertImportAgreement(agreement, sha256, expected, profile) {
  assert.deepEqual(agreement.before.observed, agreement.after.observed);
  assert.equal(agreement.before.observed.source.sha256, sha256);
  assert.equal(agreement.before.observed.source.file_bytes, expected.fileBytes);
  assert.equal(agreement.after.observed.program.ram_size, 2097152);
  assert.equal(agreement.after.observed.program.image_base, "0x80000000");
  assert.equal(agreement.after.observed.loader_selector, "PsxLoader");
  assert.equal(agreement.after.observed.loader_class, "psx.PsxLoader");
  assert.equal(
    agreement.after.observed.advertised_defaults.ram_start.value,
    "0x80000000",
  );
  assert.equal(
    agreement.after.observed.advertised_defaults.ram_size.value,
    "0x200000",
  );
  assert.deepEqual(profile.parameters.psx_import.supplied_loader_options, {});
}
async function observeStartup(path, sha256, expected) {
  const config = parseConfig(env);
  if (!config.ok) throw config.error;
  const provider = new GhidraProvider(config.value, silentLogger, env);
  const target = await parseBinaryTarget(path);
  if (!target.ok) throw target.error;
  const resolved = await provider.resolveAnalysisProfile(target.value);
  if (!resolved.ok) throw resolved.error;
  const profile = resolved.value.profile;
  assert.ok(profile);
  const runId = randomUUID();
  const client = provider.createClient(target.value, profile, { runId });
  let observation;
  let directRoot;
  let startupFailure;
  try {
    const health = await client.execute("health", {});
    if (!health.ok) throw health.error;
    const agreement = health.value.result.psx_import;
    const snapshotCoordinate =
      agreement?.before?.observed?.source?.snapshot_path;
    if (
      typeof snapshotCoordinate === "string" &&
      isAbsolute(snapshotCoordinate)
    ) {
      directRoot = dirname(snapshotCoordinate);
      directRuntimeRoots.add(directRoot);
    }
    assert.ok(
      agreement,
      "Authenticated health omitted observed import agreement",
    );
    assertImportAgreement(agreement, sha256, expected, profile);
    const runtimeObservation = await captureLiveRuntime(
      runId,
      sha256,
      profile,
      directRoot,
    );
    assert.equal(
      runtimeObservation.before_record_sha256,
      agreement.before_record_sha256,
    );
    assert.deepEqual(runtimeObservation.before, agreement.before);
    observation = {
      evidence_depth: "real-production-provider-boundary-health",
      profile,
      authenticated_health: health.value.result,
      runtime: runtimeObservation,
    };
  } catch (cause) {
    startupFailure = cause;
  }
  if (directRoot === undefined && startupFailure !== undefined) {
    const diagnostics =
      startupFailure.diagnostics ?? startupFailure.details?.diagnostics;
    const coordinate = diagnostics?.runtime_root;
    if (typeof coordinate === "string" && isAbsolute(coordinate)) {
      directRoot = coordinate;
      directRuntimeRoots.add(coordinate);
    } else
      unresolvedDirectSessions.push({
        run_id: runId,
        reason:
          "Startup failed before an exact owned runtime coordinate was available",
      });
  }
  const cleanupErrors = await attemptAll([
    async () => {
      const closed = await client.close();
      if (!closed.ok) throw closed.error;
    },
    async () => {
      if (directRoot !== undefined)
        await assert.rejects(stat(directRoot), { code: "ENOENT" });
    },
    async () => assert.equal(digest(await readFile(path)), sha256),
  ]);
  requireSettled(startupFailure, cleanupErrors);
  observation.cleanup = {
    exact_owned_root: directRoot,
    absent_after_close: true,
  };
  return observation;
}
async function verifyPolicyNegatives() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({
    name: "rea-real-psx-negative-policy",
    version: "1",
  });
  const rows = [];
  let primary;
  try {
    await client.connect(transport);
    for (const [name, fields] of [
      [
        "alternate-bank",
        [
          [0x10, 0xa0010000],
          [0x18, 0xa0010000],
        ],
      ],
      [
        "crossing-RAM-end",
        [
          [0x10, 0x801ffffc],
          [0x18, 0x801ffffc],
        ],
      ],
      [
        "overlapping-fill",
        [
          [0x28, 0x80010010],
          [0x2c, 4],
        ],
      ],
      ["nonzero-data-declaration", [[0x20, 0x80010800]]],
    ]) {
      const { bytes } = buildPsxExeFixture();
      for (const [offset, value] of fields) bytes.writeUInt32LE(value, offset);
      const path = join(workspace, `${name}.exe`);
      await writeFile(path, bytes, { mode: 0o600 });
      const sha256 = digest(bytes);
      assert.deepEqual(await roots(), []);
      const reply = await client.callTool(
        { name: "open_binary", arguments: { path, provider_id: "ghidra" } },
        { timeout: 240000 },
      );
      const rejected = requireMcpToolError(reply);
      assert.equal(rejected.code, "execution_failure");
      assert.equal(
        rejected.details.diagnostics.psx_import_policy.policy,
        "psx-kseg0-2m-defaults-v1",
      );
      assert.deepEqual(
        await roots(),
        [],
        "Rejected policy allocated a provider root",
      );
      assert.equal((await publicCall(client, "binary_session")).open, false);
      assert.equal(digest(await readFile(path)), sha256);
      rows.push({
        name,
        source_sha256: sha256,
        error: rejected,
        provider_root_allocated: false,
        source_unchanged: true,
      });
    }
  } catch (cause) {
    primary = cause;
  }
  const cleanupErrors = await attemptAll([
    () => client.close(),
    () => transport.close(),
    async () => assert.deepEqual(await roots(), []),
  ]);
  requireSettled(primary, cleanupErrors);
  return rows;
}
