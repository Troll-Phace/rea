#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseConfig } from "../dist/config/parseConfig.js";
import { GhidraProvider } from "../dist/ghidra/GhidraProvider.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { inspectGhidraPsxLoader } from "../dist/ghidra/GhidraPsxLoader.js";
import { silentLogger } from "../dist/logger.js";
import { systemProcessOwnershipHost } from "../dist/process/ProcessOwnershipObservation.js";
import { buildPsxExeFixture } from "../tests/conformance/ghidra/psx-exe-fixture.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import {
  assertPsxInstructionFlowFixture,
  psxInstructionFlowOracle,
  settlePsxVerification,
  verifyPsxInstructionFlow,
} from "./lib/real-ghidra-psx-instruction-flow.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const exec = promisify(execFile);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Preflight is read-only and runs before allocating reports, workspaces or clients. */
export async function preflightPsxOperations(args, environment = process.env) {
  assert.ok(
    args.length === 0 ||
      (args.length === 2 && args[0] === "--stage" && args[1] === "decoder"),
    "Usage: node scripts/verify-real-ghidra-psx-operations.mjs [--stage decoder]; no target path is accepted",
  );
  assert.equal(
    process.platform,
    "darwin",
    "This Phase 4 measured lane requires macOS; Linux belongs to Phase 5",
  );
  for (const key of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
    assert.ok(
      isAbsolute(environment[key] ?? ""),
      `Explicit absolute ${key} is required`,
    );
  const installation = inspectGhidraInstallation({
    installDir: environment.GHIDRA_INSTALL_DIR,
    javaHome: environment.JAVA_HOME,
    environment,
  });
  assert.equal(installation.status, "available", JSON.stringify(installation));
  assert.equal(installation.providerVersion, "12.1.4");
  assert.match(
    installation.javaVersion,
    /^25(?:\.|$)/u,
    "Requires existing Temurin 25",
  );
  const assets = await inspectGhidraPsxLoader(
    installation.installDir,
    installation.providerVersion,
  );
  assert.equal(assets.status, "available", JSON.stringify(assets));
  const captureParent =
    environment.REA_PSX_OPERATION_PROOF_CAPTURE_DIR ??
    join(repository, "docs/psx-local/phase-4-operation-runs");
  assert.ok(
    isAbsolute(captureParent),
    "REA_PSX_OPERATION_PROOF_CAPTURE_DIR must be absolute",
  );
  await exec(
    "git",
    ["check-ignore", "--quiet", join(resolve(captureParent), "report.json")],
    { cwd: repository },
  );
  const fixture = buildPsxExeFixture({ variant: "instruction-flow" });
  assertPsxInstructionFlowFixture(fixture.bytes);
  return {
    stage: args.length ? "decoder" : "operations",
    installation,
    assets,
    captureParent,
    fixture,
  };
}

/** The direct runner and deterministic wiring tests share this exact call boundary. */
export async function verifyOperationMatrix({ call, stage = "decoder" }) {
  return verifyPsxInstructionFlow({
    call,
    stage,
    oracle: psxInstructionFlowOracle,
  });
}

export async function main(args = process.argv.slice(2)) {
  const { stage, installation, assets, captureParent, fixture } =
    await preflightPsxOperations(args);
  const run = createVerifierRun();
  await mkdir(captureParent, { recursive: true, mode: 0o700 });
  const capture = await mkdtemp(join(captureParent, "run-"));
  const report = {
    schema_version: 1,
    lane: "ghidra-psx-operations",
    stage,
    plan_revision: "P4-R5",
    mocked: false,
    evidence_depth: "real-direct-production-provider",
    auto_analysis_performed: true,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      ghidra: installation.providerVersion,
      java: { home: installation.javaHome, version: installation.javaVersion },
    },
    selected_environment: {
      GHIDRA_INSTALL_DIR: installation.installDir,
      JAVA_HOME: installation.javaHome,
    },
    installed_assets: {
      before_inventory_digest: assets.candidate.asset_inventory_digest,
      asset_count: assets.candidate.assets.length,
      before: assets.candidate,
    },
    operations: [],
    fixture: { expected: fixture.expected, sha256: digest(fixture.bytes) },
    unperformed: [
      "public CLI/stdio MCP real operation journeys",
      "Linux real-host operations",
      "installed-package/fresh-client acceptance",
      "patched AC3",
      "runtime execution",
    ],
  };
  let primary, workspace, source, client, ownedRoot, codeBefore;
  let captureAttempted = false;
  const resources = [];
  const abort = new AbortController();
  const cancel = () => abort.abort(new Error("Verification interrupted"));
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  try {
    workspace = await mkdtemp(join(tmpdir(), "rea-psx-operations-proof-"));
    report.owned_workspace = workspace;
    source = join(workspace, "original synthetic PSX instruction flow 雪.exe");
    await writeFile(source, fixture.bytes, { mode: 0o600, flag: "wx" });
    report.fixture.source_path = source;
    report.code_before = codeBefore = await codeIdentity();
    const environment = {
      ...process.env,
      GHIDRA_INSTALL_DIR: installation.installDir,
      JAVA_HOME: installation.javaHome,
    };
    const config = requireResult(parseConfig(environment));
    const target = requireResult(await parseBinaryTarget(source));
    assert.equal(target.sha256, report.fixture.sha256);
    assert.equal(target.format, "ps-x-exe");
    const provider = new GhidraProvider(config, silentLogger, environment);
    report.profile = requireResult(
      await provider.resolveAnalysisProfile(target),
    ).profile;
    assert.equal(
      report.profile.parameters.psx_operation_scope,
      "inventory-load-image-and-static-functions-v1",
    );
    assert.equal(
      report.profile.parameters.instruction_flow_evidence,
      "decoded-return-before-jump-and-delay-slots-v2",
    );
    report.run_id = randomUUID();
    client = provider.createClient(target, report.profile, {
      runId: report.run_id,
    });
    // Ownership is installed immediately, before first health/import dispatch.
    resources.push({
      owner: report.run_id,
      close: async () => {
        requireResult(await client.close());
      },
    });
    const call = async (operation, parameters) => {
      const observation = { operation, parameters };
      report.operations.push(observation);
      const result = await client.execute(operation, parameters, {
        signal: abort.signal,
      });
      if (!result.ok) {
        observation.failure = failure(result.error);
        throw result.error;
      }
      observation.raw_result = result.value.rawResult;
      observation.result = result.value.result;
      observation.provider = result.value.provider;
      observation.profile = result.value.analysisProfile;
      return result.value.result;
    };
    report.health = await call("health", {});
    const agreement = report.health.psx_import;
    assert.ok(agreement, "Authenticated startup omitted PSX agreement");
    ownedRoot = dirname(agreement.before.observed.source.snapshot_path);
    assert.ok(isAbsolute(ownedRoot));
    report.owned_runtime_root = ownedRoot;
    assert.equal(agreement.schema_version, 3);
    assert.deepEqual(agreement.after.commitment, {
      run_id: report.run_id,
      profile_digest: report.profile.digest,
      source_sha256: report.fixture.sha256,
    });
    report.comparisons = await verifyOperationMatrix({ call, stage });
    if (stage === "operations") {
      for (const [operation, parameters] of [
        [
          "annotate_native_function",
          { procedure: "0x80010000", name: "forbidden" },
        ],
        ["inspect_native_data_type", { address: "0x80010100" }],
      ]) {
        const refused = await client.execute(operation, parameters);
        report.operations.push({
          operation,
          parameters,
          refusal: refused.ok ? null : failure(refused.error),
        });
        assert.equal(refused.ok, false, `${operation} unexpectedly admitted`);
        assert.equal(refused.error._tag, "AnalysisCapabilityUnavailableError");
        assert.match(refused.error.message, /PSX|PS-X/iu);
      }
      report.health_after_reads = await call("health", {});
    }
  } catch (cause) {
    primary = cause;
    // Trust only coordinates emitted by the owning provider, never directory scans.
    const root =
      cause.diagnostics?.runtime_root ??
      cause.diagnostics?.runtimeRoot ??
      cause.details?.diagnostics?.runtime_root ??
      cause.details?.diagnostics?.runtimeRoot;
    if (
      ownedRoot === undefined &&
      typeof root === "string" &&
      isAbsolute(root)
    ) {
      ownedRoot = root;
      report.owned_runtime_root = root;
    }
  } finally {
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
    const settled = await settlePsxVerification({
      primary,
      resources,
      capture: [
        async () => {
          captureAttempted = true;
          if (ownedRoot !== undefined)
            report.runtime = await captureRuntime(ownedRoot, capture, report);
          else if (client !== undefined)
            throw new Error(
              "Allocated session has no authenticated exact runtime coordinate; evidence ownership remains unresolved",
            );
        },
      ],
      postchecks: [
        async () => {
          if (source) {
            report.fixture.after_sha256 = digest(await readFile(source));
            assert.equal(
              report.fixture.after_sha256,
              report.fixture.sha256,
              "Original source changed",
            );
          }
        },
        async () => {
          const after = await inspectGhidraPsxLoader(
            installation.installDir,
            installation.providerVersion,
          );
          assert.equal(after.status, "available");
          report.installed_assets.after_inventory_digest =
            after.candidate.asset_inventory_digest;
          assert.deepEqual(
            after.candidate.assets,
            assets.candidate.assets,
            "Installed loader/assets changed",
          );
        },
        async () => {
          if (codeBefore) {
            report.code_after = await codeIdentity();
            assert.deepEqual(
              report.code_after.files,
              codeBefore.files,
              "Relevant code changed during run",
            );
            assert.equal(
              report.code_after.diff_sha256,
              codeBefore.diff_sha256,
              "Tracked diff changed during run",
            );
          }
        },
      ],
      cleanup: [
        async () => {
          if (ownedRoot) await assertAbsent(ownedRoot);
        },
      ],
    });
    report.settlement = {
      capture_attempted: captureAttempted,
      failures: settled.failures.map(({ error, ...rest }) => ({
        ...rest,
        failure: failure(error),
      })),
      unresolved_sessions: settled.unresolved,
    };
    const cleanupErrors = [];
    try {
      await systemProcessOwnershipHost.close?.();
    } catch (cause) {
      cleanupErrors.push(cause);
    }
    try {
      report.verifier_run = await completeVerifierRun(run);
      assert.equal(report.verifier_run.process_lineage.status, "verified");
      assert.deepEqual(report.verifier_run.process_lineage.descendants, []);
    } catch (cause) {
      cleanupErrors.push(cause);
    }
    const unresolvedCoordinate =
      client !== undefined && ownedRoot === undefined;
    let runtimeAbsent = client === undefined;
    if (ownedRoot)
      try {
        await assertAbsent(ownedRoot);
        runtimeAbsent = true;
      } catch (cause) {
        cleanupErrors.push(cause);
      }
    report.cleanup = {
      exact_runtime_absent: runtimeAbsent,
      workspace_removed: false,
      retained_roots: [],
      errors: cleanupErrors.map(failure),
    };
    if (
      workspace &&
      settled.unresolved.length === 0 &&
      !unresolvedCoordinate &&
      runtimeAbsent &&
      cleanupErrors.length === 0
    ) {
      try {
        await rm(workspace, { recursive: true, force: true });
        await assertAbsent(workspace);
        report.cleanup.workspace_removed = true;
      } catch (cause) {
        cleanupErrors.push(cause);
        report.cleanup.errors.push(failure(cause));
        report.cleanup.retained_roots.push(workspace);
      }
    } else if (workspace) report.cleanup.retained_roots.push(workspace);
    if (!runtimeAbsent && ownedRoot)
      report.cleanup.retained_roots.push(ownedRoot);
    report.ok =
      settled.ok &&
      cleanupErrors.length === 0 &&
      !unresolvedCoordinate &&
      report.cleanup.workspace_removed;
    const errors = [
      ...settled.failures.map((item) => item.error),
      ...cleanupErrors,
    ];
    if (unresolvedCoordinate)
      errors.push(
        new Error(
          "Unknown runtime coordinate retained; exact cleanup cannot be proved",
        ),
      );
    if (!report.ok)
      report.failure = failure(
        new AggregateError(errors, "PSX operation gate failed"),
      );
    const path = join(capture, "report.json");
    try {
      await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, {
        mode: 0o600,
        flag: "wx",
      });
    } catch (cause) {
      throw new AggregateError(
        [...errors, cause],
        "Operation gate and report persistence failed",
      );
    }
    process.stdout.write(
      `${JSON.stringify({ ok: report.ok, stage, report: path, sha256: digest(await readFile(path)) })}\n`,
    );
    if (!report.ok)
      throw new AggregateError(
        errors,
        "PSX operation gate failed; see preserved report",
      );
  }
}

async function captureRuntime(root, capture, report) {
  const ownership = JSON.parse(
    await readFile(join(root, "ownership.json"), "utf8"),
  );
  assert.equal(ownership.run_id, report.run_id);
  const argv = ownership.arguments;
  assert.ok(argv.includes("-readOnly") && argv.includes("-deleteProject"));
  assert.ok(!argv.includes("-noanalysis"));
  assert.equal(argv[argv.indexOf("-loader") + 1], "PsxLoader");
  assert.ok(
    !argv.some((argument) => /^-loader-ram(?:Start|Size)/u.test(argument)),
  );
  const snapshot = argv[argv.indexOf("-import") + 1];
  assert.equal(dirname(snapshot), await realpath(root));
  const captured = {
    owned_root: root,
    ownership,
    snapshot: { path: snapshot, sha256: digest(await readFile(snapshot)) },
    records: [],
  };
  assert.equal(captured.snapshot.sha256, report.fixture.sha256);
  // Read only fixed evidence and ownership paths; session.json contains credentials
  // and is deliberately never opened or copied by this verifier.
  const errors = [];
  for (const name of [
    "psx-import-before.json",
    "psx-provenance-original.json",
  ]) {
    try {
      const bytes = await readFile(join(root, name));
      const destination = join(capture, name);
      await writeFile(destination, bytes, { mode: 0o600, flag: "wx" });
      captured.records.push({
        path: destination,
        sha256: digest(bytes),
        content: JSON.parse(bytes.toString("utf8")),
      });
    } catch (cause) {
      errors.push(cause);
    }
  }
  report.runtime = captured;
  for (const name of ["ghidra.log", "script.log"]) {
    try {
      const text = await readFile(join(root, name), "utf8");
      captured[name] = text
        .split("\n")
        .filter((line) =>
          /REPORT: Analysis succeeded for file:|REA_PSX_IMPORT_BEFORE_COMPLETE/u.test(
            line,
          ),
        );
    } catch (cause) {
      errors.push(cause);
    }
  }
  if (report.health) {
    try {
      assert.deepEqual(
        captured.records.find((record) =>
          record.path.endsWith("psx-import-before.json"),
        )?.content,
        report.health.psx_import.before,
      );
      assert.match(
        captured["ghidra.log"].join("\n"),
        /REPORT: Analysis succeeded for file:/u,
      );
    } catch (cause) {
      errors.push(cause);
    }
  }
  if (errors.length)
    throw new AggregateError(errors, "Independent runtime captures failed");
  return captured;
}
async function codeIdentity() {
  const paths = [
    "scripts/verify-real-ghidra-psx-operations.mjs",
    "scripts/lib/real-ghidra-psx-instruction-flow.mjs",
    "tests/conformance/ghidra/psx-exe-fixture.mjs",
    "docs/active/phase-4-plan.md",
    "bridge/ghidra/ReaGhidraBridge.java",
    "bridge/ghidra/ReaGhidraPreparePsx.java",
    "bridge/ghidra/ReaGhidraPsxProvenance.java",
    "bridge/ghidra/ReaGhidraPsxImport.java",
    "src/domain/native/nativeInstruction.ts",
    "src/ghidra/GhidraFunctionValues.ts",
    "src/ghidra/GhidraAnalysisProfile.ts",
    "src/ghidra/GhidraProviderClient.ts",
    "src/ghidra/GhidraProviderCapabilities.ts",
    "src/ghidra/GhidraClient.ts",
    "src/ghidra/GhidraClientStartup.ts",
    "src/ghidra/GhidraLauncher.ts",
    "src/ghidra/GhidraPsxLoader.ts",
    "src/ghidra/GhidraPsxLoadImageValues.ts",
    "dist/domain/native/nativeInstruction.js",
    "dist/ghidra/GhidraFunctionValues.js",
    "dist/ghidra/GhidraAnalysisProfile.js",
    "dist/ghidra/GhidraProviderClient.js",
    "dist/ghidra/GhidraProviderCapabilities.js",
    "dist/ghidra/GhidraClient.js",
    "dist/ghidra/GhidraClientStartup.js",
    "dist/ghidra/GhidraLauncher.js",
    "dist/ghidra/GhidraPsxLoader.js",
    "dist/ghidra/GhidraPsxLoadImageValues.js",
  ];
  return {
    head: (
      await exec("git", ["rev-parse", "HEAD"], { cwd: repository })
    ).stdout.trim(),
    dirty: (
      await exec("git", ["status", "--short"], { cwd: repository })
    ).stdout
      .trim()
      .split("\n")
      .filter(Boolean),
    diff_sha256: digest(
      (
        await exec("git", ["diff", "--binary"], {
          cwd: repository,
          maxBuffer: 16 * 1024 * 1024,
        })
      ).stdout,
    ),
    files: await Promise.all(
      paths.map(async (path) => ({
        path,
        sha256: digest(await readFile(join(repository, path))),
      })),
    ),
  };
}
function requireResult(result) {
  if (!result.ok) throw result.error;
  return result.value;
}
async function assertAbsent(path) {
  await assert.rejects(stat(path), { code: "ENOENT" });
}
function failure(cause) {
  return {
    name: cause?.name ?? typeof cause,
    tag: cause?._tag ?? null,
    message: cause?.message ?? String(cause),
    ...(cause?.diagnostics ? { diagnostics: cause.diagnostics } : {}),
    ...(cause instanceof AggregateError
      ? { errors: [...cause.errors].map(failure) }
      : {}),
  };
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  await main();
