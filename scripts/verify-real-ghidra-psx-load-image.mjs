#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  mkdir,
  open,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv2020 from "ajv/dist/2020.js";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseConfig } from "../dist/config/parseConfig.js";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { GhidraProvider } from "../dist/ghidra/GhidraProvider.js";
import { attestGhidraPsxLoadImage } from "../dist/ghidra/GhidraPsxLoadImageValues.js";
import { silentLogger } from "../dist/logger.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import {
  createGhidraPsxCommitment,
  inspectGhidraPsxLoader,
  readGhidraPsxSource,
} from "../dist/ghidra/GhidraPsxLoader.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../dist/process/OwnedCommand.js";
import { systemProcessOwnershipHost } from "../dist/process/ProcessOwnershipObservation.js";
import { buildPsxExeFixture } from "../tests/conformance/ghidra/psx-exe-fixture.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import {
  mcpTextValue,
  requireMcpOperationResult,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";

// No caller executable path or production fault injection is accepted.
const args = process.argv.slice(2);
assert.ok(
  args.length === 0 ||
    (args.length === 2 && args[0] === "--stage" && args[1] === "feasibility"),
  "Usage: node scripts/verify-real-ghidra-psx-load-image.mjs [--stage feasibility]",
);
const stage = args.length === 0 ? "full" : "feasibility";
assert.ok(
  ["darwin", "linux"].includes(process.platform),
  "Requires macOS/Linux",
);
for (const name of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
  assert.ok(
    isAbsolute(process.env[name] ?? ""),
    `Explicit absolute ${name} is required`,
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
  environment: process.env,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
assert.equal(installation.providerVersion, "12.1.4");
assert.match(
  installation.javaVersion,
  /^25(?:\.|$)/u,
  "This measured lane requires existing Temurin 25",
);
const assets = await inspectGhidraPsxLoader(
  installation.installDir,
  installation.providerVersion,
);
assert.equal(assets.status, "available", JSON.stringify(assets));
const repository = fileURLToPath(new URL("..", import.meta.url));
const exec = promisify(execFile);
const run = createVerifierRun();
const captureParent =
  process.env.REA_PSX_LOAD_IMAGE_PROOF_CAPTURE_DIR ??
  join(repository, "docs/psx-local/phase-3-load-image-runs");
assert.ok(
  isAbsolute(captureParent),
  "REA_PSX_LOAD_IMAGE_PROOF_CAPTURE_DIR must be absolute",
);
await exec(
  "git",
  ["check-ignore", "--quiet", join(resolve(captureParent), "report.json")],
  { cwd: repository },
);
await mkdir(captureParent, { recursive: true, mode: 0o700 });
const capture = await mkdtemp(join(captureParent, "run-"));
let code;
const report = {
  schema_version: 1,
  lane: "ghidra-psx-load-image",
  stage,
  plan_revision: "P3-R2",
  auto_analysis_performed: stage === "full",
  profile_scope:
    stage === "full"
      ? "canonical-production-profile"
      : "synthetic-preparation-commitment-not-canonical-production-profile",
  mocked: false,
  evidence_depth:
    stage === "full"
      ? "public-cli-stdio-mcp-and-distinct-authenticated-provider-sessions"
      : "real-production-preparation-and-synthetic-producer-probes",
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
  code,
  installed_assets: {
    before_inventory_digest: assets.candidate.asset_inventory_digest,
    inventory_version: assets.candidate.asset_inventory_version,
    asset_count: assets.candidate.assets.length,
  },
  cases: [],
  unperformed: [
    ...(stage === "full"
      ? [
          "producer failure probes in this full run (separate feasibility reports)",
        ]
      : [
          "public stdio MCP load-image acceptance",
          "public CLI load-image acceptance",
          "authenticated production provider session",
          "real-observation attestor replay mutations",
        ]),
    process.platform === "darwin"
      ? "Linux real-host coverage"
      : "macOS real-host coverage",
    "patched AC3",
    "MIPS instruction/delay-slot semantics",
    "installed-package/fresh-client acceptance",
  ],
};
const transportCredentials = new Set();
let workspace;
let primary;
let reportPersisted = false;
let uncertainOwnership = false;
const fullOwnedRoots = new Set();
const unresolvedFullSessions = [];
const ownedEvidenceHandles = new Map();
const abort = new AbortController();
const cancel = () => abort.abort(new Error("Verification interrupted"));
process.once("SIGINT", cancel);
process.once("SIGTERM", cancel);
try {
  workspace = await mkdtemp(join(tmpdir(), "rea-psx-load-image-proof-"));
  report.owned_workspace = workspace;
  code = await codeIdentity();
  report.code = code;
  if (stage === "full") {
    await verifyFullLane(workspace);
  } else {
    // Ghidra compiles each script source directory as a separate OSGi bundle;
    // default-package helpers must share the probe's owning source directory.
    const scripts = join(workspace, "java-scripts");
    await mkdir(scripts, { mode: 0o700 });
    report.script_bundle = { owned_directory: scripts, sources: [] };
    for (const relativePath of [
      "bridge/ghidra/ReaGhidraPsxImport.java",
      "bridge/ghidra/ReaGhidraPsxProvenance.java",
      "tests/conformance/ghidra/ReaPsxProvenanceContractProbe.java",
      "bridge/ghidra/ReaGhidraPreparePsx.java",
      "tests/conformance/ghidra/ReaPsxPreparationTransactionProbe.java",
    ]) {
      const original = join(repository, relativePath);
      const copy = join(scripts, basename(relativePath));
      const bytes = await readFile(original);
      await writeFile(copy, bytes, { mode: 0o600, flag: "wx" });
      const originalDigest = digest(bytes);
      const copiedDigest = digest(await readFile(copy));
      assert.equal(copiedDigest, originalDigest);
      report.script_bundle.sources.push({
        source: relativePath,
        copy,
        source_sha256: originalDigest,
        copy_sha256: copiedDigest,
      });
    }
    // Outer cleanup is installed before creating any child resources.
    const settings = join(workspace, "settings");
    const cache = join(workspace, "cache");
    const temp = join(workspace, "temp");
    for (const path of [settings, cache, temp])
      await mkdir(path, { mode: 0o700 });
    const env = {
      JAVA_HOME: installation.javaHome,
      PATH: `${join(installation.javaHome, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      _JAVA_OPTIONS: "",
      JDK_JAVA_OPTIONS: "",
      GHIDRA_JAVA_OPTIONS: "",
      XDG_CONFIG_HOME: settings,
      XDG_CACHE_HOME: cache,
      JAVA_TOOL_OPTIONS: `-Dapplication.settingsdir=${settings} -Dapplication.cachedir=${cache} -Dapplication.tempdir=${temp} -Djava.io.tmpdir=${temp} -Djava.awt.headless=true`,
    };
    for (const test of [
      { variant: "baseline", mode: "baseline" },
      { variant: "declared-registers-fill", mode: "baseline" },
      { variant: "baseline", mode: "split" },
      { variant: "baseline", mode: "journal-multiplicity" },
      { variant: "baseline", mode: "unsupported-data" },
      { variant: "baseline", mode: "rollback" },
      { variant: "baseline", mode: "original-record-tamper" },
      { variant: "baseline", mode: "active-transaction" },
      { variant: "baseline", mode: "production-wrapper" },
      { variant: "baseline", mode: "bookmarks" },
      { variant: "baseline", mode: "bookmarks-split" },
      { variant: "baseline", mode: "bookmarks-cancel-parking" },
      { variant: "baseline", mode: "bookmarks-cancel-rebind" },
      { variant: "baseline", mode: "bookmarks-cancel-return" },
      { variant: "baseline", mode: "bookmarks-unsupported-data" },
    ]) {
      process.stderr.write(`PSX feasibility: ${test.variant}/${test.mode}\n`);
      const root = await mkdtemp(
        join(workspace, `${test.variant}-${test.mode}-`),
      );
      const fixture = buildPsxExeFixture({ variant: test.variant });
      const source = join(root, "synthetic source 雪.exe");
      const snapshotMaterialized = join(root, "immutable-snapshot.exe");
      await writeFile(source, fixture.bytes, { mode: 0o600, flag: "wx" });
      await writeFile(snapshotMaterialized, fixture.bytes, {
        mode: 0o600,
        flag: "wx",
      });
      // Establish the owning canonical coordinate before commitment creation;
      // producer observations remain untouched.
      const snapshot = await realpath(snapshotMaterialized);
      const sourceDigest = digest(fixture.bytes);
      const header = await readGhidraPsxSource(snapshot, sourceDigest);
      const commitment = {
        ...createGhidraPsxCommitment(
          header,
          assets.candidate,
          snapshot,
          sourceDigest,
        ),
        schema_version: 3,
        source_provenance: "rea-psx-filebytes-rebind-v2",
      };
      const { source_snapshot_path: _coordinate, ...semantic } = commitment;
      const profile = {
        parameters: {
          psx_import: semantic,
          psx_source_provenance: "rea-psx-filebytes-rebind-v2",
          psx_preparation_transaction: "exclusive-top-level-v1",
          load_image_evidence: "independent-psx-adapted-payload-entry-v2",
          psx_operation_scope: "inventory-load-image-and-static-functions-v1",
          startup_agreement: "psx-observed-import-and-provenance-v3",
        },
      };
      profile.digest = digest(Buffer.from(JSON.stringify(profile.parameters)));
      const runId = randomUUID();
      const descriptorPath = join(root, "session.json");
      const output = join(capture, `${test.variant}-${test.mode}.json`);
      // Credential coordinates satisfy production preparation validation but are
      // never copied into reports or diagnostics. No socket server is started.
      const token = randomBytes(32).toString("hex");
      transportCredentials.add(token);
      await json(descriptorPath, {
        transport: "unix-socket",
        endpoint_path: join(root, "unused.sock"),
        token,
        run_id: runId,
        profile_digest: profile.digest,
        target_sha256: sourceDigest,
        target_path: snapshot,
        provider_version: installation.providerVersion,
        psx_import: commitment,
      });
      const project = join(root, "project");
      await mkdir(project);
      const argv = [
        project,
        "PsxLoadImage",
        "-import",
        snapshot,
        "-readOnly",
        "-noanalysis",
        "-loader",
        "PsxLoader",
        "-processor",
        "PSX:LE:32:default",
        "-cspec",
        "default",
        "-scriptPath",
        scripts,
        ...(test.mode === "production-wrapper"
          ? [
              "-preScript",
              "ReaGhidraPreparePsx.java",
              descriptorPath,
              "-postScript",
              "ReaPsxPreparationTransactionProbe.java",
              descriptorPath,
              output,
            ]
          : [
              "-preScript",
              "ReaPsxProvenanceContractProbe.java",
              descriptorPath,
              output,
              test.mode,
            ]),
        "-deleteProject",
      ];
      const measured = {
        ...test,
        run_id: runId,
        profile,
        expected_declarations: fixture.expected,
        source: {
          path: source,
          snapshot_path: snapshot,
          snapshot_materialized_path: snapshotMaterialized,
          sha256: sourceDigest,
          file_bytes: fixture.bytes.length,
        },
        command: installation.analyzeHeadlessPath,
        arguments: argv,
        owned_root: root,
      };
      report.cases.push(measured);
      let casePrimary;
      let casePassed = false;
      let caseStage = "command";
      try {
        let commandFailure;
        try {
          measured.process = await runOwnedCommand(
            {
              command: installation.analyzeHeadlessPath,
              arguments: argv,
              runId: run.run_id,
              expectedCommand: null,
              cwd: root,
              env,
              hostEnvironment: process.env,
              platform: process.platform,
              signal: abort.signal,
            },
            { timeoutMs: 240000, diagnosticBytes: 4 * 1024 * 1024 },
            { signal: abort.signal },
          );
        } catch (cause) {
          commandFailure = cause;
          if (cause instanceof OwnedCommandFailure) {
            measured.process = cause.snapshot;
            if (cause.cleanupFailure !== null) uncertainOwnership = true;
          }
          measured.failure = failure(cause);
        }
        caseStage = "probe-report";
        let probeBytes;
        try {
          probeBytes = await readFile(output);
        } catch (cause) {
          if (cause.code !== "ENOENT") throw cause;
          const diagnostics =
            `${measured.process?.stdout.text ?? ""}\n${measured.process?.stderr.text ?? ""}`
              .split("\n")
              .filter((line) =>
                /error:|cannot find symbol|REPORT SCRIPT ERROR|SCRIPT ERROR|Exception|ERROR/u.test(
                  line,
                ),
              );
          measured.probe_output = {
            path: output,
            status: "missing",
            exit_code: measured.process?.exitCode ?? null,
            script_errors: diagnostics.map(redact),
          };
          const missing = new Error(
            `Ghidra exited ${measured.process?.exitCode ?? "unknown"} without the required probe output; ${diagnostics.length ? diagnostics.map(redact).join("\n") : "no script error was reported"}`,
            { cause },
          );
          throw commandFailure === undefined
            ? missing
            : new AggregateError(
                [commandFailure, missing],
                "Command and probe reporting failed",
              );
        }
        measured.probe_output = {
          path: output,
          status: "present",
          sha256: digest(probeBytes),
        };
        measured.probe = JSON.parse(probeBytes.toString("utf8"));
        if (
          measured.probe.ok !== true ||
          measured.probe.evidence_complete !== true
        ) {
          measured.partial_failure = measured.probe.failure ?? null;
          throw new AggregateError(
            [
              commandFailure,
              new Error(
                "Probe report is partial/nonpassing; required complete evidence was not emitted",
              ),
            ].filter(Boolean),
            "Command/probe failed",
          );
        }
        if (commandFailure !== undefined) throw commandFailure;
        assertCompleteReport(measured.probe, test.mode);
        caseStage = "complete-evidence-assertions";
        assert.match(
          `${measured.process.stdout.text}\n${measured.process.stderr.text}`,
          new RegExp(
            `REA_PSX_PROVENANCE_PROBE_COMPLETE ${test.mode}(?:\\s|$)`,
            "u",
          ),
        );
        if (test.mode === "active-transaction") {
          assertActiveTransactionProbe(measured.probe);
          assert.doesNotMatch(
            `${measured.process.stdout.text}\n${measured.process.stderr.text}`,
            /REA_PSX_IMPORT_BEFORE_COMPLETE/u,
          );
          await assert.rejects(stat(join(root, "psx-import-before.json")), {
            code: "ENOENT",
          });
        } else {
          const fixedOriginalPath = join(root, "psx-provenance-original.json");
          const { bytes: fixedOriginalBytes } = await readOwnedOriginal(root);
          const capturedFixedPath = join(
            capture,
            `${test.variant}-${test.mode}-original-on-disk.json`,
          );
          await writeFile(capturedFixedPath, fixedOriginalBytes, {
            mode: 0o600,
            flag: "wx",
          });
          let originalBytes = fixedOriginalBytes;
          if (test.mode === "original-record-tamper") {
            const retained = measured.probe.original_record_before;
            assert.equal(typeof retained.bytes_base64, "string");
            assert.ok(
              retained.bytes_base64.length <=
                Math.ceil((4 * 1024 * 1024) / 3) * 4,
              "Pre-tamper evidence exceeds synthetic capture capacity",
            );
            originalBytes = Buffer.from(retained.bytes_base64, "base64");
            assert.equal(
              originalBytes.toString("base64"),
              retained.bytes_base64,
            );
            assert.equal(digest(originalBytes), retained.sha256);
            assert.notEqual(
              digest(fixedOriginalBytes),
              retained.sha256,
              "Tamper probe did not change the owned fixed original record",
            );
          }
          const capturedOriginalPath = join(
            capture,
            `${test.variant}-${test.mode}-original-before.json`,
          );
          await writeFile(capturedOriginalPath, originalBytes, {
            mode: 0o600,
            flag: "wx",
          });
          const originalRecord = JSON.parse(originalBytes.toString("utf8"));
          measured.original_record = {
            fixed_path: fixedOriginalPath,
            captured_before_path: capturedOriginalPath,
            captured_on_disk_path: capturedFixedPath,
            before_sha256: digest(originalBytes),
            on_disk_sha256: digest(fixedOriginalBytes),
            content: originalRecord,
            stage: "original-pre-adaptation",
          };
          assertOriginalRecord(originalRecord, {
            run_id: runId,
            profile_digest: profile.digest,
            source_sha256: sourceDigest,
          });
          assertProbe(
            measured.probe,
            test.mode,
            sourceDigest,
            fixture,
            originalRecord,
            digest(originalBytes),
          );
          const outputText = `${measured.process.stdout.text}\n${measured.process.stderr.text}`;
          if (
            test.mode === "rollback" ||
            test.mode === "original-record-tamper" ||
            isBookmarkCancellation(test.mode)
          ) {
            assert.doesNotMatch(
              outputText,
              /REA_PSX_IMPORT_BEFORE_COMPLETE/u,
              "Failure probe emitted a readiness marker",
            );
            await assert.rejects(stat(join(root, "psx-import-before.json")), {
              code: "ENOENT",
            });
            measured.ready_marker_emitted = false;
          } else {
            const beforeBytes = await readFile(
              join(root, "psx-import-before.json"),
            );
            assert.deepEqual(
              JSON.parse(beforeBytes.toString("utf8")),
              measured.probe.before,
            );
            measured.before_record_sha256 = digest(beforeBytes);
            assert.match(
              outputText,
              new RegExp(
                `REA_PSX_IMPORT_BEFORE_COMPLETE ${runId} ${measured.before_record_sha256}`,
                "u",
              ),
            );
            for (const [record, expectedStage] of [
              [measured.probe.before, "before-analysis"],
              [measured.probe.after, "after-analysis"],
            ]) {
              assert.equal(record.schema_version, 3);
              assert.equal(record.stage, expectedStage);
              assert.deepEqual(record.commitment, {
                run_id: runId,
                profile_digest: profile.digest,
                source_sha256: sourceDigest,
              });
              assert.equal(record.observed.source.snapshot_path, snapshot);
              assert.equal(record.observed.source.sha256, sourceDigest);
              assert.deepEqual(
                record.provenance,
                measured.probe.load_image.psx.provenance,
              );
            }
          }
        }
        assert.deepEqual(
          await readdir(project),
          [],
          "-deleteProject left a project document",
        );
        measured.project_removed = true;
        casePassed = true;
      } catch (cause) {
        casePrimary = cause;
        measured.primary_failure = { stage: caseStage, ...failure(cause) };
      } finally {
        const captureErrors = [];
        const reportingErrors = [];
        const sourceErrors = [];
        try {
          measured.current_original_record = await captureOwnedOriginal({
            root,
            capture,
            test,
            commitment: {
              run_id: runId,
              profile_digest: profile.digest,
              source_sha256: sourceDigest,
            },
            stage: casePassed ? "current-after-success" : "current-at-failure",
          });
          if (measured.current_original_record.reporting_failure)
            reportingErrors.push(
              new Error(
                measured.current_original_record.reporting_failure.message,
              ),
            );
          if (casePassed && test.mode === "active-transaction")
            assert.equal(
              measured.current_original_record.content_status,
              "absent",
              "Rejected caller-owned transaction published original evidence",
            );
          else if (casePassed && test.mode === "original-record-tamper") {
            assert.equal(
              measured.current_original_record.content_status,
              "tampered-or-invalid",
            );
            assert.notEqual(
              measured.current_original_record.sha256,
              measured.probe.original_record_before.sha256,
            );
          } else if (casePassed && test.mode !== "original-record-tamper")
            assert.equal(
              measured.current_original_record.content_status,
              "validated-original",
            );
        } catch (cause) {
          if (measured.current_original_record === undefined)
            measured.current_original_record = {
              fixed_path: join(root, "psx-provenance-original.json"),
              stage: "current-at-failure",
              content_status: "unreadable",
              failure: failure(cause),
            };
          else {
            measured.current_original_record.stage = "current-at-failure";
            measured.current_original_record.validation_failure =
              failure(cause);
          }
          captureErrors.push(cause);
        }
        if (measured.probe?.original_record_before != null) {
          try {
            measured.probe_original_record = await captureProbeOriginal({
              retained: measured.probe.original_record_before,
              capture,
              test,
              commitment: {
                run_id: runId,
                profile_digest: profile.digest,
                source_sha256: sourceDigest,
              },
            });
            if (measured.probe_original_record.reporting_failure)
              reportingErrors.push(
                new Error(
                  measured.probe_original_record.reporting_failure.message,
                ),
              );
          } catch (cause) {
            measured.probe_original_record = {
              stage:
                test.mode === "original-record-tamper"
                  ? "original-pre-tamper"
                  : "original-at-fault",
              content_status: "unreadable",
              failure: failure(cause),
            };
            captureErrors.push(cause);
          }
        }
        for (const [path, key] of [
          [source, "after_sha256"],
          [snapshot, "snapshot_after_sha256"],
        ]) {
          try {
            measured.source[key] = digest(await readFile(path));
            assert.equal(measured.source[key], sourceDigest);
          } catch (cause) {
            sourceErrors.push(cause);
          }
        }
        measured.capture_errors = captureErrors.map(failure);
        measured.reporting_errors = reportingErrors.map(failure);
        measured.source_postcheck_errors = sourceErrors.map(failure);
        measured.ok =
          casePassed &&
          captureErrors.length === 0 &&
          reportingErrors.length === 0 &&
          sourceErrors.length === 0;
        if (
          captureErrors.length ||
          reportingErrors.length ||
          sourceErrors.length
        )
          casePrimary = new AggregateError(
            [
              casePrimary,
              ...captureErrors,
              ...reportingErrors,
              ...sourceErrors,
            ].filter(Boolean),
            "Case, evidence capture, reporting or source postchecks failed",
          );
      }
      if (casePrimary !== undefined) throw casePrimary;
    }
  }
} catch (cause) {
  primary = cause;
} finally {
  process.removeListener("SIGINT", cancel);
  process.removeListener("SIGTERM", cancel);
  const postcheckErrors = [];
  report.postchecks = {
    code: "not-captured",
    bundle: "not-created",
    errors: [],
  };
  try {
    const after = await inspectGhidraPsxLoader(
      installation.installDir,
      installation.providerVersion,
    );
    assert.equal(after.status, "available", JSON.stringify(after));
    report.installed_assets.after_inventory_digest =
      after.candidate.asset_inventory_digest;
    assert.deepEqual(
      after.candidate.assets,
      assets.candidate.assets,
      "Provider assets changed",
    );
    report.installed_assets.unchanged = true;
  } catch (cause) {
    postcheckErrors.push(cause);
    report.installed_assets.postcheck_failure = failure(cause);
  }
  if (code !== undefined) {
    try {
      report.code_after = await codeIdentity();
      assert.deepEqual(
        report.code_after.files,
        code.files,
        "Verification source changed during real imports",
      );
      assert.equal(
        report.code_after.diff_sha256,
        code.diff_sha256,
        "Tracked repository diff changed during real imports",
      );
      report.postchecks.code = "unchanged";
    } catch (cause) {
      postcheckErrors.push(cause);
      report.postchecks.code = "failed";
    }
  }
  if (report.script_bundle !== undefined) {
    const copyFailures = [];
    for (const source of report.script_bundle.sources) {
      try {
        source.copy_after_sha256 = digest(await readFile(source.copy));
        assert.equal(
          source.copy_after_sha256,
          source.source_sha256,
          "Owned Java source bundle changed during imports",
        );
      } catch (cause) {
        copyFailures.push(cause);
      }
    }
    postcheckErrors.push(...copyFailures);
    report.postchecks.bundle =
      copyFailures.length === 0 ? "unchanged" : "failed";
  }
  report.postchecks.errors = postcheckErrors.map(failure);
  if (postcheckErrors.length !== 0)
    primary = new AggregateError(
      [primary, ...postcheckErrors].filter(Boolean),
      "Verification/postchecks failed",
    );
  const cleanup = [];
  const evidenceCloseErrors = await closeOwnedEvidenceHandles();
  cleanup.push(...evidenceCloseErrors);
  const unresolvedEvidence = [...ownedEvidenceHandles.values()].map(
    (resource) => ({ ...resource }),
  );
  if (unresolvedEvidence.length) {
    uncertainOwnership = true;
    cleanup.push(new Error("Owned fixed-evidence handles remain unresolved"));
  }
  const survivingFullRoots = [];
  for (const resource of unresolvedEvidence)
    survivingFullRoots.push(resource.root);
  for (const root of fullOwnedRoots) {
    try {
      await assert.rejects(stat(root), { code: "ENOENT" });
    } catch (cause) {
      uncertainOwnership = true;
      survivingFullRoots.push(root);
      cleanup.push(cause);
    }
  }
  if (unresolvedFullSessions.length) {
    uncertainOwnership = true;
    cleanup.push(
      new Error(
        "Full session failed without exact owned-runtime cleanup evidence",
      ),
    );
  }
  try {
    await systemProcessOwnershipHost.close?.();
  } catch (cause) {
    cleanup.push(cause);
  }
  let lineage;
  try {
    lineage = await completeVerifierRun(run);
    report.verifier_run = lineage;
    if (
      lineage.process_lineage.status !== "verified" ||
      lineage.process_lineage.descendants.length !== 0
    )
      cleanup.push(new Error("Verified empty lineage was not established"));
  } catch (cause) {
    cleanup.push(cause);
  }
  report.cleanup = {
    retained_roots: survivingFullRoots,
    workspace_removed: false,
    process_lineage: lineage?.process_lineage ?? {
      status: "unavailable",
      reason: "Verifier lineage close failed",
    },
    unresolved_full_sessions: unresolvedFullSessions,
    unresolved_evidence_handles: unresolvedEvidence,
    evidence_handle_close_errors: evidenceCloseErrors.map(failure),
  };
  if (workspace !== undefined && !uncertainOwnership && cleanup.length === 0) {
    try {
      await rm(workspace, { recursive: true, force: true });
      await assert.rejects(stat(workspace), { code: "ENOENT" });
      report.cleanup.workspace_removed = true;
    } catch (cause) {
      cleanup.push(cause);
      report.cleanup.retained_roots.push(workspace);
    }
  } else if (workspace !== undefined) {
    report.cleanup.retained_roots.push(workspace);
    cleanup.push(
      new Error("Owned workspace retained because cleanup could not be proven"),
    );
  }
  report.cleanup.errors = cleanup.map(failure);
  if (cleanup.length !== 0)
    primary = new AggregateError(
      [primary, ...cleanup].filter(Boolean),
      "Verification/cleanup failed",
    );
  report.ok = primary === undefined;
  if (primary !== undefined) report.failure = failure(primary);
  try {
    await writeFile(
      join(capture, "report.json"),
      `${JSON.stringify(report, (_key, value) => (typeof value === "string" ? redact(value) : value), 2)}\n`,
      { mode: 0o600 },
    );
    reportPersisted = true;
  } catch (cause) {
    report.reporting_errors = [failure(cause)];
    primary = new AggregateError(
      [primary, cause].filter(Boolean),
      "Verification and final report publication failed",
    );
    report.ok = false;
    process.stderr.write(
      `${redact(JSON.stringify({ report_path: join(capture, "report.json"), primary_failure: report.failure ?? null, reporting_errors: report.reporting_errors }))}\n`,
    );
  }
}
const reportSha = reportPersisted
  ? digest(await readFile(join(capture, "report.json")))
  : null;
process.stdout.write(
  `${JSON.stringify({ report_path: join(capture, "report.json"), report_sha256: reportSha, ok: report.ok, stage })}\n`,
);
if (primary !== undefined) throw primary;

async function verifyFullLane(ownedWorkspace) {
  const runtime = join(ownedWorkspace, "public-runtime");
  await mkdir(runtime);
  const environment = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    JAVA_HOME: installation.javaHome,
    GHIDRA_INSTALL_DIR: installation.installDir,
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_LOG_LEVEL: "silent",
    REA_PROCESS_RUN_ID: run.run_id,
    HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  };
  const sessions = [];
  for (const variant of [
    "baseline",
    "declared-registers-fill",
    "trailing-bytes",
  ]) {
    process.stderr.write(`PSX public load-image: ${variant}\n`);
    const fixture = buildPsxExeFixture({ variant });
    const source = join(ownedWorkspace, `${variant} public source 雪.exe`);
    await writeFile(source, fixture.bytes, { mode: 0o600, flag: "wx" });
    const sourceSha = digest(fixture.bytes);
    const measured = {
      variant,
      expected_declarations: fixture.expected,
      source: {
        path: source,
        sha256: sourceSha,
        file_bytes: fixture.bytes.length,
      },
      sessions: [],
    };
    report.cases.push(measured);
    let casePrimary;
    try {
      for (const adapter of ["mcp", "cli", "direct"]) {
        const sessionRuntime = join(runtime, `${variant}-${adapter}`);
        await mkdir(sessionRuntime);
        const selected = { ...environment, TMPDIR: sessionRuntime };
        const record = {
          adapter,
          capture_scope:
            adapter === "direct"
              ? "separate-authenticated-provider-session"
              : `public-${adapter}`,
          runtime_parent: sessionRuntime,
        };
        measured.sessions.push(record);
        sessions.push(record);
        try {
          if (adapter === "mcp")
            await verifyPublicMcp(source, sourceSha, fixture, selected, record);
          else if (adapter === "cli")
            await verifyPublicCli(source, sourceSha, fixture, selected, record);
          else
            await verifyAuthenticatedDirect(
              source,
              sourceSha,
              fixture,
              selected,
              record,
            );
          record.ok = true;
        } catch (cause) {
          record.ok = false;
          record.failure = failure(cause);
          throw cause;
        }
      }
      const profiles = measured.sessions.map((session) => session.profile);
      for (const profile of profiles.slice(1))
        assert.deepEqual(
          profile,
          profiles[0],
          "Public/direct canonical profiles diverged",
        );
      measured.replay = replayActualObservations(
        fixture,
        sourceSha,
        measured.sessions.find((session) => session.adapter === "direct")
          .load_image.observations,
      );
      measured.ok = true;
    } catch (cause) {
      casePrimary = cause;
      measured.ok = false;
      measured.failure = failure(cause);
    } finally {
      const errors = await attemptEvery([
        async () => {
          measured.source.after_sha256 = digest(await readFile(source));
          assert.equal(
            measured.source.after_sha256,
            sourceSha,
            "Synthetic source changed during public imports",
          );
        },
        async () => {
          await json(join(capture, `${variant}-public.json`), measured);
        },
      ]);
      measured.postcheck_reporting_errors = errors.map(failure);
      if (errors.length)
        casePrimary = new AggregateError(
          [casePrimary, ...errors].filter(Boolean),
          "Public case/postcheck/reporting failed",
        );
    }
    if (casePrimary !== undefined) throw casePrimary;
  }
  assert.equal(sessions.length, 9);
  assert.equal(
    new Set(sessions.map((session) => session.run_id)).size,
    9,
    "Public/direct sessions reused a run identity",
  );
  report.import_count = sessions.length;
  report.distinct_run_ids = sessions.map((session) => session.run_id);
}
async function publicOperation(client, name, arguments_ = {}) {
  return requireMcpOperationResult(
    await client.callTool({ name, arguments: arguments_ }, { timeout: 240000 }),
    name,
  );
}
async function attemptEvery(actions) {
  const errors = [];
  for (const action of actions)
    try {
      await action();
    } catch (cause) {
      errors.push(cause);
    }
  return errors;
}
function requireSessionSettled(primary, errors) {
  if (errors.length) {
    uncertainOwnership = true;
    throw new AggregateError(
      [primary, ...errors].filter(Boolean),
      "Session and owned cleanup failed",
    );
  }
  if (primary !== undefined) throw primary;
}
async function ownedRuntimeRoots(parent) {
  return (await readdir(parent))
    .filter((name) => name.startsWith("rea-ghidra-"))
    .map((name) => join(parent, name));
}
async function assertNoRuntimeRoots(parent, message) {
  const roots = await ownedRuntimeRoots(parent);
  for (const root of roots) fullOwnedRoots.add(root);
  assert.deepEqual(roots, [], message);
}
async function verifyPublicMcp(
  source,
  sourceSha,
  fixture,
  environment,
  record,
) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(repository, "scripts/rea.mjs"), "mcp"],
    env: environment,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-psx-load-image", version: "1" });
  let opened = false,
    primary;
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  try {
    await client.connect(transport);
    const catalog = await client.listTools();
    const advertised = catalog.tools.find(
      (tool) => tool.name === "inspect_native_load_image",
    );
    assert.ok(
      advertised?.outputSchema,
      "Named public MCP operation omitted output schema",
    );
    const validate = new Ajv2020({ strict: false }).compile(
      advertised.outputSchema,
    );
    record.output_schema_sha256 = digest(
      Buffer.from(JSON.stringify(advertised.outputSchema)),
    );
    record.target = await publicOperation(client, "open_binary", {
      path: source,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(record.target.sha256, sourceSha);
    const result = await client.callTool(
      { name: "inspect_native_load_image", arguments: {} },
      { timeout: 240000 },
    );
    assert.notEqual(result.isError, true, mcpTextValue(result));
    const evidence = toolContract(
      "inspect_native_load_image",
    ).outputSchema.parse(JSON.parse(mcpTextValue(result)));
    assert.ok(validate(evidence), JSON.stringify(validate.errors));
    record.evidence = evidence;
    record.load_image = evidence.normalized_result;
    record.profile = evidence.analysis_profile;
    const status = await publicOperation(client, "binary_session");
    record.run_id = status.analysis_run.run_id;
    assert.deepEqual(
      record.profile,
      status.analysis_provider_binding.analysis_profile,
    );
    assert.equal(status.analysis_provider_binding.selection_source, "request");
    const roots = await ownedRuntimeRoots(environment.TMPDIR);
    assert.equal(roots.length, 1, "Expected exactly one owned MCP runtime");
    record.runtime = await captureProductionRuntime(
      roots[0],
      record.run_id,
      sourceSha,
      record.profile,
      "after-public-inspection",
    );
    assert.deepEqual(
      record.runtime.before.provenance,
      record.load_image.observations.psx.provenance,
    );
    assertPublicEvidence(evidence, sourceSha, fixture);
    assertProductionImage(record.load_image, sourceSha, fixture);
    const gated = requireMcpToolError(
      await client.callTool({
        name: "annotate_native_function",
        arguments: {
          name: "refused",
          procedure: `0x${fixture.expected.initialPc.toString(16)}`,
        },
      }),
    );
    assert.equal(gated.code, "capability_unavailable");
    assert.match(gated.details.reason, /PSX observational scope/u);
    record.gated_operation = gated;
    await publicOperation(client, "close_binary");
    opened = false;
    assert.equal((await publicOperation(client, "binary_session")).open, false);
  } catch (cause) {
    primary = cause;
    record.startup_diagnostics = stderr;
  }
  const errors = await attemptEvery([
    async () => {
      if (opened) await publicOperation(client, "close_binary");
    },
    () => client.close(),
    () => transport.close(),
    async () =>
      assertNoRuntimeRoots(environment.TMPDIR, "MCP runtime survived close"),
    async () => assert.equal(digest(await readFile(source)), sourceSha),
  ]);
  record.cleanup = {
    errors: errors.map(failure),
    exact_owned_root: record.runtime?.owned_root ?? null,
    absent_after_close: errors.length === 0,
  };
  requireSessionSettled(primary, errors);
}
async function verifyPublicCli(
  source,
  sourceSha,
  fixture,
  environment,
  record,
) {
  let settled = false,
    primary;
  const command = runOwnedCommand(
    {
      command: process.execPath,
      arguments: [
        join(repository, "scripts/rea.mjs"),
        "inspect-native-load-image",
        source,
        "--provider",
        "ghidra",
        "--json",
      ],
      runId: run.run_id,
      expectedCommand: null,
      cwd: repository,
      env: environment,
      hostEnvironment: process.env,
      platform: process.platform,
      signal: abort.signal,
    },
    { timeoutMs: 240000, diagnosticBytes: 16 * 1024 * 1024 },
    { signal: abort.signal },
  );
  const completion = command.then(
    (value) => {
      settled = true;
      return { value };
    },
    (cause) => {
      settled = true;
      return { cause };
    },
  );
  const captures = new Map();
  try {
    // Observe only this command's newly allocated private runtime parent. The
    // CLI closes its session before emitting Evidence, so retain fixed files
    // during that owned lifetime and authenticate their profile afterwards.
    while (!settled) {
      for (const root of await ownedRuntimeRoots(environment.TMPDIR)) {
        fullOwnedRoots.add(root);
        try {
          const ownership = JSON.parse(
            await readFile(join(root, "ownership.json"), "utf8"),
          );
          const beforeBytes = await readFile(
            join(root, "psx-import-before.json"),
          );
          const before = JSON.parse(beforeBytes.toString("utf8"));
          const markers =
            (await readFile(join(root, "ghidra.log"), "utf8")) +
            (await readFile(join(root, "script.log"), "utf8"));
          if (
            !markers.includes(
              `REA_PSX_IMPORT_BEFORE_COMPLETE ${ownership.run_id} ${digest(beforeBytes)}`,
            )
          )
            continue;
          captures.set(
            root,
            await captureProductionRuntime(
              root,
              ownership.run_id,
              sourceSha,
              { digest: before.commitment.profile_digest },
              "during-cli-owned-lifetime",
            ),
          );
        } catch (cause) {
          if (cause.code !== "ENOENT") throw cause;
        }
      }
      if (!settled) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const outcome = await completion;
    if (outcome.cause !== undefined) {
      if (outcome.cause instanceof OwnedCommandFailure) {
        record.process = outcome.cause.snapshot;
        if (outcome.cause.cleanupFailure !== null) uncertainOwnership = true;
      }
      throw outcome.cause;
    }
    record.process = outcome.value;
    const evidence = parseEvidence(JSON.parse(record.process.stdout.text));
    toolContract("inspect_native_load_image").outputSchema.parse(evidence);
    record.evidence = evidence;
    record.profile = evidence.analysis_profile;
    record.load_image = evidence.normalized_result;
    assert.equal(
      captures.size,
      1,
      "CLI's exact owned fixed records were not captured",
    );
    record.runtime = [...captures.values()][0];
    record.run_id = record.runtime.run_id;
    assert.equal(
      record.runtime.before.commitment.profile_digest,
      record.profile.digest,
    );
    assert.deepEqual(
      record.runtime.before.provenance,
      record.load_image.observations.psx.provenance,
    );
    assertPublicEvidence(evidence, sourceSha, fixture);
    assertProductionImage(record.load_image, sourceSha, fixture);
  } catch (cause) {
    primary = cause;
  } finally {
    const outcome = await completion;
    if (outcome.cause !== undefined && primary !== outcome.cause)
      primary = new AggregateError(
        [primary, outcome.cause].filter(Boolean),
        "CLI observation/command failed",
      );
    const errors = await attemptEvery([
      async () =>
        assertNoRuntimeRoots(
          environment.TMPDIR,
          "CLI runtime survived process close",
        ),
      async () => assert.equal(digest(await readFile(source)), sourceSha),
    ]);
    record.cleanup = {
      errors: errors.map(failure),
      exact_owned_root: record.runtime?.owned_root ?? null,
      absent_after_close: errors.length === 0,
    };
    requireSessionSettled(primary, errors);
  }
}
async function verifyAuthenticatedDirect(
  source,
  sourceSha,
  fixture,
  environment,
  record,
) {
  const config = parseConfig(environment);
  if (!config.ok) throw config.error;
  const target = await parseBinaryTarget(source);
  if (!target.ok) throw target.error;
  const provider = new GhidraProvider(config.value, silentLogger, environment);
  const resolved = await provider.resolveAnalysisProfile(target.value);
  if (!resolved.ok) throw resolved.error;
  record.profile = resolved.value.profile;
  record.run_id = randomUUID();
  const client = provider.createClient(target.value, record.profile, {
    runId: record.run_id,
  });
  let primary;
  try {
    const health = await client.execute("health", {});
    if (!health.ok) throw health.error;
    record.authenticated_health = health.value.result;
    const agreement = health.value.result.psx_import;
    assert.ok(agreement, "Authenticated session omitted preparation agreement");
    const root = dirname(agreement.before.observed.source.snapshot_path);
    record.owned_root = root;
    fullOwnedRoots.add(root);
    const image = await client.execute("inspect_native_load_image", {});
    if (!image.ok) throw image.error;
    record.load_image = image.value.result;
    assertProductionImage(record.load_image, sourceSha, fixture);
    record.runtime = await captureProductionRuntime(
      root,
      record.run_id,
      sourceSha,
      record.profile,
      "after-authenticated-inspection",
    );
    assert.deepEqual(record.runtime.before, agreement.before);
    assert.deepEqual(
      agreement.before.provenance,
      record.load_image.observations.psx.provenance,
    );
    assert.equal(
      record.runtime.before_record_sha256,
      agreement.before_record_sha256,
    );
    assert.deepEqual(agreement.before.provenance, agreement.after.provenance);
    assert.equal(agreement.schema_version, 3);
    assert.equal(agreement.after.commitment.run_id, record.run_id);
    assert.equal(
      agreement.after.commitment.profile_digest,
      record.profile.digest,
    );
    assert.equal(agreement.after.commitment.source_sha256, sourceSha);
    record.authenticated_agreement = agreement;
  } catch (cause) {
    primary = cause;
    const root =
      cause.diagnostics?.runtime_root ??
      cause.details?.diagnostics?.runtime_root;
    if (typeof root === "string" && isAbsolute(root)) fullOwnedRoots.add(root);
    else if (record.owned_root === undefined)
      unresolvedFullSessions.push({
        run_id: record.run_id,
        reason:
          "Failure before exact owned runtime coordinate was authenticated",
      });
  }
  const errors = await attemptEvery([
    async () => {
      const closed = await client.close();
      if (!closed.ok) throw closed.error;
    },
    async () => {
      if (record.owned_root)
        await assert.rejects(stat(record.owned_root), { code: "ENOENT" });
    },
    async () => assert.equal(digest(await readFile(source)), sourceSha),
  ]);
  record.cleanup = {
    errors: errors.map(failure),
    exact_owned_root: record.runtime?.owned_root ?? null,
    absent_after_close: errors.length === 0,
  };
  requireSessionSettled(primary, errors);
}
async function captureProductionRuntime(
  root,
  runId,
  sourceSha,
  profile,
  captureStage,
) {
  assert.ok(isAbsolute(root));
  fullOwnedRoots.add(root);
  const ownership = JSON.parse(
    await readFile(join(root, "ownership.json"), "utf8"),
  );
  assert.equal(ownership.run_id, runId);
  const argv = ownership.arguments;
  assert.ok(Array.isArray(argv));
  assert.ok(argv.includes("-readOnly") && argv.includes("-deleteProject"));
  assert.ok(
    !argv.includes("-noanalysis"),
    "Public lane disabled auto-analysis",
  );
  assert.equal(argv[argv.indexOf("-loader") + 1], "PsxLoader");
  assert.ok(!argv.some((value) => /^-loader-ram(?:Start|Size)/u.test(value)));
  const snapshot = argv[argv.indexOf("-import") + 1];
  assert.ok(isAbsolute(snapshot));
  assert.equal(dirname(snapshot), await realpath(root));
  const beforeBytes = await readFile(join(root, "psx-import-before.json"));
  const before = JSON.parse(beforeBytes.toString("utf8"));
  assert.equal(before.schema_version, 3);
  assert.deepEqual(before.commitment, {
    run_id: runId,
    profile_digest: profile.digest,
    source_sha256: sourceSha,
  });
  assert.equal(before.observed.source.snapshot_path, snapshot);
  assert.equal(before.observed.source.sha256, sourceSha);
  const original = await readOwnedOriginal(root);
  const originalRecord = JSON.parse(original.bytes.toString("utf8"));
  assertOriginalRecord(originalRecord, before.commitment);
  const metadata = before.provenance.metadata_preservation;
  assert.equal(digest(original.bytes), metadata.original_record_sha256);
  assert.equal(originalRecord.state_sha256, metadata.original_state_sha256);
  assert.equal(
    originalRecord.operational_state_sha256,
    metadata.original_operational_state_sha256,
  );
  assert.deepEqual(originalRecord.label_history, metadata.label_history.before);
  assert.equal(
    metadata.original_operational_state_sha256,
    metadata.adapted_operational_state_sha256,
  );
  assert.equal(metadata.operational_state_matched, true);
  const difference = journalDifference(
    metadata.label_history.before,
    metadata.label_history.after,
  );
  assert.deepEqual(
    difference.removed,
    metadata.label_history.removed_before_ordinals,
  );
  assert.deepEqual(
    difference.added,
    metadata.label_history.added_after_ordinals,
  );
  const originalCapture = join(capture, `${runId}-production-original.json`);
  const beforeCapture = join(capture, `${runId}-production-before.json`);
  await writeFile(originalCapture, original.bytes, { mode: 0o600 });
  await writeFile(beforeCapture, beforeBytes, { mode: 0o600 });
  assert.equal(digest(await readFile(snapshot)), sourceSha);
  const logs = {};
  for (const name of ["ghidra.log", "script.log"]) {
    assert.ok((await stat(join(root, name))).size < 4 * 1024 * 1024);
    logs[name] = (await readFile(join(root, name), "utf8"))
      .split("\n")
      .filter((line) =>
        /REPORT: Analysis succeeded for file:|REA_PSX_IMPORT_BEFORE_COMPLETE/u.test(
          line,
        ),
      )
      .join("\n");
  }
  assert.match(
    logs["script.log"] + logs["ghidra.log"],
    new RegExp(
      `REA_PSX_IMPORT_BEFORE_COMPLETE ${runId} ${digest(beforeBytes)}`,
      "u",
    ),
  );
  if (captureStage !== "during-cli-owned-lifetime")
    assert.match(logs["ghidra.log"], /REPORT: Analysis succeeded for file:/u);
  return {
    run_id: runId,
    owned_root: root,
    capture_stage: captureStage,
    ownership,
    snapshot: { path: snapshot, sha256: sourceSha, unchanged_at_capture: true },
    before_record_sha256: digest(beforeBytes),
    before,
    original_record: {
      captured_path: originalCapture,
      sha256: digest(original.bytes),
      identity: original.identity,
      content: originalRecord,
    },
    captured_before_path: beforeCapture,
    logs,
  };
}
function assertPublicEvidence(evidence, sourceSha, fixture) {
  assert.equal(evidence.operation, "inspect_native_load_image");
  assert.equal(evidence.provider.id, "ghidra");
  assert.equal(evidence.subject.digest.sha256, sourceSha);
  assert.equal(evidence.subject.format, "ps-x-exe");
  assert.equal(evidence.subject.architecture, "mips");
  const parameters = evidence.analysis_profile.parameters;
  assert.equal(
    parameters.psx_preparation_transaction,
    "exclusive-top-level-v1",
  );
  assert.equal(parameters.psx_source_provenance, "rea-psx-filebytes-rebind-v2");
  assert.equal(
    parameters.startup_agreement,
    "psx-observed-import-and-provenance-v3",
  );
  assert.equal(
    parameters.load_image_evidence,
    "independent-psx-adapted-payload-entry-v2",
  );
  assert.equal(
    parameters.psx_operation_scope,
    "inventory-load-image-and-static-functions-v1",
  );
  assert.equal(parameters.psx_import.schema_version, 3);
  assert.deepEqual(parameters.psx_import.supplied_loader_options, {});
  assert.equal(
    evidence.normalized_result.trailing_bytes,
    fixture.expected.trailingBytes,
  );
}
function assertProductionImage(image, sourceSha, fixture) {
  assert.equal(image.format, "ps-x-exe");
  assert.equal(
    image.status,
    "verified",
    JSON.stringify(
      image.checks.filter(
        (check) => check.required && check.status !== "matched",
      ),
    ),
  );
  assert.equal(image.target_sha256, sourceSha);
  assert.equal(image.coverage.complete, true);
  assert.equal(
    image.coverage.expected_payload_bytes,
    fixture.expected.payloadBytes,
  );
  assert.equal(
    image.coverage.verified_payload_bytes,
    fixture.expected.payloadBytes,
  );
  assert.ok(
    image.checks.every(
      (check) => !check.required || check.status === "matched",
    ),
  );
  assertLinkedPayload(image.observations, sourceSha, fixture);
  assert.deepEqual(image.observations.psx.provenance.before.source_files, []);
  assert.equal(image.observations.psx.provenance.status, "applied");
  assert.equal(
    image.observations.psx.provenance.method,
    "rea-psx-filebytes-rebind-v2",
  );
  assert.deepEqual(image.observations.psx.entry_instruction, {
    address: `0x${fixture.expected.initialPc.toString(16)}`,
    status: "instruction",
    length: 4,
  });
  assert.equal(
    image.declarations.initial_gp,
    `0x${fixture.expected.initialGp.toString(16)}`,
  );
  if (fixture.expected.initialGp === 0)
    assert.equal(
      image.checks.find((check) => check.name === "entry.gp").status,
      "unknown",
    );
  assert.equal(
    image.checks.find((check) => check.name === "entry.sp").status,
    "unknown",
  );
  const entry = image.observations.entry_context.find(
    (row) => row.address === image.entry.declared_pc,
  );
  assert.equal(
    entry.registers.find((register) => register.name === "sp").value_hex,
    null,
  );
  if (fixture.expected.initialGp !== 0)
    assert.equal(
      entry.registers.find((register) => register.name === "gp").value_hex,
      image.declarations.initial_gp,
    );
  validateJournal(image.observations.psx.current_label_history);
  if (fixture.expected.fillBytes !== 0) {
    assert.ok(
      image.coverage.auxiliary.some(
        (row) => row.classification === "declared-fill",
      ),
    );
    const fill = image.observations.mappings.filter(
      (row) =>
        /^0x[0-9a-f]+$/u.test(row.start) &&
        BigInt(row.start) <= BigInt(fixture.expected.fillEndInclusive) &&
        BigInt(row.end) >= BigInt(fixture.expected.fillAddress),
    );
    assert.ok(fill.length && fill.every((row) => !row.initialized));
  }
}
function replayActualObservations(fixture, sourceSha, actual) {
  const baseline = attestGhidraPsxLoadImage(fixture.bytes, sourceSha, actual);
  assert.ok(baseline.ok);
  assert.equal(baseline.value.status, "verified");
  const cases = [];
  for (const [name, expectedCheck, mutate] of [
    [
      "source-offset-with-memory-hashes-unchanged",
      null,
      (observation) => {
        observation.mappings.find(
          (row) => row.source_file_index !== null,
        ).file_offset -= 4;
      },
    ],
    [
      "original-source-digest-with-mapped-bytes-unchanged",
      "original_file_sha256",
      (observation) => {
        observation.source_files[0].original_sha256 = "0".repeat(64);
      },
    ],
    [
      "modified-source-digest-with-mapped-bytes-unchanged",
      "modified_file_sha256",
      (observation) => {
        observation.source_files[0].modified_sha256 = "0".repeat(64);
      },
    ],
  ]) {
    const mutated = structuredClone(actual);
    const mappingHashes = mutated.mappings.map((row) => row.sha256);
    mutate(mutated);
    assert.deepEqual(
      mutated.mappings.map((row) => row.sha256),
      mappingHashes,
    );
    const result = attestGhidraPsxLoadImage(fixture.bytes, sourceSha, mutated);
    assert.ok(result.ok);
    assert.equal(result.value.status, "mismatch");
    const failed = result.value.checks
      .filter((check) => check.status === "mismatch")
      .map((check) => check.name);
    assert.ok(
      expectedCheck === null
        ? failed.some((check) => /^mapping\[\d+\]\.file_offset$/u.test(check))
        : failed.includes(expectedCheck),
    );
    cases.push({
      name,
      expected_check:
        expectedCheck ?? "mapping[actual-observation-index].file_offset",
      failed_checks: failed,
      status: result.value.status,
      live_tampering: false,
    });
  }
  return {
    scope: "controlled-replay-of-captured-authenticated-observations",
    source_sha256: sourceSha,
    baseline: baseline.value.status,
    mutations: cases,
  };
}
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function redact(value) {
  for (const credential of transportCredentials)
    value = value.replaceAll(credential, "[REDACTED_TRANSPORT_CREDENTIAL]");
  return value;
}
async function json(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
function failure(cause) {
  return {
    name: cause instanceof Error ? cause.name : "Unknown",
    message: cause instanceof Error ? cause.message : String(cause),
    ...(cause instanceof AggregateError
      ? { errors: cause.errors.map(failure) }
      : {}),
    ...(cause instanceof Error && cause.cause !== undefined
      ? { cause: failure(cause.cause) }
      : {}),
    ...(cause?.owned_evidence_resource !== undefined
      ? {
          owned_evidence_resource: cause.owned_evidence_resource,
          evidence_read_failure:
            cause.evidence_read_failure === null
              ? null
              : failure(cause.evidence_read_failure),
          evidence_close_failure: failure(cause.evidence_close_failure),
        }
      : {}),
    ...(cause instanceof OwnedCommandFailure
      ? {
          reason: cause.reason,
          cleanup_failure: cause.cleanupFailure,
          retained_resources: cause.resources,
        }
      : {}),
  };
}
// The synthetic lane caps retained individual evidence at the same 4 MiB as
// command diagnostics. Read through the owned fixed coordinate, never a report
// path, and validate the open regular file before allocating its buffer.
async function readOwnedOriginal(root) {
  const path = join(root, "psx-provenance-original.json");
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  const resource = { path, root, close_attempts: 0, last_close_failure: null };
  ownedEvidenceHandles.set(handle, resource);
  let primary;
  let result;
  try {
    const before = await handle.stat({ bigint: true });
    assert.ok(before.isFile(), "Fixed original evidence is not a regular file");
    assert.ok(
      before.size >= 0n && before.size <= 4n * 1024n * 1024n,
      "Fixed original evidence exceeds synthetic capture capacity",
    );
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      assert.ok(
        read.bytesRead !== 0,
        "Fixed original evidence shrank during capture",
      );
      offset += read.bytesRead;
    }
    assert.equal(
      (await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead,
      0,
      "Fixed original evidence grew during capture",
    );
    const after = await handle.stat({ bigint: true });
    const identity = (stat) =>
      Object.fromEntries(
        ["dev", "ino", "mode", "size", "mtimeNs", "ctimeNs"].map((key) => [
          key,
          stat[key].toString(),
        ]),
      );
    assert.deepEqual(
      identity(after),
      identity(before),
      "Fixed original evidence changed during capture",
    );
    result = { path, bytes, identity: identity(after) };
  } catch (cause) {
    primary = cause;
  }
  try {
    resource.close_attempts += 1;
    await handle.close();
    ownedEvidenceHandles.delete(handle);
  } catch (cause) {
    const readFailure = primary;
    const closeFailure = new AggregateError(
      [primary, cause].filter(Boolean),
      "Fixed evidence read/close failed",
    );
    resource.last_close_failure = failure(cause);
    closeFailure.owned_evidence_resource = { path, root };
    closeFailure.evidence_read_failure = readFailure ?? null;
    closeFailure.evidence_close_failure = cause;
    primary = closeFailure;
  }
  if (primary !== undefined) throw primary;
  return result;
}
async function closeOwnedEvidenceHandles() {
  const errors = [];
  for (const [handle, resource] of ownedEvidenceHandles) {
    try {
      resource.close_attempts += 1;
      await handle.close();
      ownedEvidenceHandles.delete(handle);
    } catch (cause) {
      resource.last_close_failure = failure(cause);
      errors.push(cause);
    }
  }
  return errors;
}
async function captureOwnedOriginal({
  root,
  capture,
  test,
  commitment,
  stage,
}) {
  let read;
  try {
    read = await readOwnedOriginal(root);
  } catch (cause) {
    if (cause.code === "ENOENT")
      return {
        fixed_path: join(root, "psx-provenance-original.json"),
        stage,
        content_status: "absent",
      };
    throw cause;
  }
  const capturedPath = join(
    capture,
    `${test.variant}-${test.mode}-original-current.json`,
  );
  const result = {
    fixed_path: read.path,
    captured_path: capturedPath,
    stage,
    sha256: digest(read.bytes),
    identity: read.identity,
    content_status: "partial",
  };
  try {
    await writeFile(capturedPath, read.bytes, { mode: 0o600, flag: "wx" });
  } catch (cause) {
    result.captured_path = null;
    result.reporting_failure = failure(cause);
  }
  if (read.bytes.length !== 0)
    try {
      result.content = JSON.parse(read.bytes.toString("utf8"));
      assertOriginalRecord(result.content, commitment);
      result.content_status = "validated-original";
    } catch (cause) {
      result.content_status = "tampered-or-invalid";
      result.content_failure = failure(cause);
    }
  return result;
}
async function captureProbeOriginal({ retained, capture, test, commitment }) {
  assert.equal(typeof retained.bytes_base64, "string");
  assert.ok(
    retained.bytes_base64.length <= Math.ceil((4 * 1024 * 1024) / 3) * 4,
    "Probe original evidence exceeds synthetic capture capacity",
  );
  const bytes = Buffer.from(retained.bytes_base64, "base64");
  assert.equal(bytes.toString("base64"), retained.bytes_base64);
  assert.equal(digest(bytes), retained.sha256);
  const capturedPath = join(
    capture,
    `${test.variant}-${test.mode}-original-probe-before.json`,
  );
  const result = {
    stage:
      test.mode === "original-record-tamper"
        ? "original-pre-tamper"
        : "original-at-fault",
    captured_path: capturedPath,
    sha256: digest(bytes),
    content_status: "partial",
  };
  try {
    await writeFile(capturedPath, bytes, { mode: 0o600, flag: "wx" });
  } catch (cause) {
    result.captured_path = null;
    result.reporting_failure = failure(cause);
  }
  if (bytes.length !== 0)
    try {
      result.content = JSON.parse(bytes.toString("utf8"));
      assertOriginalRecord(result.content, commitment);
      result.content_status = "validated-original";
    } catch (cause) {
      result.content_status = "tampered-or-invalid";
      result.content_failure = failure(cause);
    }
  return result;
}
async function codeIdentity() {
  const paths = [
    "scripts/verify-real-ghidra-psx-load-image.mjs",
    "tests/conformance/ghidra/psx-exe-fixture.mjs",
    "tests/conformance/ghidra/ReaPsxProvenanceContractProbe.java",
    "tests/conformance/ghidra/ReaPsxPreparationTransactionProbe.java",
    "bridge/ghidra/ReaGhidraPsxProvenance.java",
    "bridge/ghidra/ReaGhidraPsxImport.java",
    "bridge/ghidra/ReaGhidraPreparePsx.java",
    "bridge/ghidra/ReaGhidraBridge.java",
    "src/domain/native/nativeLoadImage.ts",
    "src/ghidra/GhidraPsxLoadImageValues.ts",
    "src/ghidra/GhidraLoadImageAttest.ts",
    "src/ghidra/GhidraPsxLoader.ts",
    "src/ghidra/GhidraImportConfiguration.ts",
    "src/ghidra/GhidraAnalysisProfile.ts",
    "src/ghidra/GhidraClient.ts",
    "src/ghidra/GhidraClientStartup.ts",
    "src/ghidra/GhidraSessionValues.ts",
    "src/ghidra/GhidraProviderClient.ts",
    "src/ghidra/GhidraLauncher.ts",
    "src/ghidra/GhidraProviderCapabilities.ts",
    "dist/domain/native/nativeLoadImage.js",
    "dist/ghidra/GhidraPsxLoadImageValues.js",
    "dist/ghidra/GhidraLoadImageAttest.js",
    "dist/ghidra/GhidraPsxLoader.js",
    "dist/ghidra/GhidraImportConfiguration.js",
    "dist/ghidra/GhidraAnalysisProfile.js",
    "dist/ghidra/GhidraClient.js",
    "dist/ghidra/GhidraClientStartup.js",
    "dist/ghidra/GhidraSessionValues.js",
    "dist/ghidra/GhidraProviderClient.js",
    "dist/ghidra/GhidraLauncher.js",
    "dist/ghidra/GhidraProviderCapabilities.js",
    "scripts/rea.mjs",
    "scripts/lib/mcp-verifier-results.mjs",
    "dist/contracts/toolContracts.js",
    "dist/contracts/toolOutputSchemaGroups.js",
    "dist/domain/evidence.js",
    "docs/active/phase-3-plan.md",
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
function assertCompleteReport(probe, mode) {
  assert.equal(probe.schema_version, 2);
  assert.equal(probe.mode, mode);
  assert.equal(
    probe.ok,
    true,
    "Partial/nonpassing probe cannot satisfy the gate",
  );
  assert.equal(
    probe.evidence_complete,
    true,
    "Incomplete probe evidence cannot satisfy the gate",
  );
}
function assertProbe(
  probe,
  mode,
  sourceDigest,
  fixture,
  originalRecord,
  originalDigest,
) {
  const expected = fixture.expected;
  if (mode.startsWith("bookmarks"))
    assertBookmarkPreservation(
      probe,
      mode,
      sourceDigest,
      fixture,
      originalDigest,
    );
  assert.equal(probe.schema_version, 2);
  assert.equal(probe.mode, mode);
  assertTransactionOwnership(probe.transaction_ownership, mode);
  assert.equal(probe.preservation.operational_state_matched, true);
  assert.ok(
    !Object.hasOwn(probe.preservation, "matched"),
    "Whole-state preservation cannot be asserted for applied journal recreation",
  );
  for (const key of ["before_sha256", "after_sha256"])
    assertDigest(probe.preservation[key]);
  assert.equal(probe.preservation.before_sha256, originalRecord.state_sha256);
  if (
    mode === "rollback" ||
    mode === "original-record-tamper" ||
    isBookmarkCancellation(mode)
  ) {
    assert.equal(probe.before, null);
    assert.equal(probe.after, null);
    assert.equal(probe.load_image, null);
    assert.equal(probe.failure.expected, true);
    assert.equal(
      probe.failure.kind,
      mode === "original-record-tamper"
        ? "original-record-invalid"
        : "cancelled",
    );
    assert.equal(probe.failure.marker_emitted, false);
    assert.equal(probe.failure.before_record_present, false);
    assert.equal(
      probe.failure.fired_after_rebind,
      mode !== "bookmarks-cancel-parking",
    );
    if (mode === "bookmarks-cancel-parking")
      assert.deepEqual(
        probe.failure.observation_at_fault,
        probe.rollback.observations_before,
      );
    else
      assertLinkedPayload(
        probe.failure.observation_at_fault,
        sourceDigest,
        fixture,
      );
    assert.equal(probe.rollback.exercised, true);
    assert.equal(probe.rollback.matched, true);
    assert.equal(probe.rollback.original_observation_matched, true);
    assertDigest(probe.rollback.before_sha256);
    assert.equal(probe.rollback.before_sha256, originalRecord.state_sha256);
    assert.equal(probe.rollback.before_sha256, probe.rollback.after_sha256);
    assert.equal(
      probe.preservation.before_sha256,
      probe.preservation.after_sha256,
    );
    assert.equal(probe.preservation.journal_disposition, "unchanged");
    assertJournalEqual(
      originalRecord.label_history,
      probe.rollback.label_history_before,
    );
    assertJournalEqual(
      probe.rollback.label_history_before,
      probe.rollback.label_history_after,
    );
    assert.deepEqual(
      probe.rollback.observations_before,
      probe.rollback.observations_after,
    );
    assert.deepEqual(probe.rollback.observations_before.source_files, []);
    assert.deepEqual(probe.rollback.observations_after.source_files, []);
    return;
  }
  assert.equal(probe.load_image.psx.schema_version, 2);
  const provenance = probe.load_image.psx.provenance;
  assert.equal(provenance.method, "rea-psx-filebytes-rebind-v2");
  assert.equal(provenance.source_sha256, sourceDigest);
  assert.equal(provenance.source_file_bytes, expected.fileBytes);
  assert.deepEqual(provenance.before.source_files, []);
  assert.equal(
    provenance.status,
    isUnsupportedData(mode) ? "unavailable" : "applied",
  );
  const metadata = provenance.metadata_preservation;
  assert.equal(
    metadata.comparison,
    "exact-enumerated-state-except-label-history-v1",
  );
  assert.equal(metadata.original_record_sha256, originalDigest);
  assert.equal(metadata.original_state_sha256, originalRecord.state_sha256);
  assert.equal(
    metadata.original_operational_state_sha256,
    originalRecord.operational_state_sha256,
  );
  assert.equal(
    metadata.original_operational_state_sha256,
    metadata.adapted_operational_state_sha256,
  );
  assert.equal(metadata.operational_state_matched, true);
  assert.equal(
    probe.preservation.before_sha256,
    metadata.original_state_sha256,
  );
  assert.equal(probe.preservation.after_sha256, metadata.adapted_state_sha256);
  assertDigest(metadata.adapted_state_sha256);
  assert.equal(metadata.label_history.scope, "complete-program-label-history");
  assert.deepEqual(metadata.label_history.before, originalRecord.label_history);
  const difference = journalDifference(
    metadata.label_history.before,
    metadata.label_history.after,
  );
  assert.deepEqual(
    metadata.label_history.removed_before_ordinals,
    difference.removed,
  );
  assert.deepEqual(
    metadata.label_history.added_after_ordinals,
    difference.added,
  );
  const changed =
    difference.removed.length !== 0 || difference.added.length !== 0;
  const disposition = changed ? "recreated-at-payload-addresses" : "unchanged";
  assert.equal(metadata.label_history.program_journal, disposition);
  assert.equal(probe.preservation.journal_disposition, disposition);
  if (changed)
    assert.notEqual(
      metadata.original_state_sha256,
      metadata.adapted_state_sha256,
    );
  else
    assert.equal(metadata.original_state_sha256, metadata.adapted_state_sha256);
  for (const ordinal of difference.removed)
    assert.ok(
      inPayload(metadata.label_history.before[ordinal].address, expected),
      "Original journal difference outside payload",
    );
  for (const ordinal of difference.added) {
    const row = metadata.label_history.after[ordinal];
    assert.ok(
      inPayload(row.address, expected),
      "New journal difference outside payload",
    );
    assert.equal(row.action, 0, "New journal row is not an ADD event");
    assert.equal(
      typeof row.label,
      "string",
      "New journal row does not name a restored symbol",
    );
  }
  // The probe is explicitly noanalysis; inspection itself cannot create events.
  assertJournalEqual(
    metadata.label_history.after,
    probe.load_image.psx.current_label_history,
  );
  if (mode === "journal-multiplicity") {
    const affected = metadata.label_history.before.filter((row) =>
      inPayload(row.address, expected),
    );
    assert.ok(
      affected.length >= 3,
      "Journal probe did not retain multiple affected events",
    );
    assert.ok(
      affected.filter((row) => row.action === 2).length >= 2,
      "Journal probe did not observe rename-away/back events",
    );
    assert.ok(
      metadata.label_history.before.some(
        (row) => !inPayload(row.address, expected),
      ),
      "Journal probe omitted outside-payload evidence",
    );
  }
  if (isUnsupportedData(mode)) {
    assert.ok(provenance.reason);
    if (mode === "bookmarks-unsupported-data")
      assert.equal(
        provenance.reason,
        "Affected data definitions cannot be preserved by plain loader restoration",
      );
    assert.deepEqual(provenance.rebound_ranges, []);
    assert.equal(changed, false);
    assert.equal(metadata.original_state_sha256, metadata.adapted_state_sha256);
    assert.deepEqual(probe.load_image.source_files, []);
    return;
  }
  assert.equal(provenance.reason, null);
  assertLinkedPayload(probe.load_image, sourceDigest, fixture);
  const rows = probe.load_image.mappings
    .filter((row) => row.source_file_index !== null)
    .sort((a, b) => Number(BigInt(a.start) - BigInt(b.start)));
  if (mode === "split" || mode === "bookmarks-split")
    assert.ok(rows.length > 1, "Split probe did not split the payload");
  assert.deepEqual(probe.load_image.psx.entry_instruction, {
    address: `0x${expected.initialPc.toString(16)}`,
    status: "instruction",
    length: 4,
  });
  const entry = probe.load_image.entry_context.find(
    (row) => row.address === `0x${expected.initialPc.toString(16)}`,
  );
  assert.ok(entry, "Declared entry register observations absent");
  assert.equal(
    entry.registers.find((row) => row.name === "gp")?.value_hex,
    `0x${expected.initialGp.toString(16)}`,
  );
  assert.equal(
    entry.registers.find((row) => row.name === "sp")?.value_hex,
    null,
  );
  if (expected.fillBytes !== 0) {
    const fill = probe.load_image.mappings.filter(
      (row) =>
        /^0x[0-9a-f]+$/u.test(row.start) &&
        Number(BigInt(row.start)) <= expected.fillEndInclusive &&
        Number(BigInt(row.end)) >= expected.fillAddress,
    );
    assert.ok(fill.length > 0, "Declared fill memory was not observed");
    assert.ok(
      fill.every((row) => !row.initialized),
      "Uninitialized fill became initialized",
    );
  }
}
function isBookmarkCancellation(mode) {
  return mode.startsWith("bookmarks-cancel-");
}
function isUnsupportedData(mode) {
  return mode === "unsupported-data" || mode === "bookmarks-unsupported-data";
}
function assertBookmarkState(state) {
  assert.deepEqual(Object.keys(state).sort(), ["records", "types"]);
  const ids = new Set(),
    typeIds = new Set();
  for (const type of state.types) {
    assert.deepEqual(Object.keys(type).sort(), [
      "color_argb",
      "defined",
      "has_bookmarks",
      "icon",
      "id",
      "name",
      "priority",
    ]);
    assert.ok(Number.isInteger(type.id));
    assert.ok(!typeIds.has(type.id), "Duplicate bookmark type ID");
    typeIds.add(type.id);
    assert.equal(typeof type.name, "string");
    assert.equal(typeof type.defined, "boolean");
    assert.equal(typeof type.has_bookmarks, "boolean");
    assert.ok(Number.isInteger(type.priority));
    assert.ok(type.color_argb === null || Number.isInteger(type.color_argb));
    assert.equal(type.icon, null);
  }
  for (const row of state.records) {
    assert.deepEqual(Object.keys(row).sort(), [
      "address",
      "address_space",
      "category",
      "comment",
      "id",
      "type",
      "type_id",
    ]);
    assert.match(row.id, /^(?:0|[1-9][0-9]*)$/u);
    assert.ok(BigInt(row.id) <= (1n << 64n) - 1n);
    assert.ok(!ids.has(row.id), "Duplicate bookmark ID");
    ids.add(row.id);
    assert.match(row.address, /^0x(?:0|[1-9a-f][a-f0-9]*)$/u);
    for (const key of ["address_space", "category", "comment", "type"])
      assert.equal(typeof row[key], "string");
    assert.ok(
      state.types.some(
        (type) =>
          type.id === row.type_id &&
          type.name === row.type &&
          type.has_bookmarks,
      ),
    );
  }
}
function assertBookmarkSeeds(state, expected) {
  const start = expected.payloadAddress;
  for (const [offset, type, category, comment] of [
    [0, "Note", "rea_probe_first", "original first 雪"],
    [0, "Note", "rea_probe_second", "distinct category"],
    [0, "Error", "rea_probe_first", "distinct type"],
    [2047, "Warning", "rea_probe_last", "original last"],
    [1024, "Info", "rea_probe_middle", "split boundary"],
    [-1, "Note", "rea_probe_outside_before", "unaffected preceding address"],
    [2048, "Note", "rea_probe_outside_after", "unaffected succeeding address"],
  ]) {
    assert.equal(
      state.records.filter(
        (row) =>
          BigInt(row.address) === BigInt(start + offset) &&
          row.type === type &&
          row.category === category &&
          row.comment === comment,
      ).length,
      1,
      `Bookmark seed absent: ${category}/${type}`,
    );
  }
}
function assertParkedBookmarkState(before, checkpoint, expected) {
  const current = checkpoint.bookmark_identity;
  assertBookmarkState(current);
  assert.deepEqual(current.types, before.types);
  assert.equal(current.records.length, before.records.length);
  const start = BigInt(expected.payloadAddress),
    bytes = BigInt(expected.payloadBytes);
  const payloadSpace = before.records.find(
    (row) => row.category === "rea_probe_first" && row.type === "Note",
  ).address_space;
  let displacement;
  for (const original of before.records) {
    const actual = current.records.find((row) => row.id === original.id);
    assert.ok(actual, `Original bookmark ID missing: ${original.id}`);
    if (
      original.address_space !== payloadSpace ||
      !inPayload(original.address, expected)
    ) {
      assert.deepEqual(actual, original);
      continue;
    }
    assert.deepEqual({ ...actual, address: original.address }, original);
    assert.equal(inPayload(actual.address, expected), false);
    const delta = BigInt(actual.address) - BigInt(original.address);
    if (displacement !== undefined) assert.equal(delta, displacement);
    displacement = delta;
  }
  assert.notEqual(
    displacement,
    undefined,
    "No original affected bookmarks moved",
  );
  const parking = start + displacement,
    end = parking + bytes - 1n;
  assert.ok(parking >= 0n && end < 1n << 32n);
  assert.ok(end < start || parking >= start + bytes);
  for (const mapping of checkpoint.load_image.mappings)
    if (mapping.address_space === payloadSpace)
      assert.ok(
        BigInt(mapping.end) < parking || BigInt(mapping.start) > end,
        "Production parking overlaps original memory",
      );
  for (const original of before.records)
    if (
      original.address_space === payloadSpace &&
      !inPayload(original.address, expected)
    )
      assert.ok(
        BigInt(original.address) < parking || BigInt(original.address) > end,
        "Production parking overlaps unaffected bookmark",
      );
}
function assertCompleteBookmarkManifest(state) {
  assert.deepEqual(Object.keys(state).sort(), [
    "blocks",
    "bookmarks",
    "comments",
    "context",
    "data",
    "default_context",
    "default_disassembly_context",
    "entries",
    "equates",
    "functions",
    "instructions",
    "label_history",
    "property_maps",
    "references",
    "relocations",
    "source_maps",
    "symbols",
    "trees",
  ]);
  for (const [key, value] of Object.entries(state))
    if (key === "bookmarks")
      assert.deepEqual(Object.keys(value).sort(), ["records", "types"]);
    else if (key === "default_disassembly_context") {
      if (value !== null) assert.match(value, /^(?:[a-f0-9]{2})+$/u);
    } else
      assert.ok(
        Array.isArray(value),
        `Complete state category missing: ${key}`,
      );
}
function assertBookmarkPreservation(
  probe,
  mode,
  sourceDigest,
  fixture,
  originalDigest,
) {
  const preservation = probe.bookmark_preservation;
  assert.equal(preservation.schema_version, 1);
  assert.equal(preservation.production_adaptation, true);
  assert.equal(preservation.identity_and_type_matched, true);
  assertBookmarkState(preservation.before);
  assertBookmarkSeeds(preservation.before, fixture.expected);
  assert.deepEqual(preservation.before, preservation.after);
  assertCompleteBookmarkManifest(preservation.full_state_before);
  assertCompleteBookmarkManifest(preservation.full_state_after);
  const unchanged = isBookmarkCancellation(mode) || isUnsupportedData(mode);
  if (unchanged)
    assert.deepEqual(
      preservation.full_state_before,
      preservation.full_state_after,
    );
  else {
    const { label_history: _beforeJournal, ...before } =
      preservation.full_state_before;
    const { label_history: _afterJournal, ...after } =
      preservation.full_state_after;
    assert.deepEqual(before, after);
  }
  const original = preservation.original_record_before;
  assert.equal(typeof original.bytes_base64, "string");
  assert.ok(
    original.bytes_base64.length <= Math.ceil((4 * 1024 * 1024) / 3) * 4,
  );
  const bytes = Buffer.from(original.bytes_base64, "base64");
  assert.equal(bytes.toString("base64"), original.bytes_base64);
  assert.equal(digest(bytes), original.sha256);
  assert.equal(original.sha256, originalDigest);
  const boundaries = isUnsupportedData(mode)
    ? []
    : mode === "bookmarks-cancel-parking"
      ? ["parking"]
      : mode === "bookmarks-cancel-rebind"
        ? ["parking", "rebind"]
        : ["parking", "rebind", "return"];
  assert.deepEqual(
    preservation.checkpoints.map((row) => row.boundary),
    boundaries,
  );
  for (const checkpoint of preservation.checkpoints) {
    assert.equal(checkpoint.transaction_active, true);
    if (checkpoint.boundary === "return")
      assert.deepEqual(checkpoint.bookmark_identity, preservation.before);
    else
      assertParkedBookmarkState(
        preservation.before,
        checkpoint,
        fixture.expected,
      );
    if (checkpoint.boundary === "parking") {
      assert.deepEqual(checkpoint.load_image.source_files, []);
      assert.ok(
        checkpoint.load_image.mappings.every(
          (row) => row.source_file_index === null,
        ),
      );
    } else assertLinkedPayload(checkpoint.load_image, sourceDigest, fixture);
  }
  if (isBookmarkCancellation(mode)) {
    assert.equal(
      probe.failure.message,
      `Controlled bookmark cancellation after ${boundaries.at(-1)}`,
    );
    assert.deepEqual(
      probe.failure.observation_at_fault,
      preservation.checkpoints.at(-1).load_image,
    );
  }
}
function assertTransactionOwnership(ownership, mode) {
  assert.deepEqual(Object.keys(ownership).sort(), [
    "after_adaptation_active",
    "before_adaptation_active",
    "outcome",
    "policy",
    "script_transaction_observed",
    "setup_finalized",
    "setup_transaction_performed",
    "wrapper_released",
  ]);
  assert.equal(ownership.policy, "exclusive-top-level-v1");
  assert.equal(ownership.script_transaction_observed, true);
  assert.equal(ownership.wrapper_released, true);
  assert.equal(ownership.setup_finalized, true);
  assert.equal(
    ownership.setup_transaction_performed,
    ["split", "journal-multiplicity", "unsupported-data"].includes(mode) ||
      mode.startsWith("bookmarks"),
  );
  const rejected = mode === "active-transaction";
  assert.equal(ownership.before_adaptation_active, rejected);
  assert.equal(ownership.after_adaptation_active, rejected);
  assert.equal(
    ownership.outcome,
    rejected
      ? "rejected-active-transaction"
      : isUnsupportedData(mode)
        ? "unavailable"
        : ["rollback", "original-record-tamper"].includes(mode) ||
            isBookmarkCancellation(mode)
          ? "rolled-back"
          : "committed",
  );
}
function assertActiveTransactionProbe(probe) {
  assert.equal(probe.schema_version, 2);
  assert.equal(probe.mode, "active-transaction");
  assertTransactionOwnership(probe.transaction_ownership, probe.mode);
  for (const key of ["before", "after", "load_image"])
    assert.equal(probe[key], null);
  assert.equal(probe.failure.expected, true);
  assert.equal(probe.failure.kind, "active-transaction");
  assert.equal(probe.failure.marker_emitted, false);
  assert.equal(probe.failure.before_record_present, false);
  const active = probe.active_transaction;
  assert.equal(active.rejected, true);
  assert.equal(active.original_record_present, false);
  assert.equal(active.before_record_present, false);
  assert.equal(active.owned_close_return, true);
  assert.equal(active.final_active, false);
  assertDigest(active.before_sha256);
  assert.equal(active.before_sha256, active.after_sha256);
  assert.deepEqual(active.observations_before, active.observations_after);
  assert.deepEqual(active.observations_before.source_files, []);
  assertJournalEqual(active.label_history_before, active.label_history_after);
  assert.equal(probe.preservation.operational_state_matched, true);
  assert.equal(probe.preservation.before_sha256, active.before_sha256);
  assert.equal(probe.preservation.after_sha256, active.after_sha256);
  assert.equal(probe.preservation.journal_disposition, "unchanged");
  assert.equal(probe.rollback.exercised, false);
  assert.equal(probe.rollback.matched, true);
}
function assertLinkedPayload(observation, sourceDigest, fixture) {
  const expected = fixture.expected;
  assert.equal(observation.source_files.length, 1);
  assert.equal(observation.source_files[0].size, expected.fileBytes);
  for (const kind of ["original_sha256", "modified_sha256"])
    assert.equal(observation.source_files[0][kind], sourceDigest);
  const rows = observation.mappings
    .filter((row) => row.source_file_index !== null)
    .sort((a, b) => Number(BigInt(a.start) - BigInt(b.start)));
  let next = expected.payloadAddress;
  for (const row of rows) {
    assert.equal(Number(BigInt(row.start)), next);
    assert.equal(row.file_offset, 0x800 + next - expected.payloadAddress);
    assert.equal(row.source_file_index, 0);
    assert.equal(row.length, Number(BigInt(row.end)) - next + 1);
    assert.equal(row.initialized, true);
    assert.equal(row.loaded, true);
    assert.equal(row.overlay, false);
    assert.equal(
      row.sha256,
      digest(
        fixture.bytes.subarray(row.file_offset, row.file_offset + row.length),
      ),
    );
    next += row.length;
  }
  assert.equal(next, expected.payloadAddress + expected.payloadBytes);
}
function assertDigest(value) {
  assert.match(value, /^[a-f0-9]{64}$/u);
}
function assertOriginalRecord(record, commitment) {
  assert.deepEqual(Object.keys(record).sort(), [
    "commitment",
    "label_history",
    "operational_state_sha256",
    "schema_version",
    "state_sha256",
  ]);
  assert.equal(record.schema_version, 1);
  assert.deepEqual(record.commitment, commitment);
  assertDigest(record.state_sha256);
  assertDigest(record.operational_state_sha256);
  validateJournal(record.label_history);
}
function inPayload(address, expected) {
  if (!/^0x(?:0|[1-9a-f][a-f0-9]{0,7})$/u.test(address)) return false;
  const value = Number(BigInt(address));
  return (
    value >= expected.payloadAddress &&
    value < expected.payloadAddress + expected.payloadBytes
  );
}
function validateJournal(rows) {
  assert.ok(Array.isArray(rows));
  rows.forEach((row, ordinal) => {
    assert.deepEqual(Object.keys(row).sort(), [
      "action",
      "address",
      "label",
      "modification_time_ms",
      "ordinal",
      "user",
    ]);
    assert.equal(row.ordinal, ordinal);
    assert.equal(typeof row.address, "string");
    assert.ok(row.address.length > 0);
    for (const key of ["label", "user"])
      assert.ok(row[key] === null || typeof row[key] === "string");
    assert.ok(
      Number.isInteger(row.action) && row.action >= -128 && row.action <= 127,
    );
    if (row.modification_time_ms !== null) {
      assert.match(row.modification_time_ms, /^(?:0|-?[1-9][0-9]*)$/u);
      const milliseconds = BigInt(row.modification_time_ms);
      assert.ok(
        milliseconds >= -(1n << 63n) && milliseconds <= (1n << 63n) - 1n,
      );
    }
  });
}
// Independent raw-row oracle: count matching keys and pair each before row with
// the earliest unmatched after ordinal. Retain public arrays without sorting.
function journalDifference(before, after) {
  validateJournal(before);
  validateJournal(after);
  const key = (row) =>
    JSON.stringify([
      row.address,
      row.label,
      row.action,
      row.user,
      row.modification_time_ms,
    ]);
  const available = new Map();
  for (const row of after) {
    const encoded = key(row);
    const candidates = available.get(encoded) ?? [];
    candidates.push(row.ordinal);
    available.set(encoded, candidates);
  }
  const matched = new Set();
  const removed = [];
  for (const row of before) {
    const candidates = available.get(key(row));
    if (candidates?.length) matched.add(candidates.shift());
    else removed.push(row.ordinal);
  }
  return {
    removed,
    added: after
      .filter((row) => !matched.has(row.ordinal))
      .map((row) => row.ordinal),
  };
}
function assertJournalEqual(before, after) {
  assert.deepEqual(journalDifference(before, after), {
    removed: [],
    added: [],
  });
}
