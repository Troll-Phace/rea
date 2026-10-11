#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { inspectGhidraPsxLoader } from "../dist/ghidra/GhidraPsxLoader.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../dist/process/OwnedCommand.js";
import {
  ProviderProcessAcquisitionError,
  spawnOwnedProviderProcess,
} from "../dist/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../dist/process/ProcessOwnership.js";
import { systemProcessOwnershipHost } from "../dist/process/ProcessOwnershipObservation.js";
import { buildPsxExeFixture } from "../tests/conformance/ghidra/psx-exe-fixture.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

export const bookmarkScenarios = Object.freeze([
  "zero",
  "one",
  "multiple",
  "boundaries",
  "adjacent",
  "split",
  "outside",
  "occupied-destination",
  "insufficient-range",
  "overflow",
  "unsupported-manager",
  "unexpected-original",
  "unexpected-parking",
  "cancel-parking",
  "fail-parking",
  "cancel-replacement",
  "fail-replacement",
  "cancel-return",
  "fail-return",
  "commit-finalization",
  "rollback-finalization",
]);
const negativeScenarios = new Set(bookmarkScenarios.slice(7));
const repository = fileURLToPath(new URL("..", import.meta.url));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const failure = (cause, ancestors = new Set()) => {
  if (
    cause !== null &&
    typeof cause === "object" &&
    typeof cause.cleaned === "boolean" &&
    typeof cause.reason === "string"
  )
    return {
      message: cause.reason,
      cleaned: cause.cleaned,
      reason: cause.reason,
    };
  if (!(cause instanceof Error)) return { message: String(cause) };
  if (ancestors.has(cause)) return { message: "Circular error cause" };
  const next = new Set([...ancestors, cause]);
  return {
    name: cause.name,
    message: cause.message,
    ...(cause.code === undefined ? {} : { code: String(cause.code) }),
    ...(cause.cause === undefined ? {} : { cause: failure(cause.cause, next) }),
    ...(cause instanceof AggregateError
      ? { errors: cause.errors.map((e) => failure(e, next)) }
      : {}),
  };
};
const sources = [
  "bridge/ghidra/ReaGhidraPsxImport.java",
  "bridge/ghidra/ReaGhidraPsxProvenance.java",
  "tests/conformance/ghidra/ReaPsxBookmarkPreservationProbe.java",
  "scripts/verify-real-ghidra-psx-bookmarks.mjs",
  "tests/conformance/ghidra/psx-exe-fixture.mjs",
  "scripts/lib/verifier-run.mjs",
  "dist/process/OwnedCommand.js",
  "dist/process/ProviderProcess.js",
  "dist/process/ProcessCleanupScope.js",
  "dist/process/ProcessOwnership.js",
  "dist/process/ProcessOwnershipObservation.js",
  "dist/ghidra/GhidraInstallation.js",
  "dist/ghidra/GhidraPsxLoader.js",
];
async function fingerprint() {
  return Promise.all(
    sources.map(async (path) => ({
      path,
      sha256: digest(await readFile(join(repository, path))),
    })),
  );
}

/** Compare producer evidence; exit status and a completion label alone never prove feasibility. */
export function assertBookmarkProbe(probe, scenario, sourceDigest) {
  assert.ok(
    bookmarkScenarios.includes(scenario),
    "Unknown bookmark feasibility scenario",
  );
  assert.equal(probe.schema_version, 1);
  assert.equal(probe.scenario, scenario);
  assert.equal(
    probe.scope,
    "isolated-synthetic-ProgramDB-bookmark-metadata-feasibility",
  );
  assert.equal(probe.mocked, false);
  assert.equal(probe.ok, true);
  assert.equal(probe.evidence_complete, true);
  assert.equal(probe.owned_program_released, true);
  assert.equal(probe.source.sha256, sourceDigest);
  assert.equal(probe.source.after_sha256, sourceDigest);
  assert.equal(probe.source.file_bytes, 4096);
  assert.equal(probe.actual_import.language_id, "PSX:LE:32:default");
  assert.equal(probe.actual_import.compiler_spec_id, "default");
  assert.equal(probe.actual_import.examined_payload_bytes, 2048);
  assert.equal(
    probe.actual_import.payload_sha256,
    digest(buildPsxExeFixture().bytes.subarray(2048)),
  );
  assert.equal(probe.transaction.finalized, true);
  assert.equal(probe.expected_failure, negativeScenarios.has(scenario));
  assert.equal(probe.transaction.committed, !negativeScenarios.has(scenario));
  assert.deepEqual(
    probe.after.bookmark_identity,
    probe.before.bookmark_identity,
  );
  for (const value of [
    probe.before.complete_enumerated_state,
    probe.after.complete_enumerated_state,
  ]) {
    assert.ok(
      value && typeof value === "object" && !Array.isArray(value),
      "Missing complete producer manifest",
    );
    assert.deepEqual(
      Object.keys(value).sort(),
      [
        "blocks",
        "context",
        "default_context",
        "default_disassembly_context",
        "symbols",
        "label_history",
        "functions",
        "instructions",
        "data",
        "references",
        "entries",
        "bookmarks",
        "comments",
        "property_maps",
        "trees",
        "source_maps",
        "equates",
        "relocations",
      ].sort(),
    );
  }
  assert.deepEqual(
    probe.after.complete_enumerated_state,
    probe.before.complete_enumerated_state,
  );
  assert.equal(
    probe.after.complete_enumerated_state_sha256,
    probe.before.complete_enumerated_state_sha256,
  );
  assert.match(
    probe.before.complete_enumerated_state_sha256,
    /^[a-f0-9]{64}$/u,
  );
  assert.equal(
    probe.before.bookmark_identity.bookmarks.length,
    scenario === "zero"
      ? 0
      : scenario === "one"
        ? 1
        : scenario === "occupied-destination"
          ? 8
          : 7,
  );
  for (const row of probe.before.bookmark_identity.bookmarks) {
    assert.match(row.id, /^\d+$/u);
    assert.equal(typeof row.address, "string");
    assert.equal(Number.isInteger(row.type_id), true);
    for (const key of ["type", "category", "comment"])
      assert.equal(typeof row[key], "string");
  }
  if (negativeScenarios.has(scenario)) {
    assert.ok(probe.failure);
    assert.deepEqual(
      probe.after,
      probe.before,
      "Refusal/rollback changed original full state",
    );
  } else {
    assert.equal(probe.failure, null);
    assert.equal(probe.before.observation.source_files.length, 0);
    assert.equal(probe.after.observation.source_files.length, 1);
    assert.equal(
      probe.after.observation.source_files[0].original_sha256,
      sourceDigest,
    );
    assert.equal(
      probe.after.observation.source_files[0].modified_sha256,
      sourceDigest,
    );
    assert.equal(probe.after.observation.source_files[0].size, 4096);
    assert.equal(
      probe.after.observation.source_files[0].name,
      basename(probe.source.path),
    );
    const fixture = buildPsxExeFixture();
    const payloadMappings = probe.after.observation.mappings.filter(
      (row) => row.source_file_index === 0,
    );
    let next = fixture.expected.payloadAddress;
    for (const row of payloadMappings) {
      assert.equal(row.start, `0x${next.toString(16)}`);
      assert.equal(
        row.file_offset,
        2048 + next - fixture.expected.payloadAddress,
      );
      assert.equal(
        row.sha256,
        digest(
          fixture.bytes.subarray(row.file_offset, row.file_offset + row.length),
        ),
      );
      next += row.length;
    }
    assert.equal(next, fixture.expected.payloadEndInclusive + 1);
    const stripProvenance = (observation) => ({
      ...observation,
      source_files: [],
      mappings: observation.mappings.map((row) =>
        row.source_file_index === 0
          ? { ...row, source_file_index: null, file_offset: null }
          : row,
      ),
    });
    assert.deepEqual(
      stripProvenance(probe.after.observation),
      stripProvenance(probe.before.observation),
      "Unexpected non-provenance observation change",
    );
    const stages = probe.stages.map((row) => row.stage);
    for (const required of [
      "destination-validated",
      "parked",
      "blocks-removed",
      "blocks-replaced",
      "return-validated",
      "returned",
      "committed",
    ])
      assert.ok(stages.includes(required), `Missing ${required} evidence`);
  }
}

/** Acquire the actual child and raw/close observations before awaited launch publication. */
export async function acquireBookmarkProcess(
  owner,
  options,
  launcher = spawnOwnedProviderProcess,
) {
  try {
    owner.launched = await launcher({
      ...options,
      onAcquired(child) {
        assert.equal(
          owner.acquired,
          undefined,
          "Bookmark child already acquired",
        );
        owner.acquired = child;
        owner.closeObserved = false;
        owner.closed = new Promise((resolve) => {
          child.once("close", () => {
            owner.closeObserved = true;
            resolve();
          });
        });
        for (const [index, name] of ["stdout", "stderr"].entries())
          owner.streams[index].bind(child[name]);
        options.onAcquired?.(child);
      },
    });
    assert.equal(
      owner.acquired,
      owner.launched.process,
      "Bookmark launcher did not acquire the published child synchronously",
    );
    return owner.launched;
  } catch (cause) {
    owner.acquisitionFailure = cause;
    if (cause instanceof ProviderProcessAcquisitionError) {
      owner.cleanupOwner = cause.cleanupOwner;
      owner.acquisitionObservation = cause.observation;
    }
    throw cause;
  }
}

/** Retryable native/capture ownership. Retire a handle only after exact process/stream settlement. */
export async function settleBookmarkOwners(owners) {
  const errors = [];
  for (const owner of owners) {
    if (owner.settled) continue;
    let processSettled = owner.acquired === undefined && !owner.launched;
    if (owner.acquisitionFailure)
      errors.push({
        owner: owner.id,
        stage: "acquisition",
        ...failure(owner.acquisitionFailure),
        ...(owner.acquisitionObservation === undefined
          ? {}
          : {
              observation: {
                ...owner.acquisitionObservation,
                errors: owner.acquisitionObservation.errors.map((cause) =>
                  failure(cause),
                ),
              },
            }),
      });
    try {
      const receipt = owner.cleanupOwner ?? owner.launched?.cleanupReceipt;
      if (receipt) {
        const outcome = await receipt.close();
        processSettled = outcome.settled && owner.closeObserved === true;
        for (const cause of outcome.failures)
          errors.push({ owner: owner.id, stage: "process", ...failure(cause) });
        assert.ok(processSettled, "Bookmark acquired child remains unresolved");
      } else if (owner.launched) {
        const result = await (owner.launched.cleanup
          ? owner.launched.cleanup()
          : cleanupOwnedProcessGroup(owner.launched.ownership));
        assert.equal(result.cleaned, true, result.reason);
        processSettled = owner.closeObserved === true;
        assert.ok(
          processSettled,
          "Bookmark child close was not observed; retry retained",
        );
      } else if (owner.acquired) {
        processSettled = owner.closeObserved === true;
        assert.ok(
          processSettled,
          "Bookmark acquisition has no settled cleanup owner",
        );
      }
    } catch (cause) {
      errors.push({ owner: owner.id, stage: "process", ...failure(cause) });
    }
    const streams = await Promise.allSettled(
      owner.streams.map((stream) => stream.settle()),
    );
    for (const result of streams)
      if (result.status === "rejected")
        errors.push({
          owner: owner.id,
          stage: "capture",
          ...failure(result.reason),
        });
    owner.settled =
      processSettled &&
      streams.every((result) => result.status === "fulfilled");
  }
  return {
    errors,
    unresolved_owners: owners
      .filter((owner) => !owner.settled)
      .map((owner) => ({
        id: owner.id,
        ownership: owner.launched?.ownership ?? null,
        cleanup_identity:
          owner.cleanupOwner?.identity ??
          owner.launched?.cleanupReceipt?.identity ??
          null,
      })),
  };
}

export async function createBookmarkWorkspaceOwner(path, filesystem = {}) {
  const host = { lstat, realpath, rm, ...filesystem };
  const canonical = await host.realpath(path),
    initial = await host.lstat(path);
  assert.equal(
    path,
    canonical,
    "Bookmark workspace must be canonical at allocation",
  );
  assert.ok(initial.isDirectory() && !initial.isSymbolicLink());
  const identity = Object.freeze({
    kind: "bookmark-workspace",
    canonical_path: canonical,
    device: String(initial.dev),
    inode: String(initial.ino),
    birthtime_ms: initial.birthtimeMs,
  });
  const owner = {
    identity,
    removed: false,
    async close() {
      let current;
      try {
        current = await host.lstat(path);
      } catch (cause) {
        if (cause.code !== "ENOENT") throw cause;
      }
      if (current) {
        assert.ok(
          current.isDirectory() && !current.isSymbolicLink(),
          "Bookmark workspace replacement/symlink",
        );
        assert.equal(await host.realpath(path), canonical);
        assert.deepEqual(
          {
            device: String(current.dev),
            inode: String(current.ino),
            birthtime_ms: current.birthtimeMs,
          },
          {
            device: identity.device,
            inode: identity.inode,
            birthtime_ms: identity.birthtime_ms,
          },
          "Bookmark workspace generation changed",
        );
        await host.rm(path, { recursive: true, force: true });
      }
      await assert.rejects(host.lstat(path), { code: "ENOENT" });
      owner.removed = true;
    },
  };
  owner.retry = owner.close;
  return owner;
}

/** Complete raw capture keeps failed bytes at their original offsets and retains its actual file lease. */
export async function createBookmarkStreamCapture(
  path,
  abort,
  filesystem = {},
) {
  const host = { open, lstat, realpath, ...filesystem };
  let file = await host.open(path, "wx", 0o600);
  const initial = await file.stat(),
    canonical = await host.realpath(path);
  let pending = Promise.resolve(),
    original,
    ended = true,
    closed = false,
    bytes = 0,
    reported = false;
  const unpersisted = [],
    failures = [];
  const remember = (cause, stage) => {
    original ??= cause;
    failures.push({ stage, ...failure(cause) });
  };
  const writeChunk = async (chunk) => {
    while (chunk.offset < chunk.bytes.length) {
      const written = await file.write(
        chunk.bytes,
        chunk.offset,
        chunk.bytes.length - chunk.offset,
        chunk.position + chunk.offset,
      );
      assert.ok(written.bytesWritten > 0);
      chunk.offset += written.bytesWritten;
    }
  };
  return {
    path,
    bind(stream) {
      ended = stream === null;
      if (stream === null) return;
      stream.on("data", (chunk) => {
        stream.pause();
        const retained = {
          position: bytes,
          bytes: Buffer.from(chunk),
          offset: 0,
        };
        bytes += retained.bytes.length;
        pending = pending
          .then(() => writeChunk(retained))
          .catch((cause) => {
            unpersisted.push(retained);
            remember(cause, "write");
            abort.abort(cause);
          })
          .finally(() => stream.resume());
      });
      stream.once("end", () => {
        ended = true;
      });
      stream.once("error", (cause) => {
        remember(cause, "stream");
        abort.abort(cause);
      });
    },
    async settle() {
      await pending;
      // The first capture failure is reported independently before any recovery.
      if (original && !reported) {
        reported = true;
        throw new Error(
          "Native raw capture failed; retained bytes/file lease require retry",
          { cause: original },
        );
      }
      // A live producer still owns future byte offsets; retain the open file lease.
      assert.equal(
        ended,
        true,
        "Native raw stream did not reach complete end; retry retained",
      );
      if (closed) {
        const named = await host.lstat(path);
        assert.ok(named.isFile() && !named.isSymbolicLink());
        assert.equal(await host.realpath(path), canonical);
        assert.deepEqual(
          { dev: named.dev, ino: named.ino, birthtime_ms: named.birthtimeMs },
          {
            dev: initial.dev,
            ino: initial.ino,
            birthtime_ms: initial.birthtimeMs,
          },
          "Raw capture file generation changed",
        );
        file = await host.open(path, "r+");
        closed = false;
      }
      while (unpersisted.length) {
        await writeChunk(unpersisted[0]);
        unpersisted.shift();
      }
      const errors = [];
      try {
        await file.sync();
      } catch (cause) {
        remember(cause, "sync");
        errors.push(cause);
      }
      try {
        await file.close();
        closed = true;
      } catch (cause) {
        remember(cause, "close");
        errors.push(cause);
      }
      if (errors.length) {
        reported = true;
        throw new AggregateError(
          errors,
          "Raw capture sync/close failed",
          original ? { cause: original } : undefined,
        );
      }
    },
    summary: () => ({
      path,
      bytes,
      complete: ended && closed && original === undefined,
      capture_failures: [...failures],
      unpersisted_events: unpersisted.map((chunk) => ({
        path,
        position: chunk.position + chunk.offset,
        bytes_base64: chunk.bytes.subarray(chunk.offset).toString("base64"),
      })),
      ...(original ? { capture_failure: failure(original) } : {}),
    }),
  };
}

async function retainNativeLogs(workspace, capture) {
  const logs = [];
  const visit = async (directory, relative = "") => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name),
        name = join(relative, entry.name);
      if (entry.isDirectory()) await visit(path, name);
      else if (entry.isFile() && entry.name.endsWith(".log")) {
        const bytes = await readFile(path),
          copy = join(capture, "native-logs", name);
        await mkdir(dirname(copy), { recursive: true, mode: 0o700 });
        await writeFile(copy, bytes, { mode: 0o600, flag: "wx" });
        logs.push({
          owned_path: path,
          capture_path: copy,
          sha256: digest(bytes),
          bytes: bytes.length,
        });
      }
    }
  };
  await visit(workspace);
  return logs;
}

export async function verifyBookmarks() {
  assert.deepEqual(
    process.argv.slice(2),
    [],
    "Usage: node scripts/verify-real-ghidra-psx-bookmarks.mjs (synthetic inputs only)",
  );
  assert.ok(["darwin", "linux"].includes(process.platform));
  for (const key of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
    assert.ok(
      isAbsolute(process.env[key] ?? ""),
      `Explicit absolute ${key} required`,
    );
  const installation = inspectGhidraInstallation({
    installDir: process.env.GHIDRA_INSTALL_DIR,
    javaHome: process.env.JAVA_HOME,
    environment: process.env,
  });
  assert.equal(installation.status, "available", JSON.stringify(installation));
  assert.equal(installation.providerVersion, "12.1.4");
  assert.match(installation.javaVersion, /^25(?:\.|$)/u);
  const assets = await inspectGhidraPsxLoader(
    installation.installDir,
    installation.providerVersion,
  );
  assert.equal(assets.status, "available", JSON.stringify(assets));
  const captureParent =
    process.env.REA_PSX_BOOKMARK_PROOF_CAPTURE_DIR ??
    join(repository, "docs/psx-local/phase-5-bookmark-runs");
  assert.ok(isAbsolute(captureParent));
  await promisify(execFile)(
    "git",
    ["check-ignore", "--quiet", join(captureParent, "report.json")],
    { cwd: repository },
  );
  await mkdir(captureParent, { recursive: true, mode: 0o700 });
  const capture = await mkdtemp(join(captureParent, "run-"));
  const run = createVerifierRun(),
    owners = [],
    abort = new AbortController();
  const cancel = () =>
    abort.abort(new Error("Bookmark verification interrupted"));
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  const report = {
    schema_version: 1,
    plan_revision: "P5-R12",
    lane: "synthetic-bookmark-metadata-feasibility",
    mocked: false,
    run,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      ghidra: installation.providerVersion,
      java: installation.javaVersion,
    },
    selected_environment: {
      GHIDRA_INSTALL_DIR: installation.installDir,
      JAVA_HOME: installation.javaHome,
    },
    provider_assets_before: assets.candidate.asset_inventory_digest,
    cases: [],
    failures: [],
    unverified: [
      "production bookmark integration",
      "loader-seeded metadata restoration (existing Phase3 gate)",
      "AC3",
      "installed package",
      "other host",
      "Ghidra internal finalization failure (caller-boundary injection only)",
    ],
  };
  let workspace, workspaceOwner, primary;
  try {
    report.code_before = await fingerprint();
    workspace = await realpath(
      await mkdtemp(join(tmpdir(), "rea-psx-bookmark-")),
    );
    report.owned_workspace = workspace;
    workspaceOwner = await createBookmarkWorkspaceOwner(workspace);
    report.workspace_identity = workspaceOwner.identity;
    const scripts = join(workspace, "java-scripts"),
      settings = join(workspace, "settings"),
      cache = join(workspace, "cache"),
      temp = join(workspace, "temp");
    for (const directory of [scripts, settings, cache, temp])
      await mkdir(directory, { mode: 0o700 });
    report.script_bundle = [];
    for (const relative of sources.filter((path) => path.endsWith(".java"))) {
      const bytes = await readFile(join(repository, relative)),
        copy = join(scripts, basename(relative));
      await writeFile(copy, bytes, { mode: 0o600, flag: "wx" });
      assert.equal(digest(await readFile(copy)), digest(bytes));
      report.script_bundle.push({
        source: relative,
        copy,
        sha256: digest(bytes),
      });
    }
    const environment = {
      JAVA_HOME: installation.javaHome,
      PATH: `${join(installation.javaHome, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      _JAVA_OPTIONS: "",
      JDK_JAVA_OPTIONS: "",
      GHIDRA_JAVA_OPTIONS: "",
      XDG_CONFIG_HOME: settings,
      XDG_CACHE_HOME: cache,
      JAVA_TOOL_OPTIONS: `-Dapplication.settingsdir=${settings} -Dapplication.cachedir=${cache} -Dapplication.tempdir=${temp} -Djava.io.tmpdir=${temp} -Djava.awt.headless=true`,
    };
    for (const scenario of bookmarkScenarios) {
      if (abort.signal.aborted) throw abort.signal.reason;
      process.stderr.write(`PSX bookmark feasibility: ${scenario}\n`);
      const root = await mkdtemp(join(workspace, `${scenario}-`));
      const fixture = buildPsxExeFixture(),
        original = join(root, "synthetic source 雪.exe"),
        source = join(root, "immutable-snapshot.exe");
      for (const path of [original, source])
        await writeFile(path, fixture.bytes, { mode: 0o600, flag: "wx" });
      const sourceDigest = digest(fixture.bytes),
        project = join(root, "project"),
        output = join(capture, `${scenario}.json`);
      await mkdir(project, { mode: 0o700 });
      const argv = [
        project,
        "PsxBookmarks",
        "-import",
        source,
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
        "-preScript",
        "ReaPsxBookmarkPreservationProbe.java",
        source,
        output,
        scenario,
        sourceDigest,
        "-deleteProject",
      ];
      const measured = {
        scenario,
        source: { path: original, snapshot_path: source, sha256: sourceDigest },
        command: installation.analyzeHeadlessPath,
        arguments: argv,
        output,
      };
      report.cases.push(measured);
      const owner = {
        id: scenario,
        streams: [],
        settled: false,
        launched: null,
        closed: Promise.resolve(),
      };
      owners.push(owner);
      let operation;
      try {
        for (const name of ["stdout", "stderr"])
          owner.streams.push(
            await createBookmarkStreamCapture(
              join(capture, `${scenario}.${name}.log`),
              abort,
            ),
          );
        measured.process = await runOwnedCommand(
          {
            command: installation.analyzeHeadlessPath,
            arguments: argv,
            runId: run.run_id,
            expectedCommand: null,
            cwd: root,
            env: environment,
            hostEnvironment: process.env,
            platform: process.platform,
            signal: abort.signal,
          },
          { timeoutMs: 240000, diagnosticBytes: 4 * 1024 * 1024 },
          {
            signal: abort.signal,
            launcher: (options) => acquireBookmarkProcess(owner, options),
          },
        );
      } catch (cause) {
        operation = cause;
        if (cause instanceof OwnedCommandFailure)
          measured.process = cause.snapshot;
        measured.failure = failure(cause);
      }
      const settled = await settleBookmarkOwners([owner]);
      measured.cleanup = settled;
      measured.raw_streams = owner.streams.map((stream) => stream.summary());
      if (settled.errors.length)
        throw new AggregateError(
          [
            operation,
            ...settled.errors.map((e) => new Error(JSON.stringify(e))),
          ].filter(Boolean),
          "Command and native capture cleanup failed",
        );
      if (operation) throw operation;
      for (const stream of measured.raw_streams)
        assert.equal(stream.complete, true, JSON.stringify(stream));
      assert.notEqual(measured.process.diagnosticTruncated, true);
      await chmod(output, 0o600);
      const probeBytes = await readFile(output);
      measured.output_sha256 = digest(probeBytes);
      const probe = JSON.parse(probeBytes.toString("utf8"));
      assertBookmarkProbe(probe, scenario, sourceDigest);
      assert.ok(
        (
          await readFile(join(capture, `${scenario}.stdout.log`), "utf8")
        ).includes(`REA_PSX_BOOKMARK_PROBE_COMPLETE ${scenario}`),
      );
      for (const path of [original, source])
        assert.equal(digest(await readFile(path)), sourceDigest);
      measured.source.after_sha256 = sourceDigest;
      measured.status = "passed";
    }
  } catch (cause) {
    primary = cause;
    report.failures.push(failure(cause));
  }
  // Postconditions and actual owned cleanup remain independent of the first failure.
  try {
    report.code_after = await fingerprint();
    assert.deepEqual(report.code_after, report.code_before);
    for (const measured of report.cases) {
      for (const path of [measured.source.path, measured.source.snapshot_path])
        assert.equal(digest(await readFile(path)), measured.source.sha256);
      measured.source.after_sha256 = measured.source.sha256;
    }
    for (const entry of report.script_bundle ?? [])
      assert.equal(digest(await readFile(entry.copy)), entry.sha256);
    const afterAssets = await inspectGhidraPsxLoader(
      installation.installDir,
      installation.providerVersion,
    );
    assert.equal(afterAssets.status, "available");
    report.provider_assets_after = afterAssets.candidate.asset_inventory_digest;
    assert.equal(report.provider_assets_after, report.provider_assets_before);
  } catch (cause) {
    report.failures.push(failure(cause));
  }
  report.cleanup = await settleBookmarkOwners(owners);
  report.failures.push(...report.cleanup.errors);
  try {
    if (workspace && report.cleanup.unresolved_owners.length === 0)
      report.native_logs = await retainNativeLogs(workspace, capture);
    if (report.cleanup.unresolved_owners.length === 0)
      await systemProcessOwnershipHost.close?.();
    report.run = await completeVerifierRun(run);
    assert.equal(report.run.process_lineage.status, "verified");
    assert.deepEqual(report.run.process_lineage.descendants, []);
    if (report.cleanup.unresolved_owners.length === 0) {
      if (workspaceOwner) await workspaceOwner.close();
      report.cleanup.workspace_removed =
        workspaceOwner?.removed ?? workspace === undefined;
    }
  } catch (cause) {
    report.failures.push(failure(cause));
  }
  report.cleanup.retained_roots = report.cleanup.workspace_removed
    ? []
    : [workspace].filter(Boolean);
  if (workspaceOwner && !workspaceOwner.removed)
    report.cleanup.unresolved_owners.push(workspaceOwner.identity);
  report.ok =
    primary === undefined &&
    report.failures.length === 0 &&
    report.cases.length === bookmarkScenarios.length &&
    report.cleanup.workspace_removed === true;
  process.removeListener("SIGINT", cancel);
  process.removeListener("SIGTERM", cancel);
  const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`),
    path = join(capture, "report.json");
  let record,
    persisted = false;
  try {
    record = await open(path, "wx", 0o600);
    await record.writeFile(bytes);
    await record.sync();
    await record.close();
    record = undefined;
    persisted = true;
  } catch (cause) {
    report.ok = false;
    report.failures.push({ stage: "report-publication", ...failure(cause) });
  }
  const unpersistedReport = persisted
    ? null
    : `${JSON.stringify(report, null, 2)}\n`;
  return {
    report,
    path: persisted ? path : null,
    attempted_path: path,
    sha256: digest(persisted ? bytes : Buffer.from(unpersistedReport)),
    persisted,
    unpersisted_report: unpersistedReport,
    retryCleanup: async () => {
      if (record) {
        await record.close();
        record = undefined;
      }
      const cleanup = await settleBookmarkOwners(owners);
      if (cleanup.unresolved_owners.length === 0) {
        await systemProcessOwnershipHost.close?.();
        const lineage = await completeVerifierRun(run);
        assert.equal(lineage.process_lineage.status, "verified");
        assert.deepEqual(lineage.process_lineage.descendants, []);
        if (workspaceOwner) await workspaceOwner.close();
        cleanup.workspace_removed =
          workspaceOwner?.removed ?? workspace === undefined;
      }
      return cleanup;
    },
  };
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const outcome = await verifyBookmarks();
  process.stdout.write(
    `${JSON.stringify({ report_path: outcome.path, report_sha256: outcome.sha256, report_persisted: outcome.persisted, ok: outcome.report.ok })}\n`,
  );
  if (!outcome.report.ok) process.exitCode = 1;
}
