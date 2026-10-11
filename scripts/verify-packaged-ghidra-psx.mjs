#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import {
  access,
  appendFile,
  copyFile,
  mkdir,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  delimiter,
} from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { exec } from "./lib/verify-package-core.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { settlePsxVerification } from "./lib/real-ghidra-psx-instruction-flow.mjs";
import {
  psxPackageResources,
  verifyPackagePack,
} from "./verify-package-pack.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Canonical confinement is required before installation, resource reads or cleanup. */
export async function requirePackageOwnedPath(workspace, path) {
  assert.ok(
    isAbsolute(workspace) && isAbsolute(path),
    "Owned package paths must be absolute",
  );
  const root = await realpath(workspace);
  let current = path;
  const suffix = [];
  for (;;) {
    try {
      current = await realpath(current);
      break;
    } catch (cause) {
      if (cause.code !== "ENOENT") throw cause;
      suffix.unshift(current.slice(dirname(current).length + 1));
      const parent = dirname(current);
      assert.notEqual(parent, current, "Owned path has no existing parent");
      current = parent;
    }
  }
  const canonical = resolve(current, ...suffix);
  const delta = relative(root, canonical);
  assert.ok(
    delta !== "" &&
      delta !== ".." &&
      !delta.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) &&
      !isAbsolute(delta),
    `Package path escapes owned workspace: ${path}`,
  );
  return canonical;
}

/** Inherit tooling, then replace configuration/cache roots and remove module overrides. */
export async function createPsxPackageEnvironment({ workspace, inherited }) {
  const environment = Object.fromEntries(
    Object.entries(inherited).filter(([, value]) => typeof value === "string"),
  );
  for (const key of Object.keys(environment))
    if (/^npm_config_(?:prefix|cache|userconfig|globalconfig)$/iu.test(key))
      delete environment[key];
  for (const key of ["NODE_PATH", "NODE_OPTIONS"]) delete environment[key];
  const roots = {
    HOME: "home",
    XDG_CONFIG_HOME: "config",
    XDG_CACHE_HOME: "cache",
    XDG_DATA_HOME: "data",
    CODEX_HOME: "codex",
    CLAUDE_CONFIG_DIR: "claude",
    TMPDIR: "temporary",
    npm_config_cache: "npm-cache",
  };
  for (const [key, suffix] of Object.entries(roots)) {
    environment[key] = await requirePackageOwnedPath(
      workspace,
      join(workspace, suffix),
    );
    await mkdir(environment[key], { mode: 0o700 });
  }
  environment.npm_config_userconfig = join(workspace, "user.npmrc");
  environment.npm_config_globalconfig = join(workspace, "global.npmrc");
  environment.npm_config_prefix = join(workspace, "prefix");
  await writeFile(environment.npm_config_userconfig, "", { mode: 0o600 });
  await writeFile(environment.npm_config_globalconfig, "", { mode: 0o600 });
  environment.PATH = [dirname(process.execPath), environment.PATH ?? ""].join(
    delimiter,
  );
  environment.REA_LOG_LEVEL = "silent";
  return environment;
}

/** Read exactly the installed resources, prove their bytes, and resolve their Java URL. */
export async function inspectInstalledPsxPackage({
  workspace,
  prefix,
  sourceRoot,
  expectedManifest,
}) {
  await requirePackageOwnedPath(workspace, prefix);
  const packageRoot = await requirePackageOwnedPath(
    workspace,
    join(prefix, "lib/node_modules", expectedManifest.name),
  );
  const manifest = JSON.parse(
    await readFile(join(packageRoot, "package.json"), "utf8"),
  );
  assert.equal(manifest.name, expectedManifest.name);
  assert.equal(manifest.version, expectedManifest.version);
  const cli = join(prefix, "bin/rea");
  assert.equal(
    await realpath(cli),
    join(packageRoot, "scripts/rea.mjs"),
    "Installed CLI resolved outside its package",
  );
  const resources = [];
  for (const path of psxPackageResources) {
    const installed = await requirePackageOwnedPath(
      packageRoot,
      join(packageRoot, path),
    );
    assert.equal(
      installed,
      join(packageRoot, path),
      `Installed resource is an external symlink: ${path}`,
    );
    assert.ok(
      (await stat(installed)).isFile(),
      `Missing packaged resource: ${path}`,
    );
    const sha256 = digest(await readFile(installed));
    assert.equal(
      sha256,
      digest(await readFile(join(sourceRoot, path))),
      `Installed resource differs from packed source: ${path}`,
    );
    resources.push({ path, canonical_path: installed, sha256 });
  }
  const provider = join(packageRoot, "dist/ghidra/GhidraProviderClient.js");
  const javaReference = "../../bridge/ghidra/ReaGhidraBridge.java";
  assert.ok(
    (await readFile(provider, "utf8")).includes(
      `new URL("${javaReference}", import.meta.url)`,
    ),
    "Installed provider omitted its module-relative Java resource binding",
  );
  const javaPath = fileURLToPath(
    new URL(javaReference, pathToFileURL(provider)),
  );
  assert.equal(
    javaPath,
    join(packageRoot, "bridge/ghidra/ReaGhidraBridge.java"),
  );
  return {
    cli,
    package_root: packageRoot,
    name: manifest.name,
    version: manifest.version,
    resources,
    java_resource: javaPath,
  };
}

/** Capture owns streams through EOF independently of supervisor disposal. */
export async function runPackageOwnedCommand({
  executable,
  args,
  cwd,
  environment,
  resources,
  record,
  timeoutMs = 180_000,
}) {
  const { spawnOwnedProviderProcess, ProviderProcessSupervisor } =
    await import("../dist/process/ProviderProcess.js");
  const chunks = { stdout: [], stderr: [] };
  const streamErrors = [];
  let eof = false,
    resolveOutputClose;
  const outputClose = new Promise((resolve) => {
    resolveOutputClose = resolve;
  });
  const launched = await spawnOwnedProviderProcess({
    command: executable,
    arguments: args,
    cwd,
    env: environment,
    hostEnvironment: environment,
    runId: environment.REA_PROCESS_RUN_ID ?? randomUUID(),
    expectedCommand: null,
    observation: { captureStdout: false },
    onAcquired: (child) => {
      for (const name of ["stdout", "stderr"]) {
        child[name]?.on("data", (chunk) =>
          chunks[name].push(Buffer.from(chunk)),
        );
        child[name]?.on("error", (error) =>
          streamErrors.push({ stream: name, error }),
        );
      }
      child.once("close", () => {
        eof = true;
        resolveOutputClose(true);
      });
    },
  });
  // stop() disposes supervisor capture listeners after exit, which can precede
  // stream EOF. This owner alone supplies final output; disable the redundant
  // stdout buffer. The existing supervisor always captures stderr internally.
  const supervisor = new ProviderProcessSupervisor(
    { ...launched, ownsProcessLifetime: true },
    { captureStdout: false },
  );
  const identity = {
    kind: "package-command",
    id: String(launched.ownership.leaderPid),
    cwd,
    ownership: launched.ownership,
  };
  const waitOutput = async () => {
    if (eof) return true;
    let timer;
    try {
      return await Promise.race([
        outputClose,
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(false), timeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  const outcome = {
    failures: [],
    unpersisted_events: [],
    raw_result: undefined,
    settled: false,
    retained_owners: [],
  };
  const capture = async (event) => {
    try {
      await record(event);
      return true;
    } catch (error) {
      outcome.unpersisted_events.push(structuredClone(event));
      outcome.failures.push({
        stage: "capture",
        event_kind: event.kind,
        error,
      });
      return false;
    }
  };
  const snapshot = () => ({
    kind: "raw_result",
    executable,
    argv: args,
    cwd,
    owned_identity: identity,
    stdout: {
      text: Buffer.concat(chunks.stdout).toString("utf8"),
      bytes: chunks.stdout.reduce((n, chunk) => n + chunk.length, 0),
    },
    stderr: {
      text: Buffer.concat(chunks.stderr).toString("utf8"),
      bytes: chunks.stderr.reduce((n, chunk) => n + chunk.length, 0),
    },
    exitCode: launched.process.exitCode,
    signal: launched.process.signalCode,
    capture_complete: eof && streamErrors.length === 0,
    output_closed: eof,
    status_observed:
      launched.process.exitCode !== null ||
      launched.process.signalCode !== null,
    stream_errors: streamErrors.map(({ stream, error }) => ({
      stream,
      ...packageFailure(error),
    })),
  });
  const owner = {
    owner: identity.id,
    identity,
    close: async () => {
      const stopped = await supervisor.stop();
      const closed = await waitOutput();
      assert.notEqual(
        stopped.status,
        "incomplete",
        `Owned package command cleanup incomplete: ${JSON.stringify(stopped)}`,
      );
      assert.equal(closed, true, "Owned package command output EOF incomplete");
      assert.equal(
        streamErrors.length,
        0,
        "Owned package command output capture incomplete",
      );
      assert.ok(
        launched.process.exitCode !== null ||
          launched.process.signalCode !== null,
        "Owned package command final status incomplete",
      );
      outcome.settled = true;
      outcome.retained_owners.length = 0;
      if (outcome.raw_result?.capture_complete === false) {
        outcome.raw_result = snapshot();
        await capture(outcome.raw_result);
      }
    },
  };
  owner.retry = () => owner.close();
  resources.push(owner);
  const invocationRecorded = await capture({
    kind: "invocation",
    executable,
    argv: args,
    cwd,
    owned_identity: identity,
  });
  if (invocationRecorded && !(await waitOutput()))
    outcome.failures.push({
      stage: "primary",
      error: new Error("Owned package command deadline elapsed"),
    });
  try {
    await owner.close();
  } catch (error) {
    outcome.failures.push({ stage: "cleanup", error });
    outcome.retained_owners.push(owner);
  }
  outcome.raw_result = snapshot();
  await capture(outcome.raw_result);
  if (!outcome.raw_result.capture_complete)
    outcome.failures.push({
      stage: "capture",
      error: new Error("Owned package command final capture incomplete"),
    });
  if (
    outcome.raw_result.status_observed &&
    (outcome.raw_result.exitCode !== 0 || outcome.raw_result.signal !== null)
  )
    outcome.failures.push({
      stage: "primary",
      error: new Error(
        `Package command failed: ${outcome.raw_result.stderr.text}`,
      ),
    });
  if (outcome.failures.length > 0) {
    const errors = outcome.failures.map((failure) => failure.error);
    const error = new AggregateError(
      errors,
      outcome.failures.length === 1 && outcome.failures[0].stage === "primary"
        ? errors[0].message
        : "Package command and cleanup failed",
      { cause: errors[0] },
    );
    Object.defineProperty(error, "command_outcome", { value: outcome });
    throw error;
  }
  return {
    stdout: outcome.raw_result.stdout.text,
    stderr: outcome.raw_result.stderr.text,
  };
}

function retainedPublicRoots(outcome) {
  if (!outcome) return [];
  const settlement = outcome.settlement;
  if (
    settlement?.verified_empty_lineage === true &&
    (settlement.remaining_roots?.length ?? 0) === 0
  )
    return [];
  return [
    ...(settlement?.remaining_roots ?? []),
    "public-settlement-unverified",
  ];
}

function packageFailure(error, ancestors = new Set()) {
  if (typeof error !== "object" || error === null)
    return { message: String(error) };
  if (ancestors.has(error))
    return { message: "Circular error reference", circular: true };
  ancestors.add(error);
  const failure = {
    name: error.name ?? "Error",
    message: error.message ?? String(error),
  };
  if (
    ["string", "number", "boolean"].includes(typeof error.code) ||
    error.code === null
  )
    failure.code = error.code;
  if (typeof error.stack === "string") failure.stack = error.stack;
  if (error.cause !== undefined)
    failure.cause = packageFailure(error.cause, ancestors);
  if (error instanceof AggregateError)
    failure.errors = error.errors.map((child) =>
      packageFailure(child, ancestors),
    );
  ancestors.delete(error);
  return failure;
}

/** Final report keeps exact fallback events, never callable owners. */
export function projectPsxPackageSettlement(settled) {
  return {
    ...settled,
    command_outcome:
      settled.command_outcome === undefined
        ? undefined
        : {
            ...settled.command_outcome,
            failures: settled.command_outcome.failures.map(
              ({ error, ...failure }) => ({
                ...failure,
                ...packageFailure(error),
              }),
            ),
            retained_owners: settled.command_outcome.retained_owners.map(
              ({ identity }) => identity,
            ),
          },
    failures: settled.failures.map(({ error, ...failure }) => ({
      ...failure,
      ...packageFailure(error),
    })),
    retained_owners: settled.retained_owners.map(({ identity }) => identity),
  };
}

/** Removal has its own retained authority; child settlement never grants a replacement inode. */
export async function settlePsxPackageWorkspace({
  workspace,
  outcome,
  primary,
  resources = [],
  postchecks = [],
  remove = rm,
}) {
  const canonical = await realpath(workspace);
  const initial = await lstat(workspace);
  assert.equal(
    workspace,
    canonical,
    "Package cleanup requires canonical workspace",
  );
  assert.ok(
    initial.isDirectory() && !initial.isSymbolicLink(),
    "Package cleanup requires an owned directory",
  );
  const owners = [...resources];
  for (const owner of outcome?.settlement?.unresolved_owners ?? [])
    owners.push({
      owner: owner.identity?.id ?? "public-owner",
      identity: owner.identity,
      close: owner.retry ?? owner.close,
    });
  const closed = new Set();
  const guarded = owners.map((owner) => ({
    ...owner,
    close: async () => {
      await owner.close();
      closed.add(owner);
    },
  }));
  const settled = await settlePsxVerification({
    primary,
    resources: guarded,
    postchecks,
  });
  const result = {
    ok: false,
    failures: settled.failures,
    unresolved: [...settled.unresolved, ...retainedPublicRoots(outcome)],
    retained_owners: owners.filter((owner) => !closed.has(owner)),
    workspace_removed: false,
    ...(primary?.command_outcome === undefined
      ? {}
      : { command_outcome: primary.command_outcome }),
  };
  const identity = {
    kind: "package-workspace",
    id: workspace,
    canonical_path: canonical,
    device: String(initial.dev),
    inode: String(initial.ino),
  };
  const workspaceOwner = {
    owner: workspace,
    identity,
    close: async () => {
      for (const owner of owners.filter((owner) => !closed.has(owner))) {
        await owner.close();
        closed.add(owner);
        result.retained_owners = result.retained_owners.filter(
          (retained) => retained !== owner,
        );
        result.unresolved = result.unresolved.filter(
          (id) => id !== owner.owner,
        );
      }
      assert.equal(
        retainedPublicRoots(outcome).length,
        0,
        "Public child settlement remains unverified",
      );
      let current;
      try {
        current = await lstat(workspace);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      if (current) {
        assert.ok(
          current.isDirectory() && !current.isSymbolicLink(),
          "Workspace cleanup authority changed",
        );
        assert.equal(
          await realpath(workspace),
          canonical,
          "Workspace cleanup authority changed",
        );
        assert.equal(
          String(current.dev),
          identity.device,
          "Workspace cleanup device changed",
        );
        assert.equal(
          String(current.ino),
          identity.inode,
          "Workspace cleanup inode changed",
        );
        await remove(workspace, { recursive: true, force: true });
      }
      await assert.rejects(access(workspace), { code: "ENOENT" });
      result.workspace_removed = true;
      result.unresolved = result.unresolved.filter((id) => id !== workspace);
      result.retained_owners = result.retained_owners.filter(
        (owner) => owner !== workspaceOwner,
      );
      result.ok =
        result.failures.length === 0 &&
        result.unresolved.length === 0 &&
        (outcome === undefined || outcome.ok === true);
    },
  };
  workspaceOwner.retry = async () => {
    try {
      await workspaceOwner.close();
    } catch (error) {
      result.failures.push({ stage: "cleanup", owner: workspace, error });
      throw error;
    }
  };
  result.retained_owners.push(workspaceOwner);
  result.unresolved.push(workspace);
  if (
    closed.size === owners.length &&
    retainedPublicRoots(outcome).length === 0
  ) {
    try {
      await workspaceOwner.close();
    } catch (error) {
      result.failures.push({ stage: "cleanup", owner: workspace, error });
    }
  }
  return result;
}

/** All prerequisites precede private workspace/native allocation. */
export async function preflightPackagedPsx(args, environment = process.env) {
  assert.equal(
    args.length,
    0,
    "Usage: node scripts/verify-packaged-ghidra-psx.mjs; no target or prefix accepted",
  );
  assert.ok(
    ["darwin", "linux"].includes(process.platform),
    "Packaged PSX acceptance requires darwin/linux",
  );
  for (const key of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
    assert.ok(
      isAbsolute(environment[key] ?? ""),
      `Explicit absolute ${key} required`,
    );
  assert.equal(
    environment.REA_GHIDRA_NATIVEAOT_JAR,
    undefined,
    "The fixed PSX profile is incompatible with caller-selected NativeAOT extensions; remove that explicit selection before this matrix",
  );
  const { inspectGhidraInstallation } =
    await import("../dist/ghidra/GhidraInstallation.js");
  const { inspectGhidraPsxLoader } =
    await import("../dist/ghidra/GhidraPsxLoader.js");
  const installation = inspectGhidraInstallation({
    installDir: environment.GHIDRA_INSTALL_DIR,
    javaHome: environment.JAVA_HOME,
    environment,
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
    environment.REA_PSX_PACKAGE_PROOF_CAPTURE_DIR ??
    join(repository, "docs/psx-local/phase-5-package-runs");
  assert.ok(isAbsolute(captureParent), "Capture root must be absolute");
  await exec(
    "git",
    ["check-ignore", "--quiet", join(captureParent, "report.json")],
    { cwd: repository },
  );
  return { installation, assets, captureParent };
}

async function repositoryIdentity() {
  const files = [
    ...psxPackageResources,
    "package.json",
    "scripts/verify-package-pack.mjs",
    "scripts/verify-packaged-ghidra-psx.mjs",
    "scripts/lib/real-ghidra-psx-public.mjs",
    "scripts/lib/real-ghidra-psx-instruction-flow.mjs",
    "tests/conformance/ghidra/psx-exe-fixture.mjs",
    "docs/active/phase-5-plan.md",
  ];
  return {
    files: await Promise.all(
      files.map(async (path) => ({
        path,
        sha256: digest(await readFile(join(repository, path))),
      })),
    ),
    head: (
      await exec("git", ["rev-parse", "HEAD"], { cwd: repository })
    ).stdout.trim(),
    diff_sha256: digest(
      (await exec("git", ["diff", "HEAD"], { cwd: repository })).stdout,
    ),
  };
}

async function installMeasuredPackage({
  workspace,
  capture,
  environment,
  report,
  execute,
}) {
  const packed = await verifyPackagePack({
    root: repository,
    workspace,
    environment,
    execute,
  });
  await requirePackageOwnedPath(workspace, packed.tarball);
  report.tarball = {
    path: packed.tarball,
    sha256: digest(await readFile(packed.tarball)),
    files: packed.packedFiles,
  };
  report.tarball.retained_path = join(capture, "verified-package.tgz");
  await copyFile(packed.tarball, report.tarball.retained_path);
  const prefix = environment.npm_config_prefix;
  const npmEntry = process.env.npm_execpath;
  assert.ok(
    typeof npmEntry === "string" && isAbsolute(npmEntry),
    "Run through npm with existing pinned npm_execpath; no npm installation fallback",
  );
  await execute(process.execPath, [
    npmEntry,
    "install",
    "--global",
    "--ignore-scripts",
    "--prefix",
    prefix,
    "--no-audit",
    "--no-fund",
    "--prefer-offline",
    packed.tarball,
  ]);
  const installed = (report.installed = await inspectInstalledPsxPackage({
    workspace,
    prefix,
    sourceRoot: repository,
    expectedManifest: packed.packedManifest,
  }));
  return { installed, packed };
}

async function measureInstalledPublicPsx({
  workspace,
  environment,
  report,
  execute,
  installed,
  packed,
  record,
}) {
  const unrelated = join(workspace, "unrelated cwd ü");
  await mkdir(unrelated, { mode: 0o700 });
  await execute(installed.cli, ["--version"], { cwd: unrelated });
  // Identity import is performed by a child at the exact installed URL, with no resolution fallback.
  const identity = await execute(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const {PRODUCT_IDENTITY}=await import(${JSON.stringify(pathToFileURL(join(installed.package_root, "dist/identity.js")).href)}); console.log(JSON.stringify({root:${JSON.stringify(installed.package_root)},name:PRODUCT_IDENTITY.packageName,version:PRODUCT_IDENTITY.packageVersion}));`,
    ],
    { cwd: unrelated },
  );
  report.loaded_identity = JSON.parse(identity.stdout);
  assert.equal(report.loaded_identity.name, packed.packedManifest.name);
  assert.equal(report.loaded_identity.version, packed.packedManifest.version);
  const publicWorkspace = await realpath(
    await mkdtemp(join(unrelated, "public-")),
  );
  environment.TMPDIR = publicWorkspace;
  assert.deepEqual(await readdir(publicWorkspace), []);
  const { verifyPublicPsx } = await import("./lib/real-ghidra-psx-public.mjs");
  const outcome = await verifyPublicPsx({
    executable: installed.cli,
    prefixArgs: [],
    environment,
    workspace: publicWorkspace,
    record,
  });
  report.public_outcome = outcome;
  return outcome;
}

async function measurePackage(state) {
  const { workspace, capture, report, resources, record } = state;
  state.before = report.code_before = await repositoryIdentity();
  const environment = (state.environment = await createPsxPackageEnvironment({
    workspace,
    inherited: process.env,
  }));
  report.selected_environment = Object.fromEntries(
    [
      "GHIDRA_INSTALL_DIR",
      "JAVA_HOME",
      "HOME",
      "XDG_CONFIG_HOME",
      "XDG_CACHE_HOME",
      "TMPDIR",
      "npm_config_cache",
      "npm_config_userconfig",
      "npm_config_globalconfig",
      "npm_config_prefix",
    ].map((key) => [key, environment[key]]),
  );
  report.module_isolation = {
    NODE_PATH: "removed",
    NODE_OPTIONS: "removed",
    cwd: "owned unrelated directory",
    runtime: process.execPath,
  };
  const execute = (executable, argv, options = {}) =>
    runPackageOwnedCommand({
      executable,
      args: argv,
      cwd: options.cwd ?? workspace,
      environment: options.env ?? environment,
      resources,
      record,
    });
  const { installed, packed } = await installMeasuredPackage({
    workspace,
    capture,
    environment,
    report,
    execute,
  });
  state.installed = installed;
  state.outcome = await measureInstalledPublicPsx({
    workspace,
    environment,
    report,
    execute,
    installed,
    packed,
    record,
  });
  assert.equal(
    state.outcome.ok,
    true,
    "Installed public PSX matrix failed or inconclusive",
  );
}

function packagePostchecks({
  before,
  installed,
  environment,
  workspace,
  report,
  outcome,
  installation,
}) {
  return [
    async () => {
      if (before) {
        report.code_after = await repositoryIdentity();
        assert.deepEqual(
          report.code_after,
          before,
          "Relevant repository code changed during installed measurement",
        );
      }
    },
    async () => {
      const { inspectGhidraPsxLoader } =
        await import("../dist/ghidra/GhidraPsxLoader.js");
      const after = await inspectGhidraPsxLoader(
        installation.installDir,
        installation.providerVersion,
      );
      assert.equal(after.status, "available");
      report.assets_after = after.candidate.asset_inventory_digest;
      assert.equal(
        report.assets_after,
        report.assets_before,
        "Loader assets changed during installed measurement",
      );
    },
    async () => {
      if (installed)
        report.installed_after = await inspectInstalledPsxPackage({
          workspace,
          prefix: environment.npm_config_prefix,
          sourceRoot: repository,
          expectedManifest: installed,
        });
    },
    async () => {
      if (outcome)
        for (const source of outcome.fixture_sources ??
          outcome.fixtures ??
          []) {
          if (source.path && source.sha256)
            assert.equal(
              digest(await readFile(source.path)),
              source.sha256,
              "Synthetic source changed after helper",
            );
        }
    },
  ];
}

export async function main(args = process.argv.slice(2)) {
  const { installation, assets, captureParent } =
    await preflightPackagedPsx(args);
  const run = createVerifierRun();
  await mkdir(captureParent, { recursive: true, mode: 0o700 });
  const capture = await mkdtemp(join(captureParent, "run-"));
  // Module ancestry must also be separate from repository node_modules.
  const workspace = await realpath(
    await mkdtemp(join(await realpath(tmpdir()), "rea-psx-package-")),
  );
  const report = {
    schema_version: 1,
    plan_revision: "P5-R8",
    lane: "ghidra-psx-installed-package",
    evidence_depth: "real-installed-public-cli-mcp",
    mocked: false,
    ok: false,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      ghidra: installation.providerVersion,
      java: { home: installation.javaHome, version: installation.javaVersion },
    },
    capture,
    workspace,
    assets_before: assets.candidate.asset_inventory_digest,
    failures: [],
    limitations: [
      "This host only; no public release, game, Windows or fresh-client acceptance.",
    ],
  };
  const resources = [];
  let primary;
  const state = { workspace, capture, report, resources, installation };
  const record = async (event) =>
    appendFile(join(capture, "events.jsonl"), `${JSON.stringify(event)}\n`, {
      mode: 0o600,
    });
  state.record = record;
  try {
    await measurePackage(state);
  } catch (cause) {
    primary = cause;
  }
  const { outcome } = state;
  const { systemProcessOwnershipHost } =
    await import("../dist/process/ProcessOwnershipObservation.js");
  resources.push({
    owner: "package-process-inspector",
    identity: { kind: "process-inspector", id: "package-process-inspector" },
    close: async () => {
      assert.ok(
        !outcome || outcome.settlement?.verified_empty_lineage === true,
        "Inspector retained while public process settlement is unverified",
      );
      await systemProcessOwnershipHost.close?.();
    },
  });
  const settled = await settlePsxPackageWorkspace({
    workspace,
    outcome,
    primary,
    resources,
    postchecks: packagePostchecks(state),
  });
  report.settlement = projectPsxPackageSettlement(settled);
  Object.defineProperty(report, "retained_resources", {
    value: settled.retained_owners,
  });
  report.verifier_run = await completeVerifierRun(run);
  const lineage = report.verifier_run.process_lineage;
  report.ok =
    settled.ok &&
    outcome?.ok === true &&
    lineage.status === "verified" &&
    lineage.descendants.length === 0;
  await writeFile(
    join(capture, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(
    `${JSON.stringify({ ok: report.ok, capture, settlement: report.settlement, verifier_run: report.verifier_run })}\n`,
  );
  if (!report.ok) process.exitCode = 1;
  return report;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  await main().catch((cause) => {
    process.stderr.write(`${cause.stack ?? cause}\n`);
    process.exitCode = 1;
  });
