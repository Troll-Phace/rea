import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  access,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPsxExeFixture } from "../tests/conformance/ghidra/psx-exe-fixture.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { attestPsxLoaderObservations } from "./lib/psx-loader-observations.mjs";
// Development-only synthetic research lane; deliberately accepts no binary input.
const argv = process.argv.slice(2);
let outputDir;
let timeoutMs = 180_000;
for (let index = 0; index < argv.length; index += 2) {
  const [name, value] = argv.slice(index, index + 2);
  if (name === "--output-dir" && outputDir === undefined) outputDir = value;
  else if (name === "--timeout-ms" && /^\d+$/u.test(value ?? ""))
    timeoutMs = Number(value);
  else throw new Error(`Unknown or repeated probe argument: ${name}`);
}
assert.ok(
  isAbsolute(outputDir ?? ""),
  "--output-dir must select an absolute evidence directory",
);
assert.ok(
  Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= 2_147_483_647,
  "Invalid timeout",
);
assert.ok(["darwin", "linux"].includes(process.platform), "Unsupported host");
for (const name of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
  assert.ok(
    isAbsolute(process.env[name] ?? ""),
    `${name} must be explicitly set to an absolute directory`,
  );
const { inspectGhidraInstallation } =
  await import("../dist/ghidra/GhidraInstallation.js");
const { runOwnedCommand, OwnedCommandFailure } =
  await import("../dist/process/OwnedCommand.js");
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
  environment: process.env,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
const { systemProcessOwnershipHost } =
  await import("../dist/process/ProcessOwnershipObservation.js");
const limits = { timeoutMs, diagnosticBytes: 4 * 1024 * 1024 };
const run = createVerifierRun();
await mkdir(outputDir, { recursive: true });
const evidenceDir = await mkdtemp(join(outputDir, "run-"));
const reportPath = join(evidenceDir, "report.json");
const report = {
  schemaVersion: 1,
  status: "failed",
  scope: "synthetic_installed_psx_loader_research",
  installation,
  host: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
  },
  limits,
  evidenceDirectory: evidenceDir,
  imports: [],
  limitations: [
    "Linux is a separate unperformed gate when this report is produced on macOS",
    "No fixture code is executed",
    "No public REA PSX analysis is enabled",
    "User settings/cache/temp are isolated; real user extension roots are inventoried without loading them",
    "Duplicate resolution is not tested by changing a real installation; ambiguous candidates are rejected",
    "Equal mapped-byte hashes are not FileBytes provenance",
    "This defaults-only matrix does not test explicit RAM option transport",
  ],
};
let workspace;
let retainWorkspace = false;
let failure;
const abort = new AbortController();
const cancel = () => abort.abort(new Error("Probe interrupted"));
process.once("SIGINT", cancel);
process.once("SIGTERM", cancel);
const hash = async (path) => {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
};
const exists = async (path) => {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
};
const filesUnder = async (root) => {
  if (!(await exists(root))) return [];
  const paths = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) paths.push(...(await filesUnder(path)));
    else if (entry.isFile()) paths.push(path);
    else
      throw new Error(
        `Unresolved extension inventory entry (symlink or special file): ${path}`,
      );
  }
  return paths.sort();
};
const execute = async (command, arguments_, env) => {
  try {
    return await runOwnedCommand(
      {
        command,
        arguments: arguments_,
        runId: run.run_id,
        expectedCommand: null,
        cwd: workspace,
        env,
        hostEnvironment: process.env,
        platform: process.platform,
        signal: abort.signal,
      },
      limits,
      { signal: abort.signal },
    );
  } catch (error) {
    if (error instanceof OwnedCommandFailure && error.cleanupFailure !== null)
      retainWorkspace = true;
    throw error;
  }
};
const textOutput = (snapshot) =>
  `${snapshot.stdout.text}\n${snapshot.stderr.text}`;
try {
  workspace = await mkdtemp(join(tmpdir(), "rea-psx-loader-probe-"));
  report.ownedWorkspace = workspace;
  const fixturesDir = fileURLToPath(
    new URL("../tests/conformance/ghidra/", import.meta.url),
  );
  const observer = join(fixturesDir, "ReaPsxLoaderContractProbe.java");
  report.observerSha256 = await hash(observer);
  report.verifierSourcesBefore = await Promise.all(
    [
      fileURLToPath(import.meta.url),
      fileURLToPath(
        new URL("./lib/psx-loader-observations.mjs", import.meta.url),
      ),
      join(fixturesDir, "psx-exe-fixture.mjs"),
      observer,
    ].map(async (path) => ({ path, sha256: await hash(path) })),
  );
  const versionedName = `ghidra_${installation.providerVersion}_PUBLIC`;
  const defaultUserRoot =
    process.platform === "darwin"
      ? join(homedir(), "Library", "ghidra", versionedName, "Extensions")
      : join(homedir(), ".config", "ghidra", versionedName, "Extensions");
  const roots = [
    join(installation.installDir, "Ghidra", "Extensions"),
    defaultUserRoot,
  ];
  if (process.env.XDG_CONFIG_HOME && isAbsolute(process.env.XDG_CONFIG_HOME))
    roots.push(
      join(process.env.XDG_CONFIG_HOME, "ghidra", versionedName, "Extensions"),
    );
  report.inventorySearchRoots = [...new Set(roots)];
  const paths = [
    ...new Set(
      (await Promise.all(report.inventorySearchRoots.map(filesUnder))).flat(),
    ),
  ];
  report.assetsBefore = await Promise.all(
    paths.map(async (path) => ({ path, sha256: await hash(path) })),
  );
  report.loaderJarCandidates = [];
  report.analysisCoreAssetsBefore = [
    {
      path: join(
        installation.installDir,
        "Ghidra",
        "Processors",
        "MIPS",
        "lib",
        "MIPS.jar",
      ),
    },
  ];
  for (const asset of report.analysisCoreAssetsBefore)
    asset.sha256 = await hash(asset.path);
  for (const path of paths.filter((value) => value.endsWith(".jar"))) {
    const snapshot = await execute(
      join(installation.javaHome, "bin", "jar"),
      ["--list", "--file", path],
      { JAVA_HOME: installation.javaHome },
    );
    const matchingClasses = snapshot.stdout.text
      .split(/\r?\n/u)
      .filter((value) => /(?:^|\/)PsxLoader\.class$/u.test(value));
    if (matchingClasses.length)
      report.loaderJarCandidates.push({
        path: await realpath(path),
        sha256: await hash(path),
        classes: matchingClasses,
      });
  }
  assert.equal(
    report.loaderJarCandidates.length,
    1,
    "Expected one PsxLoader JAR; reject duplicates",
  );
  assert.deepEqual(
    report.loaderJarCandidates[0].classes,
    ["psx/PsxLoader.class"],
    "Ambiguous loader simple names",
  );
  // Isolate LaunchSupport settings, Java compilation caches, logs and temp files.
  // These explicit overrides are recorded; the inherited environment is never persisted.
  const env = {
    JAVA_HOME: installation.javaHome,
    PATH: `${join(installation.javaHome, "bin")}:${process.env.PATH ?? ""}`,
    _JAVA_OPTIONS: "",
    JDK_JAVA_OPTIONS: "",
    GHIDRA_JAVA_OPTIONS: "",
    XDG_CONFIG_HOME: join(workspace, "config"),
    XDG_CACHE_HOME: join(workspace, "cache"),
    JAVA_TOOL_OPTIONS: `-Dapplication.settingsdir=${join(workspace, "settings")} -Dapplication.cachedir=${join(workspace, "cache")} -Dapplication.tempdir=${join(workspace, "temp")} -Djava.io.tmpdir=${join(workspace, "temp")} -Djava.awt.headless=true`,
  };
  for (const path of [
    env.XDG_CONFIG_HOME,
    env.XDG_CACHE_HOME,
    join(workspace, "settings"),
    join(workspace, "temp"),
  ])
    await mkdir(path);
  report.explicitEnvironmentOverrides = {
    ...env,
    PATH: {
      selectedJavaBin: join(installation.javaHome, "bin"),
      inheritedPathRetained: true,
    },
  };
  const variants = ["baseline", "declared-registers-fill", "trailing-bytes"];
  const fixturePaths = {};
  report.fixtures = [];
  for (const variant of variants) {
    const fixture = buildPsxExeFixture({ variant });
    const path = join(workspace, `${variant}.exe`);
    await writeFile(path, fixture.bytes, { flag: "wx" });
    fixturePaths[variant] = path;
    report.fixtures.push({
      path,
      expected: fixture.expected,
      sha256: await hash(path),
      payloadSha256: createHash("sha256")
        .update(fixture.bytes.subarray(0x800, 0x1000))
        .digest("hex"),
    });
  }
  const cases = [
    { variant: "baseline", mode: "automatic", analysis: false },
    ...variants.flatMap((variant) =>
      [false, true].map((analysis) => ({
        variant,
        mode: "explicit",
        analysis,
      })),
    ),
  ];
  let confirmed;
  for (let index = 0; index < cases.length; index++) {
    const testCase = cases[index];
    const name = `${index}-${testCase.variant}-${testCase.mode}-${testCase.analysis ? "analysis" : "noanalysis"}`;
    const project = join(workspace, name);
    await mkdir(project);
    const beforePath = join(evidenceDir, `${name}-before.json`);
    const afterPath = join(evidenceDir, `${name}-after.json`);
    const fixturePath = fixturePaths[testCase.variant];
    const source = report.fixtures.find((value) => value.path === fixturePath);
    const suppliedOptions =
      testCase.mode === "explicit"
        ? {
            selector: "PsxLoader",
            language: confirmed.language,
            compiler: confirmed.compiler,
          }
        : null;
    const arguments_ = [
      project,
      "PsxFixture",
      "-import",
      fixturePath,
      "-readOnly",
      "-scriptPath",
      fixturesDir,
      ...(testCase.analysis ? [] : ["-noanalysis"]),
      ...(suppliedOptions === null
        ? []
        : [
            "-loader",
            suppliedOptions.selector,
            "-processor",
            suppliedOptions.language,
            "-cspec",
            suppliedOptions.compiler,
          ]),
      "-preScript",
      "ReaPsxLoaderContractProbe.java",
      beforePath,
      fixturePath,
      "before-analysis",
      "-postScript",
      "ReaPsxLoaderContractProbe.java",
      afterPath,
      fixturePath,
      "after-analysis",
      "-deleteProject",
    ];
    const observation = {
      ...testCase,
      optionMode: "loader-defaults",
      command: installation.analyzeHeadlessPath,
      arguments: arguments_,
      suppliedOptions,
      sourceBeforeSha256: await hash(fixturePath),
    };
    report.imports.push(observation);
    let importError;
    try {
      observation.process = await execute(
        installation.analyzeHeadlessPath,
        arguments_,
        env,
      );
    } catch (error) {
      importError = error;
      if (error instanceof OwnedCommandFailure)
        observation.process = error.snapshot;
      observation.failure = {
        message: error.message,
        reason: error.reason ?? null,
        cleanupFailure: error.cleanupFailure ?? null,
        retainedResources: error.resources ?? [],
      };
    } finally {
      // All generated inputs are checked even if import/observation failed.
      observation.sourceAfterSha256 = await hash(fixturePath);
      observation.allSourceHashesAfter = await Promise.all(
        report.fixtures.map(async ({ path, sha256 }) => ({
          path,
          before: sha256,
          after: await hash(path),
        })),
      );
    }
    if (observation.process)
      await writeFile(
        join(evidenceDir, `${name}.log`),
        textOutput(observation.process),
      );
    assert.equal(observation.sourceAfterSha256, source.sha256);
    for (const input of observation.allSourceHashesAfter)
      assert.equal(input.after, input.before);
    if (importError) throw importError;
    Object.assign(
      observation,
      await attestPsxLoaderObservations({
        output: textOutput(observation.process),
        beforePath,
        afterPath,
        fixture: source,
        installation,
        inventory: report.loaderJarCandidates[0],
        installExtensionRoot: report.inventorySearchRoots[0],
        workspace,
      }),
    );
    confirmed ??= {
      language: observation.after.language,
      compiler: observation.after.compiler,
    };
  }
  report.assetsAfter = await Promise.all(
    paths.map(async (path) => ({ path, sha256: await hash(path) })),
  );
  assert.deepEqual(
    report.assetsAfter,
    report.assetsBefore,
    "Extension assets changed",
  );
  assert.equal(
    await hash(observer),
    report.observerSha256,
    "Observer source changed",
  );
  for (const asset of [
    ...report.analysisCoreAssetsBefore,
    ...report.verifierSourcesBefore,
  ])
    assert.equal(await hash(asset.path), asset.sha256);
  report.provenance = {
    fileBytesObserved: report.imports.some(
      ({ after }) => after.fileBytes.length > 0,
    ),
    sourceBackedAttestation: "not_established",
  };
  report.status = "measured";
} catch (error) {
  failure = error;
  report.failure = {
    message: error.message,
    reason: error.reason ?? null,
    cleanupFailure: error.cleanupFailure ?? null,
    retainedResources: error.resources ?? [],
  };
} finally {
  process.removeListener("SIGINT", cancel);
  process.removeListener("SIGTERM", cancel);
  try {
    await systemProcessOwnershipHost.close?.();
    report.nativeInspectorCleanup = "complete";
  } catch (error) {
    failure ??= error;
    report.nativeInspectorCleanup = {
      status: "incomplete",
      error: error.message,
    };
  }
  if (workspace && !retainWorkspace) {
    try {
      await rm(workspace, { recursive: true, force: true });
      assert.equal(await exists(workspace), false);
      report.cleanup = { status: "complete", ownedRootRemoved: workspace };
    } catch (error) {
      failure ??= error;
      report.status = "failed";
      report.cleanup = {
        status: "incomplete",
        retainedRoot: workspace,
        error: error.message,
      };
    }
  } else
    report.cleanup = {
      status: workspace ? "incomplete" : "not_created",
      retainedRoot: workspace ?? null,
    };
  report.runIdentity = await completeVerifierRun(run);
  if (
    report.runIdentity.process_lineage.status !== "verified" ||
    report.runIdentity.process_lineage.descendants.length !== 0
  ) {
    failure ??= new Error("Verifier lineage incomplete");
    report.status = "failed";
  }
  if (failure) report.status = "failed";
  await writeFile(reportPath, JSON.stringify(report, null, 2));
}
console.log(reportPath);
if (failure) {
  console.error(failure.message);
  process.exitCode = 1;
}
