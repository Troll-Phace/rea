#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { inspectGhidraPsxLoader } from "../dist/ghidra/GhidraPsxLoader.js";
import {
  publicPsxDigest,
  publicPsxFailure,
  verifyPublicPsx,
} from "./lib/real-ghidra-psx-public.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const exec = promisify(execFile);

/** Read-only runner admission, shared by bounded local smoke. */
export async function preflightPsxPublicRunner(
  args,
  environment = process.env,
  lane = "public",
) {
  assert.deepEqual(
    args,
    [],
    "Usage: node scripts/verify-real-ghidra-psx.mjs; no target or stage options are accepted",
  );
  assert.ok(
    ["darwin", "linux"].includes(process.platform),
    "Requires macOS/Linux",
  );
  for (const name of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
    assert.ok(
      isAbsolute(environment[name] ?? ""),
      `Explicit absolute ${name} required`,
    );
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
    environment[
      lane === "local"
        ? "REA_PSX_LOCAL_PROOF_CAPTURE_DIR"
        : "REA_PSX_PUBLIC_PROOF_CAPTURE_DIR"
    ] ?? join(repository, `docs/psx-local/phase-5-${lane}-runs`);
  assert.ok(isAbsolute(captureParent), "Capture root must be absolute");
  await exec(
    "git",
    ["check-ignore", "--quiet", join(resolve(captureParent), "report.json")],
    { cwd: repository },
  );
  return { installation, assets, captureParent };
}

/** Relevant tree and tracked-diff fingerprints, never raw environment or game bytes. */
export async function fingerprintPsxPublicCode() {
  const files = [];
  const walk = async (directory) => {
    for (const entry of await readdir(join(repository, directory), {
      withFileTypes: true,
    })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (
        entry.isFile() &&
        /\.(?:js|mjs|ts|java|md|json|swift)$/u.test(entry.name)
      )
        files.push({
          path,
          sha256: publicPsxDigest(await readFile(join(repository, path))),
        });
    }
  };
  for (const directory of [
    "src",
    "dist",
    "bridge",
    "scripts",
    "skill-src",
    "skills",
    "tests/conformance/ghidra",
  ])
    await walk(directory);
  for (const path of ["package.json", "docs/active/phase-5-plan.md"])
    files.push({
      path,
      sha256: publicPsxDigest(await readFile(join(repository, path))),
    });
  return {
    files: files.sort((left, right) => left.path.localeCompare(right.path)),
    head: (
      await exec("git", ["rev-parse", "HEAD"], { cwd: repository })
    ).stdout.trim(),
    diff_sha256: publicPsxDigest(
      (
        await exec("git", ["diff", "--binary"], {
          cwd: repository,
          maxBuffer: 16 * 1024 * 1024,
        })
      ).stdout,
    ),
  };
}

/** Reports remain outside disposable workspace. Failures never bypass final persistence. */
export async function runCapturedPsxPublic({
  preflight,
  lane = "public",
  execute = verifyPublicPsx,
  input,
}) {
  await mkdir(preflight.captureParent, { recursive: true, mode: 0o700 });
  const capture = await mkdtemp(join(preflight.captureParent, "run-"));
  const workspace = await realpath(
    await mkdtemp(join(tmpdir(), `rea-psx-${lane}-`)),
  );
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([, value]) => typeof value === "string",
    ),
  );
  Object.assign(environment, {
    GHIDRA_INSTALL_DIR: preflight.installation.installDir,
    JAVA_HOME: preflight.installation.javaHome,
    TMPDIR: workspace,
    HOME: join(workspace, "home"),
    XDG_CONFIG_HOME: join(workspace, "config"),
    XDG_CACHE_HOME: join(workspace, "cache"),
  });
  // These paths are reserved but not created: C1a workspace must be empty at admission.
  const report = {
    schema_version: 1,
    plan_revision: "P5-R7",
    lane: `ghidra-psx-${lane}`,
    mocked: false,
    evidence_depth: "real-public-compiled-cli-and-sdk-stdio-mcp",
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      ghidra: preflight.installation.providerVersion,
      java: {
        home: preflight.installation.javaHome,
        version: preflight.installation.javaVersion,
      },
    },
    selected_environment: Object.fromEntries(
      [
        "GHIDRA_INSTALL_DIR",
        "JAVA_HOME",
        "TMPDIR",
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
      ].map((key) => [key, environment[key]]),
    ),
    installed_assets: { before: preflight.assets.candidate },
    owned_workspace: workspace,
    input,
    limitations: [
      "Static adapted payload; original-loader FileBytes lineage is not established",
      "Runtime execution and overlays are unobserved",
      "Live cache replay does not establish zero provider dispatch",
      "This report establishes only its recorded host and executable",
      "Fresh-client discovery requires its own transcript",
    ],
  };
  let outcome, primary;
  try {
    report.code_before = await fingerprintPsxPublicCode();
    outcome = await execute(
      {
        executable: process.execPath,
        prefixArgs: [join(repository, "scripts/rea.mjs")],
        environment,
        workspace,
        record: async (event) => {
          await writeFile(
            join(capture, "events.jsonl"),
            `${JSON.stringify(event)}\n`,
            { mode: 0o600, flag: "a" },
          );
        },
      },
      input,
    );
  } catch (cause) {
    primary = cause;
  }
  const failures = primary
    ? [{ stage: "primary", ...publicPsxFailure(primary) }]
    : [];
  for (const action of [
    async () => {
      report.code_after = await fingerprintPsxPublicCode();
      assert.deepEqual(
        report.code_after,
        report.code_before,
        "Relevant code/diff changed during run",
      );
    },
    async () => {
      const after = await inspectGhidraPsxLoader(
        preflight.installation.installDir,
        preflight.installation.providerVersion,
      );
      assert.equal(after.status, "available");
      report.installed_assets.after = after.candidate;
      assert.deepEqual(
        after.candidate.assets,
        preflight.assets.candidate.assets,
        "Installed assets changed",
      );
    },
  ])
    try {
      await action();
    } catch (cause) {
      failures.push({ stage: "postcheck", ...publicPsxFailure(cause) });
    }
  report.outcome = outcome;
  report.cleanup = { workspace_removed: false, retained_roots: [] };
  if (
    outcome?.settlement.verified_empty_lineage &&
    outcome.settlement.unresolved_owners.length === 0 &&
    outcome.settlement.remaining_roots.length === 0
  ) {
    try {
      await rm(workspace, { recursive: true });
      report.cleanup.workspace_removed = true;
    } catch (cause) {
      failures.push({ stage: "workspace-cleanup", ...publicPsxFailure(cause) });
      report.cleanup.retained_roots.push(workspace);
    }
  } else report.cleanup.retained_roots.push(workspace);
  report.failures = failures;
  report.ok =
    outcome?.ok === true &&
    failures.length === 0 &&
    report.cleanup.workspace_removed;
  const path = join(capture, "report.json");
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  process.stdout.write(
    `${JSON.stringify({ ok: report.ok, lane: report.lane, report: path, sha256: publicPsxDigest(await readFile(path)) })}\n`,
  );
  // Preserve the exact retry handles on an in-memory returned outcome.
  return { ok: report.ok, path, outcome, report };
}

export async function main(args = process.argv.slice(2)) {
  const preflight = await preflightPsxPublicRunner(args);
  const result = await runCapturedPsxPublic({ preflight });
  if (!result.ok) process.exitCode = 1;
  return result;
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  await main();
