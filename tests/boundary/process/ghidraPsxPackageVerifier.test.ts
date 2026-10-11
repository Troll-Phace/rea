import {
  access,
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

type Owner = {
  owner: string;
  identity?: { kind?: string };
  close: () => Promise<void>;
  retry?: () => Promise<void>;
};
type Outcome = {
  ok: boolean;
  settlement: {
    verified_empty_lineage: boolean;
    remaining_roots: string[];
    unresolved_owners: {
      identity: { id: string };
      close: () => Promise<void>;
      retry: () => Promise<void>;
    }[];
  };
};
interface Verifier {
  projectPsxPackageSettlement: (settled: unknown) => unknown;
  requirePackageOwnedPath: (workspace: string, path: string) => Promise<string>;
  createPsxPackageEnvironment: (options: {
    workspace: string;
    inherited: Record<string, string>;
  }) => Promise<Record<string, string>>;
  inspectInstalledPsxPackage: (options: {
    workspace: string;
    prefix: string;
    sourceRoot: string;
    expectedManifest: { name: string; version: string };
  }) => Promise<{ cli: string; java_resource: string; resources: unknown[] }>;
  runPackageOwnedCommand: (options: {
    executable: string;
    args: string[];
    cwd: string;
    environment: Record<string, string>;
    resources: Owner[];
    record: (event: Record<string, unknown>) => Promise<void>;
    timeoutMs?: number;
  }) => Promise<{ stdout: string; stderr: string }>;
  settlePsxPackageWorkspace: (options: {
    workspace: string;
    outcome?: Outcome;
    primary?: Error;
    resources?: Owner[];
    postchecks?: (() => Promise<void>)[];
    remove?: () => Promise<void>;
  }) => Promise<{
    ok: boolean;
    unresolved: string[];
    retained_owners: Owner[];
    workspace_removed: boolean;
    failures: { stage: string; error: Error }[];
  }>;
  preflightPackagedPsx: (
    args: string[],
    environment: Record<string, string>,
  ) => Promise<unknown>;
}
const verifier: Verifier = await import(
  new URL("../../../scripts/verify-packaged-ghidra-psx.mjs", import.meta.url)
    .href
);
const packaging: {
  psxPackageResources: readonly string[];
  assertPsxPackageContents: (paths: string[]) => void;
} = await import(
  new URL("../../../scripts/verify-package-pack.mjs", import.meta.url).href
);

async function installedFixture() {
  const workspace = await createTestTempDirectory("rea-psx-package-");
  const sourceRoot = join(workspace, "source");
  const prefix = join(workspace, "prefix");
  const packageRoot = join(prefix, "lib/node_modules/rea-agents");
  const manifest = { name: "rea-agents", version: "6.3.0" };
  for (const resource of packaging.psxPackageResources) {
    const contents = resource.endsWith("GhidraProviderClient.js")
      ? 'new URL("../../bridge/ghidra/ReaGhidraBridge.java", import.meta.url)'
      : `original resource ${resource}\n`;
    for (const root of [sourceRoot, packageRoot]) {
      await mkdir(dirname(join(root, resource)), { recursive: true });
      await writeFile(join(root, resource), contents);
    }
  }
  await writeFile(join(packageRoot, "package.json"), JSON.stringify(manifest));
  await mkdir(join(prefix, "bin"));
  await symlink(join(packageRoot, "scripts/rea.mjs"), join(prefix, "bin/rea"));
  return {
    workspace,
    sourceRoot,
    prefix,
    packageRoot,
    expectedManifest: manifest,
  };
}

// These failures cross actual filesystem/process boundaries. They attest verifier
// isolation and retained ownership, never a positive native-provider workflow.
it("rejects caller-selected targets and missing explicit provider roots before allocation", async () => {
  await expect(
    verifier.preflightPackagedPsx(["--binary", "/caller/game"], {}),
  ).rejects.toThrow("no target or prefix");
  await expect(verifier.preflightPackagedPsx([], {})).rejects.toThrow(
    "GHIDRA_INSTALL_DIR",
  );
});

it("rejects escaping prefixes and symlink ancestors without modifying their files", async () => {
  const workspace = await createTestTempDirectory("rea-psx-prefix-");
  const external = await createTestTempDirectory("rea-psx-external-");
  const sentinel = join(external, "sentinel");
  await writeFile(sentinel, "caller data");
  await symlink(external, join(workspace, "redirect"));
  await expect(
    verifier.requirePackageOwnedPath(workspace, external),
  ).rejects.toThrow("escapes owned");
  await expect(
    verifier.requirePackageOwnedPath(
      workspace,
      join(workspace, "redirect/new-prefix"),
    ),
  ).rejects.toThrow("escapes owned");
  expect(await readFile(sentinel, "utf8")).toBe("caller data");
});

it("isolates npm configuration and module resolution while preserving caller paths", async () => {
  const workspace = await createTestTempDirectory("rea-psx-environment-");
  const inherited = {
    HOME: "/caller/home",
    NODE_PATH: "/caller/modules",
    NODE_OPTIONS: "--require=/caller/hook",
    npm_config_prefix: "/caller/global",
    npm_config_userconfig: "/caller/npmrc",
    npm_config_registry: "https://registry.example.test",
    npm_config_proxy: "https://proxy.example.test",
    REA_REFERENCE_SECRET_PATTERNS_JSON: '["local"]',
    REA_GHIDRA_NATIVEAOT_JAR: "/caller/selected.jar",
    GHIDRA_INSTALL_DIR: "/provider with spaces",
    JAVA_HOME: "/caller/java",
    PATH: "/usr/bin:/bin",
  };
  const environment = await verifier.createPsxPackageEnvironment({
    workspace,
    inherited,
  });
  expect(environment.NODE_PATH).toBeUndefined();
  expect(environment.NODE_OPTIONS).toBeUndefined();
  expect(environment.npm_config_registry).toBe(inherited.npm_config_registry);
  expect(environment.npm_config_proxy).toBe(inherited.npm_config_proxy);
  expect(environment.REA_REFERENCE_SECRET_PATTERNS_JSON).toBe(
    inherited.REA_REFERENCE_SECRET_PATTERNS_JSON,
  );
  expect(environment.REA_GHIDRA_NATIVEAOT_JAR).toBe(
    inherited.REA_GHIDRA_NATIVEAOT_JAR,
  );
  expect(environment.GHIDRA_INSTALL_DIR).toBe(inherited.GHIDRA_INSTALL_DIR);
  expect(environment.JAVA_HOME).toBe(inherited.JAVA_HOME);
  for (const key of [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "npm_config_cache",
    "npm_config_prefix",
    "npm_config_userconfig",
    "npm_config_globalconfig",
  ])
    expect(environment[key]).toMatch(new RegExp(`^${workspace}/`));
  expect(await readFile(environment.npm_config_userconfig!, "utf8")).toBe("");
  expect(inherited.HOME).toBe("/caller/home");
});

it("binds each installed JS, Java and skill resource to exact source bytes", async () => {
  const fixture = await installedFixture();
  const installed = await verifier.inspectInstalledPsxPackage(fixture);
  expect(installed.resources).toHaveLength(
    packaging.psxPackageResources.length,
  );
  expect(installed.java_resource).toBe(
    join(fixture.packageRoot, "bridge/ghidra/ReaGhidraBridge.java"),
  );
  await writeFile(
    join(fixture.packageRoot, "bridge/ghidra/ReaGhidraPsxImport.java"),
    "contradictory bytes",
  );
  await expect(verifier.inspectInstalledPsxPackage(fixture)).rejects.toThrow(
    "differs from packed source",
  );
});

it("fails missing packaged resources even when the source copy remains available", async () => {
  const fixture = await installedFixture();
  const resource = "bridge/ghidra/ReaGhidraPsxProvenance.java";
  await rm(join(fixture.packageRoot, resource));
  await expect(verifier.inspectInstalledPsxPackage(fixture)).rejects.toThrow();
  expect(await readFile(join(fixture.sourceRoot, resource), "utf8")).toContain(
    "original resource",
  );
});

it("rejects an installed launcher symlink redirected to source checkout", async () => {
  const fixture = await installedFixture();
  await rm(join(fixture.prefix, "bin/rea"));
  await symlink(
    join(fixture.sourceRoot, "scripts/rea.mjs"),
    join(fixture.prefix, "bin/rea"),
  );
  await expect(verifier.inspectInstalledPsxPackage(fixture)).rejects.toThrow(
    "outside its package",
  );
});

it("executes the real dispatcher from unrelated cwd and retains missing-runtime output", async () => {
  const workspace = await createTestTempDirectory("rea-psx-no-fallback-");
  await mkdir(join(workspace, "scripts"));
  await mkdir(join(workspace, "unrelated"));
  await writeFile(
    join(workspace, "package.json"),
    '{"name":"rea-agents","version":"6.3.0","type":"module"}',
  );
  const dispatcher = await readFile(
    new URL("../../../scripts/rea.mjs", import.meta.url),
  );
  await writeFile(join(workspace, "scripts/rea.mjs"), dispatcher);
  const resources: Owner[] = [];
  const events: Record<string, unknown>[] = [];
  const environment = await verifier.createPsxPackageEnvironment({
    workspace,
    inherited: { PATH: process.env.PATH ?? "" },
  });
  await expect(
    verifier.runPackageOwnedCommand({
      executable: process.execPath,
      args: [join(workspace, "scripts/rea.mjs"), "mcp"],
      cwd: join(workspace, "unrelated"),
      environment,
      resources,
      record: async (event) => {
        events.push(event);
      },
    }),
  ).rejects.toThrow("Package command failed");
  const raw = events.find((event) => event.kind === "raw_result");
  expect(raw?.exitCode).toBe(1);
  expect((raw?.stderr as { text: string } | undefined)?.text).toContain(
    "compiled runtime is missing",
  );
  expect(resources).toHaveLength(1);
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    resources,
  });
  expect(settled.workspace_removed).toBe(true);
});

it("rejects a missing resource and private artifacts in the production tar inventory", async () => {
  const resources = packaging.psxPackageResources.map(
    (path) => `package/${path}`,
  );
  expect(() =>
    packaging.assertPsxPackageContents(
      resources.filter((path) => !path.endsWith("ReaGhidraPreparePsx.java")),
    ),
  ).toThrow("omitted");
  for (const artifact of [
    "docs/psx-local/run/report.json",
    "snapshots/private.json",
    "extracted/SLPS_020.20",
    "skill-src/reverse-engineer-anything/SKILL.md",
    "tests/conformance/ghidra/probe.java",
    "ghidra_psx_ldr/PsxLoader.jar",
    "scripts/probe-loader.mjs",
  ])
    expect(() =>
      packaging.assertPsxPackageContents([...resources, `package/${artifact}`]),
    ).toThrow("excluded artifact");
  expect(() =>
    packaging.assertPsxPackageContents([
      ...resources,
      "package/native/windows/build/manifest.json",
    ]),
  ).not.toThrow();
});

it("retains the exact workspace and retry owner when both closes fail", async () => {
  const workspace = await createTestTempDirectory("rea-psx-retained-");
  const sentinel = join(workspace, "sentinel");
  await writeFile(sentinel, "allocated state");
  let attempts = 0;
  const close = async () => {
    attempts++;
    throw new Error("owned close failed");
  };
  const primary = new Error("first semantic contradiction");
  let postcheck = false;
  const owner = { owner: "owned-install", close };
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    primary,
    resources: [owner],
    postchecks: [
      async () => {
        postcheck = true;
      },
    ],
  });
  expect(attempts).toBe(2);
  expect(postcheck).toBe(true);
  expect(settled.ok).toBe(false);
  expect(settled.unresolved).toEqual(["owned-install", workspace]);
  expect(settled.retained_owners[0]).toBe(owner);
  expect(settled.failures[0]?.error).toBe(primary);
  expect(await readFile(sentinel, "utf8")).toBe("allocated state");
});

it("preserves transient close and cleanup failures after a successful close retry", async () => {
  const workspace = await createTestTempDirectory("rea-psx-cleanup-");
  await writeFile(join(workspace, "retained"), "capture");
  let attempts = 0;
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    resources: [
      {
        owner: "retry",
        close: async () => {
          if (++attempts === 1) throw new Error("transient close");
        },
      },
    ],
    remove: async () => {
      throw new Error("prefix removal denied");
    },
  });
  expect(attempts).toBe(2);
  expect(settled.ok).toBe(false);
  expect(settled.failures.map((failure) => failure.stage)).toEqual([
    "close",
    "cleanup",
  ]);
  expect(settled.unresolved).toEqual([workspace]);
  expect(await readFile(join(workspace, "retained"), "utf8")).toBe("capture");
});

it("does not erase public remaining roots even after the retry handle returns", async () => {
  const workspace = await createTestTempDirectory("rea-psx-public-owner-");
  await writeFile(join(workspace, "source"), "immutable");
  let retried = 0;
  const close = async () => {
    retried++;
  };
  const outcome: Outcome = {
    ok: false,
    settlement: {
      verified_empty_lineage: false,
      remaining_roots: [join(workspace, "native")],
      unresolved_owners: [
        { identity: { id: "public-native" }, close, retry: close },
      ],
    },
  };
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    outcome,
  });
  expect(retried).toBe(1);
  expect(settled.ok).toBe(false);
  expect(settled.workspace_removed).toBe(false);
  expect(settled.unresolved).toContain("public-settlement-unverified");
  expect(await readFile(join(workspace, "source"), "utf8")).toBe("immutable");
});

it("preserves capture and cleanup failure together after an actual owned child launch", async () => {
  const workspace = await createTestTempDirectory("rea-psx-command-dual-");
  const environment = await verifier.createPsxPackageEnvironment({
    workspace,
    inherited: { PATH: process.env.PATH ?? "" },
  });
  const captureFailure = Object.assign(
    new Error("durable invocation capture unavailable", {
      cause: new Error("capture permission denied"),
    }),
    { code: "EACCES" },
  );
  const cleanupFailure = Object.assign(
    new Error("first owned stop acknowledgement failed"),
    { code: "CLOSE_ACK" },
  );
  const resources: Owner[] = [];
  const register = resources.push.bind(resources);
  let first = true;
  // The real supervisor still stops the actual child. Fault its acknowledgement
  // once through the retained owner registry to exercise an unreproducible close failure.
  resources.push = (...owners: Owner[]) =>
    register(
      ...owners.map((owner) => {
        const close = owner.close;
        owner.close = async () => {
          await close();
          if (first) {
            first = false;
            throw cleanupFailure;
          }
        };
        return owner;
      }),
    );
  let observed: unknown;
  try {
    await verifier.runPackageOwnedCommand({
      executable: process.execPath,
      args: ["--eval", "setInterval(() => {}, 1000)"],
      cwd: workspace,
      environment,
      resources,
      record: async () => {
        throw captureFailure;
      },
    });
  } catch (cause) {
    observed = cause;
  }
  expect(observed).toBeInstanceOf(AggregateError);
  expect((observed as AggregateError).errors).toContain(captureFailure);
  expect((observed as AggregateError).errors).toContain(cleanupFailure);
  expect((observed as AggregateError).cause).toBe(captureFailure);
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    resources,
    primary: observed as AggregateError,
  });
  expect(settled.ok).toBe(false);
  expect(settled.workspace_removed).toBe(true);
  expect(settled.failures[0]?.error).toBe(observed);
  const capture = await createTestTempDirectory("rea-psx-command-report-");
  const reportPath = join(capture, "report.json");
  await writeFile(
    reportPath,
    JSON.stringify({
      settlement: verifier.projectPsxPackageSettlement(settled),
    }),
  );
  const persisted = JSON.parse(await readFile(reportPath, "utf8"));
  expect(persisted.settlement.failures[0]).toMatchObject({
    stage: "primary",
    name: "AggregateError",
    message: "Package command and cleanup failed",
    cause: {
      name: "Error",
      code: "EACCES",
      message: "durable invocation capture unavailable",
      cause: { message: "capture permission denied" },
    },
  });
});

it("does not resolve a missing installed dependency from the available repository modules", async () => {
  const workspace = await createTestTempDirectory(
    "rea-psx-dependency-fallback-",
  );
  await mkdir(join(workspace, "scripts"));
  await mkdir(join(workspace, "dist"));
  await mkdir(join(workspace, "unrelated"));
  await writeFile(
    join(workspace, "package.json"),
    '{"name":"rea-agents","version":"6.3.0","type":"module"}',
  );
  await writeFile(
    join(workspace, "scripts/rea.mjs"),
    await readFile(new URL("../../../scripts/rea.mjs", import.meta.url)),
  );
  // zod is installed in the checkout. This isolated artifact deliberately lacks it.
  await writeFile(
    join(workspace, "dist/main.js"),
    'import "zod"; export async function runEntrypoint() { console.log("wrong repository fallback"); }',
  );
  const environment = await verifier.createPsxPackageEnvironment({
    workspace,
    inherited: {
      PATH: process.env.PATH ?? "",
      NODE_PATH: new URL("../../../node_modules", import.meta.url).pathname,
    },
  });
  const resources: Owner[] = [];
  const events: Record<string, unknown>[] = [];
  await expect(
    verifier.runPackageOwnedCommand({
      executable: process.execPath,
      args: [join(workspace, "scripts/rea.mjs"), "mcp"],
      cwd: join(workspace, "unrelated"),
      environment,
      resources,
      record: async (event) => {
        events.push(event);
      },
    }),
  ).rejects.toThrow("Package command failed");
  const raw = events.find((event) => event.kind === "raw_result");
  expect((raw?.stderr as { text: string } | undefined)?.text).toContain(
    "ERR_MODULE_NOT_FOUND",
  );
  expect((raw?.stdout as { text: string } | undefined)?.text).not.toContain(
    "wrong repository fallback",
  );
  expect(
    (await verifier.settlePsxPackageWorkspace({ workspace, resources }))
      .workspace_removed,
  ).toBe(true);
});

interface CommandFailure extends AggregateError {
  command_outcome: {
    failures: { stage: string; error: Error }[];
    unpersisted_events: Record<string, unknown>[];
    raw_result: Record<string, unknown>;
    settled: boolean;
    retained_owners: Owner[];
  };
}

async function controlledCommand(
  recordFailure: "invocation" | "raw_result" | "both" | "none",
  timeoutMs?: number,
) {
  const workspace = await createTestTempDirectory("rea-psx-final-capture-");
  const ready = join(workspace, "ready");
  const script = join(workspace, "child.cjs");
  await writeFile(
    script,
    `const fs=require('node:fs');
process.on('SIGTERM',()=>{process.stdout.write('shutdown-out\\n'); process.stderr.write('shutdown-err\\n'); process.exitCode=7; clearInterval(timer)});
process.stdout.write('before-out\\n');process.stderr.write('before-err\\n');fs.writeFileSync(${JSON.stringify(ready)},'ready');
const timer=setInterval(()=>{},1000);`,
  );
  const resources: Owner[] = [];
  const events: Record<string, unknown>[] = [];
  const invocationError = Object.assign(new Error("invocation unavailable"), {
    code: "INVOCATION",
  });
  const rawError = Object.assign(new Error("raw capture unavailable"), {
    code: "RAW",
  });
  let failed: CommandFailure | undefined;
  const options = {
    executable: process.execPath,
    args: [script],
    cwd: workspace,
    environment: { PATH: process.env.PATH ?? "" },
    resources,
    timeoutMs: timeoutMs ?? 2000,
    record: async (event: Record<string, unknown>) => {
      if (event.kind === "invocation") {
        // Readiness is a producer barrier; no timing guess chooses cancellation.
        const deadline = Date.now() + 2000;
        while (true) {
          try {
            await access(ready);
            break;
          } catch {
            if (Date.now() > deadline)
              throw new Error("child readiness deadline");
            await new Promise<void>((resolve) => setImmediate(resolve));
          }
        }
      }
      events.push(structuredClone(event));
      if (
        event.kind === "invocation" &&
        ["invocation", "both"].includes(recordFailure)
      )
        throw invocationError;
      if (
        event.kind === "raw_result" &&
        ["raw_result", "both"].includes(recordFailure)
      )
        throw rawError;
    },
  };
  return {
    workspace,
    resources,
    events,
    options,
    invocationError,
    rawError,
    run: async () => {
      try {
        await verifier.runPackageOwnedCommand(options);
      } catch (error) {
        failed = error as CommandFailure;
      }
      return failed!;
    },
  };
}

it("captures final shutdown streams/status after early invocation persistence fails", async () => {
  const command = await controlledCommand("invocation");
  const failure = await command.run();
  expect(failure.command_outcome.failures).toContainEqual({
    stage: "capture",
    event_kind: "invocation",
    error: command.invocationError,
  });
  const raw = failure.command_outcome.raw_result;
  expect(raw).toMatchObject({
    capture_complete: true,
    output_closed: true,
    status_observed: true,
    exitCode: 7,
    signal: null,
    stdout: { text: "before-out\nshutdown-out\n" },
    stderr: { text: "before-err\nshutdown-err\n" },
  });
  expect(command.events.filter((event) => event.kind === "raw_result")).toEqual(
    [raw],
  );
  expect(failure.command_outcome.unpersisted_events).toEqual([
    command.events[0],
  ]);
  expect(failure.command_outcome.retained_owners).toEqual([]);
  expect(
    (
      await verifier.settlePsxPackageWorkspace({
        workspace: command.workspace,
        resources: command.resources,
        primary: failure,
      })
    ).workspace_removed,
  ).toBe(true);
});

it("retains exact final raw fallback and independent errors when both persistence attempts fail", async () => {
  const command = await controlledCommand("both");
  const failure = await command.run();
  expect(failure.command_outcome.unpersisted_events).toEqual(command.events);
  expect(failure.command_outcome.raw_result).toMatchObject({
    exitCode: 7,
    capture_complete: true,
  });
  expect(failure.command_outcome.failures.map(({ stage }) => stage)).toEqual([
    "capture",
    "capture",
    "primary",
  ]);
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace: command.workspace,
    resources: command.resources,
    primary: failure,
  });
  const persisted = JSON.parse(
    JSON.stringify(verifier.projectPsxPackageSettlement(settled)),
  );
  expect(persisted.command_outcome.unpersisted_events).toEqual(command.events);
  expect(persisted.command_outcome.failures).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ stage: "capture", code: "INVOCATION" }),
      expect.objectContaining({ stage: "capture", code: "RAW" }),
      expect.objectContaining({
        stage: "primary",
        message: expect.stringContaining("Package command failed"),
      }),
    ]),
  );
});

it("takes deadline capture after live owned child shutdown and EOF", async () => {
  const command = await controlledCommand("none", 50);
  const failure = await command.run();
  expect(failure.command_outcome.failures).toContainEqual({
    stage: "primary",
    error: expect.objectContaining({
      message: "Owned package command deadline elapsed",
    }),
  });
  expect(failure.command_outcome.raw_result).toMatchObject({
    exitCode: 7,
    signal: null,
    capture_complete: true,
    stdout: { text: "before-out\nshutdown-out\n" },
    stderr: { text: "before-err\nshutdown-err\n" },
  });
  await verifier.settlePsxPackageWorkspace({
    workspace: command.workspace,
    resources: command.resources,
    primary: failure,
  });
});

it("retains live incomplete output owner, then captures complete output through its retry", async () => {
  const command = await controlledCommand("both", 50);
  const register = command.resources.push.bind(command.resources);
  let block = true;
  command.resources.push = (...owners: Owner[]) =>
    register(
      ...owners.map((owner) => {
        const close = owner.close;
        owner.close = async () => {
          if (block) throw new Error("controlled cleanup blocked");
          await close();
        };
        return owner;
      }),
    );
  const failure = await command.run();
  expect(failure.command_outcome.raw_result).toMatchObject({
    capture_complete: false,
    output_closed: false,
    status_observed: false,
    exitCode: null,
    signal: null,
  });
  expect(failure.command_outcome.failures.map((f) => f.stage)).toEqual([
    "capture",
    "cleanup",
    "capture",
    "capture",
  ]);
  expect(failure.command_outcome.retained_owners).toHaveLength(1);
  block = false;
  await failure.command_outcome.retained_owners[0]!.retry!();
  expect(failure.command_outcome.raw_result).toMatchObject({
    capture_complete: true,
    exitCode: 7,
    stdout: { text: "before-out\nshutdown-out\n" },
  });
  expect(failure.command_outcome.retained_owners).toHaveLength(0);
  expect(
    failure.command_outcome.failures.some((f) => f.stage === "cleanup"),
  ).toBe(true);
  await verifier.settlePsxPackageWorkspace({
    workspace: command.workspace,
    resources: command.resources,
    primary: failure,
  });
});

it("returns a callable workspace removal owner and preserves first failure after actual successful retry", async () => {
  const workspace = await createTestTempDirectory("rea-psx-workspace-retry-");
  let attempts = 0;
  const first = new Error("first removal denied");
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    remove: async () => {
      if (++attempts === 1) throw first;
      await rm(workspace, { recursive: true, force: true });
    },
  });
  expect(settled.retained_owners).toHaveLength(1);
  const owner = settled.retained_owners[0]!;
  expect(owner.identity).toMatchObject({ kind: "package-workspace" });
  await owner.retry!();
  await expect(access(workspace)).rejects.toMatchObject({ code: "ENOENT" });
  expect(settled.workspace_removed).toBe(true);
  expect(settled.retained_owners).toEqual([]);
  expect(settled.unresolved).toEqual([]);
  expect(settled.ok).toBe(false);
  expect(settled.failures[0]?.error).toBe(first);
});

it("workspace retries retain failures and refuse unknown children or replacement directory generations", async () => {
  const workspace = await createTestTempDirectory("rea-psx-generation-");
  let childBlocked = true;
  let removals = 0;
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    resources: [
      {
        owner: "child",
        close: async () => {
          if (childBlocked) throw new Error("child unknown");
        },
      },
    ],
    remove: async () => {
      removals++;
      await rm(workspace, { recursive: true, force: true });
    },
  });
  const owner = settled.retained_owners.find(
    (value) => value.identity?.kind === "package-workspace",
  )!;
  await expect(owner.retry!()).rejects.toThrow("child unknown");
  expect(removals).toBe(0);
  childBlocked = false;
  const old = workspace + "-original";
  await rename(workspace, old);
  await mkdir(workspace);
  await writeFile(join(workspace, "caller"), "unrelated replacement");
  try {
    await expect(owner.retry!()).rejects.toThrow("inode changed");
    expect(removals).toBe(0);
    expect(await readFile(join(workspace, "caller"), "utf8")).toBe(
      "unrelated replacement",
    );
    expect(settled.retained_owners).toContain(owner);
    expect(settled.workspace_removed).toBe(false);
  } finally {
    await rm(old, { recursive: true, force: true });
  }
});

it("preserves deadline primary, raw capture and physical-cleanup acknowledgement errors independently", async () => {
  const command = await controlledCommand("raw_result", 50);
  const register = command.resources.push.bind(command.resources);
  const cleanup = Object.assign(
    new Error("cleanup acknowledgement unavailable"),
    { code: "CLEANUP" },
  );
  let first = true;
  command.resources.push = (...owners: Owner[]) =>
    register(
      ...owners.map((owner) => {
        const close = owner.close;
        owner.close = async () => {
          await close();
          if (first) {
            first = false;
            throw cleanup;
          }
        };
        return owner;
      }),
    );
  const failure = await command.run();
  expect(failure.command_outcome.failures.map((f) => f.stage)).toEqual([
    "primary",
    "cleanup",
    "capture",
    "primary",
  ]);
  expect(failure.command_outcome.failures[1]?.error).toBe(cleanup);
  expect(failure.command_outcome.raw_result).toMatchObject({
    capture_complete: true,
    exitCode: 7,
    signal: null,
  });
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace: command.workspace,
    resources: command.resources,
    primary: failure,
  });
  expect(settled.workspace_removed).toBe(true);
  const report = JSON.parse(
    JSON.stringify(verifier.projectPsxPackageSettlement(settled)),
  );
  expect(report.command_outcome.failures).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ stage: "cleanup", code: "CLEANUP" }),
      expect.objectContaining({ stage: "capture", code: "RAW" }),
      expect.objectContaining({
        stage: "primary",
        message: "Owned package command deadline elapsed",
      }),
    ]),
  );
});

it("workspace retry refuses a replacement symlink and preserves unrelated caller data", async () => {
  const workspace = await createTestTempDirectory("rea-psx-workspace-symlink-");
  const unrelated = await createTestTempDirectory("rea-psx-unrelated-symlink-");
  await writeFile(join(unrelated, "sentinel"), "caller data");
  const settled = await verifier.settlePsxPackageWorkspace({
    workspace,
    remove: async () => {
      throw new Error("initial removal unavailable");
    },
  });
  await rm(workspace, { recursive: true, force: true });
  await symlink(unrelated, workspace);
  await expect(settled.retained_owners[0]!.retry!()).rejects.toThrow(
    "authority changed",
  );
  expect(await readFile(join(unrelated, "sentinel"), "utf8")).toBe(
    "caller data",
  );
  expect(settled.workspace_removed).toBe(false);
  expect(settled.retained_owners).toHaveLength(1);
});
