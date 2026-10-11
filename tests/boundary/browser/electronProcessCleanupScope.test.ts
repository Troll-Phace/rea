import { execFile, spawn, type ChildProcess } from "node:child_process";
import { realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { ElectronApplication } from "playwright-core";
import { expect, it, vi } from "vitest";
import { ProviderAdapterError } from "../../../src/domain/providerAdapterError.js";
import { PlaywrightElectronActiveProvider } from "../../../src/browser/PlaywrightElectronActiveProvider.js";
import { electronActiveObservationInputSchema } from "../../../src/domain/javascript/electronActiveObservation.js";
import {
  ProcessCleanupScope,
  withProcessCleanupScope,
} from "../../../src/process/ProcessCleanupScope.js";
import { systemProcessOwnershipHost } from "../../../src/process/ProcessOwnershipObservation.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const execFileAsync = promisify(execFile);

const ownershipDiagnostics = (value: unknown): string =>
  JSON.stringify(value, (_key, item: unknown) =>
    item instanceof Error
      ? { ...item, name: item.name, message: item.message }
      : item,
  );

const observeElectronOwnership = (
  canonicalExecutable: string,
  controls: {
    child: () => ChildProcess | undefined;
    runId: () => string | undefined;
    readable: () => boolean;
    onSignal: () => void;
  },
) => {
  const preparation = vi
    .spyOn(systemProcessOwnershipHost, "prepare")
    .mockResolvedValue();
  const baseline = vi
    .spyOn(systemProcessOwnershipHost, "captureBaseline")
    .mockResolvedValue([]);
  const processes = vi
    .spyOn(systemProcessOwnershipHost, "listProcesses")
    .mockImplementation(async () => {
      const child = controls.child();
      if (child?.pid === undefined) return [];
      let stdout: string;
      try {
        ({ stdout } = await execFileAsync("ps", [
          "-o",
          "pid=,ppid=,pgid=,uid=,stat=",
          "-p",
          String(child.pid),
        ]));
      } catch (cause: unknown) {
        if (
          cause instanceof Error &&
          "code" in cause &&
          cause.code === 1 &&
          "stdout" in cause &&
          cause.stdout === ""
        )
          return [];
        throw cause;
      }
      if (stdout.trim() === "") return [];
      const [pid, parentPid, processGroupId, uid, state] = stdout
        .trim()
        .split(/\s+/u);
      if (state === undefined)
        throw new Error("Actual child process state was malformed");
      return [
        {
          pid: Number(pid),
          parentPid: Number(parentPid),
          processGroupId: Number(processGroupId),
          uid: Number(uid),
          state,
          command: canonicalExecutable,
        },
      ];
    });
  const environment = vi
    .spyOn(systemProcessOwnershipHost, "environment")
    .mockImplementation(async (pid) => {
      expect(pid).toBe(controls.child()?.pid);
      const runId = controls.runId();
      if (runId === undefined)
        throw new Error("Actual launch has no run token");
      return { REA_PROCESS_RUN_ID: runId };
    });
  const identities = vi
    .spyOn(systemProcessOwnershipHost, "processIdentities")
    .mockImplementation(
      async (entries) =>
        new Map(
          entries.map(({ pid }) => [
            pid,
            controls.readable()
              ? {
                  state: "readable" as const,
                  identity: `controlled-start:${String(pid)}`,
                }
              : {
                  state: "unavailable" as const,
                  reason: "controlled identity withheld",
                },
          ]),
        ),
    );
  const tokens = vi
    .spyOn(systemProcessOwnershipHost, "runTokens")
    .mockImplementation(
      async (entries) =>
        new Map(
          entries.map(({ pid }) => [
            pid,
            { state: "readable" as const, runId: controls.runId() },
          ]),
        ),
    );
  const signal = vi
    .spyOn(systemProcessOwnershipHost, "signalGroup")
    .mockImplementation((group, selectedSignal) => {
      controls.onSignal();
      process.kill(-group, selectedSignal);
    });
  return [
    preparation,
    baseline,
    processes,
    environment,
    identities,
    tokens,
    signal,
  ] as const;
};

/** Controlled Playwright transport around an actual detached owned child. */
const electronBoundary = async (
  mode: "observation" | "process" | "transport" | "unknown",
) => {
  const directory = await createTestTempDirectory("rea-electron-receipt-test-");
  const applicationPath = join(directory, "application.js");
  await writeFile(applicationPath, "// controlled application input\n");
  const primary = new Error("controlled Electron observation failure");
  const transportFailure = new Error(
    "controlled Electron transport close failure",
  );
  let child: ChildProcess | undefined;
  let runId: string | undefined;
  let readable = true;
  const canonicalExecutable = await realpath(process.execPath);
  let allowTransport = mode !== "transport";
  let signals = 0;
  const observations = observeElectronOwnership(canonicalExecutable, {
    child: () => child,
    runId: () => runId,
    readable: () => readable,
    onSignal: () => {
      signals += 1;
    },
  });
  const close = vi.fn(async () => {
    if (!allowTransport) throw transportFailure;
  });
  const launch = vi.fn(
    async (
      options: Parameters<typeof import("playwright-core")._electron.launch>[0],
    ) => {
      runId = options?.env?.REA_PROCESS_RUN_ID;
      child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
        detached: true,
        env: { ...process.env, REA_PROCESS_RUN_ID: runId },
        stdio: "ignore",
      });
      await new Promise<void>((resolve, reject) => {
        child?.once("spawn", resolve);
        child?.once("error", reject);
      });
      return {
        process: () => (mode === "unknown" ? { pid: undefined } : child),
        evaluate: async () => {
          // Withhold cleanup observation only after actual acquisition and
          // successful initial token-bound lineage observation.
          if (mode === "process") readable = false;
          throw primary;
        },
        close,
      } as unknown as ElectronApplication;
    },
  );
  const provider = new PlaywrightElectronActiveProvider({}, launch);
  const scope = new ProcessCleanupScope();
  const input = electronActiveObservationInputSchema.parse({
    executable_path: process.execPath,
    application_path: applicationPath,
    application_root: directory,
  });
  return {
    scope,
    primary,
    close,
    launch,
    capture: () =>
      withProcessCleanupScope(scope, () => provider.capture(input)),
    allowProcess: () => {
      readable = true;
    },
    allowTransport: () => {
      allowTransport = true;
    },
    signals: () => signals,
    child: () => child,
    cleanup: async () => {
      readable = true;
      allowTransport = true;
      await scope.close();
      if (
        child !== undefined &&
        child.exitCode === null &&
        child.signalCode === null
      ) {
        const exited = new Promise<void>((resolve) =>
          child?.once("exit", () => resolve()),
        );
        child.kill("SIGKILL");
        await exited;
      }
      for (const spy of observations) spy.mockRestore();
    },
  };
};

it.skipIf(process.platform === "win32")(
  "closes a real acquired application after observation failure without losing its primary outcome",
  async () => {
    const boundary = await electronBoundary("observation");
    try {
      const result = await boundary.capture();
      expect(result.ok).toBe(false);
      if (result.ok)
        throw new Error("controlled observation unexpectedly succeeded");
      expect(
        result.error,
        ownershipDiagnostics({
          error: result.error,
          owners: boundary.scope.owners,
        }),
      ).toBeInstanceOf(ProviderAdapterError);
      expect(result.error.cause).toBe(boundary.primary);
      if (!(result.error instanceof ProviderAdapterError)) throw result.error;
      expect(result.error.diagnostics).toEqual({
        message: boundary.primary.message,
      });
      expect(boundary.scope.owners).toHaveLength(1);
      expect(await boundary.scope.close()).toMatchObject({
        settled: true,
        unresolved: [],
      });
      expect(boundary.close).toHaveBeenCalledOnce();
      expect(
        boundary.child()?.exitCode !== null ||
          boundary.child()?.signalCode !== null,
      ).toBe(true);
    } finally {
      await boundary.cleanup();
    }
  },
);

it.skipIf(process.platform === "win32")(
  "retains process cleanup after transport settles and retries exact lineage without closing transport twice",
  async () => {
    const boundary = await electronBoundary("process");
    try {
      const result = await boundary.capture();
      expect(result.ok).toBe(false);
      const failed = await boundary.scope.close();
      expect(failed.settled).toBe(false);
      expect(failed.unresolved).toHaveLength(1);
      expect(boundary.signals()).toBe(0);
      expect(boundary.close).toHaveBeenCalledOnce();
      boundary.allowProcess();
      const retried = await failed.unresolved[0]?.retry();
      expect(retried, ownershipDiagnostics({ failed, retried })).toMatchObject({
        settled: true,
      });
      expect(await boundary.scope.close()).toMatchObject({
        settled: true,
        unresolved: [],
        failures: expect.any(Array),
      });
      expect(boundary.close).toHaveBeenCalledOnce();
      expect(boundary.signals()).toBeGreaterThan(0);
      expect(failed.failures.length).toBeGreaterThan(0);
    } finally {
      await boundary.cleanup();
    }
  },
);

it.skipIf(process.platform === "win32")(
  "retries failed Playwright transport closure independently of already settled processes",
  async () => {
    const boundary = await electronBoundary("transport");
    try {
      const result = await boundary.capture();
      expect(result.ok).toBe(false);
      const failed = await boundary.scope.close();
      expect(failed.settled).toBe(false);
      const priorSignals = boundary.signals();
      expect(priorSignals).toBeGreaterThan(0);
      boundary.allowTransport();
      const retried = await failed.unresolved[0]?.retry();
      expect(retried, ownershipDiagnostics({ failed, retried })).toMatchObject({
        settled: true,
      });
      expect(boundary.signals()).toBe(priorSignals);
      expect(await boundary.scope.close()).toMatchObject({
        settled: true,
        unresolved: [],
      });
      expect(failed.failures.length).toBeGreaterThan(0);
    } finally {
      await boundary.cleanup();
    }
  },
);

it.skipIf(process.platform === "win32")(
  "retains an application acquired before PID validation and never signals invented ownership",
  async () => {
    const boundary = await electronBoundary("unknown");
    try {
      const result = await boundary.capture();
      expect(result.ok).toBe(false);
      const failed = await boundary.scope.close();
      expect(failed.settled).toBe(false);
      expect(failed.unresolved).toHaveLength(1);
      expect(failed.unresolved[0]?.identity.kind).toBe("electron-application");
      expect(boundary.close).toHaveBeenCalledOnce();
      expect(boundary.signals()).toBe(0);
    } finally {
      await boundary.cleanup();
    }
  },
);
