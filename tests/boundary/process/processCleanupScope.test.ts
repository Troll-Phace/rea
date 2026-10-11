import { randomUUID } from "node:crypto";
import { access, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import {
  ProcessCleanupScope,
  registerProcessCleanupOwner,
  withProcessCleanupScope,
} from "../../../src/process/ProcessCleanupScope.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../../../src/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { createDeferred } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const fileOwner = async (name: string) => {
  const root = await createTestTempDirectory("rea-process-receipt-test-");
  const path = join(root, name);
  await writeFile(path, name);
  return {
    path,
    identity: { kind: "controlled-file-generation", runId: randomUUID() },
    close: vi.fn(async () => {
      await rm(path);
      return { settled: true, failures: [] };
    }),
  };
};

it("has no default ownership sink outside an explicitly activated invocation", async () => {
  const owner = await fileOwner("outside");
  expect(registerProcessCleanupOwner(owner)).toBeUndefined();
  expect(owner.close).not.toHaveBeenCalled();
  await expect(access(owner.path)).resolves.toBeUndefined();
});

it("isolates concurrent async invocation descendants and preserves original results", async () => {
  const first = new ProcessCleanupScope();
  const second = new ProcessCleanupScope();
  const firstOwner = await fileOwner("first");
  const secondOwner = await fileOwner("second");
  const ready = createDeferred<void>();
  const release = createDeferred<void>();
  const marker = { caller: "unchanged" };
  const operation = withProcessCleanupScope(first, async () => {
    ready.resolve();
    await release.promise;
    registerProcessCleanupOwner(firstOwner);
    return marker;
  });
  await ready.promise;
  await withProcessCleanupScope(second, async () => {
    registerProcessCleanupOwner(secondOwner);
    release.resolve();
  });
  expect(await operation).toBe(marker);
  expect(first.owners.map(({ identity }) => identity)).toEqual([
    firstOwner.identity,
  ]);
  expect(second.owners.map(({ identity }) => identity)).toEqual([
    secondOwner.identity,
  ]);
  expect(await first.close()).toMatchObject({
    settled: true,
    unresolved: [],
    failures: [],
  });
  await expect(access(firstOwner.path)).rejects.toThrow();
  await expect(access(secondOwner.path)).resolves.toBeUndefined();
  await second.close();
});

it("retains an unresolved callable owner and historical failures after exact retry", async () => {
  const scope = new ProcessCleanupScope();
  const owner = await fileOwner("retry");
  const failure = new Error("controlled removal failure");
  let allowed = false;
  const receipt = scope.register({
    identity: owner.identity,
    close: async () => {
      if (!allowed) throw failure;
      return owner.close();
    },
  });
  const first = await scope.close();
  expect(first).toMatchObject({ settled: false, failures: [failure] });
  expect(first.unresolved).toEqual([receipt]);
  expect(receipt.status).toBe("unresolved");
  await expect(access(owner.path)).resolves.toBeUndefined();
  allowed = true;
  expect(await first.unresolved[0]?.retry()).toMatchObject({
    settled: true,
    failures: [failure],
  });
  expect(await scope.close()).toMatchObject({
    settled: true,
    unresolved: [],
    failures: [failure],
  });
  await expect(access(owner.path)).rejects.toThrow();
  expect(first.unresolved).toEqual([receipt]);
});

it("coalesces terminal settlement and awaits an already active owner close", async () => {
  const scope = new ProcessCleanupScope();
  const owner = await fileOwner("coalesced");
  const entered = createDeferred<void>();
  const release = createDeferred<void>();
  const close = vi.fn(async () => {
    entered.resolve();
    await release.promise;
    return owner.close();
  });
  const receipt = scope.register({ identity: owner.identity, close });
  const active = receipt.close();
  await entered.promise;
  const first = scope.close();
  const concurrent = scope.close();
  expect(first).toBe(concurrent);
  expect(close).toHaveBeenCalledOnce();
  expect(receipt.status).toBe("closing");
  await expect(access(owner.path)).resolves.toBeUndefined();
  release.resolve();
  await active;
  expect(await first).toMatchObject({ settled: true, unresolved: [] });
  expect(close).toHaveBeenCalledOnce();
  await scope.close();
  expect(close).toHaveBeenCalledOnce();
});

it("binds a stronger owner once without replacing generation identity or failure history", async () => {
  const scope = new ProcessCleanupScope();
  const owner = await fileOwner("adopted");
  const failure = new Error("prior captured cleanup failure");
  const originalClose = vi.fn(async () => ({
    settled: false,
    failures: [failure],
  }));
  const receipt = scope.register({
    identity: owner.identity,
    close: originalClose,
  });
  receipt.recordOutcome({ settled: false, failures: [failure] });
  receipt.bindClose(owner.close);
  expect(receipt.identity).toEqual(owner.identity);
  expect(Object.isFrozen(receipt.identity)).toBe(true);
  expect(() => receipt.bindClose(originalClose)).toThrow(/rebound/u);
  expect(await scope.close()).toMatchObject({
    settled: true,
    failures: [failure],
    unresolved: [],
  });
  expect(originalClose).not.toHaveBeenCalled();
  expect(owner.close).toHaveBeenCalledOnce();
});

it("retains all independent failures without losing peers when one close rejects", async () => {
  const scope = new ProcessCleanupScope();
  const first = await fileOwner("rejecting");
  const second = await fileOwner("incomplete");
  const primary = new Error("primary close failure");
  const other = new Error("independent unresolved close");
  const firstReceipt = scope.register({
    identity: first.identity,
    close: async () => {
      throw primary;
    },
  });
  const secondReceipt = scope.register({
    identity: second.identity,
    close: async () => ({ settled: false, failures: [other] }),
  });
  const result = await scope.close();
  expect(result.settled).toBe(false);
  expect(result.unresolved).toEqual([firstReceipt, secondReceipt]);
  expect(result.failures).toEqual([primary, other]);
  await expect(access(first.path)).resolves.toBeUndefined();
  await expect(access(second.path)).resolves.toBeUndefined();
});

it("refuses new registration once terminal settlement begins", async () => {
  const scope = new ProcessCleanupScope();
  await scope.close();
  const owner = await fileOwner("late");
  expect(() => scope.register(owner)).toThrow(/registration is closed/u);
  await expect(access(owner.path)).resolves.toBeUndefined();
  expect(scope.owners).toEqual([]);
});

it("propagates an operation's primary rejection while retaining its acquired owner", async () => {
  const scope = new ProcessCleanupScope();
  const owner = await fileOwner("primary");
  const primary = new Error("caller work failed");
  await expect(
    withProcessCleanupScope(scope, async () => {
      registerProcessCleanupOwner(owner);
      throw primary;
    }),
  ).rejects.toBe(primary);
  expect(owner.close).not.toHaveBeenCalled();
  await scope.close();
  await expect(access(owner.path)).rejects.toThrow();
});

it("adopts a real already-closed child without losing complete output or exact settlement", async () => {
  const scope = new ProcessCleanupScope();
  const launch = await withProcessCleanupScope(scope, () =>
    spawnOwnedProviderProcess({
      command: process.execPath,
      arguments: [
        "-e",
        'process.stdout.write("before-adoption stdout\\n");process.stderr.write("before-adoption stderr\\n")',
      ],
      runId: randomUUID(),
      expectedCommand: null,
      observation: { maxDiagnosticBytes: 4096 },
    }),
  );
  await new Promise<void>((resolve, reject) => {
    launch.process.once("error", reject);
    launch.process.once("close", () => resolve());
  });
  expect(launch.process.exitCode).toBe(0);
  const supervisor = new ProviderProcessSupervisor(
    {
      ...launch,
      ownsProcessLifetime: true,
      cleanup: () => cleanupOwnedProcessGroup(launch.ownership),
    },
    { maxDiagnosticBytes: 4096 },
  );
  try {
    expect(await supervisor.waitForOutputClose(250)).toBe(true);
    expect(supervisor.observation()).toMatchObject({
      coverage: "complete",
      outputClosed: true,
      observedBytes: { stdout: 23, stderr: 23 },
    });
    expect(supervisor.snapshot()).toMatchObject({
      exitCode: 0,
      signal: null,
      stdout: { text: "before-adoption stdout\n", bytes: 23 },
      stderr: { text: "before-adoption stderr\n", bytes: 23 },
    });
    expect(supervisor.snapshot().diagnosticTruncated).not.toBe(true);
    expect(scope.owners).toHaveLength(1);
    expect(await scope.close()).toMatchObject({
      settled: true,
      unresolved: [],
      failures: [],
    });
    expect(scope.owners[0]).toBe(launch.cleanupReceipt);
    expect(scope.owners[0]?.status).toBe("settled");
  } finally {
    await scope.close();
    supervisor.dispose();
  }
}, 10_000);
