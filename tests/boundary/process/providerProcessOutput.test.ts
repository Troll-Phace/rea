import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { expect, it, onTestFinished } from "vitest";
import {
  ProviderProcessSupervisor,
  ProviderProcessAcquisitionError,
  acquireProviderProcessObservation,
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type ProviderProcessDiagnostic,
  type ProviderProcessHandle,
} from "../../../src/process/ProviderProcess.js";
import {
  ProcessCleanupScope,
  withProcessCleanupScope,
} from "../../../src/process/ProcessCleanupScope.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../../src/process/OwnedCommand.js";
import {
  spawnProviderProcessFixture,
  stopProviderProcessFixture,
} from "../../fixtures/providerProcess.js";

it("bounds capture before diagnostic callbacks while draining both output streams", async () => {
  const child = spawnProviderProcessFixture("burst", 70_000);
  const diagnostics: ProviderProcessDiagnostic[] = [];
  acquireProviderProcessObservation(child, { maxDiagnosticBytes: 1024 });
  const supervisor = new ProviderProcessSupervisor(
    { process: child, ownsProcessLifetime: true },
    {
      maxDiagnosticBytes: 1024,
      onDiagnostic: (event) => {
        const snapshot = supervisor.snapshot();
        expect(
          snapshot.stdout.bytes + snapshot.stderr.bytes,
        ).toBeLessThanOrEqual(1024);
        diagnostics.push(event);
      },
    },
  );
  try {
    expect(await supervisor.waitForOutputClose(2_000)).toBe(true);
    expect(
      diagnostics.some((event) => event.type === "output" && event.truncated),
    ).toBe(true);
    for (const stream of ["stdout", "stderr"])
      expect(
        diagnostics
          .filter((event) => event.type === "output" && event.stream === stream)
          .at(-1),
      ).toMatchObject({ totalBytes: 70_000 });
  } finally {
    await supervisor.stop();
    await stopProviderProcessFixture(child);
  }
});

/** Publication waits for actual close; acquisition remains synchronous. */
const publishAfterClose = async (options: OwnedProviderProcessSpawnOptions) => {
  let closed: Promise<void> | undefined;
  const launched = await spawnOwnedProviderProcess({
    ...options,
    onAcquired: (child) => {
      onTestFinished(() => stopProviderProcessFixture(child));
      closed = new Promise<void>((resolve) =>
        child.once("close", () => resolve()),
      );
      options.onAcquired?.(child);
    },
  });
  if (closed === undefined) throw new Error("actual child was not acquired");
  await closed;
  return launched;
};

const splitOutputScript = `
const stdout = Buffer.from("out: 雪 / done\\n");
const stderr = Buffer.from("err: 🦊 / end\\n");
process.stdin.once("data", () => {
  process.stdout.write(stdout.subarray(6));
  process.stderr.write(stderr.subarray(6));
  process.stdin.destroy();
});
process.stdout.write(stdout.subarray(0, 6));
process.stderr.write(stderr.subarray(0, 6));
`;

it.each([false, true])(
  "retains exact split UTF-8 after actual close before adoption (scope=%s)",
  async (scoped) => {
    const scope = new ProcessCleanupScope();
    const runId = randomUUID();
    let acquired: ProviderProcessHandle | undefined;
    const totals = { stdout: 0, stderr: 0 };
    let acknowledged = false;
    const operation = async () => {
      const launched = await publishAfterClose({
        command: process.execPath,
        arguments: ["-e", splitOutputScript],
        runId,
        stdin: "pipe",
        onAcquired: (child) => {
          acquired = child;
        },
        observation: {
          onDiagnostic: (event) => {
            if (event.type !== "output") return;
            totals[event.stream] = event.totalBytes;
            if (!acknowledged && totals.stdout >= 6 && totals.stderr >= 6) {
              acknowledged = true;
              acquired?.stdin?.write("continue");
            }
          },
        },
      });
      const receipt = launched.cleanupReceipt;
      expect(launched.process).toBe(acquired);
      expect(scope.owners).toHaveLength(scoped ? 1 : 0);
      if (scoped) {
        expect(scope.owners[0]).toBe(receipt);
        expect(receipt?.identity).toEqual({ kind: "provider-child", runId });
      } else expect(receipt).toBeUndefined();
      // Ghidra projects a fresh launch record after asynchronous ownership publication.
      const supervisor = new ProviderProcessSupervisor({
        process: launched.process,
        ownership: launched.ownership,
        ownsProcessLifetime: true,
      });
      try {
        expect(acknowledged).toBe(true);
        expect(await supervisor.waitForExit(0)).toBe(true);
        expect(await supervisor.waitForOutputClose(0)).toBe(true);
        expect(supervisor.observation()).toMatchObject({
          coverage: "complete",
          outputClosed: true,
          observedBytes: {
            stdout: Buffer.byteLength("out: 雪 / done\n"),
            stderr: Buffer.byteLength("err: 🦊 / end\n"),
          },
          errors: [],
          actualExit: { code: 0, signal: null },
        });
        expect(supervisor.snapshot()).toMatchObject({
          stdout: { text: "out: 雪 / done\n", bytes: totals.stdout },
          stderr: { text: "err: 🦊 / end\n", bytes: totals.stderr },
          exitCode: 0,
          signal: null,
        });
        expect((await supervisor.stop()).status).not.toBe("incomplete");
        if (scoped) {
          expect(scope.owners[0]).toBe(receipt);
          expect(receipt?.status).toBe("settled");
          expect(await scope.close()).toMatchObject({
            settled: true,
            failures: [],
            unresolved: [],
          });
        }
      } finally {
        await supervisor.stop();
        await stopProviderProcessFixture(launched.process);
      }
    };
    if (scoped) await withProcessCleanupScope(scope, operation);
    else await operation();
  },
);

it.each([16, 17])(
  "applies an aggregate budget of 16 bytes before adoption to %s actual bytes",
  async (totalBytes) => {
    const events: ProviderProcessDiagnostic[] = [];
    const launched = await publishAfterClose({
      command: process.execPath,
      arguments: [
        "-e",
        `process.stdout.write("a".repeat(8)); process.stderr.write("b".repeat(${totalBytes - 8}));`,
      ],
      runId: randomUUID(),
      observation: {
        maxDiagnosticBytes: 16,
        onDiagnostic: (event) => events.push(event),
      },
    });
    const beforeAdoption = events.length;
    const adopted: ProviderProcessDiagnostic[] = [];
    const supervisor = new ProviderProcessSupervisor(
      { ...launched, ownsProcessLifetime: true },
      { maxDiagnosticBytes: 16, onDiagnostic: (event) => adopted.push(event) },
    );
    try {
      const snapshot = supervisor.snapshot();
      expect(snapshot.stdout.bytes + snapshot.stderr.bytes).toBe(16);
      expect(snapshot.diagnosticTruncated ?? false).toBe(totalBytes > 16);
      expect(supervisor.observation()).toMatchObject({
        observedBytes: { stdout: 8, stderr: totalBytes - 8 },
        coverage: "complete",
        outputClosed: true,
      });
      expect(events).toHaveLength(beforeAdoption);
      expect(adopted).toEqual([]);
      for (const stream of ["stdout", "stderr"])
        expect(
          events
            .filter(
              (event) => event.type === "output" && event.stream === stream,
            )
            .at(-1),
        ).toMatchObject({
          totalBytes: stream === "stdout" ? 8 : totalBytes - 8,
        });
      expect((await supervisor.stop()).status).not.toBe("incomplete");
    } finally {
      await supervisor.stop();
      await stopProviderProcessFixture(launched.process);
    }
  },
);

it("rejects an incompatible late policy while preserving the actual early observation", async () => {
  const launched = await publishAfterClose({
    command: process.execPath,
    arguments: ["-e", "process.stdout.write('startup');"],
    runId: randomUUID(),
    observation: { maxDiagnosticBytes: 16 },
  });
  expect(
    () =>
      new ProviderProcessSupervisor(
        { ...launched, ownsProcessLifetime: true },
        { maxDiagnosticBytes: 8 },
      ),
  ).toThrow();
  const supervisor = new ProviderProcessSupervisor({
    ...launched,
    ownsProcessLifetime: true,
  });
  try {
    expect(supervisor.snapshot().stdout.text).toBe("startup");
    expect((await supervisor.stop()).status).not.toBe("incomplete");
  } finally {
    await supervisor.stop();
  }
});

it("fails the bounded command contract when overflow happened before publication", async () => {
  const result = await runOwnedCommand(
    {
      command: process.execPath,
      arguments: [
        "-e",
        "process.stdout.write('12345678'); process.stderr.write('abcdefghi');",
      ],
      runId: randomUUID(),
    },
    { timeoutMs: 5_000, diagnosticBytes: 16 },
    { launcher: publishAfterClose },
  ).then(
    () => {
      throw new Error("expected aggregate output-limit failure");
    },
    (cause: unknown) => cause,
  );
  expect(result).toBeInstanceOf(OwnedCommandFailure);
  expect(result).toMatchObject({
    reason: "output-limit",
    cleanupFailure: null,
    snapshot: { diagnosticTruncated: true, exitCode: 0 },
  });
  if (!(result instanceof OwnedCommandFailure) || result.snapshot === null)
    throw new Error("missing retained bounded-command snapshot");
  expect(result.snapshot.stdout.bytes + result.snapshot.stderr.bytes).toBe(16);
});

it("refuses historical completeness for an already closed legacy child", async () => {
  const child = spawn(
    process.execPath,
    [
      "-e",
      "process.stdout.write('lost startup'); process.stderr.write('lost diagnostic');",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  child.stdout?.resume();
  child.stderr?.resume();
  await closed;
  const supervisor = new ProviderProcessSupervisor({
    process: child,
    ownsProcessLifetime: true,
  });
  try {
    expect(supervisor.observation()).toMatchObject({
      coverage: "pre-acquisition-unavailable",
    });
    expect(await supervisor.waitForOutputClose(0)).toBe(false);
    // Exact child cleanup may settle independently of unavailable historical diagnostics.
    expect((await supervisor.stop({ killGraceMs: 0 })).status).not.toBe(
      "incomplete",
    );
  } finally {
    supervisor.dispose();
    await stopProviderProcessFixture(child);
  }
});

it("rejects a bounded caller's complete-output claim from a closed legacy launch", async () => {
  const runId = randomUUID();
  const child = spawn(
    process.execPath,
    ["-e", "process.stdout.write('lost startup');"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  onTestFinished(() => stopProviderProcessFixture(child));
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  child.stdout?.resume();
  child.stderr?.resume();
  await closed;
  const pid = child.pid;
  if (pid === undefined)
    throw new Error("legacy fixture did not acquire a child");
  await expect(
    runOwnedCommand(
      { command: process.execPath, arguments: [], runId },
      { timeoutMs: 5_000, diagnosticBytes: 16 },
      {
        launcher: async () => ({
          process: child,
          ownership: {
            runId,
            leaderPid: pid,
            processGroupId: pid,
            expectedParentPid: process.pid,
          },
        }),
      },
    ),
  ).rejects.toMatchObject({
    reason: "process",
    message: expect.stringContaining("unavailable"),
  });
});

it("settles the exact acquired child after its synchronous acquisition hook throws", async () => {
  const scope = new ProcessCleanupScope();
  const failure = new Error("protocol acquisition rejected");
  let child: ProviderProcessHandle | undefined;
  let closed: Promise<void> | undefined;
  await withProcessCleanupScope(scope, async () => {
    await expect(
      spawnOwnedProviderProcess({
        command: process.execPath,
        arguments: ["-e", "setInterval(() => {}, 1000);"],
        runId: randomUUID(),
        onAcquired: (acquired) => {
          onTestFinished(() => stopProviderProcessFixture(acquired));
          child = acquired;
          closed = new Promise<void>((resolve) =>
            acquired.once("close", () => resolve()),
          );
          throw failure;
        },
      }),
    ).rejects.toBe(failure);
  });
  expect(child).toBeDefined();
  expect(scope.owners).toHaveLength(1);
  await closed;
  expect(child?.exitCode !== null || child?.signalCode !== null).toBe(true);
  expect(await scope.close()).toMatchObject({
    settled: true,
    failures: [],
    unresolved: [],
  });
});

it.skipIf(process.platform === "win32")(
  "retains the exact outside-scope owner after hook failure and POSIX identity refusal",
  async () => {
    const runId = randomUUID();
    const hookFailure = new Error(
      "protocol acquisition rejected outside scope",
    );
    const captureFailure = new Error("boundary-injected stderr read failure");
    let child: ProviderProcessHandle | undefined;
    let closed: Promise<void> | undefined;
    const failure: unknown = await spawnOwnedProviderProcess({
      command: process.execPath,
      arguments: [
        "-e",
        "process.stdin.once('data', () => { process.stdout.write('settled by child\\n'); process.stdin.destroy(); });",
      ],
      runId,
      stdin: "pipe",
      // Refuse signaling this live child through the existing identity check.
      expectedCommand: `${process.execPath}.different-owner`,
      onAcquired: (acquired) => {
        child = acquired;
        onTestFinished(() => stopProviderProcessFixture(acquired));
        closed = new Promise<void>((resolve) =>
          acquired.once("close", () => resolve()),
        );
        // Controlled read failure is separate from native child output.
        acquired.stderr?.emit("error", captureFailure);
        throw hookFailure;
      },
    }).then(
      () => {
        throw new Error("failed acquisition was published");
      },
      (cause: unknown) => cause,
    );
    if (!(failure instanceof ProviderProcessAcquisitionError))
      throw new Error("missing retained acquisition failure", {
        cause: failure,
      });
    const owner = failure.cleanupOwner;
    if (owner === undefined || child === undefined || closed === undefined)
      throw new Error(
        "missing exact acquired owner or actual close observation",
      );
    expect(failure.cause).toBe(hookFailure);
    expect(failure.errors).toContain(hookFailure);
    expect(failure.errors).toContain(captureFailure);
    const cleanupFailure = failure.errors.find(
      (cause: unknown) => cause !== hookFailure && cause !== captureFailure,
    );
    expect(cleanupFailure).toMatchObject({ cleaned: false });
    expect(failure.observation).toMatchObject({
      coverage: "complete",
      errors: [captureFailure],
      outputClosed: false,
    });
    for (const field of ["cleanupOwner", "observation"])
      expect(Object.getOwnPropertyDescriptor(failure, field)?.enumerable).toBe(
        false,
      );
    expect(owner.identity).toEqual({ kind: "provider-child", runId });
    expect(owner.status).toBe("unresolved");
    expect(child.exitCode).toBeNull();
    expect(child.signalCode).toBeNull();
    expect(owner.failures).toContain(cleanupFailure);

    const firstRetry = owner.retry();
    expect(owner.retry()).toBe(firstRetry);
    expect(await firstRetry).toMatchObject({ settled: false });
    expect(failure.cleanupOwner).toBe(owner);
    expect(child.exitCode).toBeNull();
    const retainedFailures = owner.failures;

    child.stdin?.write("settle");
    await closed;
    expect(child.exitCode).toBe(0);
    const finalRetry = owner.retry();
    expect(owner.retry()).toBe(finalRetry);
    expect(await finalRetry).toMatchObject({ settled: true });
    expect(failure.cleanupOwner).toBe(owner);
    expect(owner.status).toBe("settled");
    for (const previous of retainedFailures)
      expect(owner.failures).toContain(previous);
    expect(owner.failures).toContain(captureFailure);
    expect(failure.cause).toBe(hookFailure);
  },
);
