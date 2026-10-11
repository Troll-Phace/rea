import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { CliCleanupScope } from "../../../src/composition/CliCleanupScope.js";
import { createCli } from "../../../src/cli.js";
import * as androidComposition from "../../../src/composition/android.js";
import type { AndroidAnalysisPort } from "../../../src/application/android/AndroidAnalysisPort.js";
import { writeOrderedZip } from "../../fixtures/artifactEntryOrder.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import * as binaryComposition from "../../../src/composition/binary.js";
import { createDirectAnalysis } from "../../../src/composition/directAnalysis.js";
import { ProviderAdapterError } from "../../../src/domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { err, ok } from "../../../src/domain/result.js";
import { observed } from "../../fixtures/analysisExecution.js";
import {
  createBinarySessionTargets,
  createDeferred,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";

const cleanupFailure = () =>
  new ProviderCleanupError("fixture", ["owned-client"], {
    reason: "controlled close denied",
  });

it("registers the actual binary session before its first provider allocation", async () => {
  const scope = new CliCleanupScope();
  const register = vi.spyOn(scope, "register");
  const close = vi.fn(async () => ok(null));
  const session = createTestBinarySession(() => {
    expect(register).toHaveBeenCalledWith(session, expect.any(Function));
    return { execute: async () => observed(null), close };
  });
  const factory = vi
    .spyOn(binaryComposition, "createBinarySession")
    .mockReturnValue(session);
  const [target] = await createBinarySessionTargets();
  try {
    await createDirectAnalysis({}, scope).runDirectAnalysis(
      target,
      "binary_overview",
      {},
    );
    expect(factory).toHaveBeenCalledOnce();
    expect(register).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
    expect(await scope.settle()).toMatchObject({
      settled: true,
      unresolved: [],
      failures: [],
    });
    expect(close).toHaveBeenCalledOnce();
  } finally {
    factory.mockRestore();
    register.mockRestore();
    await session.close();
  }
});

it("preserves actual session close arguments and typed failure identity before projection", async () => {
  const scope = new CliCleanupScope();
  const failure = cleanupFailure();
  let allowed = false;
  const argumentsSeen: unknown[] = [];
  const session = createTestBinarySession(() => ({
    execute: async () => observed(null),
    close: async (options) => {
      argumentsSeen.push(options);
      return allowed ? ok(null) : err(failure);
    },
  }));
  const [target] = await createBinarySessionTargets();
  const opened = await session.open(target);
  if (!opened.ok) throw opened.error;
  const owner = scope.register(session, async () => {
    const result = await session.close({ retainProviderDocuments: true });
    return result.ok ? ok(undefined) : result;
  });
  const exactResult = await scope.observe(owner, () =>
    session.close({ retainProviderDocuments: true }),
  );
  expect(exactResult).toEqual(err(failure));
  expect(owner.identity).toBe(session);
  expect(owner.state).toBe("unresolved");
  expect(owner.failures).toEqual([failure]);
  const first = await scope.settle();
  expect(first.settled).toBe(false);
  expect(first.unresolved).toContain(owner);
  expect(first.failures).toContain(failure);
  allowed = true;
  await owner.retry();
  expect(await scope.settle()).toMatchObject({
    settled: true,
    unresolved: [],
    failures: expect.arrayContaining([failure]),
  });
  expect(argumentsSeen).toEqual([
    { retainDocument: true },
    { retainDocument: true },
    { retainDocument: true },
    { retainDocument: true },
  ]);
});

it("retains rejected original close and repeated failures until successful retry", async () => {
  const scope = new CliCleanupScope();
  const identity = {};
  const firstFailure = new Error("first rejected owner close");
  const secondFailure = cleanupFailure();
  let attempt = 0;
  const owner = scope.register(identity, async () => {
    attempt += 1;
    if (attempt === 1) throw firstFailure;
    return attempt <= 3 ? err(secondFailure) : ok(undefined);
  });
  await expect(owner.close()).rejects.toBe(firstFailure);
  const failed = await scope.settle();
  expect(failed).toMatchObject({
    settled: false,
    unresolved: [owner],
    failures: [firstFailure, secondFailure, secondFailure],
  });
  const retried = await scope.settle();
  expect(retried).toMatchObject({
    settled: true,
    unresolved: [],
    failures: [firstFailure, secondFailure, secondFailure],
  });
  expect(owner.identity).toBe(identity);
  expect(failed.failures).toEqual([firstFailure, secondFailure, secondFailure]);
});

it("coalesces terminal settlement while an observed original close is pending", async () => {
  const scope = new CliCleanupScope();
  const entered = createDeferred<void>();
  const release = createDeferred<void>();
  const close = vi.fn(async () => {
    entered.resolve();
    await release.promise;
    return ok(undefined);
  });
  const owner = scope.register({}, close);
  const active = owner.close();
  await entered.promise;
  const first = scope.settle();
  const second = scope.settle();
  expect(first).toBe(second);
  expect(owner.state).toBe("closing");
  expect(close).toHaveBeenCalledOnce();
  release.resolve();
  await active;
  expect(await first).toMatchObject({
    settled: true,
    failures: [],
    unresolved: [],
  });
  expect(close).toHaveBeenCalledOnce();
});

it("retains a status-command close failure even though status output succeeds", async () => {
  const scope = new CliCleanupScope();
  const session = createTestBinarySession(() => ({
    execute: async () => observed(null),
    close: async () => ok(null),
  }));
  const failure = cleanupFailure();
  let allowed = false;
  const original = session.close.bind(session);
  const close = vi
    .spyOn(session, "close")
    .mockImplementation(async (...args) =>
      allowed ? original(...args) : err(failure),
    );
  const factory = vi
    .spyOn(binaryComposition, "createBinarySession")
    .mockReturnValue(session);
  try {
    const output = await createDirectAnalysis({}, scope).runSessionStatus();
    expect(output).toHaveProperty("server_identity");
    const failed = await scope.settle();
    expect(failed.settled).toBe(false);
    expect(failed.failures).toContain(failure);
    expect(failed.unresolved[0]?.identity).toBe(session);
    allowed = true;
    expect(await scope.settle()).toMatchObject({
      settled: true,
      failures: expect.arrayContaining([failure]),
    });
  } finally {
    factory.mockRestore();
    close.mockRestore();
    await original();
  }
});

it("keeps the producing analysis failure and its retained cleanup owner after public projection", async () => {
  const scope = new CliCleanupScope();
  const primary = new ProviderAdapterError("fixture", "binary_overview", {
    userMessage: "controlled analysis failure",
  });
  const cleanup = cleanupFailure();
  let allowed = false;
  const session = createTestBinarySession(() => ({
    execute: async () => err(primary),
    close: async () => (allowed ? ok(null) : err(cleanup)),
  }));
  const factory = vi
    .spyOn(binaryComposition, "createBinarySession")
    .mockReturnValue(session);
  const [target] = await createBinarySessionTargets();
  try {
    const output = await createDirectAnalysis({}, scope).runDirectAnalysis(
      target,
      "binary_overview",
      {},
    );
    expect(output).toMatchObject({
      code: "cleanup_incomplete",
      message: "controlled analysis failure",
    });
    const receipt = await scope.settle();
    expect(receipt.settled).toBe(false);
    expect(receipt.failures).toContain(cleanup);
    expect(receipt.unresolved[0]?.identity).toBe(session);
    allowed = true;
    expect(await scope.settle()).toMatchObject({
      settled: true,
      failures: expect.arrayContaining([cleanup]),
    });
    expect(output).toMatchObject({
      code: "cleanup_incomplete",
      message: "controlled analysis failure",
    });
  } finally {
    allowed = true;
    factory.mockRestore();
    await session.close();
  }
});

it.each(["execute-rejection", "close-rejection", "success"] as const)(
  "retains the actual Android composition owner through %s and terminal settlement",
  async (mode) => {
    const scope = new CliCleanupScope();
    const register = vi.spyOn(scope, "register");
    const directory = await createTestTempDirectory("rea-android-cli-owner-");
    const apk = join(directory, "controlled.apk");
    await writeOrderedZip(apk, ["AndroidManifest.xml", "classes.dex"]);
    const primary = new ProviderAdapterError(
      "controlled-android",
      "inspect_android_package",
      {
        userMessage: "controlled Android execute failure",
      },
    );
    const failure = new ProviderCleanupError(
      "controlled-android",
      ["android-transport"],
      {
        reason: "controlled Android transport teardown denied",
      },
    );
    let allowed = mode === "success";
    const events: string[] = [];
    const close = vi.fn(async () => {
      events.push("provider-close");
      if (!allowed) throw failure;
    });
    const provider: AndroidAnalysisPort = {
      inspectAvailability: async () => ({
        status: "available",
        code: null,
        reason: null,
        diagnostics: {},
      }),
      execute: async (target, request) => {
        expect(register).toHaveBeenCalledWith(provider, expect.any(Function));
        expect(close).not.toHaveBeenCalled();
        expect(target.path).toBe(apk);
        expect(request.operation).toBe("inspect_android_package");
        events.push("execute");
        if (mode === "execute-rejection") throw primary;
        return observed({ controlled_package: true });
      },
      close,
    };
    const factory = vi
      .spyOn(androidComposition, "createAndroidAnalysisProvider")
      .mockReturnValue(provider);
    const previousExitCode = process.exitCode;
    let stdout = "";
    try {
      const cli = createCli({}, undefined, scope);
      expect(factory).toHaveBeenCalledOnce();
      expect(register).toHaveBeenCalledOnce();
      await scope.run(() =>
        cli.serve(["inspect-android-package", apk, "--format", "json"], {
          stdout: (text) => {
            stdout += text;
          },
          exit: () => undefined,
        }),
      );
      const publicOutput = stdout;
      if (mode === "execute-rejection") {
        expect(close).not.toHaveBeenCalled();
        expect(stdout).toContain("controlled Android execute failure");
      } else {
        expect(close).toHaveBeenCalledOnce();
      }
      const first = await scope.settle();
      // This is the exact production dispatcher prerequisite for inspector close;
      // actual dispatcher ordering is independently exercised at the public boundary.
      expect(first.settled).toBe(mode === "success");
      if (mode === "success") {
        expect(first.unresolved).toEqual([]);
        expect(first.failures).toEqual([]);
        expect(events).toEqual(["execute", "provider-close"]);
        expect(stdout).toContain("controlled_package");
      } else {
        expect(first.unresolved).toHaveLength(1);
        const owner = first.unresolved[0];
        expect(owner?.identity).toBe(provider);
        expect(owner?.state).toBe("unresolved");
        expect(first.failures).toContain(failure);
        expect(events[0]).toBe("execute");
        allowed = true;
        expect(await owner?.retry()).toEqual(ok(undefined));
        expect(await scope.settle()).toMatchObject({
          settled: true,
          unresolved: [],
          failures: expect.arrayContaining([failure]),
        });
        expect(owner?.identity).toBe(provider);
        expect(owner?.state).toBe("settled");
      }
      expect(stdout).toBe(publicOutput);
    } finally {
      allowed = true;
      await scope.settle();
      factory.mockRestore();
      register.mockRestore();
      process.exitCode = previousExitCode;
    }
  },
);

it("rejects late ownership registration and confines an empty receipt to its own invocation", async () => {
  const scope = new CliCleanupScope();
  expect(await scope.settle()).toMatchObject({
    settled: true,
    unresolved: [],
    failures: [],
  });
  expect(() => scope.register({}, async () => ok(undefined))).toThrow(
    /registration is closed/u,
  );
});
