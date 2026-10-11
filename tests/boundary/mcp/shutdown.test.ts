import type { StdioServerHandle } from "@modelcontextprotocol/server/stdio";
import pino from "pino";
import { expect, it } from "vitest";

import { createManagedBinarySession } from "../../../src/composition/binary.js";
import { MCP_SHUTDOWN_FAILED } from "../../../src/main/messages.js";
import { createShutdown } from "../../../src/main/shutdown.js";
import type { RuntimeDependencies } from "../../../src/main/types.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { err, ok } from "../../../src/domain/result.js";
import { observed } from "../../fixtures/analysisExecution.js";
import {
  createBinarySessionTargets,
  createDeferred,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";

it("keeps shutdown output stable while logging the rejected cause at debug level", async () => {
  const logs: string[] = [];
  const output: string[] = [];
  const exitCodes: number[] = [];
  const requests: Array<() => void> = [];
  let androidClosed = false;
  const failure = Object.assign(
    new TypeError("fixture transport close failed"),
    {
      code: "ECONNRESET",
    },
  );
  const handle: StdioServerHandle = {
    close: () => Promise.reject(failure),
  };
  const dependencies: RuntimeDependencies = {
    env: {},
    serve: () => {
      throw new Error("unused fixture transport");
    },
    writeStderr: (text) => output.push(text),
    setExitCode: (code) => exitCodes.push(code),
    registerShutdown: (request) => {
      requests.push(request);
      return () => undefined;
    },
  };
  const logger = pino({ level: "debug" }, { write: (line) => logs.push(line) });
  createShutdown({
    handle,
    closeAndroid: async () => {
      androidClosed = true;
    },
    session: createManagedBinarySession(),
    dependencies,
    serverLogger: logger,
  });

  requests[0]?.();
  await new Promise((resolve) => setImmediate(resolve));

  expect(exitCodes).toEqual([1]);
  expect(androidClosed).toBe(true);
  expect(output).toEqual([`${MCP_SHUTDOWN_FAILED}\n`]);
  expect(logs.map((line) => JSON.parse(line))).toContainEqual(
    expect.objectContaining({
      level: 20,
      msg: "MCP shutdown rejected",
      failure_cause: {
        name: "TypeError",
        message: "fixture transport close failed",
        code: "ECONNRESET",
      },
    }),
  );
});

it("reports a typed binary cleanup failure and retains the client for retry", async () => {
  const [target] = await createBinarySessionTargets();
  const failure = new ProviderCleanupError("fixture", ["owned-runtime"], {
    reason: "fixture removal denied",
  });
  let cleanupAllowed = false;
  let retainDocument: boolean | undefined;
  const session = createTestBinarySession(() => ({
    execute: async () => observed(null),
    close: async (options) => {
      retainDocument = options?.retainDocument;
      return cleanupAllowed ? ok(null) : err(failure);
    },
  }));
  expect((await session.open(target)).ok).toBe(true);
  const output: string[] = [];
  const exitCodes: number[] = [];
  const requests: Array<() => void> = [];
  const dependencies: RuntimeDependencies = {
    env: {},
    serve: () => {
      throw new Error("unused fixture transport");
    },
    writeStderr: (text) => output.push(text),
    setExitCode: (code) => exitCodes.push(code),
    registerShutdown: (request) => {
      requests.push(request);
      return () => undefined;
    },
  };
  createShutdown({
    handle: { close: async () => undefined },
    session,
    dependencies,
    serverLogger: pino({ enabled: false }),
  });
  requests[0]?.();
  await new Promise((resolve) => setImmediate(resolve));
  expect(exitCodes).toEqual([1]);
  expect(output).toEqual([
    `${MCP_SHUTDOWN_FAILED}\n`,
    `${failure.userMessage}\n`,
  ]);
  expect(retainDocument).toBe(true);
  cleanupAllowed = true;
  requests[0]?.();
  await new Promise((resolve) => setImmediate(resolve));
  expect((await session.close()).ok).toBe(true);
});

it("retries only failed cleanup owners after concurrent shutdown requests", async () => {
  const requests: Array<() => void> = [];
  const logs: string[] = [];
  const exitCodes: number[] = [];
  let unregisterCount = 0;
  let handleCalls = 0;
  let androidCalls = 0;
  let sessionCalls = 0;
  const dependencies: RuntimeDependencies = {
    env: {},
    serve: () => {
      throw new Error("unused fixture transport");
    },
    writeStderr: () => undefined,
    setExitCode: (code) => exitCodes.push(code),
    registerShutdown: (request) => {
      requests.push(request);
      return () => {
        unregisterCount += 1;
      };
    },
  };
  const session = createTestBinarySession(() => ({
    execute: async () => observed(null),
    close: async () => {
      sessionCalls += 1;
      return ok(null);
    },
  }));
  const [target] = await createBinarySessionTargets();
  if (target === undefined) throw new Error("Missing fixture target");
  expect((await session.open(target)).ok).toBe(true);
  const lifecycle = createShutdown({
    handle: {
      close: async () => {
        handleCalls += 1;
        if (handleCalls === 1) throw new Error("first handle close failed");
      },
    },
    closeAndroid: async () => {
      androidCalls += 1;
      if (androidCalls === 1) throw new Error("first Android close failed");
    },
    session,
    dependencies,
    serverLogger: pino(
      { level: "debug" },
      { write: (line) => logs.push(line) },
    ),
  });

  const first = lifecycle.shutdown();
  const concurrent = lifecycle.shutdown();
  requests[0]?.();
  await expect(first).rejects.toBeInstanceOf(AggregateError);
  await expect(concurrent).rejects.toBeInstanceOf(AggregateError);
  await expect(first).rejects.toMatchObject({
    errors: [
      { message: "first handle close failed" },
      { message: "first Android close failed" },
    ],
  });
  await new Promise((resolve) => setImmediate(resolve));
  expect(exitCodes).toEqual([1]);
  expect(logs.map((line) => JSON.parse(line))).toContainEqual(
    expect.objectContaining({
      msg: "MCP shutdown rejected",
      failure_cause: expect.objectContaining({
        errors: [
          expect.objectContaining({ message: "first handle close failed" }),
          expect.objectContaining({ message: "first Android close failed" }),
        ],
      }),
    }),
  );
  expect([handleCalls, androidCalls, sessionCalls, unregisterCount]).toEqual([
    1, 1, 1, 0,
  ]);

  await lifecycle.shutdown();
  expect([handleCalls, androidCalls, sessionCalls, unregisterCount]).toEqual([
    2, 2, 1, 1,
  ]);
  await lifecycle.shutdown();
  expect([handleCalls, androidCalls, sessionCalls, unregisterCount]).toEqual([
    2, 2, 1, 1,
  ]);
});

const shutdownDependencies = () => {
  const requests: Array<() => void> = [];
  let unregistered = 0;
  const dependencies: RuntimeDependencies = {
    env: {},
    serve: () => {
      throw new Error("unused test transport");
    },
    writeStderr: () => undefined,
    setExitCode: () => undefined,
    registerShutdown: (request) => {
      requests.push(request);
      return () => {
        unregistered += 1;
      };
    },
  };
  return { dependencies, requests, unregisterCount: () => unregistered };
};

it("waits for every provider stage before inspector close and coalesces concurrent requests", async () => {
  const events: string[] = [];
  const transportRelease = createDeferred<void>();
  const androidRelease = createDeferred<void>();
  const entered = createDeferred<void>();
  const state = shutdownDependencies();
  let inspectorCalls = 0;
  const lifecycle = createShutdown({
    handle: {
      close: async () => {
        events.push("transport-close");
        entered.resolve();
        await transportRelease.promise;
        events.push("transport-settled");
      },
    },
    closeAndroid: async () => {
      events.push("android-close");
      await androidRelease.promise;
      events.push("android-settled");
    },
    session: createManagedBinarySession(),
    dependencies: state.dependencies,
    serverLogger: pino({ enabled: false }),
    closeProcessOwnership: async () => {
      inspectorCalls += 1;
      events.push("inspector-close");
    },
  });
  const first = lifecycle.shutdown();
  const concurrent = lifecycle.shutdown();
  await entered.promise;
  expect(inspectorCalls).toBe(0);
  transportRelease.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  expect(inspectorCalls).toBe(0);
  expect(state.unregisterCount()).toBe(0);
  androidRelease.resolve();
  await Promise.all([first, concurrent]);
  expect(events.indexOf("inspector-close")).toBeGreaterThan(
    events.indexOf("android-settled"),
  );
  expect(events.indexOf("inspector-close")).toBeGreaterThan(
    events.indexOf("transport-settled"),
  );
  expect(inspectorCalls).toBe(1);
  expect(state.unregisterCount()).toBe(1);
  expect(lifecycle.unresolvedOwners).toEqual([]);
});

it("retains provider authority on failure and closes the inspector only after provider retry", async () => {
  const failure = new Error("provider cleanup denied");
  const state = shutdownDependencies();
  let providerCalls = 0;
  let inspectorCalls = 0;
  const lifecycle = createShutdown({
    handle: {
      close: async () => {
        providerCalls += 1;
        if (providerCalls === 1) throw failure;
      },
    },
    session: createManagedBinarySession(),
    dependencies: state.dependencies,
    serverLogger: pino({ enabled: false }),
    closeProcessOwnership: async () => {
      inspectorCalls += 1;
    },
  });
  await expect(lifecycle.shutdown()).rejects.toBe(failure);
  expect(inspectorCalls).toBe(0);
  expect(lifecycle.failures).toContain(failure);
  expect(lifecycle.unresolvedOwners.map(({ id }) => id)).toEqual([
    "mcp-transport",
    "process-inspector",
  ]);
  expect(state.unregisterCount()).toBe(0);
  await lifecycle.shutdown();
  expect([providerCalls, inspectorCalls, state.unregisterCount()]).toEqual([
    2, 1, 1,
  ]);
  expect(lifecycle.failures).toContain(failure);
});

it("retries a rejected inspector without reclosing completed providers or losing earlier causes", async () => {
  const state = shutdownDependencies();
  const primary = new Error("startup primary failure");
  const providerFailure = new Error("startup provider cleanup failure");
  const inspectorFailure = new Error("inspector root removal denied");
  let providerCalls = 0;
  let inspectorCalls = 0;
  const lifecycle = createShutdown({
    session: createManagedBinarySession(),
    dependencies: state.dependencies,
    serverLogger: pino({ enabled: false }),
    providerCleanup: {
      primary,
      failures: [providerFailure],
      owners: [
        {
          id: "retained-startup-provider",
          closed: false,
          close: async () => {
            providerCalls += 1;
          },
        },
      ],
    },
    closeProcessOwnership: async () => {
      inspectorCalls += 1;
      if (inspectorCalls === 1) throw inspectorFailure;
    },
  });
  await expect(lifecycle.shutdown()).rejects.toBe(inspectorFailure);
  expect(lifecycle.unresolvedOwners.map(({ id }) => id)).toEqual([
    "process-inspector",
  ]);
  expect(lifecycle.failures).toEqual([
    primary,
    providerFailure,
    inspectorFailure,
  ]);
  expect(state.unregisterCount()).toBe(0);
  await lifecycle.shutdown();
  expect([providerCalls, inspectorCalls, state.unregisterCount()]).toEqual([
    1, 2, 1,
  ]);
  expect(lifecycle.failures).toEqual([
    primary,
    providerFailure,
    inspectorFailure,
  ]);
});

it("keeps the inspector available across ordinary binary session open/close cycles", async () => {
  const [target, other] = await createBinarySessionTargets();
  const session = createTestBinarySession(() => ({
    execute: async () => observed(null),
    close: async () => ok(null),
  }));
  const state = shutdownDependencies();
  let inspectorCalls = 0;
  const lifecycle = createShutdown({
    handle: { close: async () => undefined },
    session,
    dependencies: state.dependencies,
    serverLogger: pino({ enabled: false }),
    closeProcessOwnership: async () => {
      inspectorCalls += 1;
    },
  });
  for (const path of [target, other]) {
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    const closed = await session.close();
    if (!closed.ok) throw closed.error;
    expect(inspectorCalls).toBe(0);
  }
  await lifecycle.shutdown();
  expect(inspectorCalls).toBe(1);
});
