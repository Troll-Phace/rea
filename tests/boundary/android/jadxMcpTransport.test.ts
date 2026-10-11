import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import {
  serializeMessage,
  type JSONRPCMessage,
} from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";
import {
  acquireProviderProcessObservation,
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type ProviderProcessDiagnostic,
  type ProviderProcessHandle,
} from "../../../src/process/ProviderProcess.js";
import {
  JadxMcpTransport,
  type JadxLauncher,
} from "../../../src/android/JadxMcpTransport.js";
import { stopProviderProcessFixture } from "../../fixtures/providerProcess.js";

class FixtureProcess extends EventEmitter implements ProviderProcessHandle {
  readonly pid = 1;
  readonly stdout = new PassThrough();
  constructor(readonly stdin: Writable = new PassThrough()) {
    super();
  }
  readonly stderr = new PassThrough();
  readonly exitCode = null;
  readonly signalCode = null;

  kill(): boolean {
    return true;
  }
}

/** Controlled launchers must honor the same synchronous acquisition boundary. */
const acquireFixture = (
  options: OwnedProviderProcessSpawnOptions,
  process: FixtureProcess,
): void => {
  acquireProviderProcessObservation(process, options.observation);
  options.onAcquired?.(process);
};

it("joins pending input errors before detaching the owned protocol stream", async () => {
  let completeWrite: ((cause: Error) => void) | undefined;
  const failure = new Error("owned pipe closed during cancellation");
  const process = new FixtureProcess(
    new Writable({
      write: (_chunk, _encoding, callback) => {
        completeWrite = callback;
      },
    }),
  );
  const transport = new JadxMcpTransport(
    { command: "fixture", arguments: [] },
    async (options) => {
      acquireFixture(options, process);
      return {
        process,
        ownership: { runId: options.runId, leaderPid: 1, processGroupId: 1 },
        cleanup: async () => {
          completeWrite?.(failure);
          process.emit("exit", 1, null);
          process.emit("close", 1, null);
          process.stdout.end();
          process.stderr.end();
          return { cleaned: true, signaled: true };
        },
      };
    },
  );
  const errors: Error[] = [];
  transport.onerror = (cause) => errors.push(cause);
  await transport.start();
  const pending = transport
    .send({ jsonrpc: "2.0", id: 1, method: "probe" })
    .then(
      () => undefined,
      (cause: unknown) => cause,
    );
  expect(completeWrite).toBeTypeOf("function");
  await transport.close();
  expect(await pending).toBe(failure);
  expect(errors).toEqual([failure]);
  expect(process.stdin.closed).toBe(true);
  await transport.close();
});

it("decodes split UTF-8 and newline bytes, then routes multiple complete frames", async () => {
  const process = new FixtureProcess();
  const launcher: JadxLauncher = async (options) => {
    acquireFixture(options, process);
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: process.pid,
        processGroupId: process.pid,
        expectedParentPid: process.pid,
      },
      cleanup: async () => {
        process.emit("exit", 0, null);
        process.emit("close", 0, null);
        process.stdout.end();
        process.stderr.end();
        process.stdin.end();
        return { cleaned: true, signaled: false };
      },
    };
  };
  const transport = new JadxMcpTransport(
    { command: "fixture", arguments: [] },
    launcher,
  );
  const received: JSONRPCMessage[] = [];
  transport.onmessage = (message) => received.push(message);

  await transport.start();
  const first = {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text: "snow 雪 🦊" }] },
  } satisfies JSONRPCMessage;
  const second = {
    jsonrpc: "2.0",
    id: 2,
    result: { content: [{ type: "text", text: "second" }] },
  } satisfies JSONRPCMessage;
  const third = {
    jsonrpc: "2.0",
    id: 3,
    result: { content: [{ type: "text", text: "third" }] },
  } satisfies JSONRPCMessage;
  for (const byte of Buffer.from(serializeMessage(first)))
    process.stdout.write(Buffer.from([byte]));
  process.stdout.write(
    Buffer.from(serializeMessage(second) + serializeMessage(third)),
  );

  expect(received).toEqual([first, second, third]);
  await transport.close();
});

it("accepts a complete JSON-RPC frame at the 8 MiB boundary", async () => {
  const process = new FixtureProcess();
  const launcher: JadxLauncher = async (options) => {
    acquireFixture(options, process);
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: process.pid,
        processGroupId: process.pid,
        expectedParentPid: process.pid,
      },
      cleanup: async () => {
        process.emit("exit", 0, null);
        process.emit("close", 0, null);
        process.stdout.end();
        process.stderr.end();
        process.stdin.end();
        return { cleaned: true, signaled: false };
      },
    };
  };
  const transport = new JadxMcpTransport(
    { command: "fixture", arguments: [] },
    launcher,
  );
  const received: JSONRPCMessage[] = [];
  transport.onmessage = (message) => received.push(message);
  const response = {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text: "" }] },
  } satisfies JSONRPCMessage;
  const emptyFrameBytes = Buffer.byteLength(serializeMessage(response)) - 1;
  const maxFrameResponse = {
    ...response,
    result: {
      content: [
        { type: "text", text: "x".repeat(8 * 1024 * 1024 - emptyFrameBytes) },
      ],
    },
  } satisfies JSONRPCMessage;
  const frame = Buffer.from(serializeMessage(maxFrameResponse));

  expect(frame.at(-1)).toBe(10);
  expect(frame.length - 1).toBe(8 * 1024 * 1024);
  await transport.start();
  process.stdout.write(frame);

  expect(received).toEqual([maxFrameResponse]);
  await transport.close();
});

it("retries an incomplete owned stop while joining concurrent close callers", async () => {
  const process = new FixtureProcess();
  let cleanupFails = true;
  const transport = new JadxMcpTransport(
    { command: "fixture", arguments: [] },
    async (options) => {
      acquireFixture(options, process);
      return {
        process,
        ownership: {
          runId: options.runId,
          leaderPid: process.pid,
          processGroupId: process.pid,
          expectedParentPid: process.pid,
        },
        cleanup: async () => {
          if (cleanupFails)
            return {
              cleaned: false,
              reason: "ownership verification unavailable",
            };
          process.emit("exit", 0, null);
          process.emit("close", 0, null);
          return { cleaned: true, signaled: false };
        },
      };
    },
  );
  await transport.start();
  const firstClose = transport.close();
  expect(transport.close()).toBe(firstClose);
  await expect(firstClose).rejects.toMatchObject({ cleanupIncomplete: true });
  cleanupFails = false;
  await transport.close();
  await transport.close();
});

it("parses immediate real protocol frames exactly once before awaited publication", async () => {
  const first = {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text: "startup 雪 🦊" }] },
  } satisfies JSONRPCMessage;
  const second = {
    jsonrpc: "2.0",
    id: 2,
    result: { content: [{ type: "text", text: "second startup frame" }] },
  } satisfies JSONRPCMessage;
  const frames = Buffer.from(
    serializeMessage(first) + serializeMessage(second),
  );
  const split = Buffer.byteLength(serializeMessage(first));
  const script = `
const bytes = Buffer.from(${JSON.stringify(frames.toString("base64"))}, "base64");
process.stdin.once("data", () => {
  process.stdout.write(bytes.subarray(${split}));
  process.stderr.write("complete startup diagnostic\\n");
  process.stdin.destroy();
});
process.stdout.write(bytes.subarray(0, ${split}));
`;
  let acquired: ProviderProcessHandle | undefined;
  let acquisitions = 0;
  const diagnostics: ProviderProcessDiagnostic[] = [];
  const launcher: JadxLauncher = async (options) => {
    let closed: Promise<void> | undefined;
    const launched = await spawnOwnedProviderProcess({
      ...options,
      observation: {
        ...options.observation,
        onDiagnostic: (event) => {
          diagnostics.push(event);
          options.observation?.onDiagnostic?.(event);
        },
      },
      onAcquired: (child) => {
        onTestFinished(() => stopProviderProcessFixture(child));
        acquisitions += 1;
        acquired = child;
        closed = new Promise<void>((resolve) =>
          child.once("close", () => resolve()),
        );
        options.onAcquired?.(child);
      },
    });
    if (closed === undefined)
      throw new Error("protocol child was not acquired");
    await closed;
    return launched;
  };
  const transport = new JadxMcpTransport(
    { command: process.execPath, arguments: ["-e", script] },
    launcher,
  );
  const messages: JSONRPCMessage[] = [];
  const errors: Error[] = [];
  transport.onmessage = (message) => {
    messages.push(message);
    if ("id" in message && message.id === 1) acquired?.stdin?.write("continue");
  };
  transport.onerror = (error) => errors.push(error);
  try {
    await transport.start();
    expect(acquisitions).toBe(1);
    expect(acquired?.exitCode).toBe(0);
    expect(messages).toEqual([first, second]);
    expect(errors).toEqual([]);
    expect(transport.diagnostics()).toBe("complete startup diagnostic\n");
    expect(
      diagnostics.filter(
        (event) => event.type === "output" && event.stream === "stdout",
      ),
    ).toEqual([]);
    expect(
      diagnostics
        .filter((event) => event.type === "output" && event.stream === "stderr")
        .at(-1),
    ).toMatchObject({
      totalBytes: Buffer.byteLength("complete startup diagnostic\n"),
    });
    await transport.close();
    expect(messages).toEqual([first, second]);
    expect(transport.diagnostics()).toBe("complete startup diagnostic\n");
  } finally {
    await transport.close();
  }
});
