import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { expect, it } from "vitest";
import {
  acquireProviderProcessObservation,
  ProviderProcessSupervisor,
} from "./ProviderProcess.js";

it("exit does not establish complete output when a producer closes its streams later", async () => {
  const producer = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  acquireProviderProcessObservation(producer);
  const supervisor = new ProviderProcessSupervisor({
    process: producer,
    ownsProcessLifetime: false,
  });
  try {
    producer.stdout.write("first");
    producer.emit("exit", 0, null);
    expect(await supervisor.waitForExit(0)).toBe(true);
    expect(await supervisor.waitForOutputClose(0)).toBe(false);
    producer.stdout.end("last");
    producer.stderr.end("diagnostic");
    producer.emit("close", 0, null);
    expect(await supervisor.waitForOutputClose(0)).toBe(true);
    expect(supervisor.snapshot()).toMatchObject({
      stdout: { text: "firstlast" },
      stderr: { text: "diagnostic" },
      exitCode: 0,
    });
  } finally {
    supervisor.dispose();
  }
});

it("retains pre-adoption stream errors without replaying diagnostic callbacks", async () => {
  const producer = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  const messages: string[] = [];
  const failure = new Error("early stderr read failed");
  acquireProviderProcessObservation(producer, {
    onDiagnostic: (event) => {
      if (event.type === "error") messages.push(event.message);
    },
  });
  producer.stderr.write("retained prefix");
  producer.stderr.emit("error", failure);
  producer.emit("exit", 1, null);
  producer.stdout.end();
  producer.stderr.end();
  producer.emit("close", 1, null);
  const adoptedMessages: string[] = [];
  const supervisor = new ProviderProcessSupervisor(
    { process: producer, ownsProcessLifetime: false },
    {
      onDiagnostic: (event) => {
        if (event.type === "error") adoptedMessages.push(event.message);
      },
    },
  );
  try {
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain(failure.message);
    expect(adoptedMessages).toEqual([]);
    expect(supervisor.observation()).toMatchObject({
      coverage: "complete",
      outputClosed: true,
      errors: [failure],
      actualExit: { code: 1, signal: null },
      snapshot: { stderr: { text: "retained prefix" } },
    });
    expect(await supervisor.waitForOutputClose(0)).toBe(true);
  } finally {
    supervisor.dispose();
  }
});
