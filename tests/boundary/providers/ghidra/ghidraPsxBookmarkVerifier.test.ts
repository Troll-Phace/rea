import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it, onTestFinished } from "vitest";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessHandle,
  ProviderProcessObservationSnapshot,
  SpawnedOwnedProviderProcess,
} from "../../../../src/process/ProviderProcess.js";
import type { ProcessCleanupReceipt } from "../../../../src/process/ProcessCleanupScope.js";
import { stopProviderProcessFixture } from "../../../fixtures/providerProcess.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

type WorkspaceOwner = {
  identity: object;
  removed: boolean;
  close(): Promise<void>;
  retry(): Promise<void>;
};
type Capture = {
  bind(stream: Readable | null): void;
  settle(): Promise<void>;
  summary(): {
    complete: boolean;
    bytes: number;
    capture_failures: { stage: string }[];
    unpersisted_events: { position: number; bytes_base64: string }[];
  };
};
type BookmarkProcessOwner = {
  id: string;
  streams: Capture[];
  settled: boolean;
  acquired?: ProviderProcessHandle;
  launched?: SpawnedOwnedProviderProcess;
  closed?: Promise<void>;
  closeObserved?: boolean;
  acquisitionFailure?: unknown;
  cleanupOwner?: ProcessCleanupReceipt;
  acquisitionObservation?: ProviderProcessObservationSnapshot;
};
const verifier: {
  createBookmarkWorkspaceOwner(
    path: string,
    filesystem?: { rm?: typeof rm },
  ): Promise<WorkspaceOwner>;
  createBookmarkStreamCapture(
    path: string,
    abort: AbortController,
    filesystem?: { open?: typeof open },
  ): Promise<Capture>;
  assertBookmarkProbe(probe: unknown, scenario: string, digest: string): void;
  acquireBookmarkProcess(
    owner: BookmarkProcessOwner,
    options: OwnedProviderProcessSpawnOptions,
    launcher?: (
      options: OwnedProviderProcessSpawnOptions,
    ) => Promise<SpawnedOwnedProviderProcess>,
  ): Promise<SpawnedOwnedProviderProcess>;
  settleBookmarkOwners(owners: BookmarkProcessOwner[]): Promise<{
    errors: { owner: string; stage: string; message: string }[];
    unresolved_owners: { id: string; cleanup_identity: object | null }[];
  }>;
} = await import(
  new URL(
    "../../../../scripts/verify-real-ghidra-psx-bookmarks.mjs",
    import.meta.url,
  ).href
);
const fixtureModule: {
  buildPsxExeFixture(): { bytes: Buffer; expected: { payloadAddress: number } };
} = await import(
  new URL("../../../conformance/ghidra/psx-exe-fixture.mjs", import.meta.url)
    .href
);
const hash = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

async function workspace() {
  const parent = await realpath(
    await createTestTempDirectory("rea-bookmark-control-"),
  );
  const path = join(parent, "owned");
  await mkdir(path, { mode: 0o700 });
  await writeFile(join(parent, "unrelated"), "preserve");
  return { parent, path };
}

describe("bookmark verifier exact workspace ownership", () => {
  it("removes only its original generation and verifies absence", async () => {
    const { parent, path } = await workspace();
    const owner = await verifier.createBookmarkWorkspaceOwner(path);
    await owner.close();
    expect(owner.removed).toBe(true);
    await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(join(parent, "unrelated"), "utf8")).toBe("preserve");
    await owner.retry();
  });
  it("retains failed removal and the exact callable retry", async () => {
    const { path } = await workspace();
    let deny = true;
    const owner = await verifier.createBookmarkWorkspaceOwner(path, {
      rm: async (...args) => {
        if (deny) throw new Error("controlled removal denial");
        return rm(...args);
      },
    });
    const identity = owner.identity;
    await expect(owner.close()).rejects.toThrow("controlled removal denial");
    expect(owner.removed).toBe(false);
    expect((await lstat(path)).isDirectory()).toBe(true);
    deny = false;
    await owner.retry();
    expect(owner.identity).toBe(identity);
    expect(owner.removed).toBe(true);
    await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it.each(["directory", "symlink"] as const)(
    "refuses a replacement %s and retries only the restored original",
    async (replacement) => {
      const { parent, path } = await workspace();
      const owner = await verifier.createBookmarkWorkspaceOwner(path);
      const retained = join(parent, "retained-original");
      await rename(path, retained);
      if (replacement === "directory") await mkdir(path);
      else await symlink(retained, path);
      await expect(owner.close()).rejects.toThrow(
        /generation changed|replacement\/symlink/u,
      );
      expect(owner.removed).toBe(false);
      expect((await lstat(retained)).isDirectory()).toBe(true);
      await rm(path, { recursive: true });
      await rename(retained, path);
      await owner.retry();
      expect(owner.removed).toBe(true);
      expect(await readFile(join(parent, "unrelated"), "utf8")).toBe(
        "preserve",
      );
    },
  );
});

/** Mutate only owned FileHandle methods, preserving the actual descriptor and filesystem. */
function controlledOpen(
  fault: (method: string) => Error | undefined,
): typeof open {
  return async (...args) => {
    const handle = await open(...args);
    return new Proxy(handle, {
      get(target, key) {
        const value: unknown = Reflect.get(target, key, target);
        if (typeof value !== "function") return value;
        return (...parameters: unknown[]) => {
          const failure = fault(String(key));
          if (failure) return Promise.reject(failure);
          return Reflect.apply(value, target, parameters);
        };
      },
    });
  };
}

async function captured(openOverride?: typeof open) {
  const parent = await realpath(
    await createTestTempDirectory("rea-bookmark-capture-"),
  );
  const path = join(parent, "output.log"),
    abort = new AbortController();
  const capture = await verifier.createBookmarkStreamCapture(
    path,
    abort,
    openOverride ? { open: openOverride } : undefined,
  );
  const stream = Readable.from([
    Buffer.from("first 雪"),
    Buffer.from("second"),
  ]);
  const ended = new Promise<void>((resolve, reject) => {
    stream.once("end", resolve);
    stream.once("error", reject);
  });
  capture.bind(stream);
  await ended;
  return { capture, abort, path, parent };
}

describe("bookmark raw capture retains failed bytes and leases", () => {
  it("awaits real writes and complete EOF before successful close", async () => {
    const { capture, path } = await captured();
    await capture.settle();
    expect(await readFile(path, "utf8")).toBe("first 雪second");
    expect(capture.summary()).toMatchObject({
      complete: true,
      capture_failures: [],
      unpersisted_events: [],
    });
    expect((await lstat(path)).mode & 0o777).toBe(0o600);
  });
  it("retains original write failure and absolute byte offsets before replay", async () => {
    let fail = true;
    const error = new Error("controlled actual write failure");
    const { capture, abort, path } = await captured(
      controlledOpen((method) => {
        if (method !== "write" || !fail) return;
        fail = false;
        return error;
      }),
    );
    await expect(capture.settle()).rejects.toMatchObject({ cause: error });
    expect(abort.signal.reason).toBe(error);
    const events = capture.summary().unpersisted_events;
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      position: 0,
      bytes_base64: Buffer.from("first 雪").toString("base64"),
    });
    await capture.settle();
    expect(await readFile(path, "utf8")).toBe("first 雪second");
    expect(capture.summary()).toMatchObject({
      complete: false,
      unpersisted_events: [],
      capture_failures: [{ stage: "write" }],
    });
  });
  it("preserves independent sync and close failures then retries the same file", async () => {
    const sync = new Error("controlled fsync failure"),
      close = new Error("controlled close failure");
    let deny = true;
    const { capture, path } = await captured(
      controlledOpen((method) =>
        deny
          ? method === "sync"
            ? sync
            : method === "close"
              ? close
              : undefined
          : undefined,
      ),
    );
    await expect(capture.settle()).rejects.toMatchObject({
      errors: [sync, close],
    });
    expect(capture.summary().capture_failures.map((row) => row.stage)).toEqual([
      "sync",
      "close",
    ]);
    deny = false;
    await capture.settle();
    expect(await readFile(path, "utf8")).toBe("first 雪second");
    expect(capture.summary().complete).toBe(false);
  });
  it("refuses reopening a substituted generation after failed fsync", async () => {
    let first = true;
    const { capture, path, parent } = await captured(
      controlledOpen((method) => {
        if (method !== "sync" || !first) return;
        first = false;
        return new Error("controlled fsync denial");
      }),
    );
    await expect(capture.settle()).rejects.toThrow("sync/close failed");
    const original = join(parent, "original.log");
    await rename(path, original);
    await writeFile(path, "unrelated replacement");
    await expect(capture.settle()).rejects.toThrow("generation changed");
    expect(await readFile(path, "utf8")).toBe("unrelated replacement");
    await rm(path);
    await rename(original, path);
    await capture.settle();
    expect(await readFile(path, "utf8")).toBe("first 雪second");
  });
});

function positiveProbe() {
  const fixture = fixtureModule.buildPsxExeFixture(),
    sourceDigest = hash(fixture.bytes);
  const mapping = {
    start: `0x${fixture.expected.payloadAddress.toString(16)}`,
    length: 2048,
    sha256: hash(fixture.bytes.subarray(2048)),
    source_file_index: null as number | null,
    file_offset: null as number | null,
  };
  const manifest = Object.fromEntries(
    [
      "blocks",
      "context",
      "default_context",
      "default_disassembly_context",
      "symbols",
      "label_history",
      "functions",
      "instructions",
      "data",
      "references",
      "entries",
      "bookmarks",
      "comments",
      "property_maps",
      "trees",
      "source_maps",
      "equates",
      "relocations",
    ].map((key) => [key, []]),
  );
  const before = {
    bookmark_identity: { bookmarks: [], types: [] },
    complete_enumerated_state: manifest,
    complete_enumerated_state_sha256: "a".repeat(64),
    observation: { source_files: [] as object[], mappings: [mapping] },
  };
  const after = structuredClone(before);
  after.observation.source_files.push({
    name: "synthetic.exe",
    size: 4096,
    original_sha256: sourceDigest,
    modified_sha256: sourceDigest,
  });
  after.observation.mappings[0] = {
    ...mapping,
    source_file_index: 0,
    file_offset: 2048,
  };
  return {
    sourceDigest,
    probe: {
      schema_version: 1,
      scenario: "zero",
      scope: "isolated-synthetic-ProgramDB-bookmark-metadata-feasibility",
      mocked: false,
      ok: true,
      evidence_complete: true,
      owned_program_released: true,
      source: {
        path: "/synthetic.exe",
        sha256: sourceDigest,
        after_sha256: sourceDigest,
        file_bytes: 4096,
      },
      actual_import: {
        language_id: "PSX:LE:32:default",
        compiler_spec_id: "default",
        examined_payload_bytes: 2048,
        payload_sha256: hash(fixture.bytes.subarray(2048)),
      },
      transaction: { finalized: true, committed: true },
      expected_failure: false,
      failure: null,
      before,
      after,
      stages: [
        "destination-validated",
        "parked",
        "blocks-removed",
        "blocks-replaced",
        "return-validated",
        "returned",
        "committed",
      ].map((stage) => ({ stage })),
    },
  };
}

describe("bookmark producer acceptance uses retained facts", () => {
  it("accepts only the exact synthetic source-backed observation", () => {
    const { probe, sourceDigest } = positiveProbe();
    expect(() =>
      verifier.assertBookmarkProbe(probe, "zero", sourceDigest),
    ).not.toThrow();
  });
  it.each([
    "full manifest",
    "omitted manifest",
    "source digest",
    "source offset",
    "source coverage",
    "owned release",
    "transaction",
    "runtime language",
  ])(
    "rejects a changed %s with the summary still claiming success",
    (mutation) => {
      const { probe, sourceDigest } = positiveProbe();
      switch (mutation) {
        case "full manifest":
          probe.after.complete_enumerated_state.comments = [
            "unexpected",
          ] as never[];
          break;
        case "omitted manifest":
          Reflect.deleteProperty(probe.after, "complete_enumerated_state");
          break;
        case "source digest":
          probe.source.after_sha256 = "b".repeat(64);
          break;
        case "source offset":
          probe.after.observation.mappings[0]!.file_offset = 2049;
          break;
        case "source coverage":
          probe.after.observation.mappings[0]!.length = 2047;
          break;
        case "owned release":
          probe.owned_program_released = false;
          break;
        case "transaction":
          probe.transaction.finalized = false;
          break;
        case "runtime language":
          probe.actual_import.language_id = "MIPS:LE:32:default";
          break;
      }
      expect(() =>
        verifier.assertBookmarkProbe(probe, "zero", sourceDigest),
      ).toThrow();
    },
  );
});

const provider: typeof import("../../../../src/process/ProviderProcess.js") =
  await import(
    new URL("../../../../dist/process/ProviderProcess.js", import.meta.url).href
  );
const commands: typeof import("../../../../src/process/OwnedCommand.js") =
  await import(
    new URL("../../../../dist/process/OwnedCommand.js", import.meta.url).href
  );
const scopes: typeof import("../../../../src/process/ProcessCleanupScope.js") =
  await import(
    new URL("../../../../dist/process/ProcessCleanupScope.js", import.meta.url)
      .href
  );

async function processCaptures(openOverride?: typeof open) {
  const parent = await realpath(
    await createTestTempDirectory("rea-bookmark-acquisition-"),
  );
  const paths = [join(parent, "stdout.log"), join(parent, "stderr.log")];
  const abort = new AbortController();
  const owner: BookmarkProcessOwner = {
    id: randomUUID(),
    streams: [],
    settled: false,
  };
  for (const [index, path] of paths.entries())
    owner.streams.push(
      await verifier.createBookmarkStreamCapture(
        path,
        abort,
        index === 0 && openOverride ? { open: openOverride } : undefined,
      ),
    );
  onTestFinished(async () => {
    if (owner.acquired) await stopProviderProcessFixture(owner.acquired);
    await owner.closed;
    // Emergency cleanup retains the same process and capture authorities.
    await verifier.settleBookmarkOwners([owner]);
    await verifier.settleBookmarkOwners([owner]);
  });
  return { owner, paths, abort };
}

const stdoutBytes = Buffer.from("out: 雪 / done\n"),
  stderrBytes = Buffer.from("err: 🦊 / end\n");
const immediateOutput = `
const out = Buffer.from('out: 雪 / done\\n'), err = Buffer.from('err: 🦊 / end\\n');
process.stdout.write(out.subarray(0, 6));
process.stdout.write(out.subarray(6));
process.stderr.write(err.subarray(0, 6));
process.stderr.write(err.subarray(6));
`;

/** Real close is the publication barrier; no synthetic event or delay establishes completion. */
const publishBookmarkAfterClose = async (
  options: OwnedProviderProcessSpawnOptions,
) => {
  let closed: Promise<void> | undefined;
  const launched = await provider.spawnOwnedProviderProcess({
    ...options,
    onAcquired(child) {
      closed = new Promise<void>((resolve) =>
        child.once("close", () => resolve()),
      );
      options.onAcquired?.(child);
    },
  });
  if (!closed) throw new Error("Actual acquisition hook missing");
  await closed;
  return launched;
};

describe("bookmark capture acquisition before publication", () => {
  it.each([false, true])(
    "retains exact raw bytes and budget policy after close before publication (scope=%s)",
    async (scoped) => {
      const { owner, paths } = await processCaptures();
      const scope = new scopes.ProcessCleanupScope();
      let hookCalls = 0;
      const execute = () =>
        commands.runOwnedCommand(
          {
            command: process.execPath,
            arguments: ["-e", immediateOutput],
            runId: owner.id,
            onAcquired(child) {
              expect(owner.acquired).toBe(child);
              expect(owner.closed).toBeInstanceOf(Promise);
              hookCalls++;
            },
          },
          {
            timeoutMs: 10_000,
            diagnosticBytes: stdoutBytes.length + stderrBytes.length,
          },
          {
            launcher: (options) =>
              verifier.acquireBookmarkProcess(
                owner,
                options,
                publishBookmarkAfterClose,
              ),
          },
        );
      const snapshot = await (scoped
        ? scopes.withProcessCleanupScope(scope, execute)
        : execute());
      expect(hookCalls).toBe(1);
      expect(owner.closeObserved).toBe(true);
      expect(snapshot).toMatchObject({
        exitCode: 0,
        signal: null,
        stdout: { text: stdoutBytes.toString(), bytes: stdoutBytes.length },
        stderr: { text: stderrBytes.toString(), bytes: stderrBytes.length },
      });
      expect(snapshot.diagnosticTruncated).not.toBe(true);
      expect(scope.owners).toHaveLength(scoped ? 1 : 0);
      if (scoped) expect(owner.launched?.cleanupReceipt).toBe(scope.owners[0]);
      expect(await verifier.settleBookmarkOwners([owner])).toEqual({
        errors: [],
        unresolved_owners: [],
      });
      for (const [index, bytes] of [stdoutBytes, stderrBytes].entries()) {
        expect(await readFile(paths[index]!)).toEqual(bytes);
        expect(owner.streams[index]?.summary()).toMatchObject({
          bytes: bytes.length,
          complete: true,
        });
        expect((await lstat(paths[index]!)).mode & 0o777).toBe(0o600);
      }
      expect(await scope.close()).toMatchObject({
        settled: true,
        unresolved: [],
      });
    },
  );

  it("preserves full raw output while early budget overflow fails the actual bounded command", async () => {
    const { owner, paths } = await processCaptures();
    await expect(
      commands.runOwnedCommand(
        {
          command: process.execPath,
          arguments: ["-e", immediateOutput],
          runId: owner.id,
        },
        { timeoutMs: 10_000, diagnosticBytes: 5 },
        {
          launcher: (options) =>
            verifier.acquireBookmarkProcess(
              owner,
              options,
              publishBookmarkAfterClose,
            ),
        },
      ),
    ).rejects.toMatchObject({
      reason: "output-limit",
      snapshot: { diagnosticTruncated: true },
    });
    expect(await verifier.settleBookmarkOwners([owner])).toEqual({
      errors: [],
      unresolved_owners: [],
    });
    expect(await readFile(paths[0]!)).toEqual(stdoutBytes);
    expect(await readFile(paths[1]!)).toEqual(stderrBytes);
  });
});

describe("bookmark capture acquisition failure and retry", () => {
  it.skipIf(process.platform === "win32")(
    "retains live capture leases and exact cleanup authority after hook failure and identity denial",
    async () => {
      const methods: string[] = [];
      const { owner, paths } = await processCaptures(
        controlledOpen((method) => {
          methods.push(method);
          return undefined;
        }),
      );
      const primary = new Error("controlled bookmark acquisition rejection");
      const captureError = new Error("controlled acquired stderr error");
      let acknowledge!: () => void;
      const ready = new Promise<void>((resolve) => {
        acknowledge = resolve;
      });
      const outcome: unknown = await verifier
        .acquireBookmarkProcess(owner, {
          command: process.execPath,
          arguments: [
            "-e",
            "process.stdout.write('ready\\n'); process.stdin.once('data', () => { process.stdout.write('final 雪\\n'); process.stderr.write('final err\\n'); process.stdin.destroy(); });",
          ],
          runId: owner.id,
          stdin: "pipe",
          expectedCommand: `${process.execPath}.different-owner`,
          onAcquired(child) {
            child.stdout?.once("data", () => acknowledge());
            child.stderr?.emit("error", captureError);
            throw primary;
          },
        })
        .catch((cause: unknown) => cause);
      if (!(outcome instanceof provider.ProviderProcessAcquisitionError))
        throw new Error("Missing actual retained acquisition failure", {
          cause: outcome,
        });
      expect(outcome.cause).toBe(primary);
      expect(outcome.errors).toContain(primary);
      expect(outcome.errors).toContain(captureError);
      expect(owner.cleanupOwner).toBe(outcome.cleanupOwner);
      expect(owner.cleanupOwner).toBeDefined();
      expect(owner.acquisitionObservation).toBe(outcome.observation);
      expect(owner.cleanupOwner?.identity).toEqual({
        kind: "provider-child",
        runId: owner.id,
      });
      expect(owner.launched).toBeUndefined();
      await ready;
      const first = await verifier.settleBookmarkOwners([owner]);
      expect(first.unresolved_owners).toHaveLength(1);
      expect(first.errors.map((error) => error.stage)).toContain("process");
      expect(first.errors.map((error) => error.stage)).toContain("capture");
      expect(first.errors).toContainEqual(
        expect.objectContaining({
          stage: "acquisition",
          cause: expect.objectContaining({ message: primary.message }),
        }),
      );
      expect(first.errors).toContainEqual(
        expect.objectContaining({
          stage: "capture",
          cause: expect.objectContaining({ message: captureError.message }),
        }),
      );
      expect(methods).not.toContain("sync");
      expect(methods).not.toContain("close");
      expect(owner.closeObserved).toBe(false);
      expect(owner.settled).toBe(false);
      const retained = owner.cleanupOwner;
      owner.acquired?.stdin?.write("finish");
      await owner.closed;
      const final = await verifier.settleBookmarkOwners([owner]);
      expect(final.unresolved_owners).toEqual([]);
      expect(owner.cleanupOwner).toBe(retained);
      expect(retained?.status).toBe("settled");
      expect(final.errors.some((error) => error.stage === "acquisition")).toBe(
        true,
      );
      expect(owner.acquisitionFailure).toBe(outcome);
      expect(owner.settled).toBe(true);
      expect(await readFile(paths[0]!, "utf8")).toBe("ready\nfinal 雪\n");
      expect(await readFile(paths[1]!, "utf8")).toBe("final err\n");
      expect(owner.streams[1]?.summary()).toMatchObject({
        complete: false,
        capture_failures: [{ stage: "stream" }],
      });
    },
  );
});
