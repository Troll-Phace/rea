import { lstat, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { lstatSync, realpathSync, rmSync, type Stats } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { safeParseJson } from "../domain/safeJson.js";
import { execFileOutput } from "./ExecFileOutput.js";
import type {
  ProcessIdentityObservation,
  ProcessRunTokenObservation,
  ProcessTableEntry,
} from "./ProcessOwnership.js";

const responseSchema = z.strictObject({
  results: z.array(
    z.discriminatedUnion("state", [
      z.strictObject({
        pid: z.number().int().positive(),
        state: z.literal("readable"),
        run_id: z.string().optional(),
        reason: z.null().optional(),
      }),
      z.strictObject({
        pid: z.number().int().positive(),
        state: z.literal("unavailable"),
        run_id: z.union([z.string(), z.null()]).optional(),
        reason: z.string().min(1),
      }),
    ]),
  ),
});
const identityResponseSchema = z.strictObject({
  results: z.array(
    z.discriminatedUnion("state", [
      z.strictObject({
        pid: z.number().int().positive(),
        state: z.literal("readable"),
        identity: z.string().min(1),
        reason: z.null().optional(),
      }),
      z.strictObject({
        pid: z.number().int().positive(),
        state: z.literal("unavailable"),
        identity: z.null().optional(),
        reason: z.string().min(1),
      }),
    ]),
  ),
});

const sourceFiles = [
  fileURLToPath(
    new URL(
      "../../bridge/process/ProcessRunTokenReader.swift",
      import.meta.url,
    ),
  ),
  fileURLToPath(
    new URL(
      "../../bridge/process/ProcessRunTokenReaderMain.swift",
      import.meta.url,
    ),
  ),
];

/**
 * swift-driver runs each frontend job in its own process group. On SIGINT it
 * stops those jobs and deletes their objects before exiting; on SIGTERM it
 * exits while a job can still write objects under TMPDIR.
 */
export const SWIFTC_INTERRUPT = "SIGINT";

/** The native Darwin process-ownership reader could not be prepared. */
export class DarwinProcessOwnershipInspectionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DarwinProcessOwnershipInspectionError";
  }
}

interface ProcessReaderCompilation {
  readonly controller: AbortController;
  promise: Promise<string>;
  waiters: number;
  aborting: boolean;
  settled: boolean;
}

interface CompilerTemporaryOwner {
  readonly path: string;
  readonly base: string;
  identity?: { readonly device: number; readonly inode: number };
}

interface CompilerTemporaryFiles {
  readonly realpath: (path: string) => Promise<string>;
  readonly mkdtemp: (prefix: string) => Promise<string>;
  readonly lstat: (path: string) => Promise<Stats>;
  readonly rm: (
    path: string,
    options: { readonly recursive: true; readonly force: true },
  ) => Promise<void>;
}

const abortReason = (signal: AbortSignal): unknown => {
  if (signal.reason !== undefined) return signal.reason;
  const error = new Error("The operation was aborted");
  error.name = "AbortError";
  return error;
};

const isExpectedAbort = (cause: unknown, signal: AbortSignal): boolean =>
  signal.aborted &&
  (cause === signal.reason ||
    (cause instanceof Error && cause.name === "AbortError"));

const waitForCompilation = async (
  promise: Promise<string>,
  signal: AbortSignal | undefined,
): Promise<string> => {
  if (signal === undefined) return promise;
  if (signal.aborted) throw abortReason(signal);
  return new Promise((resolve, reject) => {
    let completed = false;
    const finish = (callback: () => void) => {
      if (completed) return;
      completed = true;
      signal.removeEventListener("abort", onAbort);
      callback();
    };
    const onAbort = () => finish(() => reject(abortReason(signal)));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => finish(() => resolve(value)),
      (cause: unknown) => finish(() => reject(cause)),
    );
    if (signal.aborted) onAbort();
  });
};

/** Compile and retain the narrow Darwin sysctl reader for this REA process. */
export const createDarwinProcessRunTokenReader = (
  options: {
    readonly xcrun?: string;
    /** Fault individual filesystem boundaries without changing the base policy. */
    readonly temporaryFiles?: Partial<CompilerTemporaryFiles>;
  } = {},
) => {
  const files: CompilerTemporaryFiles = {
    realpath,
    mkdtemp,
    lstat,
    rm,
    ...options.temporaryFiles,
  };
  let root: CompilerTemporaryOwner | undefined;
  let executable: string | undefined;
  let compilation: ProcessReaderCompilation | undefined;
  let closePromise: Promise<void> | undefined;
  let closed = false;
  let exitCleanupInstalled = false;

  const cleanupAtExit = () => {
    // Exit cleanup cannot await compiler settlement and is never proof of it.
    // Even best effort must not erase a replacement directory or symlink.
    if (
      root?.identity === undefined ||
      (compilation !== undefined && !compilation.settled)
    )
      return;
    try {
      const current = lstatSync(root.path);
      if (
        current.isDirectory() &&
        !current.isSymbolicLink() &&
        realpathSync(root.path) === root.path &&
        current.dev === root.identity.device &&
        current.ino === root.identity.inode
      )
        rmSync(root.path, { recursive: true, force: true });
    } catch {
      // The awaited close owner retains failures; exit is best effort only.
    }
  };
  const observeRoot = async (target: CompilerTemporaryOwner) => {
    if (target.identity === undefined)
      throw new Error("Darwin compiler temporary generation is unverified");
    let current;
    try {
      current = await files.lstat(target.path);
    } catch (cause: unknown) {
      if (
        !(cause instanceof Error) ||
        !("code" in cause) ||
        cause.code !== "ENOENT"
      )
        throw cause;
    }
    if (current !== undefined) {
      if (
        !current.isDirectory() ||
        current.isSymbolicLink() ||
        dirname(target.path) !== target.base ||
        current.dev !== target.identity.device ||
        current.ino !== target.identity.inode ||
        (await files.realpath(target.path)) !== target.path
      )
        throw new Error("Darwin compiler temporary generation changed");
    }
    return current;
  };
  const cleanupRoot = async (target = root): Promise<void> => {
    if (target === undefined) return;
    if ((await observeRoot(target)) !== undefined)
      await files.rm(target.path, { recursive: true, force: true });
    try {
      await files.lstat(target.path);
    } catch (cause: unknown) {
      if (
        cause instanceof Error &&
        "code" in cause &&
        cause.code === "ENOENT"
      ) {
        if (root !== target) return;
        root = undefined;
        executable = undefined;
        if (exitCleanupInstalled) process.removeListener("exit", cleanupAtExit);
        exitCleanupInstalled = false;
        return;
      }
      throw cause;
    }
    throw new Error("Darwin compiler temporary removal is incomplete");
  };
  const runCompilation = async (signal: AbortSignal): Promise<string> => {
    let operationRoot: CompilerTemporaryOwner | undefined;
    try {
      // This internal compiler artifact has its own OS temporary owner. Caller
      // analysis TMPDIR/cwd remain unchanged, including Unicode source paths.
      const base = await files.realpath("/tmp");
      if (!isAbsolute(base) || !(await files.lstat(base)).isDirectory())
        throw new Error("Darwin compiler temporary base is not a directory");
      const path = await files.mkdtemp(join(base, "rea-process-token-"));
      if (
        dirname(path) !== base ||
        !basename(path).startsWith("rea-process-token-") ||
        basename(path) === "rea-process-token-"
      )
        throw new Error(
          "Darwin compiler temporary allocation escaped its base",
        );
      operationRoot = { path, base };
      root = operationRoot;
      process.once("exit", cleanupAtExit);
      exitCleanupInstalled = true;
      const generation = await files.lstat(path);
      operationRoot.identity = {
        device: generation.dev,
        inode: generation.ino,
      };
      if (
        !generation.isDirectory() ||
        generation.isSymbolicLink() ||
        (generation.mode & 0o777) !== 0o700 ||
        (await files.realpath(path)) !== path
      )
        throw new Error(
          "Darwin compiler temporary root is not private/canonical",
        );
      if (signal.aborted || closed) throw abortReason(signal);
      const output = join(operationRoot.path, "reader");
      // swiftc keeps intermediate objects under TMPDIR, so keep them inside
      // the root that cleanup removes.
      const compilerTemporary = join(operationRoot.path, "tmp");
      await mkdir(compilerTemporary, { mode: 0o700 });
      const compilerEnvironment: NodeJS.ProcessEnv = {
        ...process.env,
        TMPDIR: compilerTemporary,
      };
      // Use Swift's reusable default cache for REA's internal helper compilation.
      delete compilerEnvironment.CLANG_MODULE_CACHE_PATH;
      try {
        await execFileOutput(
          options.xcrun ?? "/usr/bin/xcrun",
          ["swiftc", ...sourceFiles, "-o", output],
          {
            timeout: 60_000,
            maxBuffer: 1024 * 1024,
            signal,
            stopSignal: SWIFTC_INTERRUPT,
            env: compilerEnvironment,
          },
        );
      } catch (cause: unknown) {
        if (isExpectedAbort(cause, signal)) throw cause;
        const code =
          cause instanceof Error && "code" in cause
            ? String(cause.code)
            : "unknown";
        throw new DarwinProcessOwnershipInspectionError(
          code === "ENOENT"
            ? `macOS process ownership inspection requires the Apple Swift compiler via xcrun (compiler result: ${code})`
            : `macOS process ownership helper compilation failed via xcrun (compiler result: ${code}): ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        );
      }
      if ((await observeRoot(operationRoot)) === undefined)
        throw new Error("Darwin compiler temporary root disappeared");
      if (signal.aborted || closed) throw abortReason(signal);
      executable = output;
      return output;
    } catch (cause: unknown) {
      if (operationRoot !== undefined) {
        try {
          await cleanupRoot(operationRoot);
        } catch (cleanup: unknown) {
          throw new AggregateError(
            [cause, cleanup],
            "Darwin compiler preparation and temporary cleanup failed",
            { cause },
          );
        }
      }
      throw cause;
    }
  };

  const beginCompilation = (): ProcessReaderCompilation => {
    const controller = new AbortController();
    const operation: ProcessReaderCompilation = {
      controller,
      promise: runCompilation(controller.signal).finally(() => {
        operation.settled = true;
        if (compilation === operation) compilation = undefined;
      }),
      waiters: 0,
      aborting: false,
      settled: false,
    };
    compilation = operation;
    return operation;
  };

  const compile = async (signal?: AbortSignal): Promise<string> => {
    if (closed) throw new Error("Darwin process token reader is closed");
    signal?.throwIfAborted();
    while (true) {
      if (closed) throw new Error("Darwin process token reader is closed");
      signal?.throwIfAborted();
      if (executable !== undefined) {
        if (root === undefined || (await observeRoot(root)) === undefined)
          throw new Error("Darwin compiler executable owner is unavailable");
        if (closed) throw new Error("Darwin process token reader is closed");
        signal?.throwIfAborted();
        return executable;
      }
      if (compilation === undefined && root !== undefined) {
        await cleanupRoot();
        continue;
      }
      let operation = compilation;
      if (operation?.aborting === true) {
        try {
          await waitForCompilation(operation.promise, signal);
        } catch (cause: unknown) {
          if (signal !== undefined && isExpectedAbort(cause, signal))
            throw cause;
          if (root !== undefined) throw cause;
        }
        continue;
      }
      operation ??= beginCompilation();
      operation.waiters += 1;
      let primary: unknown;
      try {
        return await waitForCompilation(operation.promise, signal);
      } catch (cause: unknown) {
        primary = cause;
        throw cause;
      } finally {
        operation.waiters -= 1;
        if (
          operation.waiters === 0 &&
          !operation.settled &&
          !operation.aborting
        ) {
          operation.aborting = true;
          operation.controller.abort();
          try {
            await operation.promise;
          } catch (cause: unknown) {
            // An expected abort with successful rollback does not replace the
            // waiter's reason. Failed rollback remains independently visible.
            if (root !== undefined)
              throw primary === undefined || primary === cause
                ? cause
                : new AggregateError(
                    [primary, cause],
                    "Darwin compiler cancellation and temporary cleanup failed",
                    { cause: primary },
                  );
          }
        }
      }
    }
  };

  const read = async (
    processes: readonly ProcessTableEntry[],
  ): Promise<ReadonlyMap<number, ProcessRunTokenObservation>> => {
    if (processes.length === 0) return new Map();
    const binary = await compile();
    const pids = processes.map(({ pid }) => String(pid));
    const { stdout } = await execFileOutput(binary, pids, { timeout: 15_000 });
    const decoded = safeParseJson(stdout);
    if (!decoded.ok)
      throw new Error(
        `macOS process token helper returned invalid JSON: ${decoded.error}`,
        { cause: decoded.cause },
      );
    const parsed = responseSchema.safeParse(decoded.value);
    if (!parsed.success)
      throw new Error(
        "macOS process token helper returned an invalid response",
        {
          cause: parsed.error,
        },
      );
    const requested = new Set(processes.map(({ pid }) => pid));
    const observations = new Map<number, ProcessRunTokenObservation>();
    for (const result of parsed.data.results) {
      if (!requested.has(result.pid) || observations.has(result.pid))
        throw new Error(
          "macOS process token helper returned an unexpected PID set",
        );
      observations.set(
        result.pid,
        result.state === "readable"
          ? { state: "readable", runId: result.run_id }
          : {
              state: "unavailable",
              reason:
                result.reason ?? "process token observation is unavailable",
            },
      );
    }
    if (observations.size !== requested.size)
      throw new Error(
        "macOS process token helper returned an incomplete PID set",
      );
    return observations;
  };

  const identities = async (
    processes: readonly ProcessTableEntry[],
    signal?: AbortSignal,
  ): Promise<ReadonlyMap<number, ProcessIdentityObservation>> => {
    if (processes.length === 0) return new Map();
    const binary = await compile(signal);
    const pids = processes.map(({ pid }) => String(pid));
    const { stdout } = await execFileOutput(binary, ["--identities", ...pids], {
      timeout: 15_000,
      ...(signal === undefined ? {} : { signal }),
    });
    const decoded = safeParseJson(stdout);
    if (!decoded.ok)
      throw new Error(
        `macOS process identity helper returned invalid JSON: ${decoded.error}`,
        { cause: decoded.cause },
      );
    const parsed = identityResponseSchema.safeParse(decoded.value);
    if (!parsed.success)
      throw new Error(
        "macOS process identity helper returned an invalid response",
        {
          cause: parsed.error,
        },
      );
    const requested = new Set(processes.map(({ pid }) => pid));
    const observations = new Map<number, ProcessIdentityObservation>();
    for (const result of parsed.data.results) {
      if (!requested.has(result.pid) || observations.has(result.pid))
        throw new Error(
          "macOS process identity helper returned an unexpected PID set",
        );
      observations.set(
        result.pid,
        result.state === "readable"
          ? { state: "readable", identity: result.identity }
          : { state: "unavailable", reason: result.reason },
      );
    }
    if (observations.size !== requested.size)
      throw new Error(
        "macOS process identity helper returned an incomplete PID set",
      );
    return observations;
  };

  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    closed = true;
    const pendingClose = (async () => {
      let primary: unknown;
      const operation = compilation;
      if (operation !== undefined && !operation.settled) {
        operation.aborting = true;
        operation.controller.abort();
        await operation.promise.catch((cause: unknown) => {
          if (root !== undefined) primary = cause;
        });
      }
      try {
        await cleanupRoot();
      } catch (cleanup: unknown) {
        if (primary !== undefined)
          throw new AggregateError(
            [primary, cleanup],
            "Darwin compiler close and temporary cleanup failed",
            { cause: primary },
          );
        throw cleanup;
      }
      if (primary !== undefined) throw primary;
    })().catch((cause: unknown) => {
      if (closePromise === pendingClose) closePromise = undefined;
      throw cause;
    });
    closePromise = pendingClose;
    return closePromise;
  };

  return { read, identities, prepare: compile, close };
};
