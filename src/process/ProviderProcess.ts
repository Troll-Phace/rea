import { spawn, type ChildProcess } from "node:child_process";
import type { EventEmitter } from "node:events";
import type { Readable, Writable } from "node:stream";

import { WindowsOwnedProcess } from "../windows/WindowsOwnedProcess.js";

import type {
  OwnedProcessGroup,
  ProcessCleanupResult,
} from "./ProcessOwnership.js";
import { cleanupOwnedProcessGroup } from "./ProcessOwnership.js";
import {
  assertProcessCleanupRegistrationOpen,
  registerProcessCleanupOwner,
  ProcessCleanupReceipt,
  type ProcessCleanupOutcome,
} from "./ProcessCleanupScope.js";
import { prepareProcessOwnershipInspection } from "./ProcessOwnershipObservation.js";

const DEFAULT_TERMINATION_GRACE_MS = 250;
const DEFAULT_KILL_GRACE_MS = 1_000;
const cleanupReceiptKey = Symbol("REA acquired child cleanup receipt");
const observationKey = Symbol("REA acquired child observations");
type ObservedProcessHandle = ProviderProcessHandle & {
  readonly [observationKey]?: ProviderProcessObservation;
};

type ReceiptedProcessHandle = ProviderProcessHandle & {
  readonly [cleanupReceiptKey]?: ProcessCleanupReceipt;
};

/** Spawn coordinates shared by owned, long-lived provider processes. */
export interface OwnedProviderProcessSpawnOptions {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly runId: string;
  /** Null disables argv-prefix matching for interpreter-driven launch scripts. */
  readonly expectedCommand?: string | null;
  /** Preserve a pre-quoted Windows command-interpreter invocation exactly. */
  readonly windowsVerbatimArguments?: boolean;
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Host platform used to choose detached process-group behavior. */
  readonly platform?: NodeJS.Platform;
  /** Host environment used as the base for the child environment. */
  readonly hostEnvironment?: NodeJS.ProcessEnv;
  /** Opt into a writable protocol stream; other providers retain ignored stdin. */
  readonly stdin?: "pipe";
  /** Cancels native ownership preparation before provider process creation. */
  readonly signal?: AbortSignal;
  readonly observation?: ProviderProcessObservationPolicy;
  /** Installs protocol handlers synchronously before any awaited publication. */
  readonly onAcquired?: (process: ProviderProcessHandle) => void;
}

/** Spawned process paired with the identity proof required for group cleanup. */
export interface SpawnedOwnedProviderProcess {
  readonly process: ProviderProcessHandle;
  readonly ownership: OwnedProcessGroup;
  readonly cleanup?: () => Promise<ProcessCleanupResult>;
  readonly cleanupReceipt?: ProcessCleanupReceipt;
}

/** Process events and streams required by provider lifecycle supervision. */
export interface ProviderProcessHandle extends Pick<
  EventEmitter,
  "on" | "once" | "off"
> {
  readonly pid?: number | undefined;
  readonly stdout: Readable | null;
  readonly stdin?: Writable | null;
  readonly stderr: Readable | null;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  kill(signal?: NodeJS.Signals | number): boolean;
}

/** Process handle returned by a provider-specific launcher. */
export type ProviderProcessLaunch =
  | {
      readonly process: ProviderProcessHandle;
      readonly ownsProcessLifetime: false;
      readonly ownership?: never;
      readonly cleanup?: never;
    }
  | {
      readonly process: ProviderProcessHandle;
      readonly ownsProcessLifetime: true;
      readonly ownership?: OwnedProcessGroup;
      readonly cleanup?: () => Promise<ProcessCleanupResult>;
      readonly cleanupReceipt?: ProcessCleanupReceipt;
    };

/** Detached diagnostics captured for one supervised provider process. */
export interface ProviderProcessObservationPolicy extends ProviderProcessSupervisorOptions {}

export interface ProviderProcessObservationSnapshot {
  readonly snapshot: ProviderProcessSnapshot;
  readonly coverage: "complete" | "pre-acquisition-unavailable";
  readonly observedBytes: { readonly stdout: number; readonly stderr: number };
  readonly errors: readonly Error[];
  readonly outputClosed: boolean;
  readonly actualExit?: {
    readonly code: number | null;
    readonly signal: NodeJS.Signals | null;
  };
}

export interface ProviderProcessSnapshot {
  /** True only when a configured diagnostic budget excluded output bytes. */
  readonly diagnosticTruncated?: boolean;
  readonly stdout: {
    readonly text: string;
    readonly bytes: number;
  };
  readonly stderr: {
    readonly text: string;
    readonly bytes: number;
  };
  readonly exitCode: number | null | undefined;
  readonly signal: NodeJS.Signals | null | undefined;
}

/** Resource-safe events emitted without imposing provider protocol semantics. */
export type ProviderProcessDiagnostic =
  | {
      readonly type: "output";
      readonly stream: "stdout" | "stderr";
      readonly bytes: number;
      readonly totalBytes: number;
      readonly truncated?: boolean;
    }
  | {
      readonly type: "exit";
      readonly code: number | null;
      readonly signal: NodeJS.Signals | null;
      readonly snapshot: ProviderProcessSnapshot;
    }
  | { readonly type: "error"; readonly message: string };

/** Options for process lifecycle diagnostics. */
export interface ProviderProcessSupervisorOptions {
  /** Retain stdout for diagnostics; disable when it carries a parsed protocol. Defaults to true. */
  readonly captureStdout?: boolean;
  /** Aggregate retained stdout/stderr byte budget; overflow is drained and reported, not retained. */
  readonly maxDiagnosticBytes?: number;
  readonly onDiagnostic?: (event: ProviderProcessDiagnostic) => void;
}

/** Optional result of provider-specific cleanup performed before stop. */
export interface ProviderProcessStopOptions {
  readonly cleanupResult?: ProcessCleanupResult;
  readonly terminationGraceMs?: number;
  readonly killGraceMs?: number;
}

/** Exact disposition of one owned process stop attempt. */
export type ProviderProcessStopResult =
  | {
      readonly status:
        | "not-owned"
        | "already-exited"
        | "verified-cleanup"
        | "terminated"
        | "killed";
    }
  | {
      readonly status: "incomplete";
      readonly reason: string;
      readonly cause?: unknown;
    };

/** Controlled launchers share the same synchronous acquisition contract as production. */
export const acquireProviderProcessObservation = (
  process: ProviderProcessHandle,
  policy: ProviderProcessObservationPolicy = {},
): void => {
  acquireObservation(process, policy, "complete");
};

const acquireObservation = (
  process: ProviderProcessHandle,
  policy: ProviderProcessObservationPolicy,
  coverage: "complete" | "pre-acquisition-unavailable",
): ProviderProcessObservation => {
  if ((process as ObservedProcessHandle)[observationKey] !== undefined)
    throw new Error("Provider child observation already acquired");
  const observation = new ProviderProcessObservation(
    process,
    policy,
    coverage === "complete" &&
      (process.exitCode !== null ||
        process.signalCode !== null ||
        process.stdout?.readableDidRead === true ||
        process.stderr?.readableDidRead === true)
      ? "pre-acquisition-unavailable"
      : coverage,
  );
  Object.defineProperty(process, observationKey, { value: observation });
  return observation;
};

/**
 * Spawn a provider in an owned Windows job or dedicated POSIX process group.
 *
 * The caller remains responsible for persisting any ownership manifest and for
 * selecting provider-specific command arguments or environment values.
 */
export const spawnOwnedProviderProcess = async (
  options: OwnedProviderProcessSpawnOptions,
): Promise<SpawnedOwnedProviderProcess> => {
  options.signal?.throwIfAborted();
  await prepareProcessOwnershipInspection(options.signal);
  options.signal?.throwIfAborted();
  const platform = options.platform ?? process.platform;
  const hostEnvironment = options.hostEnvironment ?? process.env;
  const environment = {
    ...hostEnvironment,
    ...options.env,
    REA_PROCESS_RUN_ID: options.runId,
  };
  assertProcessCleanupRegistrationOpen();
  if (platform === "win32" && process.platform === "win32") {
    const child = new WindowsOwnedProcess(
      options.command,
      options.arguments,
      options.cwd,
      environment,
      options.windowsVerbatimArguments ?? false,
      options.stdin === "pipe",
    );
    acquireProviderProcessObservation(child, options.observation);
    const closeChild = () => child.cleanup();
    const receipt = retainPendingChild(child, options.runId, closeChild);
    try {
      options.onAcquired?.(child);
    } catch (cause: unknown) {
      const cleanup = await (receipt?.close() ??
        settlePendingChild(child, closeChild));
      return throwAcquisitionFailure(
        child,
        options.runId,
        closeChild,
        receipt,
        cause,
        cleanup,
      );
    }
    return {
      process: child,
      ownership: {
        runId: options.runId,
        leaderPid: child.pid,
        processGroupId: child.pid,
        expectedParentPid: process.pid,
      },
      cleanup: () => child.cleanup(),
      ...(receipt === undefined ? {} : { cleanupReceipt: receipt }),
    };
  }
  const child = spawn(options.command, [...options.arguments], {
    shell: false,
    windowsHide: true,
    stdio: [options.stdin ?? "ignore", "pipe", "pipe"],
    detached: platform !== "win32",
    windowsVerbatimArguments: options.windowsVerbatimArguments ?? false,
    env: environment,
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
  });
  acquireProviderProcessObservation(child, options.observation);
  const ownershipFor = (pid: number): OwnedProcessGroup => ({
    runId: options.runId,
    leaderPid: pid,
    processGroupId: pid,
    expectedParentPid: process.pid,
    ...(options.expectedCommand === null
      ? {}
      : { expectedCommand: options.expectedCommand ?? options.command }),
  });
  let ownership = child.pid === undefined ? undefined : ownershipFor(child.pid);
  const closeChild = async (): Promise<ProcessCleanupResult> =>
    ownership === undefined
      ? {
          cleaned: false,
          reason: "Provider child ownership was not established",
        }
      : cleanupOwnedProcessGroup(ownership);
  const receipt = retainPendingChild(child, options.runId, closeChild);
  try {
    const spawning = waitForSpawn(child);
    // The hook can reject before this promise is awaited; retain its spawn error too.
    void spawning.catch(() => undefined);
    options.onAcquired?.(child);
    await spawning;
    const pid = child.pid;
    if (pid === undefined)
      throw new Error("Provider launcher has no process ID");
    ownership ??= ownershipFor(pid);
    return {
      process: child,
      ownership,
      ...(receipt === undefined ? {} : { cleanupReceipt: receipt }),
    };
  } catch (cause: unknown) {
    const cleanup = await (receipt?.close() ??
      settlePendingChild(child, closeChild));
    return throwAcquisitionFailure(
      child,
      options.runId,
      closeChild,
      receipt,
      cause,
      cleanup,
    );
  }
};

/** Internal acquisition failure retains authority before any public error projection. */
export class ProviderProcessAcquisitionError extends AggregateError {
  declare readonly cleanupOwner: ProcessCleanupReceipt | undefined;
  declare readonly observation: ProviderProcessObservationSnapshot | undefined;

  constructor(
    primary: unknown,
    failures: readonly unknown[],
    owner: ProcessCleanupReceipt | undefined,
    observation: ProviderProcessObservationSnapshot | undefined,
  ) {
    super(failures, "Provider acquisition, capture, or cleanup failed", {
      cause: primary,
    });
    Object.defineProperties(this, {
      cleanupOwner: { value: owner },
      observation: { value: observation },
    });
  }
}

const throwAcquisitionFailure = (
  child: ProviderProcessHandle,
  runId: string,
  closeChild: () => Promise<ProcessCleanupResult>,
  receipt: ProcessCleanupReceipt | undefined,
  cause: unknown,
  cleanup: ProcessCleanupOutcome,
): never => {
  const observation = (child as ObservedProcessHandle)[
    observationKey
  ]?.observation();
  const failures = [
    ...new Set([cause, ...(observation?.errors ?? []), ...cleanup.failures]),
  ];
  if (failures.length === 1 && cleanup.settled) throw cause;
  const owner = cleanup.settled
    ? receipt
    : (receipt ??
      new ProcessCleanupReceipt({
        identity: { kind: "provider-child", runId },
        close: () => settlePendingChild(child, closeChild),
      }));
  owner?.recordOutcome(cleanup);
  throw new ProviderProcessAcquisitionError(
    cause,
    failures,
    owner,
    observation,
  );
};

/** Retain the actual handle before awaited publication; never authorize a PID-only sweep. */
const retainPendingChild = (
  child: ProviderProcessHandle,
  runId: string,
  cleanup: () => Promise<ProcessCleanupResult>,
): ProcessCleanupReceipt | undefined => {
  const receipt = registerProcessCleanupOwner({
    identity: { kind: "provider-child", runId },
    close: () => settlePendingChild(child, cleanup),
  });
  if (receipt !== undefined)
    Object.defineProperty(child, cleanupReceiptKey, { value: receipt });
  return receipt;
};

const settlePendingChild = async (
  child: ProviderProcessHandle,
  cleanup: () => Promise<ProcessCleanupResult>,
): Promise<ProcessCleanupOutcome> => {
  const observation = (child as ObservedProcessHandle)[observationKey];
  try {
    if (observation === undefined)
      return {
        settled: false,
        failures: [new Error("Provider acquisition observations unavailable")],
      };
    if (
      child.pid === undefined &&
      (await observation.waitForOutputClose(DEFAULT_KILL_GRACE_MS))
    )
      return { settled: true, failures: observation.observation().errors };
    const result = await cleanup();
    if (!result.cleaned) return { settled: false, failures: [result] };
    const complete = await observation.waitForOutputClose(
      DEFAULT_KILL_GRACE_MS,
    );
    return {
      settled: complete,
      failures: [
        ...observation.observation().errors,
        ...(complete
          ? []
          : [new Error("Provider child output closure was not observed")]),
      ],
    };
  } catch (cause: unknown) {
    return { settled: false, failures: [cause] };
  }
};

/**
 * Supervises only generic process resources; wire protocol remains adapter-owned.
 *
 * Output retention is complete per stream; adapters own resource budgets. Stop
 * first honors token-verified group cleanup when supplied, otherwise it uses a
 * bounded TERM-to-KILL escalation for a directly owned child.
 */
export class ProviderProcessSupervisor {
  readonly #observation: ProviderProcessObservation;
  readonly #receipt: ProcessCleanupReceipt | undefined;
  #stopPromise: Promise<ProviderProcessStopResult> | undefined;

  constructor(
    readonly launch: ProviderProcessLaunch,
    options: ProviderProcessSupervisorOptions = {},
  ) {
    this.#observation =
      (launch.process as ObservedProcessHandle)[observationKey] ??
      acquireObservation(
        launch.process,
        options,
        "pre-acquisition-unavailable",
      );
    this.#observation.adopt(options);
    const acquiredReceipt = launch.ownsProcessLifetime
      ? (launch.cleanupReceipt ??
        (launch.process as ReceiptedProcessHandle)[cleanupReceiptKey])
      : undefined;
    this.#receipt = launch.ownsProcessLifetime
      ? (acquiredReceipt ??
        (launch.ownership === undefined
          ? undefined
          : registerProcessCleanupOwner({
              identity: {
                kind: "provider-child",
                runId: launch.ownership.runId,
              },
              close: () => this.#closeForScope(),
            })))
      : undefined;
    if (acquiredReceipt !== undefined && acquiredReceipt.status !== "settled")
      acquiredReceipt.bindClose(() => this.#closeForScope());
  }

  snapshot(): ProviderProcessSnapshot {
    return this.#observation.snapshot();
  }
  observation(): ProviderProcessObservationSnapshot {
    return this.#observation.observation();
  }
  resetOutput(): void {
    this.#observation.resetOutput();
  }
  waitForExit(timeoutMs: number): Promise<boolean> {
    return this.#observation.waitForExit(timeoutMs);
  }
  waitForOutputClose(timeoutMs: number): Promise<boolean> {
    return this.#observation.waitForOutputClose(timeoutMs);
  }

  /** Share each stop attempt; incomplete cleanup retains ownership and permits retry. */
  stop(
    options: ProviderProcessStopOptions = {},
  ): Promise<ProviderProcessStopResult> {
    this.#stopPromise ??= this.#stop(options).then(
      (result) => {
        if (result.status === "incomplete") this.#stopPromise = undefined;
        this.#receipt?.recordOutcome({
          settled: result.status !== "incomplete",
          failures: [
            ...(result.status === "incomplete" ? [result] : []),
            ...this.#observation.observation().errors,
          ],
        });
        return result;
      },
      (cause: unknown) => {
        this.#stopPromise = undefined;
        this.#receipt?.recordOutcome({ settled: false, failures: [cause] });
        throw cause;
      },
    );
    return this.#stopPromise;
  }

  /** Release this one observation consumer only after owned cleanup settles. */
  dispose(): void {
    if (this.#receipt !== undefined && this.#receipt.status !== "settled")
      return;
    this.#observation.dispose();
  }

  async #stop(
    options: ProviderProcessStopOptions,
  ): Promise<ProviderProcessStopResult> {
    let completed = false;
    try {
      const result = await this.#stopWithin(options);
      if (
        this.launch.ownsProcessLifetime &&
        this.#observation.coverage === "complete" &&
        result.status !== "incomplete" &&
        !(await this.waitForOutputClose(
          options.killGraceMs ?? DEFAULT_KILL_GRACE_MS,
        ))
      )
        return {
          status: "incomplete",
          reason: "Provider exited without complete output closure",
        };
      completed = result.status !== "incomplete";
      this.#receipt?.recordOutcome({
        settled: completed,
        failures: [
          ...(completed ? [] : [result]),
          ...this.#observation.observation().errors,
        ],
      });
      return result;
    } finally {
      if (completed) this.dispose();
    }
  }

  async #closeForScope() {
    const result = await this.stop();
    return {
      settled: result.status !== "incomplete",
      failures: [
        ...(result.status === "incomplete" ? [result] : []),
        ...this.#observation.observation().errors,
      ],
    };
  }

  async #stopWithin(
    options: ProviderProcessStopOptions,
  ): Promise<ProviderProcessStopResult> {
    try {
      if (!this.launch.ownsProcessLifetime) return { status: "not-owned" };
      if (this.launch.cleanup !== undefined) {
        const cleanup = await this.#ownedCleanup(options.cleanupResult);
        if (!cleanup.cleaned)
          return {
            status: "incomplete",
            reason: cleanup.reason,
            cause: cleanup,
          };
        const graceMs = options.killGraceMs ?? DEFAULT_KILL_GRACE_MS;
        if (await this.waitForExit(graceMs))
          return { status: "verified-cleanup" };
        const retried = await this.launch.cleanup();
        if (!retried.cleaned)
          return {
            status: "incomplete",
            reason: retried.reason,
            cause: retried,
          };
        if (await this.waitForExit(graceMs))
          return { status: "verified-cleanup" };
        return {
          status: "incomplete",
          reason: "verified process-group cleanup did not stop the launcher",
        };
      }

      if (this.#observation.exitObservation !== undefined)
        return { status: "already-exited" };

      this.#signal("SIGTERM");
      if (
        await this.waitForExit(
          options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS,
        )
      )
        return { status: "terminated" };
      this.#signal("SIGKILL");
      if (await this.waitForExit(options.killGraceMs ?? DEFAULT_KILL_GRACE_MS))
        return { status: "killed" };
      return {
        status: "incomplete",
        reason: "owned provider process did not exit after SIGKILL",
      };
    } catch (cause: unknown) {
      return {
        status: "incomplete",
        cause,
        reason:
          cause instanceof Error
            ? cause.message
            : "owned provider process cleanup failed",
      };
    }
  }

  #ownedCleanup(
    supplied: ProcessCleanupResult | undefined,
  ): Promise<ProcessCleanupResult> {
    if (supplied !== undefined) return Promise.resolve(supplied);
    const cleanup = this.launch.cleanup;
    return cleanup === undefined
      ? Promise.resolve({
          cleaned: false,
          reason: "owned provider process has no cleanup capability",
        })
      : cleanup();
  }

  #signal(signal: NodeJS.Signals): void {
    if (this.#observation.exitObservation !== undefined) return;
    this.launch.process.kill(signal);
  }
}

/** One acquired child's actual byte and lifecycle observations, before publication. */
class ProviderProcessObservation {
  readonly #policy: Readonly<ProviderProcessObservationPolicy>;
  readonly #callbacks = new Set<
    NonNullable<ProviderProcessSupervisorOptions["onDiagnostic"]>
  >();
  readonly #errors: Error[] = [];
  #adopted = false;
  #disposed = false;
  readonly #stdout = new ProcessOutputCapture();
  readonly #stderr = new ProcessOutputCapture();
  readonly #exit = deferred<{
    readonly code: number | null;
    readonly signal: NodeJS.Signals | null;
  }>();
  readonly #outputClose = deferred<void>();
  #outputClosed = false;
  #stdoutObservedBytes = 0;
  #stderrObservedBytes = 0;
  #diagnosticTruncated = false;
  readonly #onStdout = (chunk: Buffer | string): void => {
    this.#capture("stdout", this.#stdout, chunk);
  };
  readonly #onStderr = (chunk: Buffer | string): void => {
    this.#capture("stderr", this.#stderr, chunk);
  };
  readonly #onStdoutError = (cause: Error): void => {
    this.#recordStreamError("stdout", cause);
  };
  readonly #onStderrError = (cause: Error): void => {
    this.#recordStreamError("stderr", cause);
  };
  readonly #onExit = (
    code: number | null,
    signal: NodeJS.Signals | null,
  ): void => {
    this.#recordExit(code, signal);
  };
  readonly #onClose = (
    code: number | null,
    signal: NodeJS.Signals | null,
  ): void => {
    this.#recordExit(code, signal);
    this.#outputClosed = true;
    this.#outputClose.resolve(undefined);
  };
  readonly #onError = (cause: Error): void => {
    this.#errors.push(cause);
    this.#notify({ type: "error", message: cause.message });
  };
  #actualExitObserved = false;
  #exitObservation:
    | { readonly code: number | null; readonly signal: NodeJS.Signals | null }
    | undefined;

  constructor(
    readonly process: ProviderProcessHandle,
    policy: ProviderProcessObservationPolicy,
    readonly coverage: "complete" | "pre-acquisition-unavailable",
  ) {
    this.#policy = Object.freeze({
      captureStdout: policy.captureStdout !== false,
      ...(policy.maxDiagnosticBytes === undefined
        ? {}
        : { maxDiagnosticBytes: policy.maxDiagnosticBytes }),
    });
    if (policy.onDiagnostic !== undefined)
      this.#callbacks.add(policy.onDiagnostic);
    if (this.#policy.captureStdout !== false)
      this.#attach(process.stdout, "stdout");
    else process.stdout?.on("error", this.#onStdoutError);
    this.#attach(process.stderr, "stderr");
    process.once("exit", this.#onExit);
    process.once("close", this.#onClose);
    process.on("error", this.#onError);
    if (
      coverage !== "complete" &&
      (process.exitCode !== null || process.signalCode !== null)
    ) {
      this.#exitObservation = {
        code: process.exitCode,
        signal: process.signalCode,
      };
      this.#exit.resolve(this.#exitObservation);
    }
  }

  adopt(options: ProviderProcessSupervisorOptions): void {
    if (this.#adopted)
      throw new Error("Provider child observation already adopted");
    if (
      (options.captureStdout !== undefined &&
        options.captureStdout !== this.#policy.captureStdout) ||
      (options.maxDiagnosticBytes !== undefined &&
        options.maxDiagnosticBytes !== this.#policy.maxDiagnosticBytes)
    )
      throw new Error(
        "Provider observation policy cannot change after acquisition",
      );
    this.#adopted = true;
    if (options.onDiagnostic !== undefined)
      this.#callbacks.add(options.onDiagnostic);
  }

  get exitObservation() {
    return this.#exitObservation;
  }
  observation(): ProviderProcessObservationSnapshot {
    return {
      snapshot: this.snapshot(),
      coverage: this.coverage,
      observedBytes: {
        stdout: this.#stdoutObservedBytes,
        stderr: this.#stderrObservedBytes,
      },
      errors: this.#errors.slice(),
      outputClosed: this.#outputClosed,
      ...(this.#exitObservation === undefined || !this.#actualExitObserved
        ? {}
        : { actualExit: this.#exitObservation }),
    };
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.process.stdout?.off("data", this.#onStdout);
    this.process.stdout?.off("error", this.#onStdoutError);
    this.process.stderr?.off("data", this.#onStderr);
    this.process.stderr?.off("error", this.#onStderrError);
    this.process.off("exit", this.#onExit);
    this.process.off("close", this.#onClose);
    this.process.off("error", this.#onError);
  }

  #notify(event: ProviderProcessDiagnostic): void {
    for (const callback of this.#callbacks) {
      try {
        callback(event);
      } catch (cause: unknown) {
        this.#errors.push(
          cause instanceof Error
            ? cause
            : new Error("Provider diagnostic callback failed", { cause }),
        );
      }
    }
  }

  /** Latest retained output and exit observation, with explicit configured truncation. */
  snapshot(): ProviderProcessSnapshot {
    return {
      ...(this.#diagnosticTruncated ? { diagnosticTruncated: true } : {}),
      stdout: this.#stdout.snapshot(),
      stderr: this.#stderr.snapshot(),
      exitCode: this.#exitObservation?.code,
      signal: this.#exitObservation?.signal,
    };
  }

  /** Begin a new observation on a retained process without retaining earlier output. */
  resetOutput(): void {
    this.#stdout.reset();
    this.#stderr.reset();
    this.#stdoutObservedBytes = 0;
    this.#stderrObservedBytes = 0;
    this.#diagnosticTruncated = false;
  }

  /** Wait for process exit up to a caller-owned bounded interval. */
  async waitForExit(timeoutMs: number): Promise<boolean> {
    return waitForProcessEvent(
      this.#exitObservation !== undefined,
      this.#exit.promise,
      timeoutMs,
    );
  }

  /** Wait until the producer has closed its output streams; exit alone does not prove complete output. */
  async waitForOutputClose(timeoutMs: number): Promise<boolean> {
    return waitForProcessEvent(
      this.#outputClosed,
      this.#outputClose.promise,
      timeoutMs,
    );
  }

  #attach(stream: Readable | null, name: "stdout" | "stderr"): void {
    if (name === "stdout") {
      stream?.on("data", this.#onStdout);
      stream?.on("error", this.#onStdoutError);
    } else {
      stream?.on("data", this.#onStderr);
      stream?.on("error", this.#onStderrError);
    }
  }

  #recordStreamError(stream: "stdout" | "stderr", cause: Error): void {
    this.#errors.push(cause);
    this.#notify({
      type: "error",
      message: `${stream} stream failed: ${cause.message}`,
    });
  }

  #capture(
    stream: "stdout" | "stderr",
    capture: ProcessOutputCapture,
    chunk: Buffer | string,
  ): void {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (stream === "stdout") this.#stdoutObservedBytes += bytes.byteLength;
    else this.#stderrObservedBytes += bytes.byteLength;
    const remaining =
      this.#policy.maxDiagnosticBytes === undefined
        ? bytes.byteLength
        : Math.max(
            0,
            this.#policy.maxDiagnosticBytes -
              this.#stdout.bytes -
              this.#stderr.bytes,
          );
    const retained = Math.min(bytes.byteLength, remaining);
    if (retained < bytes.byteLength) this.#diagnosticTruncated = true;
    if (retained > 0) capture.append(bytes.subarray(0, retained));
    this.#notify({
      type: "output",
      stream,
      bytes: bytes.byteLength,
      totalBytes:
        stream === "stdout"
          ? this.#stdoutObservedBytes
          : this.#stderrObservedBytes,
      ...(retained < bytes.byteLength ? { truncated: true } : {}),
    });
  }

  #recordExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.#actualExitObserved) return;
    this.#actualExitObserved = true;
    this.#exitObservation = { code, signal };
    this.#exit.resolve(this.#exitObservation);
    this.#notify({
      type: "exit",
      code,
      signal,
      snapshot: this.snapshot(),
    });
  }
}

class ProcessOutputCapture {
  readonly #chunks: Buffer[] = [];
  #bytes = 0;

  get bytes(): number {
    return this.#bytes;
  }

  reset(): void {
    this.#chunks.length = 0;
    this.#bytes = 0;
  }

  append(chunk: Buffer): void {
    this.#bytes += chunk.byteLength;
    this.#chunks.push(Buffer.from(chunk));
  }

  snapshot(): ProviderProcessSnapshot["stdout"] {
    const text = Buffer.concat(this.#chunks, this.#bytes).toString("utf8");
    return {
      text,
      bytes: this.#bytes,
    };
  }
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  readonly resolve: (value: Value) => void;
}

const deferred = <Value>(): Deferred<Value> => {
  let resolver: ((value: Value) => void) | undefined;
  const promise = new Promise<Value>((resolve) => {
    resolver = resolve;
  });
  return {
    promise,
    resolve: (value) => {
      resolver?.(value);
    },
  };
};

const waitForSpawn = (child: ChildProcess): Promise<void> =>
  new Promise((resolve, reject) => {
    const onSpawn = (): void => {
      child.off("error", onError);
      resolve();
    };
    const onError = (cause: Error): void => {
      child.off("spawn", onSpawn);
      reject(cause);
    };
    child.once("spawn", onSpawn);
    child.once("error", onError);
  });

const waitForProcessEvent = async (
  observed: boolean,
  event: Promise<unknown>,
  timeoutMs: number,
): Promise<boolean> => {
  if (observed) return true;
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      event.then(() => true),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), Math.max(0, timeoutMs));
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};
