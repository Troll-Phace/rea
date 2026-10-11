import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import {
  ProcessCleanupScope,
  withProcessCleanupScope,
  type ProcessCleanupSettlement,
} from "../process/ProcessCleanupScope.js";

export interface CliCleanupOwner {
  readonly identity: object;
  readonly state: "active" | "closing" | "settled" | "unresolved";
  readonly failures: readonly unknown[];
  readonly close: () => Promise<Result<void, AnalysisError>>;
  readonly retry: () => Promise<Result<void, AnalysisError>>;
}

export interface CliCleanupReceipt {
  readonly settled: boolean;
  readonly unresolved: readonly CliCleanupOwner[];
  readonly failures: readonly unknown[];
  readonly processes: ProcessCleanupSettlement;
}

interface CleanupRecord {
  readonly owner: CliCleanupOwner;
  readonly pending: Set<Promise<unknown>>;
  readonly failures: unknown[];
  state: CliCleanupOwner["state"];
  lastClosed: boolean;
}

/** One CLI instance owns its actual close results before public projection. */
export class CliCleanupScope {
  readonly processScope = new ProcessCleanupScope();
  readonly #records = new Map<CliCleanupOwner, CleanupRecord>();
  #terminal = false;
  #settlement: Promise<CliCleanupReceipt> | undefined;

  run<Value>(operation: () => Promise<Value>): Promise<Value> {
    return withProcessCleanupScope(this.processScope, operation);
  }

  register(
    identity: object,
    close: () => Promise<Result<void, AnalysisError>>,
  ): CliCleanupOwner {
    if (this.#terminal) throw new Error("CLI cleanup registration is closed");
    const failures: unknown[] = [];
    const owner: CliCleanupOwner = {
      identity,
      get state() {
        return record.state;
      },
      get failures() {
        return failures.slice();
      },
      close: () => this.observe(owner, close),
      retry: () => owner.close(),
    };
    const record: CleanupRecord = {
      owner,
      pending: new Set(),
      failures,
      state: "active",
      lastClosed: false,
    };
    this.#records.set(owner, record);
    return owner;
  }

  /** Preserve the exact operation Result/rejection; only its owner state changes. */
  observe<Value>(
    owner: CliCleanupOwner,
    close: () => Promise<Result<Value, AnalysisError>>,
  ): Promise<Result<Value, AnalysisError>> {
    const record = this.#records.get(owner);
    if (record === undefined)
      throw new Error("CLI cleanup owner is unregistered");
    record.state = "closing";
    const pending = Promise.resolve()
      .then(close)
      .then(
        (result) => {
          record.lastClosed = result.ok;
          if (!result.ok) record.failures.push(result.error);
          return result;
        },
        (cause: unknown) => {
          record.lastClosed = false;
          record.failures.push(cause);
          throw cause;
        },
      )
      .finally(() => {
        record.pending.delete(pending);
        record.state =
          record.pending.size > 0
            ? "closing"
            : record.lastClosed
              ? "settled"
              : "unresolved";
      });
    record.pending.add(pending);
    return pending;
  }

  /** An empty receipt speaks only for this scope, never unregistered commands. */
  settle(): Promise<CliCleanupReceipt> {
    this.#terminal = true;
    if (this.#settlement !== undefined) return this.#settlement;
    const drain = async () => {
      await Promise.all(
        [...this.#records.values()].map(async (record) => {
          await Promise.allSettled(record.pending);
          if (record.state !== "settled")
            await record.owner.close().catch(() => undefined);
        }),
      );
    };
    const attempt = this.run(async () => {
      await drain();
      const processes = await this.processScope.close();
      if (
        processes.settled &&
        [...this.#records.values()].some((record) => record.state !== "settled")
      )
        await drain();
      const records = [...this.#records.values()];
      return {
        settled:
          processes.settled &&
          records.every((record) => record.state === "settled"),
        unresolved: records
          .filter((record) => record.state !== "settled")
          .map((record) => record.owner),
        failures: [
          ...records.flatMap((record) => record.failures),
          ...processes.failures,
        ],
        processes,
      };
    });
    this.#settlement = attempt;
    const release = (): void => {
      if (this.#settlement === attempt) this.#settlement = undefined;
    };
    void attempt.then(release, release);
    return attempt;
  }
}
