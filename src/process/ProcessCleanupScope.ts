import { AsyncLocalStorage } from "node:async_hooks";

/** One exact process-generation cleanup attempt, independent of public output. */
export interface ProcessCleanupOutcome {
  readonly settled: boolean;
  readonly failures: readonly unknown[];
}

export interface ProcessCleanupSettlement extends ProcessCleanupOutcome {
  readonly unresolved: readonly ProcessCleanupReceipt[];
}

export interface ProcessCleanupOwner {
  readonly identity: Readonly<{ kind: string; runId: string }>;
  readonly close: () => Promise<ProcessCleanupOutcome>;
}

/** Retained authority for a single acquired generation, including failed attempts. */
export class ProcessCleanupReceipt {
  readonly identity: ProcessCleanupOwner["identity"];
  readonly #failures: unknown[] = [];
  #close: ProcessCleanupOwner["close"];
  #bound = false;
  #status: "active" | "closing" | "settled" | "unresolved" = "active";
  #pending: Promise<ProcessCleanupOutcome> | undefined;

  constructor(owner: ProcessCleanupOwner) {
    this.identity = Object.freeze({ ...owner.identity });
    this.#close = owner.close;
  }

  get status(): "active" | "closing" | "settled" | "unresolved" {
    return this.#status;
  }

  get failures(): readonly unknown[] {
    return this.#failures.slice();
  }

  /** Adopt the supervisor for this acquired child without replacing its identity. */
  bindClose(close: ProcessCleanupOwner["close"]): void {
    if (
      this.#bound ||
      this.#pending !== undefined ||
      this.#status === "settled"
    )
      throw new Error("Process cleanup owner cannot be rebound");
    this.#bound = true;
    this.#close = close;
  }

  recordOutcome(outcome: ProcessCleanupOutcome): void {
    for (const failure of outcome.failures)
      if (!this.#failures.includes(failure)) this.#failures.push(failure);
    this.#status = outcome.settled ? "settled" : "unresolved";
  }

  close(): Promise<ProcessCleanupOutcome> {
    if (this.#pending !== undefined) return this.#pending;
    if (this.#status === "settled")
      return Promise.resolve({ settled: true, failures: this.failures });
    this.#status = "closing";
    const attempt = Promise.resolve()
      .then(this.#close)
      .catch((cause: unknown) => ({
        settled: false,
        failures: [cause],
      }))
      .then((outcome) => {
        this.recordOutcome(outcome);
        return { settled: outcome.settled, failures: this.failures };
      })
      .finally(() => {
        if (this.#pending === attempt) this.#pending = undefined;
      });
    this.#pending = attempt;
    return attempt;
  }

  retry(): Promise<ProcessCleanupOutcome> {
    return this.close();
  }
}

/** Explicitly supplied invocation ownership; there is no ambient default scope. */
export class ProcessCleanupScope {
  readonly #owners: ProcessCleanupReceipt[] = [];
  #terminal = false;
  #pending: Promise<ProcessCleanupSettlement> | undefined;

  register(owner: ProcessCleanupOwner): ProcessCleanupReceipt {
    this.assertAccepting();
    const receipt = new ProcessCleanupReceipt(owner);
    this.#owners.push(receipt);
    return receipt;
  }

  assertAccepting(): void {
    if (this.#terminal)
      throw new Error("Process cleanup registration is closed");
  }

  get owners(): readonly ProcessCleanupReceipt[] {
    return this.#owners.slice();
  }

  close(): Promise<ProcessCleanupSettlement> {
    this.#terminal = true;
    if (this.#pending !== undefined) return this.#pending;
    const attempt = Promise.all(this.#owners.map((owner) => owner.close()))
      .then((outcomes) => ({
        settled: outcomes.every((outcome) => outcome.settled),
        failures: this.#owners.flatMap((owner) => owner.failures),
        unresolved: this.#owners.filter((owner) => owner.status !== "settled"),
      }))
      .finally(() => {
        if (this.#pending === attempt) this.#pending = undefined;
      });
    this.#pending = attempt;
    return attempt;
  }
}

const invocationScope = new AsyncLocalStorage<ProcessCleanupScope>();

/** Check immediately before synchronous acquisition so refused registration cannot orphan a child. */
export const assertProcessCleanupRegistrationOpen = (): void =>
  invocationScope.getStore()?.assertAccepting();

export const withProcessCleanupScope = async <Value>(
  scope: ProcessCleanupScope,
  operation: () => Promise<Value>,
): Promise<Value> => invocationScope.run(scope, operation);

export const registerProcessCleanupOwner = (
  owner: ProcessCleanupOwner,
): ProcessCleanupReceipt | undefined =>
  invocationScope.getStore()?.register(owner);
