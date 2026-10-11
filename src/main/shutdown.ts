import type { StdioServerHandle } from "@modelcontextprotocol/server/stdio";

import type { BinarySession } from "../application/binary/BinarySession.js";
import type { Logger } from "pino";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type {
  RuntimeCleanupOwner,
  RuntimeDependencies,
  RuntimeShutdown,
  StartupCleanupState,
} from "./types.js";
import { MCP_SHUTDOWN_FAILED } from "./messages.js";

/** Startup exposes the exact provider owners before its failure is projected. */
export const closeStartupProviders = async (
  primary: unknown,
  owners: readonly RuntimeCleanupOwner[],
): Promise<StartupCleanupState> => {
  const results = await Promise.allSettled(
    owners.map(async (owner) => {
      if (!owner.closed) {
        await owner.close();
        owner.closed = true;
      }
    }),
  );
  return {
    primary,
    owners,
    failures: results.flatMap((result) =>
      result.status === "rejected" ? [result.reason as unknown] : [],
    ),
  };
};

export const createShutdown = (input: {
  readonly handle?: StdioServerHandle;
  readonly closeAndroid?: () => Promise<void>;
  readonly session?: BinarySession;
  readonly dependencies: RuntimeDependencies;
  readonly serverLogger: Logger;
  readonly providerCleanup?: StartupCleanupState;
  readonly closeProcessOwnership?: () => Promise<void>;
}): RuntimeShutdown => {
  const { handle, session, dependencies, serverLogger } = input;
  let shutdownAttempt: Promise<void> | undefined;
  const cleanupOwners: readonly RuntimeCleanupOwner[] = input.providerCleanup
    ?.owners ?? [
    ...(handle === undefined
      ? []
      : [{ id: "mcp-transport", close: () => handle.close(), closed: false }]),
    ...(input.closeAndroid === undefined
      ? []
      : [
          { id: "android-providers", close: input.closeAndroid, closed: false },
        ]),
    ...(session === undefined
      ? []
      : [
          {
            id: "binary-session",
            close: async () => {
              const closed = await session.close({
                retainProviderDocuments: true,
              });
              if (!closed.ok) throw closed.error;
            },
            closed: false,
          },
        ]),
  ];
  const inspector: RuntimeCleanupOwner = {
    id: "process-inspector",
    close:
      input.closeProcessOwnership ??
      dependencies.closeProcessOwnership ??
      (async () => undefined),
    closed: false,
  };
  const history: unknown[] =
    input.providerCleanup === undefined
      ? []
      : [input.providerCleanup.primary, ...input.providerCleanup.failures];
  let shutdownUnregistered = false;
  let unregisterShutdown = (): void => undefined;
  const shutdown = async (): Promise<void> => {
    if (shutdownAttempt !== undefined) return shutdownAttempt;
    const pending = cleanupOwners.filter(({ closed }) => !closed);
    const attempt = (async () => {
      const results = await Promise.allSettled(
        pending.map(async (owner) => {
          await owner.close();
          owner.closed = true;
        }),
      );
      const failures: unknown[] = [];
      for (const result of results)
        if (result.status === "rejected") failures.push(result.reason);
      history.push(...failures);
      if (failures.length === 1) throw failures[0];
      if (failures.length > 1)
        throw new AggregateError(
          failures,
          "Multiple MCP cleanup operations failed",
        );
      if (!inspector.closed) {
        try {
          await inspector.close();
          inspector.closed = true;
        } catch (cause: unknown) {
          history.push(cause);
          throw cause;
        }
      }
      if (!shutdownUnregistered) {
        unregisterShutdown();
        shutdownUnregistered = true;
      }
    })();
    shutdownAttempt = attempt;
    void attempt.catch(() => {
      if (shutdownAttempt === attempt) shutdownAttempt = undefined;
    });
    return attempt;
  };
  const requestShutdown = (): void => {
    shutdown().catch((cause: unknown) => {
      serverLogger.debug(
        { failure_cause: describeShutdownFailure(cause) },
        "MCP shutdown rejected",
      );
      dependencies.setExitCode(1);
      serverLogger.error(MCP_SHUTDOWN_FAILED);
      dependencies.writeStderr(`${MCP_SHUTDOWN_FAILED}\n`);
      if (cause instanceof AnalysisError)
        dependencies.writeStderr(`${projectAnalysisError(cause).message}\n`);
    });
  };
  unregisterShutdown = dependencies.registerShutdown(requestShutdown);
  return {
    shutdown,
    request: requestShutdown,
    get failures() {
      return history.slice();
    },
    get unresolvedOwners() {
      return [...cleanupOwners, inspector].filter((owner) => !owner.closed);
    },
  };
};

const describeShutdownFailure = (
  cause: unknown,
): Readonly<Record<string, JsonValue>> =>
  describeShutdownFailureNode(cause, new WeakSet<object>());

const describeShutdownFailureNode = (
  cause: unknown,
  active: WeakSet<object>,
): Readonly<Record<string, JsonValue>> => {
  if (typeof cause === "object" && cause !== null) {
    if (active.has(cause)) return { type: "cyclic_error" };
    active.add(cause);
  }
  try {
    if (cause instanceof AnalysisError)
      return { analysis_error: projectAnalysisError(cause) };
    if (cause instanceof Error) {
      const code = "code" in cause ? cause.code : undefined;
      return {
        name: cause.name,
        message: cause.message,
        ...(cause.cause === undefined
          ? {}
          : { cause: describeShutdownFailureNode(cause.cause, active) }),
        ...(typeof code === "string" ||
        (typeof code === "number" && Number.isFinite(code))
          ? { code }
          : {}),
        ...(cause instanceof AggregateError
          ? {
              errors: cause.errors.map((error: unknown) =>
                describeShutdownFailureNode(error, active),
              ),
            }
          : {}),
      };
    }
    if (
      cause === null ||
      typeof cause === "string" ||
      typeof cause === "boolean" ||
      (typeof cause === "number" && Number.isFinite(cause))
    )
      return { type: cause === null ? "null" : typeof cause, value: cause };
    return { type: typeof cause };
  } finally {
    if (typeof cause === "object" && cause !== null) active.delete(cause);
  }
};
