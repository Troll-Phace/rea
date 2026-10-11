#!/usr/bin/env node

import { snapshotEnvironment } from "./process/snapshotEnvironment.js";
import { pathToFileURL } from "node:url";
import { realpathSync } from "node:fs";

import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { parseConfig } from "./config/parseConfig.js";
import { createBinarySession } from "./composition/binary.js";
import { createLogger } from "./logger.js";
import { projectAnalysisError } from "./domain/analysisErrorProjection.js";
import type {
  RuntimeDependencies,
  RuntimeShutdown,
  StartupCleanupState,
} from "./main/types.js";
import { MCP_SHUTDOWN_FAILED, SERVER_START_FAILED } from "./main/messages.js";
import { openInitialTarget } from "./main/startup.js";
import { startMcpTransport } from "./main/transport.js";
import {
  createOptionalObservationFactories,
  loadOptionalObservationProviders,
} from "./composition/optionalObservationProviders.js";
import { createToolResultDelivery } from "./server/toolResult.js";
import { createShutdown } from "./main/shutdown.js";
import { closeProcessOwnershipInspection } from "./process/ProcessOwnershipObservation.js";
import type { BinarySession } from "./application/binary/BinarySession.js";

const runtimeDependencies = (): RuntimeDependencies => ({
  env: process.env,
  closeProcessOwnership: closeProcessOwnershipInspection,
  serve: serveStdio,
  writeStderr: (text) => process.stderr.write(text),
  setExitCode: (code) => {
    process.exitCode = code;
  },
  registerShutdown: (handler) => {
    process.once("SIGINT", handler);
    process.once("SIGTERM", handler);
    process.stdin.once("end", handler);
    process.stdin.once("close", handler);
    return () => {
      process.off("SIGINT", handler);
      process.off("SIGTERM", handler);
      process.stdin.off("end", handler);
      process.stdin.off("close", handler);
    };
  },
});

/**
 * Start the long-lived MCP adapter and install idempotent shutdown handlers.
 * The adapter owns its BinarySession for the process lifetime; EOF and process
 * signals close bridge resources without assuming ownership of the Hopper app.
 */
export const run = async (
  dependencies: RuntimeDependencies = runtimeDependencies(),
): Promise<number> => {
  const environment = snapshotEnvironment(dependencies.env);
  const config = parseConfig(environment);
  if (!config.ok) {
    dependencies.writeStderr(`${projectAnalysisError(config.error).message}\n`);
    const cleanup = createShutdown({
      dependencies,
      serverLogger: createLogger("mcp", "error"),
      providerCleanup: { primary: config.error, owners: [], failures: [] },
      closeProcessOwnership:
        dependencies.closeProcessOwnership ?? closeProcessOwnershipInspection,
    });
    dependencies.retainCleanup?.(cleanup);
    try {
      await cleanup.shutdown();
    } catch {
      dependencies.setExitCode(1);
      dependencies.writeStderr(`${MCP_SHUTDOWN_FAILED}\n`);
    }
    return 1;
  }
  const logger = createLogger("mcp", config.value.logLevel);
  const serverLogger = logger.child({ layer: "server" });
  let session: BinarySession | undefined;
  let shutdown: RuntimeShutdown | undefined;
  const installCleanup = (
    providerCleanup: StartupCleanupState,
  ): RuntimeShutdown => {
    const owner = createShutdown({
      ...(session === undefined ? {} : { session }),
      providerCleanup,
      dependencies,
      serverLogger,
      closeProcessOwnership:
        dependencies.closeProcessOwnership ?? closeProcessOwnershipInspection,
    });
    dependencies.retainCleanup?.(owner);
    return owner;
  };
  const finishStartupFailure = async (
    cleanup: StartupCleanupState,
  ): Promise<1> => {
    shutdown = installCleanup(cleanup);
    try {
      await shutdown.shutdown();
    } catch (cause: unknown) {
      serverLogger.debug({ err: cause }, "Startup cleanup retained for retry");
      dependencies.setExitCode(1);
      dependencies.writeStderr(`${MCP_SHUTDOWN_FAILED}\n`);
    }
    return 1;
  };
  try {
    session = createBinarySession(config.value, logger, environment);
    const opened = await openInitialTarget(
      session,
      config.value,
      serverLogger,
      dependencies.writeStderr,
    );
    if (!opened.ok) return await finishStartupFailure(opened.cleanup);
    const transport = await startMcpTransport(dependencies, session, {
      logger,
      serverLogger,
      environment,
      delivery: createToolResultDelivery(config.value.mcpMaxResponseBytes),
      loadOptionalProviders:
        dependencies.loadOptionalProviders ??
        (() =>
          loadOptionalObservationProviders(
            createOptionalObservationFactories(environment),
          )),
    });
    if (!transport.ok) return await finishStartupFailure(transport.cleanup);
    shutdown = createShutdown({
      handle: transport.handle,
      closeAndroid: transport.closeAndroid,
      session,
      dependencies,
      serverLogger,
      closeProcessOwnership:
        dependencies.closeProcessOwnership ?? closeProcessOwnershipInspection,
    });
    dependencies.retainCleanup?.(shutdown);
    return 0;
  } catch (cause: unknown) {
    if (shutdown === undefined) {
      const created = session;
      shutdown = installCleanup({
        primary: cause,
        failures: [],
        owners:
          created === undefined
            ? []
            : [
                {
                  id: "binary-session",
                  closed: false,
                  close: async () => {
                    const result = await created.close();
                    if (!result.ok) throw result.error;
                  },
                },
              ],
      });
    }
    try {
      await shutdown.shutdown();
    } catch (cleanup: unknown) {
      throw new AggregateError(
        [cause, cleanup],
        "MCP startup and cleanup failed",
        { cause },
      );
    }
    throw cause;
  }
};

/** Run the executable boundary without exposing an unexpected startup cause. */
export const runEntrypoint = async (
  start: () => Promise<number> = () => run(),
  writeStderr: (text: string) => void = (text) => process.stderr.write(text),
  setExitCode: (code: number) => void = (code) => {
    process.exitCode = code;
  },
): Promise<void> => {
  try {
    setExitCode(await start());
  } catch (cause: unknown) {
    // Intentionally redact the startup cause from caller-visible output;
    // unexpected failures must not leak internal details.
    void cause;
    writeStderr(`${SERVER_START_FAILED}\n`);
    setExitCode(1);
  }
};

const entryPath = process.argv[1];
if (
  entryPath !== undefined &&
  pathToFileURL(realpathSync(entryPath)).href === import.meta.url
) {
  void runEntrypoint();
}
