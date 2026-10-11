import { createAndroidAnalysisProvider } from "../composition/android.js";
import type { AndroidAnalysisPort } from "../application/android/AndroidAnalysisPort.js";
import type { StdioServerHandle } from "@modelcontextprotocol/server/stdio";

import type { BinarySession } from "../application/binary/BinarySession.js";
import type { Logger } from "pino";
import { createServer } from "../server/createServer.js";
import type { ToolResultDelivery } from "../server/toolResult.js";
import type { RuntimeDependencies, StartupCleanupState } from "./types.js";
import type { OptionalProviderLoadResult } from "../application/OptionalObservationProviders.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { closeStartupProviders } from "./shutdown.js";
import {
  MCP_CONNECTION_LOST,
  MCP_CONNECTION_START_FAILED,
} from "./messages.js";

interface ServerContext {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly delivery: ToolResultDelivery;
  readonly logger: Logger;
  readonly serverLogger: Logger;
  readonly loadOptionalProviders: () => Promise<OptionalProviderLoadResult>;
}

export const startMcpTransport = async (
  dependencies: RuntimeDependencies,
  session: BinarySession,
  serverContext: ServerContext,
): Promise<
  | {
      readonly ok: true;
      readonly handle: StdioServerHandle;
      readonly closeAndroid: () => Promise<void>;
    }
  | { readonly ok: false; readonly cleanup: StartupCleanupState }
> => {
  const { serverLogger } = serverContext;
  let optionalProviders: OptionalProviderLoadResult = {};
  try {
    optionalProviders = await serverContext.loadOptionalProviders();
  } catch (cause: unknown) {
    serverLogger.warn(
      {
        error: cause instanceof Error ? cause.message : String(cause),
      },
      "Optional MCP providers could not load; affected tools remain unavailable",
    );
  }
  for (const failure of Object.values(
    optionalProviders.optionalProviderLoadFailures ?? {},
  )) {
    serverLogger.warn(
      { providerId: failure.providerId, error: failure.reason },
      "Optional MCP adapter could not load; its peers remain available",
    );
  }
  const androidProviders: AndroidAnalysisPort[] = [];
  const closedAndroid = new Set<AndroidAnalysisPort>();
  const closeAndroid = async (): Promise<void> => {
    const results = await Promise.allSettled(
      androidProviders
        .filter((provider) => !closedAndroid.has(provider))
        .map(async (provider) => {
          await provider.close();
          closedAndroid.add(provider);
        }),
    );
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason as unknown] : [],
    );
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(failures, "Android provider cleanup failed");
  };
  let handle: StdioServerHandle;
  try {
    handle = dependencies.serve(
      () => {
        // The SDK can discard a discovery probe and construct a replacement server.
        const android = createAndroidAnalysisProvider(
          serverContext.environment,
        );
        androidProviders.push(android);
        return (dependencies.createServer ?? createServer)(
          { kind: "session", session },
          {
            logger: serverContext.logger,
            environment: serverContext.environment,
            delivery: serverContext.delivery,
            ...optionalProviders,
            androidAnalysis: android,
          },
        );
      },
      {
        onerror: () => {
          serverLogger.error(MCP_CONNECTION_LOST);
          dependencies.writeStderr(`${MCP_CONNECTION_LOST}\n`);
        },
      },
    );
  } catch (cause: unknown) {
    const cleanup = await closeStartupProviders(cause, [
      {
        id: "binary-session",
        closed: false,
        close: async () => {
          const result = await session.close();
          if (!result.ok) throw result.error;
        },
      },
      { id: "android-providers", closed: false, close: closeAndroid },
    ]);
    serverLogger.error(
      {
        error: cause instanceof Error ? cause.message : String(cause),
      },
      MCP_CONNECTION_START_FAILED,
    );
    dependencies.writeStderr(`${MCP_CONNECTION_START_FAILED}\n`);
    for (const failure of cleanup.failures) {
      if (failure instanceof AnalysisError) {
        const projected = projectAnalysisError(failure);
        serverLogger.error(
          { cleanup_error: projected },
          "Binary provider cleanup failed after MCP startup",
        );
        dependencies.writeStderr(`${projected.message}\n`);
      } else {
        const reason =
          failure instanceof Error ? failure.message : String(failure);
        serverLogger.error(
          { cleanup_error: reason },
          "Provider cleanup rejected after MCP startup",
        );
        dependencies.writeStderr(`Provider cleanup failed: ${reason}\n`);
      }
    }
    return { ok: false, cleanup };
  }
  return { ok: true, handle, closeAndroid };
};
