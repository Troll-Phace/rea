import type { BinarySession } from "../application/binary/BinarySession.js";
import type { AppConfig } from "../config/types.js";
import type { Logger } from "pino";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { StartupCleanupState } from "./types.js";
import { closeStartupProviders } from "./shutdown.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";

export const openInitialTarget = async (
  session: BinarySession,
  config: AppConfig,
  serverLogger: Logger,
  writeStderr: (text: string) => void,
): Promise<
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly exitCode: 1;
      readonly cleanup: StartupCleanupState;
    }
> => {
  if (config.hopperTargetPath === undefined) return { ok: true };
  const opened = await session.open(config.hopperTargetPath, {
    targetKind: config.hopperTargetKind,
  });
  if (opened.ok) return { ok: true };
  const cleanup = await closeStartupProviders(opened.error, [
    {
      id: "binary-session",
      closed: false,
      close: async () => {
        const result = await session.close();
        if (!result.ok) throw result.error;
      },
    },
  ]);
  serverLogger.error(
    {
      error: projectAnalysisError(opened.error),
      ...(cleanup.failures.length === 0
        ? {}
        : { cleanup_errors: cleanup.failures }),
    },
    "Initial target failed to open",
  );
  writeStderr(`${projectAnalysisError(opened.error).message}\n`);
  for (const failure of cleanup.failures)
    writeStderr(
      `${failure instanceof AnalysisError ? projectAnalysisError(failure).message : "Provider cleanup failed"}\n`,
    );
  return { ok: false, exitCode: 1, cleanup };
};
