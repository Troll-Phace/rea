import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { parseConfig } from "../config/parseConfig.js";
import {
  runDirectAnalysis as executeDirectAnalysis,
  runProviderAnalysis as executeProviderAnalysis,
  runManagedProviderExecution as executeManagedProvider,
} from "../application/DirectAnalysis.js";
import { runSessionStatus as executeSessionStatus } from "../application/DirectAnalysisStatus.js";
import type { DirectAnalysisDependencies } from "../application/DirectAnalysisDependencies.js";
import { createBinarySession, createManagedBinarySession } from "./binary.js";
import { ok } from "../domain/result.js";
import type { BinarySession } from "../application/binary/BinarySession.js";
import type { CliCleanupScope } from "./CliCleanupScope.js";

/** Bind one-shot analysis and status commands to one caller-selected environment. */
export const createDirectAnalysis = (
  selectedEnvironment: Readonly<Record<string, string | undefined>>,
  cleanupScope?: CliCleanupScope,
) => {
  const environment = snapshotEnvironment(selectedEnvironment);
  const dependencies: DirectAnalysisDependencies = {
    readConfiguration: () => parseConfig(environment),
    createBinarySession: (config, logger) =>
      observeSessionClose(
        createBinarySession(config, logger, environment),
        cleanupScope,
      ),
    createManagedBinarySession: () =>
      observeSessionClose(createManagedBinarySession(), cleanupScope),
  };
  return {
    runDirectAnalysis: executeDirectAnalysis.bind(undefined, dependencies),
    runProviderAnalysis: executeProviderAnalysis.bind(undefined, dependencies),
    runSessionStatus: executeSessionStatus.bind(undefined, dependencies),
  };
};

const observeSessionClose = (
  session: BinarySession,
  scope: CliCleanupScope | undefined,
): BinarySession => {
  if (scope === undefined) return session;
  const close = session.close.bind(session);
  let lastArguments: Parameters<BinarySession["close"]> = [];
  const owner = scope.register(session, async () => {
    const result = await close(...lastArguments);
    return result.ok ? ok(undefined) : result;
  });
  session.close = (...arguments_) => {
    lastArguments = arguments_;
    return scope.observe(owner, () => close(...arguments_));
  };
  return session;
};

/** Bound operations used by CLI command registration. */
export type DirectAnalysis = ReturnType<typeof createDirectAnalysis>;

/** Execute managed metadata without configuration or native provider candidates. */
export const runManagedProviderExecution = executeManagedProvider.bind(
  undefined,
  {
    createManagedBinarySession,
  },
);
