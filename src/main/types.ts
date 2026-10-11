import type { OptionalProviderLoadResult } from "../application/OptionalObservationProviders.js";

export interface RuntimeCleanupOwner {
  readonly id: string;
  readonly close: () => Promise<void>;
  closed: boolean;
}

export interface StartupCleanupState {
  readonly primary: unknown;
  readonly owners: readonly RuntimeCleanupOwner[];
  readonly failures: readonly unknown[];
}

export interface RuntimeShutdown {
  readonly shutdown: () => Promise<void>;
  readonly request: () => void;
  readonly failures: readonly unknown[];
  readonly unresolvedOwners: readonly RuntimeCleanupOwner[];
}

export interface RuntimeDependencies {
  readonly env: NodeJS.ProcessEnv;
  readonly serve: typeof import("@modelcontextprotocol/server/stdio").serveStdio;
  readonly writeStderr: (text: string) => void;
  readonly setExitCode: (code: number) => void;
  readonly registerShutdown: (handler: () => void) => () => void;
  readonly createServer?: typeof import("../server/createServer.js").createServer;
  readonly loadOptionalProviders?: () => Promise<OptionalProviderLoadResult>;
  readonly closeProcessOwnership?: () => Promise<void>;
  readonly retainCleanup?: (cleanup: RuntimeShutdown) => void;
}
