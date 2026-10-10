import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type AnalysisProvider,
  type AnalysisProviderCandidate,
  type CapabilityDescriptor,
  type ProviderIdentity,
} from "../../../src/application/AnalysisProvider.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import { HopperProvider } from "../../../src/hopper/HopperProvider.js";
import { IdaProvider } from "../../../src/ida/IdaProvider.js";
import { silentLogger } from "../../../src/logger.js";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import type { BinarySession } from "../../../src/application/binary/BinarySession.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { SessionProviderRouter } from "../../../src/application/binary/SessionProviderRouter.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { AnalysisCancelledError } from "../../../src/domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../../src/domain/providerAdapterError.js";
import { err, ok } from "../../../src/domain/result.js";

type DeclaredOperation = Exclude<AnalysisOperation, "health">;

describe("PSX provider selection admission", () => {
  it("rejects PSX explicit selection and leaves automatic selection unbound without profiles or clients", async () => {
    const config = parseConfig({});
    if (!config.ok) throw config.error;
    const target: BinaryTarget = {
      path: "/tmp/original.psx",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "ps-x-exe",
      architecture: "mips",
      availableArchitectures: ["mips"],
    };
    const providers = [
      new IdaProvider(config.value, {}),
      new HopperProvider(config.value, silentLogger, {}),
      new GhidraProvider(config.value, silentLogger, {}),
    ];
    const recordings = providers.map((provider) => ({
      profile: vi
        .spyOn(provider, "resolveAnalysisProfile")
        .mockImplementation(() => {
          throw new Error("unsupported target resolved a profile");
        }),
      client: vi.spyOn(provider, "createClient").mockImplementation(() => {
        throw new Error("unsupported target created a client");
      }),
      availability: vi.spyOn(provider, "inspectAvailability").mockReturnValue({
        status: "available",
        code: null,
        reason: null,
        diagnostics: {},
      }),
    }));
    try {
      for (const candidates of [providers, [...providers].reverse()]) {
        const registry = new AnalysisProviderRegistry(candidates);
        for (const provider of providers) {
          const rejected = await registry.select(
            target,
            provider.identity().id,
          );
          expect(rejected).toMatchObject({
            ok: false,
            error: {
              reason: "target_unsupported",
              rejections: expect.arrayContaining([
                expect.objectContaining({ code: "target_format_unsupported" }),
              ]),
            },
          });
        }
        const automatic = await registry.select(target);
        if (!automatic.ok) throw automatic.error;
        expect(automatic.value.binding).toBeNull();
        expect(
          automatic.value.candidates.map(({ provider }) => provider.id),
        ).toEqual(["ghidra", "hopper", "ida"]);
        for (const candidate of automatic.value.candidates)
          expect(candidate.targetSupport).toMatchObject({
            status: "unsupported",
            code: "target_format_unsupported",
          });
      }
      for (const recording of recordings) {
        expect(recording.profile).not.toHaveBeenCalled();
        expect(recording.client).not.toHaveBeenCalled();
      }
      // Availability is independent of PSX installation; refusal also survives unavailable candidates.
      for (const recording of recordings)
        recording.availability.mockReturnValue({
          status: "unavailable",
          code: "runtime_missing",
          reason: "synthetic unavailable provider",
          diagnostics: {},
        });
      const unavailable = await new AnalysisProviderRegistry(providers).select(
        target,
      );
      if (!unavailable.ok) throw unavailable.error;
      expect(unavailable.value.binding).toBeNull();
      for (const recording of recordings) {
        expect(recording.profile).not.toHaveBeenCalled();
        expect(recording.client).not.toHaveBeenCalled();
      }
    } finally {
      for (const recording of recordings) {
        recording.profile.mockRestore();
        recording.client.mockRestore();
        recording.availability.mockRestore();
      }
    }
  });
});

describe("target-bound provider routing", () => {
  it("rejects provider identity and operation-family collisions at composition", () => {
    const alpha = deepProvider("alpha");
    const registry = new AnalysisProviderRegistry([alpha.provider]);
    expect(() =>
      SessionProviderRouter.selectable(registry, [auxiliaryProvider("alpha")]),
    ).toThrow(/Duplicate configured provider ID: alpha/u);
    expect(() =>
      SessionProviderRouter.selectable(registry, [
        auxiliaryProvider("auxiliary", "address_name"),
      ]),
    ).toThrow(
      /Deep and auxiliary providers both declare operation address_name/u,
    );
  });

  it("binds one overlapping provider, preserves provenance, and never falls back", async () => {
    const target = await databaseTarget();
    const alpha = deepProvider("alpha");
    const beta = deepProvider("beta");
    const auxiliary = auxiliaryProvider();
    const session = selectableSession(
      [beta.provider, alpha.provider],
      auxiliary,
    );

    const ambiguous = await session.open(target);
    expect(ambiguous.ok).toBe(false);
    if (!ambiguous.ok)
      expect(ambiguous.error).toMatchObject({ reason: "ambiguous" });
    expect(alpha.clients).toHaveLength(0);
    expect(beta.clients).toHaveLength(0);
    expect(session.activeTarget()).toBeUndefined();

    expect((await session.open(target, { providerId: "alpha" })).ok).toBe(true);
    expect(bindingStatus(session)).toMatchObject({
      analysis_provider_binding: {
        provider: { id: "alpha", version: "1" },
        selection_source: "request",
      },
      analysis_provider_candidates: [
        { provider: { id: "alpha" }, selected: true },
        { provider: { id: "beta" }, selected: false },
      ],
    });
    expect(alpha.clients).toHaveLength(0);

    const observed = await session.execute("address_name", { address: "0x1" });
    expect(observed.ok).toBe(true);
    if (observed.ok)
      expect(observed.value).toMatchObject({
        provider: { id: "alpha", version: "1" },
        analysisProfile: { provider: { id: "alpha", version: "1" } },
        result: "alpha:address_name",
        subject: {
          sha256: expect.any(String),
          path: target,
          format: "analysis-database",
        },
      });
    expect(alpha.clients).toHaveLength(1);
    expect(beta.clients).toHaveLength(0);

    expect((await session.open(target, { providerId: "alpha" })).ok).toBe(true);
    expect(alpha.clients).toHaveLength(1);
    expect(alpha.clients[0]?.closed).toBe(false);

    const auxiliaryResult = await session.execute("inspect_macho", {});
    expect(auxiliaryResult.ok && auxiliaryResult.value.provider.id).toBe(
      "auxiliary",
    );

    alpha.available = false;
    expect((await session.open(target)).ok).toBe(true);
    expect(bindingStatus(session)).toMatchObject({
      analysis_provider_binding: { provider: { id: "alpha" } },
    });

    const unknown = await session.open(target, { providerId: "missing" });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok)
      expect(unknown.error).toMatchObject({ reason: "unknown_provider" });
    expect(bindingStatus(session)).toMatchObject({
      analysis_provider_binding: { provider: { id: "alpha" } },
    });

    expect((await session.open(target, { providerId: "beta" })).ok).toBe(true);
    expect(alpha.clients[0]?.closed).toBe(true);
    beta.fail = true;
    const failed = await session.execute("address_name", { address: "0x2" });
    expect(failed.ok).toBe(false);
    if (!failed.ok) expect(failed.error._tag).toBe("ProviderAdapterError");
    expect(alpha.clients[0]?.calls).toEqual(["address_name"]);
    expect(bindingStatus(session)).toMatchObject({
      analysis_provider_binding: { provider: { id: "beta" } },
    });

    await session.close();
    expect(beta.clients[0]?.closed).toBe(true);
  });

  it("preserves bundle-root identity for artifact inventory operations", async () => {
    const target = await databaseTarget();
    const analysis = deepProvider("alpha");
    const artifact = auxiliaryProvider("artifact", "inventory_artifact");
    const session = selectableSession([analysis.provider], artifact);

    expect((await session.open(target, { providerId: "alpha" })).ok).toBe(true);
    const result = await session.execute("inventory_artifact", {});
    if (!result.ok) throw result.error;

    expect(result).toMatchObject({
      ok: true,
      value: {
        subject: {
          path: target,
          sha256: "f".repeat(64),
          format: "directory",
        },
      },
    });
  });

  it("preserves the active client when a provider switch is cancelled while draining", async () => {
    const target = await databaseTarget();
    const alpha = deepProvider("alpha");
    const beta = deepProvider("beta");
    const pending = deferred<ReturnType<typeof successfulExecution>>();
    alpha.pending = pending.promise;
    const session = selectableSession([alpha.provider, beta.provider]);
    expect((await session.open(target, { providerId: "alpha" })).ok).toBe(true);
    const running = session.execute("address_name", { address: "0x1" });
    await new Promise<void>((resolve) => setImmediate(resolve));

    const controller = new AbortController();
    const switching = session.open(target, {
      providerId: "beta",
      signal: controller.signal,
    });
    while (beta.profileResolutions === 0)
      await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    pending.resolve(successfulExecution("alpha"));

    expect(await running).toMatchObject({ ok: true });
    const cancelled = await switching;
    expect(cancelled).toEqual({
      ok: false,
      error: new AnalysisCancelledError("open_binary"),
    });
    expect(alpha.clients[0]?.closed).toBe(false);
    expect(beta.clients).toHaveLength(0);
    expect(bindingStatus(session)).toMatchObject({
      analysis_provider_binding: { provider: { id: "alpha" } },
    });

    alpha.pending = undefined;
    const retained = await session.execute("address_name", { address: "0x2" });
    expect(retained.ok && retained.value.provider.id).toBe("alpha");
    expect(alpha.clients).toHaveLength(1);
    await session.close();
    expect(alpha.clients[0]?.closed).toBe(true);
  });
});

interface ClientState {
  readonly calls: string[];
  closed: boolean;
}

interface DeepProviderFixture {
  provider: AnalysisProviderCandidate;
  readonly clients: ClientState[];
  available: boolean;
  fail: boolean;
  profileResolutions: number;
  pending: Promise<ReturnType<typeof successfulExecution>> | undefined;
}

const deepProvider = (id: string): DeepProviderFixture => {
  const identity: ProviderIdentity = {
    id,
    name: `${id} provider`,
    version: null,
  };
  const fixture: Omit<DeepProviderFixture, "provider"> = {
    clients: [],
    available: true,
    fail: false,
    profileResolutions: 0,
    pending: undefined,
  };
  const provider: AnalysisProviderCandidate = {
    identity: () => identity,
    capabilities: () => [capability(identity, "address_name")],
    inspectAvailability: () =>
      fixture.available
        ? {
            status: "available",
            code: null,
            reason: null,
            diagnostics: { executable_path: `/opt/${id}/bin/analyze` },
          }
        : {
            status: "unavailable",
            code: "runtime_missing",
            reason: `${id} runtime is unavailable`,
            diagnostics: { executable_path: `/opt/${id}/bin/analyze` },
          },
    inspectTargetSupport: () => ({
      status: "supported",
      code: null,
      reason: null,
      diagnostics: {},
    }),
    resolveAnalysisProfile: () => {
      fixture.profileResolutions += 1;
      return Promise.resolve(
        ok({
          profile: createAnalysisProfile(
            { id, name: identity.name, version: "1" },
            { provider: id },
          ),
        }),
      );
    },
    createClient: (_target, profile): AnalysisClient => {
      const state: ClientState = { calls: [], closed: false };
      fixture.clients.push(state);
      return {
        execute: (operation) => {
          if (operation === "health")
            return Promise.resolve(successfulExecution(id, profile?.provider));
          state.calls.push(operation);
          if (fixture.fail)
            return Promise.resolve(
              err(new ProviderAdapterError(id, operation)),
            );
          if (fixture.pending !== undefined) return fixture.pending;
          return Promise.resolve(successfulExecution(id, profile?.provider));
        },
        close: () => {
          state.closed = true;
          return Promise.resolve(ok(null));
        },
      };
    },
  };
  return Object.assign(fixture, { provider });
};

const successfulExecution = (
  id: string,
  provider: ProviderIdentity = {
    id,
    name: `${id} provider`,
    version: "1",
  },
) => ok(createAnalysisExecution(`${id}:address_name`, provider));

const auxiliaryProvider = (
  id = "auxiliary",
  operation: DeclaredOperation = "inspect_macho",
): AnalysisProvider => {
  const identity = {
    id,
    name: `${id} provider`,
    version: "1",
  };
  return {
    identity: () => identity,
    capabilities: () => [capability(identity, operation)],
    createClient: (target) => ({
      execute: (operation) =>
        Promise.resolve(
          ok(
            createAnalysisExecution(
              `${operation}:auxiliary`,
              identity,
              operation === "inventory_artifact" ||
                operation === "inspect_artifact"
                ? {
                    subject: {
                      path: target.sourcePath ?? target.path,
                      sha256: "f".repeat(64),
                      format: "directory",
                    },
                  }
                : {},
            ),
          ),
        ),
      close: () => Promise.resolve(ok(null)),
    }),
  };
};

const selectableSession = (
  providers: readonly AnalysisProviderCandidate[],
  auxiliary?: AnalysisProvider,
): BinarySession =>
  composeBinarySession(
    new AnalysisProviderRegistry(providers),
    auxiliary === undefined ? [] : [auxiliary],
  );

const capability = (
  provider: ProviderIdentity,
  operation: DeclaredOperation,
): CapabilityDescriptor => ({
  provider,
  operation,
  available: true,
  reason: null,
  effects: {
    mutatesArtifact: false,
    launchesProcess: operation === "address_name",
    mayShowUi: false,
    mayAccessNetwork: false,
    mayWriteFilesystem: false,
    changesPermissions: false,
    requiresRoot: false,
  },
  limitations: [],
});

const databaseTarget = async (): Promise<string> => {
  const directory = await createTestTempDirectory("rea-provider-binding-");
  const path = join(directory, "fixture.hop");
  await writeFile(path, "fixture");
  return path;
};

const bindingStatus = (session: BinarySession) =>
  z
    .object({
      analysis_provider_binding: z.unknown(),
      analysis_provider_candidates: z.array(z.unknown()),
    })
    .passthrough()
    .parse(session.status());

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
}

const deferred = <Value>(): Deferred<Value> => {
  let resolvePromise: ((value: Value) => void) | undefined;
  const promise = new Promise<Value>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve(value) {
      resolvePromise?.(value);
    },
  };
};
