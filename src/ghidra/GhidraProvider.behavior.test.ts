import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
// Fake-backed provider coverage; real Ghidra verification lives in
// `npm run verify:ghidra` and its focused variants.
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { fixtureDosLoadImage } from "./GhidraLoadImage.fixture.js";
import { jsonObjectSchema, jsonValueSchema } from "../domain/jsonValue.js";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { parseExecutableHeader } from "../domain/binaryTarget.js";
import { GhidraProvider } from "./GhidraProvider.js";
import {
  createGhidraProviderClient,
  type GhidraProviderClientFactory,
} from "./GhidraProviderClient.js";
import {
  inspectGhidraInstallation,
  type GhidraInstallationHost,
} from "./GhidraInstallation.js";
import { GHIDRA_SESSION_CAPABILITIES } from "./GhidraSessionValues.js";
import { err, ok } from "../domain/result.js";
import { GhidraSessionError } from "./GhidraSessionError.js";
import { silentLogger } from "../logger.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import { psxFixtureCommitment } from "../../tests/fixtures/ghidraPsxImport.js";
import {
  ghidraFunctionDossier,
  ghidraFunctionIdentity,
} from "../domain/ghidraValues.fixture.js";

const INSTALL = "/opt/ghidra_12.1.4_PUBLIC";
const installationHost = (): GhidraInstallationHost => ({
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/usr/lib/jvm/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
});

const provider = (
  host = installationHost(),
  clientFactory?: GhidraProviderClientFactory,
): GhidraProvider => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: INSTALL });
  if (!config.ok) throw config.error;
  return new GhidraProvider(
    config.value,
    silentLogger,
    {},
    host,
    clientFactory,
  );
};

describe("Ghidra PSX target admission", () => {
  it.each(["linux", "darwin", "win32"] as const)(
    "reports coarse PSX support on %s without installation or client work",
    (platform) => {
      let installationProbes = 0;
      let clients = 0;
      const ghidra = provider(
        {
          ...installationHost(),
          platform,
          probeJava: () => {
            installationProbes += 1;
            throw new Error("unexpected installation probe");
          },
        },
        () => {
          clients += 1;
          throw new Error("unexpected client creation");
        },
      );
      const target: BinaryTarget = {
        path: "/tmp/original.psx",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "ps-x-exe",
        architecture: "mips",
        availableArchitectures: ["mips"],
      };
      expect(ghidra.inspectTargetSupport(target)).toMatchObject({
        status: platform === "win32" ? "unsupported" : "supported",
        code: platform === "win32" ? "target_format_unsupported" : null,
        diagnostics: {
          target_format: "ps-x-exe",
          architecture: "mips",
          host_platform: platform,
          psx_loader: { status: "profile inspection pending" },
        },
      });
      expect(installationProbes).toBe(0);
      expect(clients).toBe(0);
    },
  );
});

const psxOperationOutputs = () => {
  const identity = ghidraFunctionIdentity();
  // The seam reports contract values, not measured PSX decoder/decompiler facts.
  return jsonObjectSchema.parse({
    inspect_native_instruction: {
      address: "0x80010008",
      status: "decoded",
      procedure: "0x80010000",
      architecture: "PSX:LE:32:default",
      mode: "default",
      bytes: "2040000c",
      length: 4,
      mnemonic: "jal",
      raw_disassembly: "jal 0x80010080",
      operands: [],
      flow: {
        kind: "call",
        conditional: false,
        computed: false,
        direct_destinations: ["0x80010080"],
      },
      references: [],
      delay_slots: {
        is_in_delay_slot: false,
        depth: 1,
        addresses: ["0x8001000c"],
      },
      limitations: [],
    },
    resolve_native_call_targets: {
      call_site: "0x80010034",
      procedure: "0x80010000",
      status: "unresolved",
      mechanism: "computed",
      targets: [],
      limitations: [],
    },
    analyze_function: ghidraFunctionDossier(),
    procedure_assembly: "synthetic assembly",
    procedure_callees: [],
    procedure_callers: [],
    procedure_info: {
      name: identity.name,
      entrypoint: identity.address,
      basicblock_count: 1,
      length: identity.body.total_bytes,
      signature: null,
      locals: [],
      classification: identity.classification,
      body: identity.body,
    },
    procedure_pseudo_code: "synthetic decompiler text",
    read_function_instructions: {
      procedure: identity,
      instructions: [],
      limitations: [],
    },
    procedure_references: {
      procedure: identity,
      direction: "outgoing",
      references: [],
      reference_kinds_available: true,
      unresolved_calls: [],
    },
    xrefs: [],
  });
};

const psxClientFixture = () => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: INSTALL });
  if (!config.ok) throw config.error;
  const { source_snapshot_path: _transportPath, ...commitment } =
    psxFixtureCommitment();
  const target: BinaryTarget = {
    path: "/synthetic.psx",
    sha256: commitment.source_sha256,
    kind: "executable",
    format: "ps-x-exe",
    architecture: "mips",
    availableArchitectures: ["mips"],
  };
  const calls: string[] = [];
  let closes = 0;
  const outputs = psxOperationOutputs();
  const client = createGhidraProviderClient({
    config: config.value,
    environment: {},
    logger: silentLogger,
    target,
    installation: inspectGhidraInstallation(
      {
        environment: {},
        installDir: INSTALL,
        platform: "linux",
        architecture: "x64",
      },
      installationHost(),
    ),
    profile: createAnalysisProfile(
      { id: "ghidra", name: "Ghidra", version: "12.1.4" },
      {
        psx_import: jsonValueSchema.parse(commitment),
        psx_asset_inventory: [],
        psx_language_assets: [],
        psx_analyzer_classes: [],
        psx_operation_scope: "inventory-load-image-and-static-functions-v1",
        instruction_flow_evidence:
          "decoded-return-before-jump-and-delay-slots-v2",
        psx_source_provenance: "rea-psx-filebytes-rebind-v2",
        psx_preparation_transaction: "exclusive-top-level-v1",
        startup_agreement: "psx-observed-import-and-provenance-v3",
        load_image_evidence: "independent-psx-adapted-payload-entry-v2",
      },
    ),
    clientFactory: () => ({
      start: async () => ok(sessionInfo()),
      callTool: async (operation) => {
        calls.push(operation);
        const value = outputs[operation];
        if (value === undefined)
          throw new Error(`unmodeled operation ${operation}`);
        return ok(value);
      },
      close: async () => {
        closes++;
        return ok(null);
      },
    }),
  });
  return { client, calls, closes: () => closes };
};

describe("PSX observational operation admission through the production adapter", () => {
  it("routes every admitted static function query and retains its canonical profile", async () => {
    const fixture = psxClientFixture();
    try {
      for (const operation of [
        "inspect_native_instruction",
        "resolve_native_call_targets",
        "analyze_function",
        "procedure_assembly",
        "procedure_callees",
        "procedure_callers",
        "procedure_info",
        "procedure_pseudo_code",
        "read_function_instructions",
        "procedure_references",
        "xrefs",
      ] as const) {
        const result = await fixture.client.execute(
          operation,
          [
            "inspect_native_instruction",
            "resolve_native_call_targets",
            "xrefs",
          ].includes(operation)
            ? { address: "0x80010008" }
            : { procedure: "0x80010000" },
        );
        if (!result.ok) throw result.error;
        expect(
          result.value.analysisProfile?.parameters.psx_operation_scope,
        ).toBe("inventory-load-image-and-static-functions-v1");
        expect(fixture.calls.at(-1)).toBe(operation);
      }
      expect(fixture.calls).toHaveLength(11);
    } finally {
      const closed = await fixture.client.close();
      expect(closed).toEqual(ok(null));
    }
    expect(fixture.closes()).toBe(1);
  });

  it("refuses annotation and data-type requests before bridge dispatch with distinct reasons", async () => {
    const fixture = psxClientFixture();
    try {
      for (const [operation, input, reason] of [
        [
          "annotate_native_function",
          { procedure: "0x80010000", name: "authored" },
          "annotation mutation",
        ],
        [
          "inspect_native_data_type",
          { address: "0x80010100" },
          "data-type inspection",
        ],
      ] as const) {
        const result = await fixture.client.execute(operation, input);
        expect(result).toMatchObject({
          ok: false,
          error: {
            _tag: "AnalysisCapabilityUnavailableError",
            reason: expect.stringContaining(reason),
          },
        });
      }
      expect(fixture.calls).toEqual([]);
    } finally {
      const closed = await fixture.client.close();
      expect(closed).toEqual(ok(null));
    }
  });
});

describe("Ghidra provider", () => {
  it("commits DOS loader and real-mode language while retaining the CPU family", async () => {
    const ghidra = provider();
    const target: BinaryTarget = {
      path: "/tmp/legacy.exe",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "dos-mz",
      architecture: "x86",
      availableArchitectures: ["x86"],
    };
    expect(ghidra.inspectTargetSupport(target).status).toBe("supported");
    const resolved = await ghidra.resolveAnalysisProfile(target);
    expect(resolved.ok && resolved.value).toMatchObject({
      profile: {
        parameters: {
          target_format: "dos-mz",
          architecture: "x86",
          loader: "MzLoader",
          language_id: "x86:LE:16:Real Mode",
          compiler_spec_id: "default",
          load_segment: "0x1000",
          address_coordinates: "linear-byte-offset",
        },
      },
    });
    const windows = provider({ ...installationHost(), platform: "win32" });
    expect(windows.inspectTargetSupport(target).status).toBe("unsupported");
  });
  it("discovers the exact installation once without launching Ghidra", () => {
    let probeCount = 0;
    const host: GhidraInstallationHost = {
      ...installationHost(),
      probeJava: () => {
        probeCount += 1;
        return {
          version: "21.0.11",
          major: 21,
          home: "/usr/lib/jvm/jdk-21",
          bits: 64,
          runtime: "jdk",
        };
      },
    };
    const ghidra = provider(host);

    expect(ghidra.capabilities()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "list_procedures",
          effects: expect.objectContaining({
            mutatesArtifact: false,
            mayShowUi: false,
            mayWriteFilesystem: true,
          }),
        }),
        expect.objectContaining({
          operation: "analyze_function",
          limitations: expect.arrayContaining([
            expect.stringContaining(
              "unresolved targetless flows remain unknown",
            ),
          ]),
        }),
      ]),
    );
    expect(ghidra.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: {
        install_dir: INSTALL,
        provider_version: "12.1.4",
        java_version: "21.0.11",
      },
    });
    expect(ghidra.inspectAvailability()).toMatchObject({ status: "available" });
    expect(probeCount).toBe(1);
  });

  it("separates target kind, format, and concrete architecture", () => {
    const ghidra = provider();
    expect(
      ghidra.inspectTargetSupport(executableTarget("elf", "x86_64")),
    ).toMatchObject({
      status: "supported",
    });
    expect(
      ghidra.inspectTargetSupport(executableTarget("pe", "arm64")),
    ).toMatchObject({
      status: "supported",
    });
    expect(
      ghidra.inspectTargetSupport({
        path: "/tmp/fixture.asar",
        sha256: "a".repeat(64),
        kind: "archive",
        format: "asar",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_kind_unsupported",
    });
    expect(
      ghidra.inspectTargetSupport({
        path: "/tmp/fixture.js",
        sha256: "a".repeat(64),
        kind: "artifact",
        format: "javascript",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_kind_unsupported",
    });
  });
});

describe("Ghidra Mach-O slice support", () => {
  it("refuses universal targets whose selected slice cannot be enforced", () => {
    const ghidra = provider();
    const universal: BinaryTarget = {
      path: "/tmp/fixture",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "mach-o",
      architecture: "arm64",
      availableArchitectures: ["x86_64", "arm64"],
    };

    expect(ghidra.inspectTargetSupport(universal)).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining("universal Mach-O"),
      diagnostics: {
        architecture: "arm64",
        available_architectures: ["x86_64", "arm64"],
      },
    });
    expect(
      ghidra.inspectTargetSupport(executableTarget("mach-o", "arm64")),
    ).toMatchObject({ status: "supported" });
  });
});

describe("Ghidra platform support", () => {
  it("keeps Windows annotation mutation unavailable independently of native controls", () => {
    const ghidra = provider({ ...installationHost(), platform: "win32" });
    expect(
      ghidra
        .capabilities()
        .find(({ operation }) => operation === "annotate_native_function"),
    ).toMatchObject({
      available: false,
      reason: "Windows Ghidra P0 does not admit database mutation.",
      availabilityCode: "unsupported_host",
    });
  });

  it("keeps Windows P0 unavailable until native isolation authority exists", () => {
    const ghidra = provider({ ...installationHost(), platform: "win32" });
    const nativeApplication = peTarget("x86_64");

    for (const architecture of ["x86", "x86_64"] as const)
      expect(ghidra.inspectTargetSupport(peTarget(architecture))).toMatchObject(
        {
          status: "supported",
          diagnostics: {
            host_platform: "win32",
            architecture,
            executable_role: "application",
            managed: false,
          },
        },
      );
    expect(ghidra.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "unsupported_host",
      reason: expect.stringContaining(
        "Windows native controls are unavailable",
      ),
      diagnostics: {
        windows_security: {
          job_object_process_ownership: expect.objectContaining({
            available: false,
            proof: "not-proven",
          }),
          private_runtime_dacl: expect.objectContaining({
            available: false,
            proof: "not-proven",
          }),
          reparse_safe_path_admission: expect.objectContaining({
            available: false,
            proof: "not-proven",
          }),
        },
      },
    });
    expect(ghidra.capabilities()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "list_procedures",
          available: false,
          availabilityCode: "unsupported_host",
          limitations: expect.arrayContaining([
            expect.stringContaining(
              "matching packaged Windows x64 native addon",
            ),
            expect.stringContaining(
              "private DACLs, and Job Object ownership automatically",
            ),
          ]),
        }),
      ]),
    );
    expect(
      ghidra.inspectTargetSupport({
        ...nativeApplication,
        executableRole: "shared-library",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_role_unsupported",
    });
    expect(
      ghidra.inspectTargetSupport({ ...nativeApplication, managed: true }),
    ).toMatchObject({
      status: "unsupported",
      code: "managed_target_unsupported",
    });
    expect(
      ghidra.inspectTargetSupport(executableTarget("elf", "x86_64")),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
    expect(
      ghidra.inspectTargetSupport(executableTarget("pe", "arm64")),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
  });
  it("admits generated PE32 applications while rejecting unsupported x86 roles", async () => {
    const root = fileURLToPath(new URL("../../", import.meta.url));
    await promisify(execFile)(process.execPath, [
      join(root, "scripts/create-ghidra-windows-fixture.mjs"),
    ]);
    const path = join(root, "build/fixtures/rea-ghidra-windows-x86.exe");
    const bytes = await readFile(path);
    const metadata = parseExecutableHeader(bytes, "x64");
    expect(metadata).toMatchObject({
      ok: true,
      value: {
        format: "pe",
        architecture: "x86",
        executableRole: "application",
        managed: false,
      },
    });
    if (!metadata.ok) throw new Error(metadata.error);
    if (metadata.value.format !== "pe")
      throw new Error("Expected a PE fixture");
    const target: BinaryTarget = {
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      kind: "executable",
      ...metadata.value,
    };
    const ghidra = provider({ ...installationHost(), platform: "win32" });
    expect(ghidra.inspectTargetSupport(target).status).toBe("supported");
    for (const [candidate, code] of [
      [
        { ...target, executableRole: "shared-library" },
        "target_role_unsupported",
      ],
      [{ ...target, managed: true }, "managed_target_unsupported"],
    ] as const)
      expect(ghidra.inspectTargetSupport(candidate)).toMatchObject({
        status: "unsupported",
        code,
      });
  });
});

describe("Ghidra startup configuration", () => {
  it("carries supplied startup settings through configuration, the provider, the timer and timeout diagnostics", async () => {
    const target = executableTarget("elf", "x86_64");
    for (const [raw, expected] of [
      [undefined, 330_000],
      ["900000", 900_000],
      ["1260000", 1_260_000],
      ["2147483647", 2_147_483_647],
    ] as const) {
      const config = parseConfig({
        GHIDRA_INSTALL_DIR: INSTALL,
        ...(raw === undefined ? {} : { REA_GHIDRA_STARTUP_TIMEOUT_MS: raw }),
      });
      if (!config.ok) throw config.error;
      let timeout: number | undefined;
      const ghidra = new GhidraProvider(
        config.value,
        silentLogger,
        {},
        installationHost(),
        (options) => {
          timeout = options.startupTimeoutMs;
          return {
            start: () =>
              Promise.resolve(
                err(
                  new GhidraSessionError(
                    "timeout",
                    "Startup deadline elapsed",
                    {},
                  ),
                ),
              ),
            callTool: () => Promise.resolve(ok([])),
            close: () => Promise.resolve(ok(null)),
          };
        },
      );
      const profile = await ghidra.resolveAnalysisProfile(target);
      if (!profile.ok) throw profile.error;
      if (profile.value.profile === null)
        throw new Error("Expected a bound profile");
      const client = ghidra.createClient(target, profile.value.profile);
      try {
        const failure = await client.execute("health", {});
        expect(timeout, String(raw)).toBe(expected);
        expect(failure).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisTimeoutError", timeoutMs: expected },
        });
        if (timeout === undefined)
          throw new Error("Provider omitted startup deadline");
        const deadline = new ProviderStartupDeadline(timeout);
        try {
          expect(await deadline.wait(20)).toBe("elapsed");
          expect(deadline.signal.aborted).toBe(false);
        } finally {
          deadline.dispose();
        }
      } finally {
        await client.close();
      }
    }
  });
});

describe("Ghidra client projection", () => {
  it("commits exact provider, isolation, and resource semantics", async () => {
    const toolCalls: Array<{
      readonly operation: string;
      readonly input: unknown;
      readonly options: unknown;
    }> = [];
    let startCount = 0;
    const factoryOptions: unknown[] = [];
    const callTool: ReturnType<GhidraProviderClientFactory>["callTool"] = (
      operation,
      input,
      options,
    ) => {
      toolCalls.push({ operation, input, options });
      return Promise.resolve(
        ok([
          {
            address: "0x1000",
            value: "fixture_main",
            procedure: {
              external: false,
              thunk: false,
              thunk_target: null,
            },
          },
        ]),
      );
    };
    const clientFactory: GhidraProviderClientFactory = (options) => {
      factoryOptions.push(options);
      return {
        start: () => {
          startCount += 1;
          return Promise.resolve(ok(sessionInfo()));
        },
        callTool,
        close: () => Promise.resolve(ok(null)),
      };
    };
    const ghidra = provider(installationHost(), clientFactory);
    const resolved = await ghidra.resolveAnalysisProfile(
      executableTarget("elf", "x86_64"),
    );

    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null)
      throw new Error("Expected a bound Ghidra profile");
    expect(resolved.value.profile).toMatchObject({
      provider: { id: "ghidra", name: "Ghidra", version: "12.1.4" },
      parameters: {
        import_mode: "ephemeral-source-immutable",
        annotation_policy: "atomic-function-entry-metadata-v1",
        analyzer_preset: "ghidra-default",
      },
    });
    expect(resolved.value.profile.parameters).toMatchObject({
      language_id: "auto-from-header",
      compiler_spec_id: "auto-default",
    });

    const result = await ghidra
      .createClient(executableTarget("elf", "x86_64"), resolved.value.profile, {
        runId: "11111111-1111-4111-8111-111111111111",
      })
      .execute("list_procedures", {});
    expect(factoryOptions).toEqual([
      expect.objectContaining({
        runId: "11111111-1111-4111-8111-111111111111",
        platform: "linux",
      }),
    ]);
    expect(toolCalls).toEqual([
      {
        operation: "list_procedures",
        input: { document: null },
        options: {},
      },
    ]);
    expect(result).toMatchObject({
      ok: true,
      value: {
        provider: {
          id: "ghidra",
          name: "Ghidra",
          version: "12.1.4",
        },
        analysisProfile: resolved.value.profile,
        result: [{ address: "0x1000", value: "fixture_main" }],
        rawResult: [{ procedure: { external: false, thunk: false } }],
      },
    });
    expect(startCount).toBe(0);
  });
});

describe("Ghidra result projection", () => {
  it("rejects malformed inventory output before Evidence creation", async () => {
    const ghidra = provider(installationHost(), () => ({
      start: () => Promise.resolve(ok(sessionInfo())),
      callTool: () => Promise.resolve(ok({ items: "not-an-inventory" })),
      close: () => Promise.resolve(ok(null)),
    }));
    const resolved = await ghidra.resolveAnalysisProfile(
      executableTarget("elf", "x86_64"),
    );
    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null)
      throw new Error("Expected a bound Ghidra profile");

    await expect(
      ghidra
        .createClient(executableTarget("elf", "x86_64"), resolved.value.profile)
        .execute("list_procedures", {}),
    ).resolves.toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
  });

  it.each([
    ["invalid_request", "AnalysisInputError"],
    ["not_found", "AnalysisInputError"],
    ["ambiguous", "AnalysisInputError"],
    ["method_unavailable", "AnalysisCapabilityUnavailableError"],
  ] as const)(
    "projects remote %s without losing its typed meaning",
    async (code, tag) => {
      const ghidra = provider(installationHost(), () => ({
        start: () => Promise.resolve(ok(sessionInfo())),
        callTool: () =>
          Promise.resolve(
            err(
              new GhidraSessionError(
                "remote",
                "Fixture remote failure",
                { remote_code: code },
                { remoteCode: code },
              ),
            ),
          ),
        close: () => Promise.resolve(ok(null)),
      }));
      const resolved = await ghidra.resolveAnalysisProfile(
        executableTarget("elf", "x86_64"),
      );
      if (!resolved.ok) throw resolved.error;
      if (resolved.value.profile === null)
        throw new Error("Expected a bound Ghidra profile");

      await expect(
        ghidra
          .createClient(
            executableTarget("elf", "x86_64"),
            resolved.value.profile,
          )
          .execute("list_procedures", {}),
      ).resolves.toMatchObject({ ok: false, error: { _tag: tag } });
    },
  );

  it("preserves the rejected name constraint and function address", async () => {
    const message =
      "Invalid function name at 0x10100: Symbol name contains invalid characters";
    const ghidra = provider(installationHost(), () => ({
      start: () => Promise.resolve(ok(sessionInfo())),
      callTool: () =>
        Promise.resolve(
          err(
            new GhidraSessionError(
              "remote",
              message,
              {},
              { remoteCode: "invalid_function_name" },
            ),
          ),
        ),
      close: () => Promise.resolve(ok(null)),
    }));
    const resolved = await ghidra.resolveAnalysisProfile(
      executableTarget("elf", "x86_64"),
    );
    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null)
      throw new Error("Expected a bound profile");
    await expect(
      ghidra
        .createClient(executableTarget("elf", "x86_64"), resolved.value.profile)
        .execute("annotate_native_function", {
          procedure: "0x10100",
          name: "bad name",
        }),
    ).resolves.toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        issues: [{ path: ["name"], reason: "invalid_value", message }],
      },
    });
  });

  it("projects remote decompile cancellation as a provider-neutral interruption", async () => {
    const code = "decompile_cancelled";
    const tag = "AnalysisCancelledError";
    const ghidra = provider(installationHost(), () => ({
      start: () => Promise.resolve(ok(sessionInfo())),
      callTool: () =>
        Promise.resolve(
          err(
            new GhidraSessionError(
              "remote",
              "Fixture decompiler interruption",
              { remote_code: code },
              { remoteCode: code },
            ),
          ),
        ),
      close: () => Promise.resolve(ok(null)),
    }));
    const resolved = await ghidra.resolveAnalysisProfile(
      executableTarget("elf", "x86_64"),
    );
    if (!resolved.ok) throw resolved.error;
    if (resolved.value.profile === null)
      throw new Error("Expected a bound Ghidra profile");

    const result = await ghidra
      .createClient(executableTarget("elf", "x86_64"), resolved.value.profile)
      .execute("procedure_pseudo_code", { procedure: "main" });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: tag },
    });
  });

  it("returns cancellation before profile work", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      provider().resolveAnalysisProfile(executableTarget("elf", "x86_64"), {
        signal: controller.signal,
      }),
    ).resolves.toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError", operation: "open_binary" },
    });
  });
});

describe("Ghidra measured load-image projection", () => {
  it.each([
    "verified",
    "mismatch",
    "changed-snapshot",
    "unsupported",
    "missing-snapshot",
  ] as const)(
    "preserves %s state and producing observations",
    async (state) => {
      const fixture = fixtureDosLoadImage();
      if (state === "mismatch") fixture.observation.entry_points = ["0x10001"];
      if (state === "changed-snapshot") fixture.bytes[0] = 0;
      const factory: GhidraProviderClientFactory = () => ({
        start: () => Promise.resolve(ok(sessionInfo())),
        callTool: () =>
          Promise.resolve(ok(jsonValueSchema.parse(fixture.observation))),
        close: () => Promise.resolve(ok(null)),
        ...(state === "missing-snapshot"
          ? {}
          : {
              readTargetSnapshot: () => Promise.resolve(ok(fixture.bytes)),
            }),
      });
      const ghidra = provider(installationHost(), factory);
      const target: BinaryTarget = {
        path: "/tmp/source-owned-fixture.exe",
        sha256: fixture.sha256,
        kind: "executable",
        format: state === "unsupported" ? "elf" : "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      };
      const profile = await ghidra.resolveAnalysisProfile(target);
      if (!profile.ok || profile.value.profile === null)
        throw new Error("Expected admitted profile");
      const result = await ghidra
        .createClient(target, profile.value.profile)
        .execute("inspect_native_load_image", {});
      if (state === "changed-snapshot" || state === "missing-snapshot") {
        expect(result).toMatchObject({
          ok: false,
          error: {
            _tag: "ProviderAdapterError",
            diagnostics: { reason: expect.stringContaining("snapshot") },
          },
        });
      } else {
        expect(result).toMatchObject({
          ok: true,
          value: {
            result: { status: state, observations: fixture.observation },
            rawResult: fixture.observation,
            analysisProfile: profile.value.profile,
          },
        });
      }
    },
  );
});

const sessionInfo = () => ({
  name: "REA Ghidra bridge" as const,
  run_id: "11111111-1111-4111-8111-111111111111",
  profile_digest: "a".repeat(64),
  provider: { id: "ghidra" as const, version: "12.1.4" },
  read_only: false as const,
  analysis_complete: true,
  analysis_timed_out: false,
  capabilities: [...GHIDRA_SESSION_CAPABILITIES],
  target: {
    name: "fixture",
    language_id: "x86:LE:64:default",
    compiler_spec_id: "gcc",
    image_base: "0x1000",
    default_address_space: "ram",
    sha256: "a".repeat(64),
  },
});

const executableTarget = (
  format: "mach-o" | "elf" | "pe",
  architecture: Extract<BinaryTarget, { format: "pe" }>["architecture"],
): BinaryTarget =>
  format === "pe"
    ? peTarget(architecture)
    : {
        path: "/tmp/fixture",
        sha256: "a".repeat(64),
        kind: "executable",
        format,
        architecture,
        availableArchitectures: [architecture],
      };

const peTarget = (
  architecture: Extract<BinaryTarget, { format: "pe" }>["architecture"],
): Extract<BinaryTarget, { format: "pe" }> => ({
  path: "/tmp/fixture",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture,
  availableArchitectures: [architecture],
  executableRole: "application",
  managed: false,
});

describe("Ghidra extension failures", () => {
  it.each(["unsupported", "failed", "malformed"] as const)(
    "preserves %s recovery diagnostics and closes without restarting",
    async (status) => {
      const directory = await mkdtemp(
        join(tmpdir(), "rea-provider-extension-"),
      );
      try {
        const jar = join(directory, "addon.jar");
        await writeFile(jar, Buffer.from([0x50, 0x4b, 3, 4]));
        const config = parseConfig({
          GHIDRA_INSTALL_DIR: INSTALL,
          REA_GHIDRA_NATIVEAOT_JAR: jar,
        });
        if (!config.ok) throw config.error;
        let starts = 0,
          calls = 0,
          closes = 0;
        const ghidra = new GhidraProvider(
          config.value,
          silentLogger,
          {},
          installationHost(),
          () => ({
            start: () => {
              starts++;
              return Promise.resolve(
                ok({
                  ...sessionInfo(),
                  analysis_extensions: [
                    {
                      id: "nativeaot",
                      sha256:
                        status === "malformed"
                          ? "0".repeat(64)
                          : createHash("sha256")
                              .update(Buffer.from([0x50, 0x4b, 3, 4]))
                              .digest("hex"),
                      status: status === "malformed" ? "failed" : status,
                      reason:
                        "directory-discovery: Unsupported layout at 0x401000",
                      result: {
                        id: "nativeaot",
                        integration_api: 1,
                        source_revision:
                          "effeb734fc570c32650f88b159608979dc7b423e",
                        source_revision_authority: "build-reported-unattested",
                        status: status === "malformed" ? "failed" : status,
                        reason:
                          "directory-discovery: Unsupported layout at 0x401000",
                        method_tables: 0,
                        diagnostics: ["exact producer diagnostic"],
                      },
                    },
                  ],
                }),
              );
            },
            callTool: () => {
              calls++;
              return Promise.resolve(ok(null));
            },
            close: () => {
              closes++;
              return Promise.resolve(ok(null));
            },
          }),
        );
        const target = executableTarget("elf", "x86_64");
        const resolved = await ghidra.resolveAnalysisProfile(target);
        if (!resolved.ok || resolved.value.profile === null)
          throw new Error("expected extension profile");
        const client = ghidra.createClient(target, resolved.value.profile);
        const failed = await client.execute("health", {});
        expect(failed.ok).toBe(false);
        if (!failed.ok) {
          expect(failed.error._tag).toBe(
            status === "unsupported"
              ? "AnalysisCapabilityUnavailableError"
              : "ProviderAdapterError",
          );
          expect(JSON.stringify(failed.error)).toContain(
            status === "malformed"
              ? "identity mismatch"
              : "Unsupported layout at 0x401000",
          );
        }
        expect(await client.execute("list_procedures", {})).toEqual(failed);
        expect({ starts, calls, closes }).toEqual({
          starts: 1,
          calls: 0,
          closes: 1,
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
});

describe("compatible Ghidra builds", () => {
  it("accepts the build and reports that it is unverified", async () => {
    const ghidra = provider(
      {
        ...installationHost(),
        readText: () =>
          "application.version=12.1.2\napplication.java.min=21\napplication.java.max=\n",
        probeJava: () => ({
          version: "27",
          major: 27,
          home: "/usr/lib/jvm/java-27-openjdk",
          bits: 64,
          runtime: "jdk",
        }),
      },
      () => ({
        start: () =>
          Promise.resolve(
            ok({
              ...sessionInfo(),
              provider: { id: "ghidra", version: "12.1.2" },
            }),
          ),
        callTool: () =>
          Promise.resolve(
            ok([
              {
                address: "0x1000",
                value: "fixture_main",
                procedure: {
                  external: false,
                  thunk: false,
                  thunk_target: null,
                },
              },
            ]),
          ),
        close: () => Promise.resolve(ok(null)),
      }),
    );
    const resolved = await ghidra.resolveAnalysisProfile(
      executableTarget("elf", "x86_64"),
    );
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected a compatible Ghidra profile");
    const client = ghidra.createClient(
      executableTarget("elf", "x86_64"),
      resolved.value.profile,
    );
    const health = await client.execute("health", {});
    const procedures = await client.execute("list_procedures", {});
    expect(ghidra.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: { provider_version: "12.1.2", java_version: "27" },
    });
    expect(health.ok && health.value.provider.version).toBe("12.1.2");
    const unverified = expect.stringContaining("12.1.2");
    expect(health.ok && health.value.limitations).toEqual(
      expect.arrayContaining([unverified]),
    );
    expect(procedures.ok && procedures.value.limitations).toEqual(
      expect.arrayContaining([unverified]),
    );
    expect(procedures.ok && procedures.value.provider.version).toBe("12.1.2");
  });
});

it("projects Ghidra startup failure and its incomplete cleanup together", async () => {
  const cleanup = new ProviderCleanupError("ghidra", ["owned-ghidra-process"], {
    reason: "process cleanup unconfirmed",
  });
  const ghidra = provider(installationHost(), () => ({
    start: async () =>
      err(
        new GhidraSessionError(
          "timeout",
          "Ghidra startup deadline elapsed",
          { failure_kind: "timeout" },
          { timeoutMs: 250, cleanupFailure: cleanup },
        ),
      ),
    callTool: async () => ok(null),
    close: async () => err(cleanup),
  }));
  const target = executableTarget("elf", "x86_64");
  const profile = await ghidra.resolveAnalysisProfile(target);
  if (!profile.ok || profile.value.profile === null)
    throw new Error("Expected Ghidra analysis profile");
  const result = await ghidra
    .createClient(target, profile.value.profile)
    .execute("health", {});
  expect(result.ok).toBe(false);
  if (!result.ok)
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        resources: ["owned-ghidra-process"],
        diagnostics: {
          primary_error: {
            code: "provider_timeout",
            details: { timeout_ms: 250 },
          },
          cleanup_error: { code: "cleanup_incomplete" },
        },
      },
    });
});
