import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";

import type {
  NativeLoadImageObservation,
  PsxLabelHistoryRow,
  PsxMetadataPreservation,
} from "../../src/domain/native/nativeLoadImage.js";
import type {
  PsxImportAgreement,
  PsxImportCommitment,
  PsxImportObservation,
  PsxOriginalEvidenceRecord,
} from "../../src/ghidra/GhidraImportConfiguration.js";
import type { GhidraInstallationHost } from "../../src/ghidra/GhidraInstallation.js";
import { createTestTempDirectory } from "./temporaryDirectory.js";
import { parseConfig } from "../../src/config/parseConfig.js";
import { GhidraProvider } from "../../src/ghidra/GhidraProvider.js";
import { GHIDRA_SESSION_CAPABILITIES } from "../../src/ghidra/GhidraSessionValues.js";
import type { GhidraOperation } from "../../src/ghidra/GhidraClient.js";
import type { GhidraSessionError } from "../../src/ghidra/GhidraSessionError.js";
import { jsonValueSchema } from "../../src/domain/jsonValue.js";
import { ok, type Result } from "../../src/domain/result.js";
import { silentLogger } from "../../src/logger.js";

/** Real filesystem inventory fixture; these JAR entries are synthetic, not runnable Java. */
export const createPsxInstallationFixture = async () => {
  const root = await createTestTempDirectory("rea-psx-install-");
  const installationRoot = join(root, "Ghidra installation 雪");
  const extension = join(installationRoot, "Ghidra/Extensions/renamed-psx");
  const languages = join(extension, "data/languages");
  const write = async (relativePath: string, value: string | Uint8Array) => {
    const path = join(installationRoot, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, value);
    return path;
  };
  await write("Ghidra/application.properties", "application.version=12.1.4\n");
  await write(
    "Ghidra/Extensions/renamed-psx/extension.properties",
    "name=ghidra_psx_ldr\nversion=12.1.4\n",
  );
  await write(
    "Ghidra/Extensions/renamed-psx/Module.manifest",
    "MODULE FILE LICENSE: lib/psx.jar BSD\n",
  );
  await write(
    "Ghidra/Extensions/renamed-psx/data/languages/psx.ldefs",
    '<language_definitions><language id="PSX:LE:32:default" slafile="mips32le.sla" processorspec="mips32.pspec"><compiler id="default" spec="mips32le.cspec"/></language></language_definitions>',
  );
  for (const name of [
    "mips32le.sla",
    "mips32.pspec",
    "mips32le.cspec",
    "include.sinc",
  ])
    await write(
      `Ghidra/Extensions/renamed-psx/data/languages/${name}`,
      `synthetic ${name}\n`,
    );
  const loaderJar = await write(
    "Ghidra/Extensions/renamed-psx/lib/psx.jar",
    await psxFixtureJar([
      "psx/PsxLoader.class",
      "psx/PsxAnalyzer.class",
      "ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class",
    ]),
  );
  const coreJar = await write(
    "Ghidra/Processors/MIPS/lib/MIPS.jar",
    await psxFixtureJar([
      "ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class",
    ]),
  );
  const coreData = await write(
    "Ghidra/Processors/MIPS/data/core.sinc",
    "core language input\n",
  );
  const source = await write("synthetic source 雪.exe", psxImportBytes());
  const installationHost: GhidraInstallationHost = {
    platform: "linux",
    architecture: "x64",
    readText: (path) =>
      path.endsWith("application.properties")
        ? "application.version=12.1.4\n"
        : "",
    executable: () => true,
    probeJava: () => ({
      version: "21.0.11",
      major: 21,
      home: "/synthetic/jdk",
      bits: 64,
      runtime: "jdk",
    }),
  };
  return {
    root,
    installationRoot,
    extension,
    languages,
    loaderJar,
    coreJar,
    coreData,
    source,
    write,
    installationHost,
  };
};

export const psxFixtureJar = async (
  entries: readonly string[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const entry of entries)
    await writer.add(entry, new TextReader("synthetic class resource\n"), {
      lastModDate: new Date("2020-01-01T00:00:00Z"),
    });
  return writer.close();
};

/** Real provider/profile/projection with a strictly modeled, simulated bridge seam. */
export const createPsxRecordingProvider = (
  fixture: Awaited<ReturnType<typeof createPsxInstallationFixture>>,
  recordingOptions: {
    readonly loadImage?: (bytes: Buffer) => NativeLoadImageObservation;
    readonly snapshot?: () => Promise<Result<Buffer, GhidraSessionError>>;
  } = {},
) => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: fixture.installationRoot });
  if (!config.ok) throw config.error;
  const calls: GhidraOperation[] = [];
  let closes = 0;
  let clients = 0;
  const provider = new GhidraProvider(
    config.value,
    silentLogger,
    {},
    fixture.installationHost,
    (options) => {
      clients += 1;
      return {
        start: async () =>
          ok({
            name: "REA Ghidra bridge" as const,
            run_id: options.runId ?? "11111111-1111-4111-8111-111111111111",
            profile_digest: options.profileDigest,
            provider: { id: "ghidra" as const, version: "12.1.4" },
            read_only: false,
            analysis_complete: true,
            analysis_timed_out: false,
            capabilities: [...GHIDRA_SESSION_CAPABILITIES],
            target: {
              name: "synthetic PSX",
              language_id: "PSX:LE:32:default",
              compiler_spec_id: "default",
              image_base: "0x80000000",
              default_address_space: "ram",
              sha256: options.targetSha256,
            },
          }),
        callTool: async (operation) => {
          calls.push(operation);
          switch (operation) {
            case "list_documents":
              return ok(["synthetic PSX"]);
            case "list_strings":
              return ok(
                jsonValueSchema.parse([
                  {
                    address: "0x80010100",
                    value: "synthetic inventory",
                    string: {
                      encoding: "UTF-8",
                      termination: "present_or_not_required",
                      byte_length: 20,
                    },
                  },
                ]),
              );
            case "read_bytes":
              return ok({
                address: "0x80010000",
                requested_bytes: 4,
                returned_bytes: 4,
                bytes_hex: "07000224",
                complete: true,
              });
            case "inspect_native_load_image":
              return ok(
                jsonValueSchema.parse(
                  (recordingOptions.loadImage ?? psxLoadImageObservation)(
                    await readFile(fixture.source),
                  ),
                ),
              );
            default:
              throw new Error(
                `Unmodeled simulated PSX bridge operation: ${operation}`,
              );
          }
        },
        readTargetSnapshot:
          recordingOptions.snapshot ??
          (async () => ok(await readFile(fixture.source))),
        close: async () => {
          closes += 1;
          return ok(null);
        },
      };
    },
  );
  return {
    provider,
    config: config.value,
    calls,
    counts: () => ({ closes, clients }),
  };
};

/** Original generated PS-X EXE input; no parser or admission constants are reused. */
export const psxImportBytes = (
  fields: Readonly<Record<number, number>> = {},
  trailingBytes = 0,
): Buffer => {
  const bytes = Buffer.alloc(0x1000 + trailingBytes);
  bytes.write("PS-X EXE", 0, "ascii");
  bytes.writeUInt32LE(0x80010000, 0x10);
  bytes.writeUInt32LE(0x80010000, 0x18);
  bytes.writeUInt32LE(0x800, 0x1c);
  // A tiny original function includes return and its delay slot. This fixture
  // establishes source bytes only, never verified MIPS instruction semantics.
  bytes.writeUInt32LE(0x24020007, 0x800);
  bytes.writeUInt32LE(0x03e00008, 0x804);
  bytes.writeUInt32LE(0, 0x808);
  for (const [offset, value] of Object.entries(fields))
    bytes.writeUInt32LE(value, Number(offset));
  if (trailingBytes !== 0) bytes.fill(0xa5, 0x1000);
  return bytes;
};

export const psxFixtureSha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/** Exact original baseline declaration oracle, independent of the source parser. */
export const psxFixtureCommitment = (
  sourcePath = "/tmp/owned PSX 雪/target",
  bytes = psxImportBytes(),
): PsxImportCommitment => ({
  schema_version: 3,
  source_provenance: "rea-psx-filebytes-rebind-v2",
  policy: "psx-kseg0-2m-defaults-v1",
  source_snapshot_path: sourcePath,
  source_sha256: psxFixtureSha256(bytes),
  declarations: {
    file_bytes: bytes.length,
    payload_file_offset: 2048,
    payload_address: "0x80010000",
    payload_bytes: 2048,
    trailing_bytes: bytes.length - 4096,
    initial_pc: "0x80010000",
    initial_gp: "0x0",
    data_address: "0x0",
    data_bytes: 0,
    fill_address: "0x0",
    fill_bytes: 0,
    stack_base: "0x0",
    stack_offset: "0x0",
    initial_sp: null,
  },
  loader: {
    selector: "PsxLoader",
    class_name: "psx.PsxLoader",
    display_name: "PSX Executables Loader",
    code_source_relative: "Ghidra/Extensions/renamed-psx/lib/psx.jar",
    code_source_sha256: "b".repeat(64),
  },
  language_id: "PSX:LE:32:default",
  compiler_spec_id: "default",
  option_mode: "loader-defaults",
  supplied_loader_options: {},
  expected_ram_base: "0x80000000",
  expected_ram_size: 2097152,
  asset_inventory_version: "ghidra-code-data-v1",
  asset_inventory_digest: "c".repeat(64),
});

/** Simulated independently observed metadata; correlation fields remain explicit. */
export const psxFixtureAgreement = (input: {
  readonly commitment: PsxImportCommitment;
  readonly runId: string;
  readonly profileDigest: string;
  readonly selectedClasses: PsxImportObservation["observed"]["selected_classes"];
  readonly languageAssets: PsxImportObservation["observed"]["language_assets"];
}): PsxImportAgreement => {
  const provenance = psxAppliedLoadImageObservation().psx!.provenance;
  provenance.source_sha256 = input.commitment.source_sha256;
  provenance.source_file_bytes = input.commitment.declarations.file_bytes;
  const original = psxFixtureOriginalRecord(
    {
      run_id: input.runId,
      profile_digest: input.profileDigest,
      source_sha256: input.commitment.source_sha256,
    },
    provenance.metadata_preservation,
  );
  provenance.metadata_preservation.original_record_sha256 = psxFixtureSha256(
    Buffer.from(`${JSON.stringify(original)}\n`),
  );
  const before: PsxImportObservation = {
    schema_version: 3,
    stage: "before-analysis",
    commitment: {
      run_id: input.runId,
      profile_digest: input.profileDigest,
      source_sha256: input.commitment.source_sha256,
    },
    provenance,
    observed: {
      ghidra_version: "12.1.4",
      source: {
        snapshot_path: input.commitment.source_snapshot_path,
        sha256: input.commitment.source_sha256,
        file_bytes: 4096,
      },
      program: {
        executable_path: input.commitment.source_snapshot_path,
        executable_format: "PSX Executables Loader",
        language_id: "PSX:LE:32:default",
        compiler_spec_id: "default",
        image_base: "0x80000000",
        default_address_space: "ram",
        ram_size: 2097152,
        external_entries: ["0x80010000"],
      },
      loader_selector: "PsxLoader",
      loader_class: "psx.PsxLoader",
      advertised_defaults: {
        ram_start: {
          argument: "-loader-ramStart",
          value_class: "java.lang.String",
          value: "0x80000000",
        },
        ram_size: {
          argument: "-loader-ramSize",
          value_class: "java.lang.String",
          value: "0x200000",
        },
      },
      selected_classes: structuredClone(input.selectedClasses),
      language_assets: structuredClone(input.languageAssets),
      asset_inventory_version: "ghidra-code-data-v1",
      asset_inventory_digest: input.commitment.asset_inventory_digest,
    },
  };
  return {
    schema_version: 3,
    before_record_sha256: psxFixtureSha256(
      Buffer.from(`${JSON.stringify(before)}\n`),
    ),
    before,
    after: { ...structuredClone(before), stage: "after-analysis" },
  };
};

export const psxFixtureOriginalRecord = (
  commitment: {
    readonly run_id: string;
    readonly profile_digest: string;
    readonly source_sha256: string;
  },
  metadata: PsxMetadataPreservation,
): PsxOriginalEvidenceRecord => ({
  schema_version: 1,
  commitment,
  state_sha256: metadata.original_state_sha256,
  operational_state_sha256: metadata.original_operational_state_sha256,
  label_history: structuredClone(metadata.label_history.before),
});

/** Producer-shaped simulated observations with deliberately absent FileBytes. */
export const psxLoadImageObservation = (
  bytes: Buffer,
): NativeLoadImageObservation => ({
  executable_format: "PSX Executables Loader",
  language_id: "PSX:LE:32:default",
  compiler_spec_id: "default",
  image_base: "0x80000000",
  default_address_space: "ram",
  source_files: [],
  mappings: [
    {
      block: "TEXT",
      start: "0x80010000",
      end: "0x800107ff",
      address_space: "ram",
      initialized: true,
      loaded: true,
      overlay: false,
      length: 0x800,
      source_file_index: null,
      file_offset: null,
      sha256: psxFixtureSha256(bytes.subarray(0x800, 0x1000)),
    },
  ],
  relocations: [],
  entry_points: ["0x80010000"],
  entry_context: [],
});

/** Simulated API-backed rebind, independent of the production attestor/parser. */
export const psxFixtureMetadataPreservation = (
  status: "applied" | "unavailable",
): PsxMetadataPreservation => {
  const before: PsxLabelHistoryRow[] = [
    {
      ordinal: 0,
      address: "0x80010000",
      label: "start",
      action: 0,
      user: null,
      modification_time_ms: "-9223372036854775808",
    },
    {
      ordinal: 1,
      address: "0x80010000",
      label: "start",
      action: 0,
      user: null,
      modification_time_ms: "-9223372036854775808",
    },
    {
      ordinal: 2,
      address: "0x80000010",
      label: "outside %雪",
      action: 127,
      user: "",
      modification_time_ms: null,
    },
  ];
  const after: PsxLabelHistoryRow[] =
    status === "unavailable"
      ? structuredClone(before)
      : [
          { ...before[2]!, ordinal: 0 },
          {
            ordinal: 1,
            address: "0x80010000",
            label: "start",
            action: 0,
            user: "REA simulated restoration",
            modification_time_ms: "9223372036854775807",
          },
        ];
  return {
    comparison: "exact-enumerated-state-except-label-history-v1",
    original_state_sha256: "d".repeat(64),
    adapted_state_sha256: (status === "unavailable" ? "d" : "e").repeat(64),
    original_operational_state_sha256: "c".repeat(64),
    adapted_operational_state_sha256: "c".repeat(64),
    operational_state_matched: true,
    original_record_sha256: "b".repeat(64),
    label_history: {
      scope: "complete-program-label-history",
      before,
      after,
      removed_before_ordinals: status === "unavailable" ? [] : [0, 1],
      added_after_ordinals: status === "unavailable" ? [] : [1],
      program_journal:
        status === "unavailable"
          ? "unchanged"
          : "recreated-at-payload-addresses",
    },
  };
};

export const psxAppliedLoadImageObservation = (
  bytes = psxImportBytes(),
): NativeLoadImageObservation => {
  const before = psxLoadImageObservation(bytes);
  const targetDigest = psxFixtureSha256(bytes);
  const payloadDigest = psxFixtureSha256(bytes.subarray(0x800, 0x1000));
  const metadata = psxFixtureMetadataPreservation("applied");
  const entryContext = [
    {
      address: "0x80010000",
      registers: [
        { name: "gp", value_hex: `0x${bytes.readUInt32LE(0x14).toString(16)}` },
        { name: "sp", value_hex: null },
      ],
    },
  ];
  return {
    ...before,
    source_files: [
      {
        name: "immutable snapshot 雪",
        size: bytes.length,
        original_sha256: targetDigest,
        modified_sha256: targetDigest,
      },
    ],
    mappings: before.mappings.map((mapping) => ({
      ...mapping,
      source_file_index: 0,
      file_offset: 0x800,
    })),
    entry_context: entryContext,
    psx: {
      schema_version: 2,
      provenance: {
        method: "rea-psx-filebytes-rebind-v2",
        status: "applied",
        reason: null,
        source_sha256: targetDigest,
        source_file_bytes: bytes.length,
        before: {
          source_files: [],
          mappings: before.mappings,
          entry_points: before.entry_points,
          entry_context: entryContext,
        },
        rebound_ranges: [
          {
            start: "0x80010000",
            end: "0x800107ff",
            length: 0x800,
            file_offset: 0x800,
            source_file_index: 0,
            before_sha256: payloadDigest,
            after_sha256: payloadDigest,
          },
        ],
        metadata_preservation: metadata,
      },
      current_label_history: structuredClone(metadata.label_history.after),
      entry_instruction: {
        address: "0x80010000",
        status: "instruction",
        length: 4,
      },
    },
  };
};

/** Honest unavailable preparation preserves the original unbacked observations. */
export const psxUnavailableLoadImageObservation = (
  bytes = psxImportBytes(),
): NativeLoadImageObservation => {
  const original = psxLoadImageObservation(bytes);
  const applied = psxAppliedLoadImageObservation(bytes);
  return {
    ...original,
    psx: {
      ...applied.psx!,
      provenance: {
        ...applied.psx!.provenance,
        status: "unavailable",
        reason: "Synthetic unsupported affected data definition",
        rebound_ranges: [],
        metadata_preservation: psxFixtureMetadataPreservation("unavailable"),
      },
      current_label_history:
        psxFixtureMetadataPreservation("unavailable").label_history.after,
    },
  };
};
