import { resolve, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import {
  psxImportAgreementSchema,
  type GhidraPsxStartupExpectation,
  type PsxImportAgreement,
} from "./GhidraImportConfiguration.js";
import { z } from "zod";

import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { GHIDRA_INVENTORY_OPERATIONS } from "./GhidraInventoryValues.js";
import { GHIDRA_FUNCTION_OPERATIONS } from "./GhidraFunctionValues.js";
import { ghidraExtensionResultSchema } from "./extensions/GhidraExtensions.js";

/** Exact methods proved by the bridge handshake after auto-analysis. */
export const GHIDRA_SESSION_CAPABILITIES = [
  "ping",
  "shutdown",
  ...GHIDRA_INVENTORY_OPERATIONS,
  ...GHIDRA_FUNCTION_OPERATIONS,
] as const;

const capabilitySchema = z.enum(GHIDRA_SESSION_CAPABILITIES);

const sessionInfoSchema = z
  .object({
    name: z.literal("REA Ghidra bridge"),
    run_id: z.string().uuid(),
    profile_digest: z.string().regex(/^[a-f0-9]{64}$/u),
    provider: z
      .object({
        id: z.literal("ghidra"),
        version: z.string().min(1),
      })
      .strict(),
    read_only: z.boolean(),
    analysis_complete: z.boolean(),
    analysis_timed_out: z.boolean(),
    psx_import: psxImportAgreementSchema.optional(),
    analysis_extensions: z.array(ghidraExtensionResultSchema).optional(),
    capabilities: z.array(capabilitySchema),
    target: z
      .object({
        name: z.string().min(1),
        language_id: z.string().min(1),
        compiler_spec_id: z.string().min(1),
        image_base: z.string().regex(/^0x[0-9a-f]+$/u),
        default_address_space: z.string().min(1),
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      })
      .strict(),
  })
  .strict();

/** Authenticated metadata produced after Ghidra finishes auto-analysis. */
export type GhidraSessionInfo = z.infer<typeof sessionInfoSchema>;

/** Require exact run, provider, and profile identity from the Java bridge. */
export const parseGhidraSessionInfo = (
  value: JsonValue,
  expected: {
    readonly runId: string;
    readonly providerVersion: string;
    readonly profileDigest: string;
    readonly targetSha256: string;
    readonly psxImport?: GhidraPsxStartupExpectation;
    readonly psxBeforeRecordSha256?: string;
    readonly expectedReadOnly?: boolean;
    readonly expectedLanguageId?: string;
    readonly expectedCompilerSpecId?: string;
  },
): Result<GhidraSessionInfo, Error> => {
  const parsed = sessionInfoSchema.safeParse(value);
  const readOnly = expected.expectedReadOnly ?? false;
  const expectedCapabilities = GHIDRA_SESSION_CAPABILITIES.filter(
    (capability) => !readOnly || capability !== "annotate_native_function",
  );
  if (
    !parsed.success ||
    parsed.data.run_id !== expected.runId ||
    parsed.data.read_only !== readOnly ||
    parsed.data.capabilities.length !== expectedCapabilities.length ||
    parsed.data.provider.version !== expected.providerVersion ||
    parsed.data.profile_digest !== expected.profileDigest ||
    parsed.data.target.sha256 !== expected.targetSha256 ||
    (expected.expectedLanguageId !== undefined &&
      parsed.data.target.language_id !== expected.expectedLanguageId) ||
    (expected.expectedCompilerSpecId !== undefined &&
      parsed.data.target.compiler_spec_id !==
        expected.expectedCompilerSpecId) ||
    new Set(parsed.data.capabilities).size !== expectedCapabilities.length ||
    expectedCapabilities.some(
      (capability) => !parsed.data.capabilities.includes(capability),
    ) ||
    parsed.data.analysis_complete === parsed.data.analysis_timed_out ||
    (expected.psxImport === undefined
      ? parsed.data.psx_import !== undefined
      : parsed.data.psx_import === undefined ||
        !validatePsxAgreement(
          parsed.data.psx_import,
          expected.psxImport,
          expected.runId,
          expected.profileDigest,
          expected.providerVersion,
          expected.psxBeforeRecordSha256,
        ))
  )
    return err(new Error("Ghidra bridge handshake identity is invalid"));
  return ok(parsed.data);
};

/** Require acknowledgement that the private bridge loop has ended. */
export const isGhidraShutdownAcknowledgement = (value: JsonValue): boolean =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  value.shutdown === true &&
  value.project_ephemeral === true;

const samePath = (actual: string, expected: string): boolean =>
  isAbsolute(actual) &&
  isAbsolute(expected) &&
  resolve(actual) === resolve(expected);
const assetUrlPath = (url: string, root: string): string | null => {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "file:") return null;
    const path = relative(root, fileURLToPath(parsed));
    return path.startsWith("..") || isAbsolute(path) ? null : path;
  } catch {
    return null;
  }
};
const classResourceMatches = (
  resource: string,
  source: string,
  className: string,
): boolean => {
  if (!resource.startsWith("jar:")) return false;
  const index = resource.indexOf("!/");
  if (
    index < 0 ||
    resource.slice(index + 2) !== `${className.replaceAll(".", "/")}.class`
  )
    return false;
  try {
    return samePath(
      fileURLToPath(new URL(resource.slice(4, index))),
      fileURLToPath(new URL(source)),
    );
  } catch {
    return false;
  }
};
const advertisedNumber = (value: string): number | null =>
  /^0x[0-9a-f]+$/iu.test(value)
    ? Number.parseInt(value.slice(2), 16)
    : /^\d+$/u.test(value)
      ? Number(value)
      : null;
/** Compare independent source/program/resource observations, never echoed commitment alone. */
const validatePsxAgreement = (
  agreement: PsxImportAgreement,
  expected: GhidraPsxStartupExpectation,
  runId: string,
  profileDigest: string,
  version: string,
  beforeHash?: string,
): boolean => {
  const commitment = expected.commitment;
  if (beforeHash !== undefined && agreement.before_record_sha256 !== beforeHash)
    return false;
  for (const record of [agreement.before, agreement.after]) {
    const observed = record.observed;
    const program = observed.program;
    if (
      record.commitment.run_id !== runId ||
      record.commitment.profile_digest !== profileDigest ||
      record.commitment.source_sha256 !== commitment.source_sha256 ||
      observed.ghidra_version !== version ||
      !samePath(
        observed.source.snapshot_path,
        commitment.source_snapshot_path,
      ) ||
      observed.source.sha256 !== commitment.source_sha256 ||
      observed.source.file_bytes !== commitment.declarations.file_bytes ||
      !samePath(program.executable_path, commitment.source_snapshot_path) ||
      program.executable_format !== commitment.loader.display_name ||
      program.language_id !== commitment.language_id ||
      program.compiler_spec_id !== commitment.compiler_spec_id ||
      program.image_base !== commitment.expected_ram_base ||
      program.default_address_space !== "ram" ||
      program.ram_size !== commitment.expected_ram_size ||
      program.external_entries.length !== 1 ||
      program.external_entries[0] !== commitment.declarations.initial_pc ||
      observed.loader_selector !== commitment.loader.selector ||
      observed.loader_class !== commitment.loader.class_name ||
      observed.asset_inventory_version !== commitment.asset_inventory_version ||
      observed.asset_inventory_digest !== commitment.asset_inventory_digest ||
      advertisedNumber(observed.advertised_defaults.ram_start.value) !==
        Number.parseInt(commitment.expected_ram_base.slice(2), 16) ||
      advertisedNumber(observed.advertised_defaults.ram_size.value) !==
        commitment.expected_ram_size
    )
      return false;
    const loaders = observed.selected_classes.filter(
      (value) => value.role === "loader",
    );
    const analyzers = observed.selected_classes.filter(
      (value) => value.role === "analyzer",
    );
    if (
      loaders.length !== 1 ||
      loaders[0]!.class_name !== commitment.loader.class_name ||
      loaders[0]!.enabled !== null ||
      loaders[0]!.code_source_relative !==
        commitment.loader.code_source_relative ||
      loaders[0]!.code_source_sha256 !== commitment.loader.code_source_sha256 ||
      analyzers.length !== expected.analyzerClasses.length ||
      analyzers.some(
        (value, index) => value.class_name !== expected.analyzerClasses[index],
      )
    )
      return false;
    for (const cls of observed.selected_classes) {
      const asset = expected.assets.find(
        (asset) => asset.relative_path === cls.code_source_relative,
      );
      if (
        asset === undefined ||
        asset.sha256 !== cls.code_source_sha256 ||
        assetUrlPath(cls.code_source_url, expected.installationRoot) !==
          cls.code_source_relative ||
        !classResourceMatches(
          cls.class_resource_url,
          cls.code_source_url,
          cls.class_name,
        )
      )
        return false;
      if (
        cls.class_name === "ghidra.app.plugin.core.analysis.MipsPreAnalyzer" &&
        cls.code_source_relative !== "Ghidra/Processors/MIPS/lib/MIPS.jar"
      )
        return false;
    }
    if (
      !analyzers.some(
        (value) =>
          value.class_name ===
          "ghidra.app.plugin.core.analysis.MipsPreAnalyzer",
      )
    )
      return false;
    if (
      JSON.stringify(observed.language_assets) !==
      JSON.stringify(expected.languageAssets)
    )
      return false;
    for (const asset of observed.language_assets)
      if (
        !expected.assets.some(
          (value) =>
            value.relative_path === asset.relative_path &&
            value.sha256 === asset.sha256,
        )
      )
        return false;
  }
  return (
    JSON.stringify(agreement.before.observed) ===
    JSON.stringify(agreement.after.observed)
  );
};
