import { z } from "zod";
import {
  psxLabelHistoryRowSchema,
  psxLoadImageProvenanceSchema,
} from "../domain/native/nativeLoadImage.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const address = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/u);
const length = z.number().int().nonnegative().safe();
const text = z.string().min(1);
const relativePath = text.refine(
  (value) =>
    !value.startsWith("/") &&
    value
      .split("/")
      .every((part) => part !== ".." && part !== "." && part.length > 0),
);
const ordered = <T>(
  values: readonly T[],
  identity: (value: T) => string,
): boolean =>
  values.every(
    (value, index) =>
      index === 0 || identity(values[index - 1]!) < identity(value),
  );

/** Strict source declarations; these are expectations, never observed runtime state. */
export const psxDeclarationsSchema = z
  .object({
    file_bytes: length,
    payload_file_offset: z.literal(2048),
    payload_address: address,
    payload_bytes: length,
    trailing_bytes: length,
    initial_pc: address,
    initial_gp: address,
    data_address: address,
    data_bytes: length,
    fill_address: address,
    fill_bytes: length,
    stack_base: address,
    stack_offset: address,
    initial_sp: address.nullable(),
  })
  .strict();

/** Deterministic, provider-owned import expectation. Snapshot path is transport only. */
export const psxImportCommitmentSchema = z
  .object({
    schema_version: z.literal(3),
    source_provenance: z.literal("rea-psx-filebytes-rebind-v2"),
    policy: z.literal("psx-kseg0-2m-defaults-v1"),
    source_snapshot_path: text,
    source_sha256: digest,
    declarations: psxDeclarationsSchema,
    loader: z
      .object({
        selector: z.literal("PsxLoader"),
        class_name: z.literal("psx.PsxLoader"),
        display_name: z.literal("PSX Executables Loader"),
        code_source_relative: relativePath,
        code_source_sha256: digest,
      })
      .strict(),
    language_id: z.literal("PSX:LE:32:default"),
    compiler_spec_id: z.literal("default"),
    option_mode: z.literal("loader-defaults"),
    supplied_loader_options: z.object({}).strict(),
    expected_ram_base: z.literal("0x80000000"),
    expected_ram_size: z.literal(2097152),
    asset_inventory_version: z.literal("ghidra-code-data-v1"),
    asset_inventory_digest: digest,
  })
  .strict();

export type PsxImportCommitment = Readonly<
  z.infer<typeof psxImportCommitmentSchema>
>;
/** One launch mode replaces independent loader booleans. */
export type GhidraImportConfiguration =
  | { readonly kind: "automatic" }
  | { readonly kind: "dos-mz" }
  | { readonly kind: "dos-com" }
  | { readonly kind: "psx"; readonly commitment: PsxImportCommitment };

const selectedClassSchema = z
  .object({
    class_name: text,
    role: z.enum(["loader", "analyzer"]),
    code_source_url: text,
    code_source_relative: relativePath,
    code_source_sha256: digest,
    class_resource_url: text,
    enabled: z.boolean().nullable(),
  })
  .strict();
export type PsxSelectedClass = Readonly<z.infer<typeof selectedClassSchema>>;
const option = (argument: "-loader-ramStart" | "-loader-ramSize") =>
  z
    .object({
      argument: z.literal(argument),
      value_class: z.literal("java.lang.String"),
      value: text,
    })
    .strict();

/** Independent JVM observations at one analysis stage, with explicit correlation metadata. */
export const psxImportObservationSchema = z
  .object({
    schema_version: z.literal(3),
    stage: z.enum(["before-analysis", "after-analysis"]),
    commitment: z
      .object({
        run_id: z.string().uuid(),
        profile_digest: digest,
        source_sha256: digest,
      })
      .strict(),
    provenance: psxLoadImageProvenanceSchema,
    observed: z
      .object({
        ghidra_version: text,
        source: z
          .object({ snapshot_path: text, sha256: digest, file_bytes: length })
          .strict(),
        program: z
          .object({
            executable_path: text,
            executable_format: text,
            language_id: text,
            compiler_spec_id: text,
            image_base: address,
            default_address_space: text,
            ram_size: length,
            external_entries: z
              .array(address)
              .refine((values) => ordered(values, (value) => value)),
          })
          .strict(),
        loader_selector: text,
        loader_class: text,
        advertised_defaults: z
          .object({
            ram_start: option("-loader-ramStart"),
            ram_size: option("-loader-ramSize"),
          })
          .strict(),
        selected_classes: z
          .array(selectedClassSchema)
          .min(1)
          .refine((values) => ordered(values, (value) => value.class_name)),
        language_assets: z
          .array(
            z.object({ relative_path: relativePath, sha256: digest }).strict(),
          )
          .min(1)
          .refine((values) => ordered(values, (value) => value.relative_path)),
        asset_inventory_version: z.literal("ghidra-code-data-v1"),
        asset_inventory_digest: digest,
      })
      .strict(),
  })
  .strict();
export type PsxImportObservation = Readonly<
  z.infer<typeof psxImportObservationSchema>
>;
export const psxImportAgreementSchema = z
  .object({
    schema_version: z.literal(3),
    before_record_sha256: digest,
    before: psxImportObservationSchema.refine(
      (value) => value.stage === "before-analysis",
    ),
    after: psxImportObservationSchema.refine(
      (value) => value.stage === "after-analysis",
    ),
  })
  .strict();
export type PsxImportAgreement = Readonly<
  z.infer<typeof psxImportAgreementSchema>
>;

/** Exact fixed private file retained before preparation mutates its disposable Program. */
export const psxOriginalEvidenceRecordSchema = z.strictObject({
  schema_version: z.literal(1),
  commitment: z.strictObject({
    run_id: z.string().uuid(),
    profile_digest: digest,
    source_sha256: digest,
  }),
  state_sha256: digest,
  operational_state_sha256: digest,
  label_history: z.array(psxLabelHistoryRowSchema),
});
export type PsxOriginalEvidenceRecord = z.infer<
  typeof psxOriginalEvidenceRecordSchema
>;

/** Internal startup expectation; transport observations keep their single wire shape. */
export interface GhidraPsxStartupExpectation {
  readonly commitment: PsxImportCommitment;
  readonly installationRoot: string;
  readonly assets: readonly {
    readonly relative_path: string;
    readonly file_bytes: number;
    readonly sha256: string;
  }[];
  readonly languageAssets: readonly {
    readonly relative_path: string;
    readonly sha256: string;
  }[];
  readonly analyzerClasses: readonly string[];
}
