import { z } from "zod";
import { nativeMetadataRecoverySummarySchema } from "./nativeMetadataRecovery.js";
import { jsonValueSchema } from "../jsonValue.js";

const integer = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const hexBytes = z.string().regex(/^(?:[a-f0-9]{2})*$/u);
const address = z.string().min(1);

/** Exact measured FileBytes identity, retaining the provider's source name. */
export const nativeLoadImageSourceFileSchema = z.strictObject({
  name: z.string(),
  size: integer,
  original_sha256: digest,
  modified_sha256: digest,
});
/** One measured source interval; ends are inclusive. */
export const nativeLoadImageMappingSchema = z.strictObject({
  block: z.string(),
  start: address,
  end: address,
  address_space: z.string().min(1),
  initialized: z.boolean(),
  loaded: z.boolean(),
  overlay: z.boolean(),
  length: integer.min(1),
  source_file_index: integer.nullable(),
  file_offset: integer.nullable(),
  sha256: digest.nullable(),
});
/** Register context at an observed external entry, including unavailable values. */
export const nativeLoadImageEntryContextSchema = z.strictObject({
  address,
  registers: z.array(
    z.strictObject({
      name: z.string().min(1),
      value_hex: z
        .string()
        .regex(/^0x[a-f0-9]+$/u)
        .nullable(),
    }),
  ),
});
const psxAddress = z.string().regex(/^0x(?:0|[1-9a-f][a-f0-9]{0,7})$/u);
/** Complete public API journal row, retaining source enumeration and lossless dates. */
export const psxLabelHistoryRowSchema = z.strictObject({
  ordinal: integer,
  address,
  label: z.string().nullable(),
  action: z.number().int().min(-128).max(127),
  user: z.string().nullable(),
  modification_time_ms: z
    .string()
    .regex(/^(?:0|-?[1-9][0-9]*)$/u)
    .nullable(),
});
/** Authenticated producer state comparisons; full journal rows remain explicit. */
export const psxMetadataPreservationSchema = z.strictObject({
  comparison: z.literal("exact-enumerated-state-except-label-history-v1"),
  original_state_sha256: digest,
  adapted_state_sha256: digest,
  original_operational_state_sha256: digest,
  adapted_operational_state_sha256: digest,
  operational_state_matched: z.boolean(),
  original_record_sha256: digest,
  label_history: z.strictObject({
    scope: z.literal("complete-program-label-history"),
    before: z.array(psxLabelHistoryRowSchema),
    after: z.array(psxLabelHistoryRowSchema),
    removed_before_ordinals: z.array(integer),
    added_after_ordinals: z.array(integer),
    program_journal: z.enum(["unchanged", "recreated-at-payload-addresses"]),
  }),
});
/** Retained preparation evidence; interpretation belongs to the provider adapter. */
export const psxLoadImageProvenanceSchema = z.strictObject({
  method: z.literal("rea-psx-filebytes-rebind-v2"),
  status: z.enum(["applied", "unavailable"]),
  reason: z.string().min(1).nullable(),
  source_sha256: digest,
  source_file_bytes: integer,
  before: z.strictObject({
    source_files: z.array(nativeLoadImageSourceFileSchema),
    mappings: z.array(nativeLoadImageMappingSchema),
    entry_points: z.array(address),
    entry_context: z.array(nativeLoadImageEntryContextSchema),
  }),
  rebound_ranges: z.array(
    z.strictObject({
      start: psxAddress,
      end: psxAddress,
      length: integer.min(1),
      file_offset: integer,
      source_file_index: integer,
      before_sha256: digest,
      after_sha256: digest,
    }),
  ),
  metadata_preservation: psxMetadataPreservationSchema,
});
/** PSX-specific observations without inferring runtime behavior. */
export const psxLoadImageObservationSchema = z.strictObject({
  schema_version: z.literal(2),
  provenance: psxLoadImageProvenanceSchema,
  current_label_history: z.array(psxLabelHistoryRowSchema),
  entry_instruction: z.strictObject({
    address: psxAddress,
    status: z.enum(["instruction", "not-instruction", "unmapped"]),
    length: integer.min(1).nullable(),
  }),
});
/** Measured provider image, without exporting the complete executable bytes. */
export const nativeLoadImageObservationSchema = z.strictObject({
  metadata_recovery: z.array(nativeMetadataRecoverySummarySchema).optional(),
  executable_format: z.string().min(1),
  language_id: z.string().min(1),
  compiler_spec_id: z.string().min(1),
  image_base: address,
  default_address_space: z.string().min(1),
  source_files: z.array(nativeLoadImageSourceFileSchema),
  mappings: z.array(nativeLoadImageMappingSchema),
  relocations: z.array(
    z.strictObject({
      address,
      segment: integer.max(0xffff).nullable(),
      offset: integer.max(0xffff).nullable(),
      status: z.string().min(1),
      type: z.number().int(),
      values: z.array(
        z
          .number()
          .int()
          .min(Number.MIN_SAFE_INTEGER)
          .max(Number.MAX_SAFE_INTEGER),
      ),
      original_bytes_hex: hexBytes.nullable(),
      memory_bytes_hex: hexBytes.nullable(),
    }),
  ),
  entry_points: z.array(address),
  entry_context: z.array(nativeLoadImageEntryContextSchema),
  psx: psxLoadImageObservationSchema.optional(),
});

/** Independent comparison, preserving both expectations and measured values. */
export const nativeLoadImageCheckSchema = z.strictObject({
  name: z.string().min(1),
  matched: z.boolean(),
  expected: jsonValueSchema,
  observed: jsonValueSchema,
  file_offset: integer.nullable(),
  address: address.nullable(),
});

/** Read-only native image verification; verified applies only to declared coverage. */
export const legacyNativeLoadImageSchema = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("unsupported"),
    reason: z.string().min(1),
    observations: nativeLoadImageObservationSchema,
    limitations: z.array(z.string().min(1)),
  }),
  z.strictObject({
    status: z.enum(["verified", "mismatch"]),
    format: z.enum(["dos-mz", "dos-com"]),
    target_sha256: digest,
    load_segment: integer.max(0xffff),
    header_bytes: integer,
    module_bytes: integer,
    overlay_bytes: integer,
    entry: z.strictObject({
      relative_segment: integer.max(0xffff),
      offset: integer.max(0xffff),
      linear_address: address,
    }),
    observations: nativeLoadImageObservationSchema,
    checks: z.array(nativeLoadImageCheckSchema),
    limitations: z.array(z.string().min(1)),
  }),
]);

/** A PSX comparison retains unknown independently from contradiction. */
export const psxLoadImageCheckSchema = z.strictObject({
  name: z.string().min(1),
  status: z.enum(["matched", "mismatch", "unknown"]),
  required: z.boolean(),
  expected: jsonValueSchema,
  observed: jsonValueSchema,
  file_offset: integer.nullable(),
  address: psxAddress.nullable(),
  reason: z.string().min(1).nullable(),
});
/** Independently checked static PSX payload; declarations remain separate. */
const psxLoadImageBaseSchema = z.strictObject({
  status: z.enum(["verified", "mismatch", "unsupported"]),
  format: z.literal("ps-x-exe"),
  reason: z.string().min(1).nullable(),
  target_sha256: digest,
  header_bytes: z.literal(2048),
  payload_bytes: integer,
  trailing_bytes: integer,
  payload: z.strictObject({
    file_offset: z.literal(2048),
    start: psxAddress,
    end: psxAddress,
  }),
  entry: z.strictObject({ declared_pc: psxAddress }),
  declarations: z.strictObject({
    initial_gp: psxAddress,
    data_address: psxAddress,
    data_bytes: integer,
    fill_address: psxAddress,
    fill_bytes: integer,
    stack_base: psxAddress,
    stack_offset: psxAddress,
    initial_sp: psxAddress.nullable(),
  }),
  observations: nativeLoadImageObservationSchema,
  checks: z.array(psxLoadImageCheckSchema),
  coverage: z.strictObject({
    scope: z.literal("rea-adapted-static-payload-v1"),
    expected_payload_bytes: integer,
    examined_payload_bytes: integer,
    verified_payload_bytes: integer,
    complete: z.boolean(),
    auxiliary: z.array(
      z.strictObject({
        mapping_index: integer,
        classification: z.enum([
          "uninitialized-memory",
          "initialized-auxiliary",
          "alias-or-overlay",
          "declared-fill",
          "unknown",
        ]),
      }),
    ),
  }),
  limitations: z.array(z.string().min(1)),
});
/** Status-dependent reason is part of the advertised JSON contract. */
export const psxLoadImageSchema = z.union([
  psxLoadImageBaseSchema.extend({
    status: z.literal("unsupported"),
    reason: z.string().min(1),
  }),
  psxLoadImageBaseSchema.extend({
    status: z.enum(["verified", "mismatch"]),
    reason: z.string().min(1).nullable(),
  }),
]);
/** Preserve legacy DOS/unsupported wire shapes alongside PSX's distinct result. */
export const nativeLoadImageSchema = z.union([
  legacyNativeLoadImageSchema,
  psxLoadImageSchema,
]);
export type PsxLoadImageProvenance = z.infer<
  typeof psxLoadImageProvenanceSchema
>;
export type PsxLabelHistoryRow = z.infer<typeof psxLabelHistoryRowSchema>;
export type PsxMetadataPreservation = z.infer<
  typeof psxMetadataPreservationSchema
>;
export type PsxLoadImage = z.infer<typeof psxLoadImageSchema>;
export type PsxLoadImageCheck = z.infer<typeof psxLoadImageCheckSchema>;

/** Provider-neutral native load-image result. */
export type LegacyNativeLoadImage = z.infer<typeof legacyNativeLoadImageSchema>;
export type NativeLoadImage = z.infer<typeof nativeLoadImageSchema>;
/** Measured source mappings, bytes, relocations and entries. */
export type NativeLoadImageObservation = z.infer<
  typeof nativeLoadImageObservationSchema
>;
/** One independently compared native import fact. */
export type NativeLoadImageCheck = z.infer<typeof nativeLoadImageCheckSchema>;
