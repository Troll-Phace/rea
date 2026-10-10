import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  nativeLoadImageObservationSchema,
  nativeLoadImageSchema,
  psxLoadImageSchema,
  psxLabelHistoryRowSchema,
  type NativeLoadImageObservation,
} from "./nativeLoadImage.js";

const observation = (): NativeLoadImageObservation => ({
  executable_format: "provider source spelling",
  language_id: "provider language",
  compiler_spec_id: "default",
  image_base: "0x0",
  default_address_space: "ram",
  source_files: [
    {
      name: "source 雪.exe",
      size: 4096,
      original_sha256: "a".repeat(64),
      modified_sha256: "a".repeat(64),
    },
  ],
  mappings: [
    {
      block: "source",
      start: "0x80010000",
      end: "0x800107ff",
      address_space: "ram",
      initialized: true,
      loaded: true,
      overlay: false,
      length: 2048,
      source_file_index: 0,
      file_offset: 2048,
      sha256: "b".repeat(64),
    },
  ],
  relocations: [],
  entry_points: [],
  entry_context: [],
  psx: {
    schema_version: 2,
    provenance: {
      method: "rea-psx-filebytes-rebind-v2",
      status: "unavailable",
      reason: "Measured unavailable preparation",
      source_sha256: "a".repeat(64),
      source_file_bytes: 4096,
      before: {
        source_files: [],
        mappings: [],
        entry_points: [],
        entry_context: [],
      },
      rebound_ranges: [],
      metadata_preservation: {
        comparison: "exact-enumerated-state-except-label-history-v1",
        original_state_sha256: "b".repeat(64),
        adapted_state_sha256: "b".repeat(64),
        original_operational_state_sha256: "c".repeat(64),
        adapted_operational_state_sha256: "c".repeat(64),
        operational_state_matched: true,
        original_record_sha256: "d".repeat(64),
        label_history: {
          scope: "complete-program-label-history",
          before: [],
          after: [],
          removed_before_ordinals: [],
          added_after_ordinals: [],
          program_journal: "unchanged",
        },
      },
    },
    current_label_history: [],
    entry_instruction: {
      address: "0x80010000",
      status: "unmapped",
      length: null,
    },
  },
});
const psxResult = () => ({
  status: "unsupported",
  format: "ps-x-exe",
  reason: "Required coverage unavailable",
  target_sha256: "a".repeat(64),
  header_bytes: 2048,
  payload_bytes: 2048,
  trailing_bytes: 0,
  payload: { file_offset: 2048, start: "0x80010000", end: "0x800107ff" },
  entry: { declared_pc: "0x80010000" },
  declarations: {
    initial_gp: "0x0",
    data_address: "0x0",
    data_bytes: 0,
    fill_address: "0x0",
    fill_bytes: 0,
    stack_base: "0x0",
    stack_offset: "0x100",
    initial_sp: null,
  },
  observations: observation(),
  checks: [
    {
      name: "provenance",
      status: "unknown",
      required: true,
      expected: "applied",
      observed: "unavailable",
      file_offset: null,
      address: null,
      reason: "Measured unavailable preparation",
    },
  ],
  coverage: {
    scope: "rea-adapted-static-payload-v1",
    expected_payload_bytes: 2048,
    examined_payload_bytes: 0,
    verified_payload_bytes: 0,
    complete: false,
    auxiliary: [],
  },
  limitations: ["Runtime behavior is unknown"],
});

describe("native load-image wire contracts", () => {
  it("preserves DOS MZ/COM and legacy unsupported JSON shapes", () => {
    const measured = observation();
    delete measured.psx;
    for (const format of ["dos-mz", "dos-com"]) {
      const value = {
        status: "verified",
        format,
        target_sha256: "a".repeat(64),
        load_segment: 4096,
        header_bytes: 0,
        module_bytes: 4,
        overlay_bytes: 0,
        entry: { relative_segment: 0, offset: 256, linear_address: "0x10100" },
        observations: measured,
        checks: [
          {
            name: "source",
            matched: true,
            expected: "source",
            observed: "source",
            file_offset: 0,
            address: "0x10100",
          },
        ],
        limitations: [],
      };
      expect(nativeLoadImageSchema.parse(value)).toEqual(value);
    }
    expect(nativeLoadImageObservationSchema.parse(measured)).toEqual(measured);
    const unsupported = {
      status: "unsupported",
      reason: "No verifier",
      observations: measured,
      limitations: [],
    };
    expect(nativeLoadImageSchema.parse(unsupported)).toEqual(unsupported);
  });
  it("advertises all PSX statuses and requires a reason for unsupported", () => {
    const value = psxResult();
    expect(nativeLoadImageSchema.parse(value)).toEqual(value);
    for (const status of ["verified", "mismatch"])
      expect(
        nativeLoadImageSchema.safeParse({ ...value, status, reason: null })
          .success,
      ).toBe(true);
    const encoded = JSON.stringify(
      z.toJSONSchema(nativeLoadImageSchema, { target: "draft-2020-12" }),
    );
    expect(encoded).toContain("rea-adapted-static-payload-v1");
    expect(encoded).toContain("ps-x-exe");
    expect(
      psxLoadImageSchema.safeParse({ ...value, reason: null }).success,
    ).toBe(false);
    expect(psxLoadImageSchema.safeParse({ ...value, reason: "" }).success).toBe(
      false,
    );
    expect(
      psxLoadImageSchema.safeParse({ ...value, load_segment: 4096 }).success,
    ).toBe(false);
  });
  it.each([
    [
      "extra PSX field",
      (x: NativeLoadImageObservation) => Object.assign(x.psx!, { extra: true }),
    ],
    [
      "unsafe count",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.source_file_bytes = Number.MAX_SAFE_INTEGER + 1;
      },
    ],
    [
      "uppercase digest",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.source_sha256 = "A".repeat(64);
      },
    ],
    [
      "nondefault PSX coordinate",
      (x: NativeLoadImageObservation) => {
        x.psx!.entry_instruction.address = "ram:0x80010000";
      },
    ],
    [
      "overflow coordinate",
      (x: NativeLoadImageObservation) => {
        x.psx!.entry_instruction.address = "0x100000000";
      },
    ],
    [
      "padded coordinate",
      (x: NativeLoadImageObservation) => {
        x.psx!.entry_instruction.address = "0x080010000";
      },
    ],
    [
      "wrong observation version",
      (x: NativeLoadImageObservation) =>
        Object.assign(x.psx!, { schema_version: 1 }),
    ],
  ] as const)("rejects malformed %s", (_name, mutate) => {
    const measured = observation();
    mutate(measured);
    expect(nativeLoadImageObservationSchema.safeParse(measured).success).toBe(
      false,
    );
  });
  it("retains generic coordinate/source spelling for provider semantic validation", () => {
    const measured = observation();
    measured.mappings[0]!.start = "other:0x80010000";
    measured.source_files[0]!.name = "/caller/selected source.exe";
    expect(nativeLoadImageObservationSchema.parse(measured)).toEqual(measured);
  });
});

describe("PSX complete journal wire contract", () => {
  it("retains journal source strings, nulls, unknown signed actions and lossless dates", () => {
    const row = {
      ordinal: 0,
      address: "overlay:0x80010000",
      label: "old -> new 雪",
      action: -128,
      user: "  source user  ",
      modification_time_ms: "-9223372036854775808",
    };
    expect(psxLabelHistoryRowSchema.parse(row)).toEqual(row);
    expect(
      psxLabelHistoryRowSchema.parse({
        ...row,
        label: null,
        user: null,
        modification_time_ms: null,
      }),
    ).toMatchObject({ label: null, user: null, modification_time_ms: null });
    for (const modification_time_ms of [
      "+1",
      "01",
      "-0",
      "1.5",
      "1e9",
      " 1",
      "",
    ])
      expect(
        psxLabelHistoryRowSchema.safeParse({ ...row, modification_time_ms })
          .success,
      ).toBe(false);
    for (const action of [-129, 128, 0.5])
      expect(
        psxLabelHistoryRowSchema.safeParse({ ...row, action }).success,
      ).toBe(false);
  });
  it("requires complete metadata and current rows and rejects superseded hash fields", () => {
    for (const mutate of [
      (value: Record<string, unknown>) => {
        delete value.current_label_history;
      },
      (value: Record<string, unknown>) => {
        delete (value.provenance as Record<string, unknown>)
          .metadata_preservation;
      },
      (value: Record<string, unknown>) => {
        Object.assign(value.provenance as Record<string, unknown>, {
          preserved_state_sha256: null,
          restored_state_sha256: null,
        });
      },
    ]) {
      const value = observation();
      mutate(value.psx!);
      expect(nativeLoadImageObservationSchema.safeParse(value).success).toBe(
        false,
      );
    }
  });
});
