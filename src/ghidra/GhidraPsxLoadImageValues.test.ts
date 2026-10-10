import { describe, expect, it } from "vitest";
import { attestGhidraNativeLoadImage } from "./GhidraLoadImageAttest.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { attestGhidraPsxLoadImage } from "./GhidraPsxLoadImageValues.js";
import { fixturePsxLoadImage } from "./GhidraPsxLoadImage.fixture.js";
import type {
  NativeLoadImageObservation,
  PsxLoadImage,
} from "../domain/native/nativeLoadImage.js";

const attest = (fixture = fixturePsxLoadImage()): PsxLoadImage => {
  const result = attestGhidraPsxLoadImage(
    fixture.bytes,
    fixture.sha256,
    fixture.observation,
  );
  expect(result.ok).toBe(true);
  if (
    !result.ok ||
    !("format" in result.value) ||
    result.value.format !== "ps-x-exe"
  )
    throw new Error("Expected PSX result");
  return result.value;
};
const mutations: readonly [
  string,
  string,
  (x: NativeLoadImageObservation) => void,
][] = [
  [
    "mapping start",
    "mapping[0].coordinates",
    (x) => {
      x.mappings[0]!.start = "0x80010004";
    },
  ],
  [
    "mapping end",
    "mapping[0].coordinates",
    (x) => {
      x.mappings[0]!.end = "0x800103fe";
    },
  ],
  [
    "mapping length",
    "mapping[0].coordinates",
    (x) => {
      x.mappings[0]!.length--;
    },
  ],
  [
    "nondefault coordinate",
    "mapping[0].coordinates",
    (x) => {
      x.mappings[0]!.start = "other:0x80010000";
    },
  ],
  [
    "noncanonical coordinate",
    "mapping[0].coordinates",
    (x) => {
      x.mappings[0]!.start = "0x080010000";
    },
  ],
  [
    "source index",
    "mapping[0].source_file_index",
    (x) => {
      x.mappings[0]!.source_file_index = 1;
    },
  ],
  [
    "offset despite equal memory hash",
    "mapping[1].file_offset",
    (x) => {
      x.mappings[1]!.file_offset = 3068;
    },
  ],
  [
    "original digest",
    "original_file_sha256",
    (x) => {
      x.source_files[0]!.original_sha256 = "f".repeat(64);
    },
  ],
  [
    "modified digest",
    "modified_file_sha256",
    (x) => {
      x.source_files[0]!.modified_sha256 = "f".repeat(64);
    },
  ],
  [
    "source size",
    "source_file_size",
    (x) => {
      x.source_files[0]!.size++;
    },
  ],
  [
    "source collection",
    "source_file_count",
    (x) => {
      x.source_files = [];
    },
  ],
  [
    "payload digest",
    "mapping[0].memory_sha256",
    (x) => {
      x.mappings[0]!.sha256 = "f".repeat(64);
    },
  ],
  [
    "gap",
    "payload.coverage",
    (x) => {
      x.mappings.splice(0, 1);
    },
  ],
  [
    "duplicate",
    "payload.exactly_once",
    (x) => {
      x.mappings.push(structuredClone(x.mappings[0]!));
    },
  ],
  [
    "overlap",
    "payload.exactly_once",
    (x) => {
      x.mappings[1]!.start = "0x800103fc";
    },
  ],
  [
    "unbacked intersection",
    "mapping[2].source_file_index",
    (x) => {
      x.mappings.push({
        ...x.mappings[0]!,
        source_file_index: null,
        file_offset: null,
      });
    },
  ],
  [
    "header source range",
    "mapping[0].file_offset",
    (x) => {
      x.mappings[0]!.file_offset = 0;
    },
  ],
  [
    "trailing source range",
    "mapping[1].file_offset",
    (x) => {
      x.mappings[1]!.file_offset = 4096;
    },
  ],
  [
    "overlay",
    "mapping[0].overlay",
    (x) => {
      x.mappings[0]!.overlay = true;
    },
  ],
  [
    "uninitialized",
    "mapping[0].initialized",
    (x) => {
      x.mappings[0]!.initialized = false;
    },
  ],
  [
    "unloaded",
    "mapping[0].loaded",
    (x) => {
      x.mappings[0]!.loaded = false;
    },
  ],
  [
    "forged empty applied links",
    "payload.source_verified_bytes",
    (x) => {
      x.mappings = [];
    },
  ],
  [
    "provenance source digest",
    "provenance.source_sha256",
    (x) => {
      x.psx!.provenance.source_sha256 = "f".repeat(64);
    },
  ],
  [
    "provenance source bytes",
    "provenance.source_file_bytes",
    (x) => {
      x.psx!.provenance.source_file_bytes++;
    },
  ],
  [
    "producer operational comparison false",
    "provenance.operational_state",
    (x) => {
      x.psx!.provenance.metadata_preservation.operational_state_matched = false;
    },
  ],
  [
    "unavailable outcome with applied links",
    "provenance.outcome_shape",
    (x) => {
      x.psx!.provenance.status = "unavailable";
      x.psx!.provenance.reason = "Unsupported state";
    },
  ],
  [
    "operational restoration disagreement",
    "provenance.operational_state",
    (x) => {
      x.psx!.provenance.metadata_preservation.adapted_operational_state_sha256 =
        "f".repeat(64);
    },
  ],
  [
    "rebound offset",
    "provenance.rebound[0].source_extent",
    (x) => {
      x.psx!.provenance.rebound_ranges[0]!.file_offset++;
    },
  ],
  [
    "stale rebound hash",
    "provenance.rebound[0].after_sha256",
    (x) => {
      x.psx!.provenance.rebound_ranges[0]!.after_sha256 = "f".repeat(64);
    },
  ],
  [
    "original payload digest",
    "provenance.rebound[0].original_mapping_sha256",
    (x) => {
      x.psx!.provenance.before.mappings[0]!.sha256 = "f".repeat(64);
    },
  ],
  [
    "omitted entry",
    "entry.external",
    (x) => {
      x.entry_points = [];
    },
  ],
  [
    "misaligned external entry",
    "entry.external",
    (x) => {
      x.entry_points = ["0x80010001"];
    },
  ],
  [
    "wrong external entry",
    "entry.external",
    (x) => {
      x.entry_points = ["0x80010004"];
    },
  ],
  [
    "containing instruction",
    "entry.instruction_address",
    (x) => {
      x.psx!.entry_instruction.address = "0x8000fffc";
    },
  ],
  [
    "not instruction",
    "entry.instruction_status",
    (x) => {
      x.psx!.entry_instruction.status = "not-instruction";
      x.psx!.entry_instruction.length = null;
    },
  ],
  [
    "unmapped entry",
    "entry.instruction_status",
    (x) => {
      x.psx!.entry_instruction.status = "unmapped";
      x.psx!.entry_instruction.length = null;
    },
  ],
  [
    "instruction length",
    "entry.instruction_length",
    (x) => {
      x.psx!.entry_instruction.length = 8;
    },
  ],
  [
    "nonzero GP",
    "entry.gp",
    (x) => {
      x.entry_context[0]!.registers[0]!.value_hex = "0x80018004";
    },
  ],
  [
    "nonzero SP",
    "entry.sp",
    (x) => {
      x.entry_context[0]!.registers[1]!.value_hex = "0x801ff004";
    },
  ],
  [
    "duplicate contexts",
    "entry.context_rows",
    (x) => {
      x.entry_context.push(structuredClone(x.entry_context[0]!));
    },
  ],
  [
    "duplicate registers",
    "entry.context_rows",
    (x) => {
      x.entry_context[0]!.registers.push({ name: "gp", value_hex: null });
    },
  ],
  [
    "unexpected register",
    "entry.context_rows",
    (x) => {
      x.entry_context[0]!.registers.push({ name: "CS", value_hex: null });
    },
  ],
  [
    "unexpected context",
    "entry.context_rows",
    (x) => {
      x.entry_context[0]!.address = "0x80010100";
    },
  ],
  [
    "payload relocation",
    "payload.relocations",
    (x) => {
      x.relocations.push({
        address: "0x80010000",
        segment: null,
        offset: null,
        status: "APPLIED",
        type: 1,
        values: [],
        original_bytes_hex: null,
        memory_bytes_hex: null,
      });
    },
  ],
  [
    "format",
    "executable_format",
    (x) => {
      x.executable_format = "Raw Binary";
    },
  ],
  [
    "language",
    "language_id",
    (x) => {
      x.language_id = "MIPS:LE:32:default";
    },
  ],
  [
    "compiler",
    "compiler_spec_id",
    (x) => {
      x.compiler_spec_id = "windows";
    },
  ],
  [
    "image base",
    "image_base",
    (x) => {
      x.image_base = "0x80010000";
    },
  ],
];

describe("independent PSX static load image", () => {
  it("verifies complete split payload, retaining measured GP and unavailable SP", () => {
    const result = attest();
    expect(result.status).toBe("verified");
    expect(result.coverage).toMatchObject({
      complete: true,
      expected_payload_bytes: 2048,
      examined_payload_bytes: 2048,
      verified_payload_bytes: 2048,
    });
    expect(
      result.checks.find((item) => item.name === "entry.sp"),
    ).toMatchObject({ status: "unknown", required: false });
    expect(result.observations.source_files[0]!.name).toBe(
      "caller selected fixture 雪.exe",
    );
  });
  it.each(mutations)("rejects %s at named check %s", (_name, check, mutate) => {
    const fixture = fixturePsxLoadImage();
    mutate(fixture.observation);
    const result = attest(fixture);
    expect(result.status).toBe("mismatch");
    expect(result.checks.find((item) => item.name === check)?.status).toBe(
      "mismatch",
    );
  });
  it("accepts arbitrary order, names, extra external entries and unrelated initialized auxiliary memory", () => {
    const fixture = fixturePsxLoadImage({ trailingBytes: 16, fill: true });
    fixture.observation.mappings.reverse();
    fixture.observation.mappings[0]!.block = "not a hardware assertion";
    fixture.observation.mappings.push({
      block: "BIOS by name only",
      start: "0x1fc00000",
      end: "0x1fc00003",
      address_space: "ram",
      initialized: true,
      loaded: true,
      overlay: false,
      length: 4,
      source_file_index: null,
      file_offset: null,
      sha256: "f".repeat(64),
    });
    fixture.observation.entry_points.push("0x80010010");
    const result = attest(fixture);
    expect(result.status).toBe("verified");
    expect(result.trailing_bytes).toBe(16);
    expect(
      result.coverage.auxiliary.map((item) => item.classification).sort(),
    ).toEqual(["declared-fill", "initialized-auxiliary"]);
    expect(
      result.checks.find((item) => item.name === "fill.contents")?.status,
    ).toBe("unknown");
  });
});

describe("PSX coverage and uncertainty", () => {
  it("does not double count duplicated coverage", () => {
    const fixture = fixturePsxLoadImage();
    fixture.observation.mappings.push(
      structuredClone(fixture.observation.mappings[0]!),
    );
    const result = attest(fixture);
    expect(result.coverage.examined_payload_bytes).toBe(2048);
    expect(result.coverage.verified_payload_bytes).toBe(2048);
    expect(result.coverage.complete).toBe(false);
  });
  it("keeps perfect memory equality unsupported when adaptation is absent", () => {
    const fixture = fixturePsxLoadImage();
    delete fixture.observation.psx;
    fixture.observation.source_files = [];
    fixture.observation.mappings.forEach((mapping) => {
      mapping.source_file_index = null;
      mapping.file_offset = null;
    });
    const result = attest(fixture);
    expect(result.status).toBe("unsupported");
    expect(
      result.checks.find((item) => item.name === "provenance")?.status,
    ).toBe("unknown");
    expect(result.coverage).toMatchObject({
      examined_payload_bytes: 2048,
      verified_payload_bytes: 0,
      complete: false,
    });
    expect(result.checks.some((item) => item.status === "mismatch")).toBe(
      false,
    );
  });
  it("retains valid unavailable preparation with empty sources as unknown", () => {
    const fixture = fixturePsxLoadImage();
    const provenance = fixture.observation.psx!.provenance;
    provenance.status = "unavailable";
    provenance.reason = "Affected data definitions cannot be preserved.";
    provenance.rebound_ranges = [];
    const metadata = provenance.metadata_preservation;
    metadata.adapted_state_sha256 = metadata.original_state_sha256;
    metadata.label_history.after = structuredClone(
      metadata.label_history.before,
    );
    metadata.label_history.removed_before_ordinals = [];
    metadata.label_history.added_after_ordinals = [];
    metadata.label_history.program_journal = "unchanged";
    fixture.observation.source_files = [];
    fixture.observation.mappings = [];
    const result = attest(fixture);
    expect(result.status).toBe("unsupported");
    expect(
      result.checks.find((item) => item.name === "source_file_count")?.status,
    ).toBe("unknown");
  });
  it("gives contradictions precedence over required unknowns", () => {
    const fixture = fixturePsxLoadImage();
    delete fixture.observation.psx;
    fixture.observation.source_files[0]!.original_sha256 = "f".repeat(64);
    const result = attest(fixture);
    expect(result.status).toBe("mismatch");
    expect(
      result.checks.find((item) => item.name === "provenance")?.status,
    ).toBe("unknown");
  });
  it("retains zero GP with derived observation and unspecified SP with nonzero raw offset", () => {
    const fixture = fixturePsxLoadImage({
      gp: 0,
      stackBase: 0,
      stackOffset: 0x100,
    });
    fixture.observation.entry_context[0]!.registers[0]!.value_hex =
      "0x80018000";
    fixture.observation.entry_context[0]!.registers[1]!.value_hex =
      "0x801ff000";
    const result = attest(fixture);
    expect(result.status).toBe("verified");
    expect(result.declarations).toMatchObject({
      initial_gp: "0x0",
      stack_base: "0x0",
      stack_offset: "0x100",
      initial_sp: null,
    });
    expect(result.checks.find((item) => item.name === "entry.gp")?.status).toBe(
      "unknown",
    );
    expect(result.checks.find((item) => item.name === "entry.sp")?.status).toBe(
      "unknown",
    );
  });
  it("preserves optional null GP and SP", () => {
    const fixture = fixturePsxLoadImage();
    fixture.observation.entry_context[0]!.registers.forEach((register) => {
      register.value_hex = null;
    });
    expect(attest(fixture).status).toBe("verified");
  });
  it("returns boundary errors without throwing on malformed observations or changed snapshot", async () => {
    const fixture = fixturePsxLoadImage();
    expect(
      attestGhidraPsxLoadImage(
        fixture.bytes,
        "f".repeat(64),
        fixture.observation,
      ),
    ).toMatchObject({ ok: false });
    fixture.observation.psx!.entry_instruction.address = "overlay:0x80010000";
    const failure = await attestGhidraNativeLoadImage(
      {
        path: "/caller/selected.exe",
        sha256: fixture.sha256,
        kind: "executable",
        format: "ps-x-exe",
        architecture: "mips",
        availableArchitectures: ["mips"],
      },
      "inspect_native_load_image",
      jsonValueSchema.parse(fixture.observation),
      {},
      () => {
        throw new Error("No session error expected");
      },
    );
    expect(failure.ok).toBe(false);
    if (!failure.ok) expect(failure.error).toBeInstanceOf(AnalysisOutputError);
  });
});

describe("PSX retained journal evidence", () => {
  it("matches reordered duplicates by earliest available ordinal and preserves raw rows", () => {
    const fixture = fixturePsxLoadImage();
    const metadata = fixture.observation.psx!.provenance.metadata_preservation;
    const original = metadata.label_history.before[0]!;
    const outside = {
      ...original,
      address: "overlay:outside",
      label: null,
      action: 127,
      user: null,
      modification_time_ms: "-9223372036854775808",
    };
    const recreated = metadata.label_history.after[0]!;
    metadata.label_history.before = [
      { ...original, ordinal: 0 },
      { ...outside, ordinal: 1 },
      { ...original, ordinal: 2 },
    ];
    metadata.label_history.after = [
      { ...outside, ordinal: 0 },
      { ...original, ordinal: 1 },
      { ...recreated, ordinal: 2 },
    ];
    metadata.label_history.removed_before_ordinals = [2];
    metadata.label_history.added_after_ordinals = [2];
    const result = attest(fixture);
    expect(result.status).toBe("verified");
    expect(
      result.observations.psx!.provenance.metadata_preservation.label_history,
    ).toEqual(metadata.label_history);
    expect(
      result.limitations.some((value) =>
        value.includes("its original journal was not restored in place"),
      ),
    ).toBe(true);
    metadata.label_history.removed_before_ordinals = [0];
    const mutated = attest(fixture);
    expect(mutated.status).toBe("mismatch");
    expect(
      mutated.checks.find(
        (value) => value.name === "provenance.label_history_delta",
      ),
    ).toMatchObject({
      status: "mismatch",
      expected: { removed_before_ordinals: [2], added_after_ordinals: [2] },
    });
  });
  it("keeps full equality mandatory for unavailable and unchanged journals", () => {
    const fixture = fixturePsxLoadImage();
    const provenance = fixture.observation.psx!.provenance;
    provenance.status = "unavailable";
    provenance.reason = "Unsupported measured data";
    provenance.rebound_ranges = [];
    const result = attest(fixture);
    expect(result.status).toBe("mismatch");
    expect(
      result.checks.find(
        (value) => value.name === "provenance.unavailable_state",
      )?.status,
    ).toBe("mismatch");
    provenance.status = "applied";
    provenance.reason = null;
    const journal = provenance.metadata_preservation.label_history;
    journal.after = structuredClone(journal.before);
    journal.removed_before_ordinals = [];
    journal.added_after_ordinals = [];
    journal.program_journal = "unchanged";
    expect(
      attest(fixture).checks.find(
        (value) => value.name === "provenance.full_state_consistency",
      )?.status,
    ).toBe("mismatch");
  });
  it("accepts Java long endpoints and keeps post-analysis journal independent", () => {
    const fixture = fixturePsxLoadImage();
    fixture.observation.psx!.provenance.metadata_preservation.label_history.before[0]!.modification_time_ms =
      "-9223372036854775808";
    fixture.observation.psx!.provenance.metadata_preservation.label_history.after[0]!.modification_time_ms =
      "9223372036854775807";
    fixture.observation.psx!.current_label_history[0]!.action = 2;
    fixture.observation.psx!.current_label_history[0]!.address =
      "later-overlay:1";
    const result = attest(fixture);
    expect(result.status).toBe("verified");
    expect(result.observations.psx!.current_label_history).toEqual(
      fixture.observation.psx!.current_label_history,
    );
  });
});

describe("PSX journal contradictions", () => {
  it.each([
    [
      "changed journal with forged equal full-state hashes",
      "provenance.full_state_consistency",
      (x: NativeLoadImageObservation) => {
        const metadata = x.psx!.provenance.metadata_preservation;
        metadata.adapted_state_sha256 = metadata.original_state_sha256;
      },
    ],
    [
      "incorrect before ordinal",
      "provenance.label_history_ordinals",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.before[0]!.ordinal = 1;
      },
    ],
    [
      "incorrect current ordinal",
      "current_label_history.ordinals",
      (x: NativeLoadImageObservation) => {
        x.psx!.current_label_history[0]!.ordinal = 1;
      },
    ],
    [
      "outside removal",
      "provenance.label_history_scope",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.before[0]!.address =
          "0x80020000";
      },
    ],
    [
      "overlay addition",
      "provenance.label_history_scope",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.after[0]!.address =
          "overlay:0x80010000";
      },
    ],
    [
      "rename addition",
      "provenance.label_history_scope",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.after[0]!.action = 2;
      },
    ],
    [
      "unknown added action",
      "provenance.label_history_scope",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.after[0]!.action =
          -1;
      },
    ],
    [
      "false unchanged disposition",
      "provenance.journal_disposition",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.program_journal =
          "unchanged";
      },
    ],
    [
      "out of long range preparation date",
      "provenance.label_history_dates",
      (x: NativeLoadImageObservation) => {
        x.psx!.provenance.metadata_preservation.label_history.before[0]!.modification_time_ms =
          "9223372036854775808";
      },
    ],
    [
      "out of long range current date",
      "current_label_history.dates",
      (x: NativeLoadImageObservation) => {
        x.psx!.current_label_history[0]!.modification_time_ms =
          "-9223372036854775809";
      },
    ],
  ] as const)(
    "rejects %s without altering source coverage",
    (_name, checkName, mutate) => {
      const fixture = fixturePsxLoadImage();
      mutate(fixture.observation);
      const result = attest(fixture);
      expect(result.status).toBe("mismatch");
      expect(result.coverage.verified_payload_bytes).toBe(2048);
      expect(
        result.checks.find((value) => value.name === checkName)?.status,
      ).toBe("mismatch");
    },
  );
});
