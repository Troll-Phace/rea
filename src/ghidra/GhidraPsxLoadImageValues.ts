import { createHash } from "node:crypto";
import {
  psxLoadImageSchema,
  type NativeLoadImage,
  type NativeLoadImageObservation,
  type PsxLoadImage,
  type PsxLoadImageCheck,
  type PsxLoadImageProvenance,
  type PsxLabelHistoryRow,
} from "../domain/native/nativeLoadImage.js";
import { parsePsxExeHeader, type PsxExeHeader } from "../domain/psxExe.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";

const hash = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const hex = (value: number): string => `0x${value.toString(16)}`;
const coordinate = (value: string): number | null =>
  /^0x(?:0|[1-9a-f][a-f0-9]{0,7})$/u.test(value)
    ? Number.parseInt(value.slice(2), 16)
    : null;
type Interval = readonly [number, number]; // exclusive end
const unionBytes = (intervals: readonly Interval[]): number => {
  const sorted = [...intervals].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let total = 0;
  let end = -1;
  for (const [start, stop] of sorted) {
    total += Math.max(0, stop - Math.max(start, end));
    end = Math.max(end, stop);
  }
  return total;
};

/** Independently verify immutable PSX source bytes against fresh provider observations. */
export const attestGhidraPsxLoadImage = (
  bytes: Buffer,
  targetSha256: string,
  measured: NativeLoadImageObservation,
): Result<NativeLoadImage, string> => {
  const observations = measured;
  if (hash(bytes) !== targetSha256)
    return err(
      "Ghidra load-image snapshot digest does not match the admitted target",
    );
  const parsed = parsePsxExeHeader(bytes);
  if (!parsed.ok) return err(parsed.error.reason);
  const header = parsed.value;
  if (header.payloadExtent === null)
    return err(
      "PSX load-image attestation requires a nonempty admitted payload",
    );
  const payloadStart = header.payloadAddress;
  const payloadEnd = payloadStart + header.payloadBytes;
  const pc = hex(header.initialPc);
  const checks: PsxLoadImageCheck[] = [];
  const limitations = [
    "Verification covers only REA-adapted static payload source coverage and exact declared entry instruction; it does not establish original-loader lineage or runtime behavior.",
    "Mapping ends are inclusive; source ranges have exclusive ends. Header and trailing bytes participate in source identity, never payload coverage.",
    "Operational preservation hashes record authenticated producer comparisons, not independent reconstruction of private Program state. Journal row differences and exposed source, mapping, entry and register facts are checked independently.",
    "The original-evidence file reference is validated against exact fixed-file bytes, run, profile, source and retained original state during authenticated startup; inspection does not reconstruct that file from its digest.",
    "Current label history is fresh inspection evidence after analysis; the retained before/after journal rows describe the preparation transaction, so later analysis events are not attributed to adaptation.",
  ];
  const check = (
    name: string,
    expected: JsonValue,
    observed: JsonValue,
    options: {
      required?: boolean;
      unknown?: string;
      fileOffset?: number | null;
      address?: string | null;
    } = {},
  ): void => {
    checks.push({
      name,
      status:
        options.unknown !== undefined
          ? "unknown"
          : JSON.stringify(expected) === JSON.stringify(observed)
            ? "matched"
            : "mismatch",
      required: options.required ?? true,
      expected,
      observed,
      file_offset: options.fileOffset ?? null,
      address: options.address ?? null,
      reason: options.unknown ?? null,
    });
  };
  const provenance = observations.psx?.provenance;
  const applied = provenance?.status === "applied";
  const context: AttestationContext = {
    bytes,
    targetSha256,
    observations,
    header,
    payloadStart,
    payloadEnd,
    pc,
    provenance,
    applied,
    checks,
    check,
    limitations,
  };
  const sourceMatched = checkSource(context);
  checkMetadata(context);
  const { examined, verified, exact, auxiliary } = checkMappings(
    context,
    sourceMatched,
  );
  checkRebound(context);
  checkEntry(context, verified);
  checkRegisters(context);
  checkAuxiliary(context);
  const complete =
    exact &&
    unionBytes(examined) === header.payloadBytes &&
    unionBytes(verified) === header.payloadBytes;
  const status = checks.some((item) => item.status === "mismatch")
    ? "mismatch"
    : complete &&
        checks.every((item) => !item.required || item.status === "matched")
      ? "verified"
      : "unsupported";
  const result = psxLoadImageSchema.safeParse({
    status,
    format: "ps-x-exe",
    reason:
      status === "unsupported"
        ? "Required independent PSX provenance, coverage or entry evidence is unavailable."
        : null,
    target_sha256: targetSha256,
    header_bytes: 2048,
    payload_bytes: header.payloadBytes,
    trailing_bytes: header.trailingBytes,
    payload: {
      file_offset: 2048,
      start: hex(payloadStart),
      end: hex(payloadEnd - 1),
    },
    entry: { declared_pc: pc },
    declarations: {
      initial_gp: hex(header.initialGp),
      data_address: hex(header.declaredDataAddress),
      data_bytes: header.declaredDataBytes,
      fill_address: hex(header.fillAddress),
      fill_bytes: header.fillBytes,
      stack_base: hex(header.stackBase),
      stack_offset: hex(header.stackOffset),
      initial_sp: header.initialSp === null ? null : hex(header.initialSp),
    },
    observations,
    checks,
    coverage: {
      scope: "rea-adapted-static-payload-v1",
      expected_payload_bytes: header.payloadBytes,
      examined_payload_bytes: unionBytes(examined),
      verified_payload_bytes: unionBytes(verified),
      complete,
      auxiliary,
    },
    limitations,
  });
  return result.success
    ? ok(result.data)
    : err("Independent PSX load-image result did not match its contract");
};

type CheckOptions = {
  required?: boolean;
  unknown?: string;
  fileOffset?: number | null;
  address?: string | null;
};
interface AttestationContext {
  bytes: Buffer;
  targetSha256: string;
  observations: NativeLoadImageObservation;
  header: PsxExeHeader;
  payloadStart: number;
  payloadEnd: number;
  pc: string;
  provenance: PsxLoadImageProvenance | undefined;
  applied: boolean;
  checks: PsxLoadImageCheck[];
  check: (
    name: string,
    expected: JsonValue,
    observed: JsonValue,
    options?: CheckOptions,
  ) => void;
  limitations: string[];
}

const checkSource = (context: AttestationContext): boolean => {
  const {
    bytes,
    targetSha256,
    observations,
    header,
    payloadStart,
    payloadEnd,
    provenance,
    applied,
    check,
  } = context;
  check(
    "executable_format",
    "PSX Executables Loader",
    observations.executable_format,
  );
  check("language_id", "PSX:LE:32:default", observations.language_id);
  check("compiler_spec_id", "default", observations.compiler_spec_id);
  check("default_address_space", "ram", observations.default_address_space);
  check("image_base", "0x80000000", observations.image_base);
  check(
    "admitted_payload",
    true,
    payloadStart >= 0x80000000 &&
      payloadEnd <= 0x80200000 &&
      header.initialPc % 4 === 0 &&
      header.initialPc >= payloadStart &&
      header.initialPc + 4 <= payloadEnd,
  );
  check(
    "provenance",
    "applied",
    provenance?.status ?? null,
    applied
      ? {}
      : {
          unknown:
            provenance?.reason ??
            "Required PSX source adaptation evidence is unavailable.",
        },
  );
  if (provenance !== undefined) {
    check(
      "provenance.method",
      "rea-psx-filebytes-rebind-v2",
      provenance.method,
    );
    check("provenance.source_sha256", targetSha256, provenance.source_sha256);
    check(
      "provenance.source_file_bytes",
      bytes.length,
      provenance.source_file_bytes,
    );
    check(
      "provenance.outcome_shape",
      true,
      applied
        ? provenance.reason === null && provenance.rebound_ranges.length > 0
        : provenance.reason !== null && provenance.rebound_ranges.length === 0,
    );
    check(
      "provenance.external_entries_preserved",
      true,
      provenance.before.entry_points.every((entry) =>
        observations.entry_points.includes(entry),
      ),
    );
  }
  const missingSource = !applied && observations.source_files.length === 0;
  const sourceOptions = missingSource
    ? { unknown: "No FileBytes source identity is available." }
    : {};
  check(
    "source_file_count",
    1,
    observations.source_files.length,
    sourceOptions,
  );
  const source = observations.source_files[0];
  check("source_file_size", bytes.length, source?.size ?? null, sourceOptions);
  check(
    "original_file_sha256",
    targetSha256,
    source?.original_sha256 ?? null,
    sourceOptions,
  );
  check(
    "modified_file_sha256",
    targetSha256,
    source?.modified_sha256 ?? null,
    sourceOptions,
  );
  const sourceMatched =
    observations.source_files.length === 1 &&
    source?.size === bytes.length &&
    source.original_sha256 === targetSha256 &&
    source.modified_sha256 === targetSha256;
  return sourceMatched;
};

const rowKey = (row: PsxLabelHistoryRow): string =>
  JSON.stringify([
    row.address,
    row.label,
    row.action,
    row.user,
    row.modification_time_ms,
  ]);
const contiguousOrdinals = (rows: readonly PsxLabelHistoryRow[]): boolean =>
  rows.every((row, index) => row.ordinal === index);
const javaLongDates = (rows: readonly PsxLabelHistoryRow[]): boolean =>
  rows.every((row) => {
    const value = row.modification_time_ms;
    if (value === null) return true;
    if (value.length > 20) return false;
    const date = BigInt(value);
    return date >= -9223372036854775808n && date <= 9223372036854775807n;
  });
/** Match duplicates in source order, without sorting or rewriting observed rows. */
const journalDelta = (
  before: readonly PsxLabelHistoryRow[],
  after: readonly PsxLabelHistoryRow[],
): { removed: number[]; added: number[] } => {
  const available = new Map<string, { ordinals: number[]; cursor: number }>();
  for (const row of after) {
    const key = rowKey(row);
    const matches = available.get(key) ?? { ordinals: [], cursor: 0 };
    matches.ordinals.push(row.ordinal);
    available.set(key, matches);
  }
  const matched = new Set<number>();
  const removed: number[] = [];
  for (const row of before) {
    const candidates = available.get(rowKey(row));
    const ordinal = candidates?.ordinals[candidates.cursor];
    if (ordinal === undefined) removed.push(row.ordinal);
    else {
      candidates!.cursor++;
      matched.add(ordinal);
    }
  }
  return {
    removed,
    added: after
      .filter((row) => !matched.has(row.ordinal))
      .map((row) => row.ordinal),
  };
};

const checkMetadata = (
  context: Pick<
    AttestationContext,
    | "provenance"
    | "applied"
    | "check"
    | "payloadStart"
    | "payloadEnd"
    | "limitations"
  > & {
    observations?: NativeLoadImageObservation;
  },
): void => {
  const {
    provenance,
    observations,
    applied,
    check,
    payloadStart,
    payloadEnd,
    limitations,
  } = context;
  if (provenance === undefined) return;
  const metadata = provenance.metadata_preservation;
  const journal = metadata.label_history;
  const delta = journalDelta(journal.before, journal.after);
  const changed = delta.removed.length > 0 || delta.added.length > 0;
  check(
    "provenance.operational_state",
    true,
    metadata.operational_state_matched &&
      metadata.original_operational_state_sha256 ===
        metadata.adapted_operational_state_sha256,
  );
  check(
    "provenance.label_history_ordinals",
    true,
    contiguousOrdinals(journal.before) && contiguousOrdinals(journal.after),
  );
  if (observations?.psx !== undefined)
    check(
      "current_label_history.ordinals",
      true,
      contiguousOrdinals(observations.psx.current_label_history),
    );
  check(
    "provenance.label_history_dates",
    true,
    javaLongDates(journal.before) && javaLongDates(journal.after),
  );
  if (observations?.psx !== undefined)
    check(
      "current_label_history.dates",
      true,
      javaLongDates(observations.psx.current_label_history),
    );
  check(
    "provenance.label_history_delta",
    {
      removed_before_ordinals: delta.removed,
      added_after_ordinals: delta.added,
    },
    {
      removed_before_ordinals: journal.removed_before_ordinals,
      added_after_ordinals: journal.added_after_ordinals,
    },
  );
  const affected = (row: PsxLabelHistoryRow): boolean => {
    const address = coordinate(row.address);
    return address !== null && address >= payloadStart && address < payloadEnd;
  };
  const removed = new Set(delta.removed);
  const added = new Set(delta.added);
  check(
    "provenance.label_history_scope",
    true,
    journal.before.every((row) => !removed.has(row.ordinal) || affected(row)) &&
      journal.after.every(
        (row) => !added.has(row.ordinal) || (affected(row) && row.action === 0),
      ),
  );
  check(
    "provenance.journal_disposition",
    changed ? "recreated-at-payload-addresses" : "unchanged",
    journal.program_journal,
  );
  check(
    "provenance.original_evidence_linkage",
    true,
    /^[a-f0-9]{64}$/u.test(metadata.original_record_sha256),
  );
  check(
    "provenance.full_state_consistency",
    true,
    changed ===
      (metadata.original_state_sha256 !== metadata.adapted_state_sha256),
  );
  if (!applied)
    check(
      "provenance.unavailable_state",
      true,
      !changed &&
        metadata.original_state_sha256 === metadata.adapted_state_sha256 &&
        journal.program_journal === "unchanged",
    );
  if (changed)
    limitations.push(
      "Original label history is retained as evidence. The adapted Program may contain newly generated label-history events from REA restoration; its original journal was not restored in place.",
      "Correlation of recreated ADD journal rows with measured symbol/function restoration operations is an authenticated producer check; inspection independently checks row differences and affected scope.",
    );
};

/** Apply the same retained-metadata invariants at authenticated startup and inspection. */
export const validateGhidraPsxPreparation = (
  provenance: PsxLoadImageProvenance,
  expected: {
    sourceSha256: string;
    sourceFileBytes: number;
    payloadStart: number;
    payloadBytes: number;
  },
): Result<undefined, string> => {
  const failed: string[] = [];
  const check: AttestationContext["check"] = (name, wanted, observed) => {
    if (JSON.stringify(wanted) !== JSON.stringify(observed)) failed.push(name);
  };
  const applied = provenance.status === "applied";
  check("provenance.method", "rea-psx-filebytes-rebind-v2", provenance.method);
  check(
    "provenance.source_sha256",
    expected.sourceSha256,
    provenance.source_sha256,
  );
  check(
    "provenance.source_file_bytes",
    expected.sourceFileBytes,
    provenance.source_file_bytes,
  );
  check(
    "provenance.outcome_shape",
    true,
    applied
      ? provenance.reason === null && provenance.rebound_ranges.length > 0
      : provenance.reason !== null &&
          provenance.reason.trim().length > 0 &&
          provenance.rebound_ranges.length === 0,
  );
  checkMetadata({
    provenance,
    applied,
    check,
    payloadStart: expected.payloadStart,
    payloadEnd: expected.payloadStart + expected.payloadBytes,
    limitations: [],
  });
  return failed.length === 0
    ? ok(undefined)
    : err(`PSX preparation contradicts ${failed.join(", ")}`);
};

const checkMappings = (context: AttestationContext, sourceMatched: boolean) => {
  const {
    bytes,
    observations,
    header,
    payloadStart,
    payloadEnd,
    applied,
    checks,
    check,
  } = context;
  const examined: Interval[] = [];
  const verified: Interval[] = [];
  const payloadIntervals: Interval[] = [];
  const auxiliary: PsxLoadImage["coverage"]["auxiliary"] = [];
  const backed = observations.mappings
    .map((mapping, index) => ({ mapping, index }))
    .sort(
      (a, b) =>
        (coordinate(a.mapping.start) ?? -1) -
          (coordinate(b.mapping.start) ?? -1) ||
        (a.mapping.file_offset ?? -1) - (b.mapping.file_offset ?? -1),
    );
  for (const { mapping, index } of backed) {
    const start = coordinate(mapping.start);
    const endInclusive = coordinate(mapping.end);
    const end = endInclusive === null ? null : endInclusive + 1;
    const intersects =
      start !== null &&
      end !== null &&
      start < payloadEnd &&
      end > payloadStart;
    const inDefault = mapping.address_space === "ram" && !mapping.overlay;
    const isBacked =
      mapping.source_file_index !== null || mapping.file_offset !== null;
    const at = `mapping[${index}]`;
    if (isBacked || (inDefault && intersects)) {
      const firstCheck = checks.length;
      const location = start === null ? null : mapping.start;
      const options = { fileOffset: mapping.file_offset, address: location };
      check(
        `${at}.coordinates`,
        true,
        start !== null && end !== null && end - start === mapping.length,
        options,
      );
      check(
        `${at}.payload_extent`,
        true,
        start !== null &&
          end !== null &&
          start >= payloadStart &&
          end <= payloadEnd,
        options,
      );
      check(`${at}.address_space`, "ram", mapping.address_space, options);
      check(`${at}.overlay`, false, mapping.overlay, options);
      check(`${at}.initialized`, true, mapping.initialized, options);
      check(`${at}.loaded`, true, mapping.loaded, options);
      check(
        `${at}.source_file_index`,
        0,
        mapping.source_file_index,
        !applied && !isBacked
          ? { ...options, unknown: "Payload memory has no source link." }
          : options,
      );
      const expectedOffset =
        start === null ? null : 2048 + start - payloadStart;
      check(
        `${at}.file_offset`,
        expectedOffset,
        mapping.file_offset,
        !applied && !isBacked
          ? { ...options, unknown: "Payload memory has no source offset." }
          : options,
      );
      const validSlice =
        expectedOffset !== null &&
        expectedOffset >= 2048 &&
        expectedOffset + mapping.length <= 2048 + header.payloadBytes;
      check(
        `${at}.memory_sha256`,
        validSlice
          ? hash(
              bytes.subarray(expectedOffset, expectedOffset + mapping.length),
            )
          : null,
        mapping.sha256,
        mapping.sha256 === null && !applied
          ? { ...options, unknown: "No measured payload digest is available." }
          : options,
      );
      if (inDefault && intersects && start !== null && end !== null) {
        const interval: Interval = [
          Math.max(start, payloadStart),
          Math.min(end, payloadEnd),
        ];
        payloadIntervals.push(interval);
        if (mapping.initialized && mapping.sha256 !== null)
          examined.push(interval);
        if (
          applied &&
          sourceMatched &&
          checks.slice(firstCheck).every((item) => item.status === "matched")
        )
          verified.push(interval);
      }
    } else {
      const declaredFill =
        start !== null &&
        end !== null &&
        header.fillExtent !== null &&
        start < header.fillExtent.endInclusive + 1 &&
        end > header.fillAddress;
      auxiliary.push({
        mapping_index: index,
        classification:
          !inDefault || mapping.start.includes(":")
            ? "alias-or-overlay"
            : start === null || end === null
              ? "unknown"
              : declaredFill
                ? "declared-fill"
                : mapping.initialized
                  ? "initialized-auxiliary"
                  : "uninitialized-memory",
      });
    }
  }
  const ordered = [...payloadIntervals].sort(
    (a, b) => a[0] - b[0] || a[1] - b[1],
  );
  let cursor = payloadStart;
  let exact = ordered.length > 0;
  for (const [start, end] of ordered) {
    if (start !== cursor) exact = false;
    cursor = Math.max(cursor, end);
  }
  exact &&= cursor === payloadEnd;
  check(
    "payload.coverage",
    header.payloadBytes,
    unionBytes(payloadIntervals),
    !applied && payloadIntervals.length === 0
      ? { unknown: "No payload mappings were observed." }
      : {},
  );
  check(
    "payload.exactly_once",
    true,
    exact,
    !applied && payloadIntervals.length === 0
      ? { unknown: "Payload source coverage is unavailable." }
      : {},
  );
  check(
    "payload.source_verified_bytes",
    header.payloadBytes,
    unionBytes(verified),
    !applied
      ? { unknown: "Adapted source-backed payload coverage is unavailable." }
      : {},
  );
  return { examined, verified, exact, auxiliary };
};

const checkRebound = (context: AttestationContext): void => {
  const {
    bytes,
    observations,
    payloadStart,
    payloadEnd,
    provenance,
    applied,
    check,
  } = context;

  if (provenance !== undefined && applied) {
    const canonicalRanges = (
      rows: readonly {
        start: string;
        end: string;
        length: number;
        file_offset: number | null;
        source_file_index: number | null;
      }[],
    ) =>
      rows
        .map((row) =>
          JSON.stringify([
            row.start,
            row.end,
            row.length,
            row.file_offset,
            row.source_file_index,
          ]),
        )
        .sort();
    const linked = observations.mappings.filter(
      (mapping) => mapping.source_file_index !== null,
    );
    check(
      "provenance.rebound_mapping_ranges",
      canonicalRanges(provenance.rebound_ranges),
      canonicalRanges(linked),
    );
    provenance.rebound_ranges.forEach((range, index) => {
      const at = `provenance.rebound[${index}]`;
      const start = coordinate(range.start)!;
      const end = coordinate(range.end)! + 1;
      const offset = 2048 + start - payloadStart;
      const valid =
        start >= payloadStart &&
        end <= payloadEnd &&
        end - start === range.length &&
        range.file_offset === offset &&
        range.source_file_index === 0;
      check(`${at}.source_extent`, true, valid, {
        fileOffset: range.file_offset,
        address: range.start,
      });
      const expectedHash = valid
        ? hash(bytes.subarray(offset, offset + range.length))
        : null;
      check(`${at}.before_sha256`, expectedHash, range.before_sha256, {
        fileOffset: range.file_offset,
        address: range.start,
      });
      check(`${at}.after_sha256`, expectedHash, range.after_sha256, {
        fileOffset: range.file_offset,
        address: range.start,
      });
      const before = provenance.before.mappings.filter(
        (mapping) =>
          mapping.start === range.start &&
          mapping.end === range.end &&
          mapping.length === range.length &&
          mapping.address_space === "ram" &&
          mapping.initialized &&
          mapping.loaded &&
          !mapping.overlay,
      );
      check(`${at}.original_mapping`, 1, before.length, {
        address: range.start,
      });
      check(
        `${at}.original_mapping_sha256`,
        range.before_sha256,
        before[0]?.sha256 ?? null,
        { address: range.start },
      );
    });
  }
};

const checkEntry = (
  context: AttestationContext,
  verified: readonly Interval[],
): void => {
  const { observations, header, pc, applied, check } = context;
  check(
    "entry.external",
    true,
    observations.entry_points.includes(pc),
    observations.entry_points.length === 0 && !applied
      ? { unknown: "External entry observation is unavailable." }
      : { address: pc },
  );
  check(
    "entry.verified_coverage",
    true,
    header.initialPc % 4 === 0 &&
      unionBytes(
        verified
          .filter(
            ([start, end]) =>
              start < header.initialPc + 4 && end > header.initialPc,
          )
          .map(
            ([start, end]) =>
              [
                Math.max(start, header.initialPc),
                Math.min(end, header.initialPc + 4),
              ] as Interval,
          ),
      ) === 4,
    !applied
      ? { unknown: "Entry source coverage is unavailable.", address: pc }
      : { address: pc },
  );
  const instruction = observations.psx?.entry_instruction;
  const entryUnknown =
    instruction === undefined
      ? {
          unknown: "Exact listing entry observation is unavailable.",
          address: pc,
        }
      : { address: pc };
  check(
    "entry.instruction_address",
    pc,
    instruction?.address ?? null,
    entryUnknown,
  );
  check(
    "entry.instruction_status",
    "instruction",
    instruction?.status ?? null,
    entryUnknown,
  );
  check(
    "entry.instruction_length",
    4,
    instruction?.length ?? null,
    entryUnknown,
  );
};

const checkRegisters = (context: AttestationContext): void => {
  const { observations, header, pc, check, limitations } = context;
  const contexts = observations.entry_context;
  check(
    "entry.context_rows",
    true,
    new Set(contexts.map((row) => row.address)).size === contexts.length &&
      contexts.every(
        (row) =>
          coordinate(row.address) !== null &&
          observations.entry_points.includes(row.address) &&
          new Set(row.registers.map((register) => register.name)).size ===
            row.registers.length &&
          row.registers.every(
            (register) => register.name === "gp" || register.name === "sp",
          ),
      ),
  );
  const entryRegisters = contexts.find((row) => row.address === pc)?.registers;
  for (const [name, declaration] of [
    ["gp", header.initialGp === 0 ? null : header.initialGp],
    ["sp", header.initialSp],
  ] as const) {
    const register = entryRegisters?.find((row) => row.name === name);
    const value = register?.value_hex ?? null;
    const valid = value === null || /^0x[0-9a-f]{1,8}$/u.test(value);
    check(`entry.${name}.coordinate`, true, valid, {
      required: false,
      address: pc,
    });
    const unknown =
      declaration === null
        ? `The ${name} declaration is unspecified; observed context is retained.`
        : value === null
          ? `Ghidra did not report ${name} at the declared entry.`
          : undefined;
    check(
      `entry.${name}`,
      declaration === null ? null : hex(declaration),
      value === null
        ? null
        : valid
          ? hex(Number.parseInt(value.slice(2), 16))
          : value,
      {
        required: false,
        address: pc,
        ...(unknown === undefined ? {} : { unknown }),
      },
    );
    if (unknown !== undefined) limitations.push(unknown);
  }
};

const checkAuxiliary = (context: AttestationContext): void => {
  const { observations, header, payloadStart, payloadEnd, check, limitations } =
    context;
  const payloadRelocations = observations.relocations.filter((row) => {
    const at = coordinate(row.address);
    return at === null || (at >= payloadStart && at < payloadEnd);
  });
  check("payload.relocations", [], payloadRelocations);
  if (observations.relocations.length > payloadRelocations.length)
    limitations.push(
      "Auxiliary relocation records outside the declared payload are retained without DOS relocation interpretation.",
    );
  if (header.fillBytes > 0) {
    const fillRows = observations.mappings.filter((mapping) => {
      const start = coordinate(mapping.start);
      const end = coordinate(mapping.end);
      return (
        mapping.address_space === "ram" &&
        !mapping.overlay &&
        start !== null &&
        end !== null &&
        start < header.fillAddress + header.fillBytes &&
        end >= header.fillAddress
      );
    });
    check("fill.intersection", true, fillRows.length > 0, {
      required: false,
      ...(fillRows.length === 0
        ? { unknown: "No declared fill interval intersection was observed." }
        : {}),
    });
    check("fill.contents", "declared fill contents", null, {
      required: false,
      unknown:
        "Fill intersection and initialization are observations; zero contents and runtime initialization are not established.",
    });
    limitations.push(
      "Declared fill intersection does not prove zero content; uninitialized fill contents remain unknown.",
    );
  }
};
