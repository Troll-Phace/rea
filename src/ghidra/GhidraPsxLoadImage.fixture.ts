import { createHash } from "node:crypto";
import type {
  NativeLoadImageObservation,
  PsxMetadataPreservation,
} from "../domain/native/nativeLoadImage.js";

const hash = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const fixtureMetadata = (): PsxMetadataPreservation => ({
  comparison: "exact-enumerated-state-except-label-history-v1",
  original_state_sha256: "a".repeat(64),
  adapted_state_sha256: "b".repeat(64),
  original_operational_state_sha256: "c".repeat(64),
  adapted_operational_state_sha256: "c".repeat(64),
  operational_state_matched: true,
  original_record_sha256: "d".repeat(64),
  label_history: {
    scope: "complete-program-label-history",
    before: [
      {
        ordinal: 0,
        address: "0x80010000",
        label: "start",
        action: 0,
        user: "exact original user",
        modification_time_ms: "9007199254740993",
      },
    ],
    after: [
      {
        ordinal: 0,
        address: "0x80010000",
        label: "start",
        action: 0,
        user: "adaptation user",
        modification_time_ms: "9007199254740994",
      },
    ],
    removed_before_ordinals: [0],
    added_after_ordinals: [0],
    program_journal: "recreated-at-payload-addresses",
  },
});

/** Independent source builder: fixed bytes and measured split ranges, without parser/attestor reuse. */
export const fixturePsxLoadImage = (
  options: {
    trailingBytes?: number;
    gp?: number;
    stackBase?: number;
    stackOffset?: number;
    fill?: boolean;
  } = {},
): {
  bytes: Buffer;
  sha256: string;
  observation: NativeLoadImageObservation;
} => {
  const bytes = Buffer.alloc(4096 + (options.trailingBytes ?? 0));
  bytes.write("PS-X EXE", 0, "ascii");
  bytes.writeUInt32LE(0x80010000, 0x10);
  bytes.writeUInt32LE(options.gp ?? 0x80018000, 0x14);
  bytes.writeUInt32LE(0x80010000, 0x18);
  bytes.writeUInt32LE(2048, 0x1c);
  bytes.writeUInt32LE(options.fill ? 0x80011000 : 0, 0x28);
  bytes.writeUInt32LE(options.fill ? 256 : 0, 0x2c);
  bytes.writeUInt32LE(options.stackBase ?? 0x801ff000, 0x30);
  bytes.writeUInt32LE(options.stackOffset ?? 0, 0x34);
  for (let offset = 2048; offset < 4096; offset += 4)
    bytes.writeUInt32LE(0x24020001, offset);
  bytes.fill(0xa5, 4096);
  const sha256 = hash(bytes);
  const mappings: NativeLoadImageObservation["mappings"] = [0, 1].map(
    (part) => ({
      block: `source-part-${part}`,
      start: `0x${(0x80010000 + part * 1024).toString(16)}`,
      end: `0x${(0x800103ff + part * 1024).toString(16)}`,
      address_space: "ram",
      initialized: true,
      loaded: true,
      overlay: false,
      length: 1024,
      source_file_index: 0,
      file_offset: 2048 + part * 1024,
      sha256: hash(bytes.subarray(2048 + part * 1024, 3072 + part * 1024)),
    }),
  );
  const entry_context = [
    {
      address: "0x80010000",
      registers: [
        {
          name: "gp",
          value_hex: `0x${(options.gp ?? 0x80018000).toString(16)}`,
        },
        { name: "sp", value_hex: null },
      ],
    },
  ];
  const beforeMappings = mappings.map((mapping) => ({
    ...mapping,
    source_file_index: null,
    file_offset: null,
  }));
  if (options.fill)
    mappings.push({
      block: "uninitialized declared fill",
      start: "0x80011000",
      end: "0x800110ff",
      address_space: "ram",
      initialized: false,
      loaded: true,
      overlay: false,
      length: 256,
      source_file_index: null,
      file_offset: null,
      sha256: null,
    });
  return {
    bytes,
    sha256,
    observation: {
      executable_format: "PSX Executables Loader",
      language_id: "PSX:LE:32:default",
      compiler_spec_id: "default",
      image_base: "0x80000000",
      default_address_space: "ram",
      source_files: [
        {
          name: "caller selected fixture 雪.exe",
          size: bytes.length,
          original_sha256: sha256,
          modified_sha256: sha256,
        },
      ],
      mappings,
      relocations: [],
      entry_points: ["0x80010000"],
      entry_context,
      psx: {
        schema_version: 2,
        provenance: {
          method: "rea-psx-filebytes-rebind-v2",
          status: "applied",
          reason: null,
          source_sha256: sha256,
          source_file_bytes: bytes.length,
          before: {
            source_files: [],
            mappings: beforeMappings,
            entry_points: ["0x80010000"],
            entry_context: structuredClone(entry_context),
          },
          rebound_ranges: mappings
            .filter((mapping) => mapping.source_file_index !== null)
            .map((mapping) => ({
              start: mapping.start,
              end: mapping.end,
              length: mapping.length,
              file_offset: mapping.file_offset!,
              source_file_index: 0,
              before_sha256: mapping.sha256!,
              after_sha256: mapping.sha256!,
            })),
          metadata_preservation: fixtureMetadata(),
        },
        current_label_history: [
          {
            ordinal: 0,
            address: "0x80010000",
            label: "later analysis label",
            action: 0,
            user: null,
            modification_time_ms: null,
          },
        ],
        entry_instruction: {
          address: "0x80010000",
          status: "instruction",
          length: 4,
        },
      },
    },
  };
};
