import { describe, expect, it } from "vitest";

import {
  GHIDRA_SESSION_CAPABILITIES,
  parseGhidraSessionInfo,
} from "./GhidraSessionValues.js";

const expected = {
  runId: "d6fcbb66-e829-4ff6-a535-0035aec63139",
  providerVersion: "12.1.4",
  profileDigest: "a".repeat(64),
  targetSha256: "b".repeat(64),
  expectedLanguageId: "x86:LE:16:Real Mode",
  expectedCompilerSpecId: "default",
};
const session = (
  language = expected.expectedLanguageId,
  compiler = "default",
) => ({
  name: "REA Ghidra bridge",
  run_id: expected.runId,
  profile_digest: expected.profileDigest,
  provider: { id: "ghidra", version: expected.providerVersion },
  read_only: false,
  analysis_complete: true,
  analysis_timed_out: false,
  capabilities: [...GHIDRA_SESSION_CAPABILITIES],
  target: {
    name: "legacy.exe",
    language_id: language,
    compiler_spec_id: compiler,
    image_base: "0x0",
    default_address_space: "ram",
    sha256: expected.targetSha256,
  },
});

describe("Ghidra DOS import commitment", () => {
  it("accepts the exact admitted real-mode language and compiler", () => {
    expect(parseGhidraSessionInfo(session(), expected).ok).toBe(true);
  });
  it("rejects a 32-bit interpretation even when artifact and profile hashes match", () => {
    expect(
      parseGhidraSessionInfo(session("x86:LE:32:default"), expected).ok,
    ).toBe(false);
  });
  it("rejects compiler drift independently of the language", () => {
    expect(
      parseGhidraSessionInfo(session(undefined, "windows"), expected).ok,
    ).toBe(false);
  });
});

describe("Ghidra mutation handshake", () => {
  it("requires the exact mutation authority and rejects duplicate capabilities", () => {
    const value = session();
    expect(
      parseGhidraSessionInfo({ ...value, read_only: true }, expected).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(
        { ...value, capabilities: [...value.capabilities, "ping"] },
        expected,
      ).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(
        {
          ...value,
          capabilities: value.capabilities.filter(
            (c) => c !== "annotate_native_function",
          ),
        },
        expected,
      ).ok,
    ).toBe(false);
  });
  it("excludes database mutation from the Windows transport handshake", () => {
    const value = session();
    const windows = {
      ...value,
      read_only: true,
      capabilities: value.capabilities.filter(
        (c) => c !== "annotate_native_function",
      ),
    };
    expect(
      parseGhidraSessionInfo(windows, { ...expected, expectedReadOnly: true })
        .ok,
    ).toBe(true);
    expect(
      parseGhidraSessionInfo(value, { ...expected, expectedReadOnly: true }).ok,
    ).toBe(false);
  });
});

// Producer-shaped synthetic startup evidence; no real provider is invoked here.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  psxFixtureAgreement,
  psxFixtureCommitment,
  psxFixtureOriginalRecord,
} from "../../tests/fixtures/ghidraPsxImport.js";
import type {
  GhidraPsxStartupExpectation,
  PsxImportObservation,
} from "./GhidraImportConfiguration.js";
import { jsonValueSchema } from "../domain/jsonValue.js";

const psxRoot = "/selected Ghidra 雪";
const psxCommitment = psxFixtureCommitment();
const corePath = "Ghidra/Processors/MIPS/lib/MIPS.jar";
const classes: PsxImportObservation["observed"]["selected_classes"] = [
  {
    class_name: "ghidra.app.plugin.core.analysis.MipsPreAnalyzer",
    role: "analyzer",
    code_source_url: pathToFileURL(join(psxRoot, corePath)).href,
    code_source_relative: corePath,
    code_source_sha256: "e".repeat(64),
    class_resource_url: `jar:${pathToFileURL(join(psxRoot, corePath)).href}!/ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class`,
    enabled: null,
  },
  {
    class_name: "psx.PsxLoader",
    role: "loader",
    code_source_url: pathToFileURL(
      join(psxRoot, psxCommitment.loader.code_source_relative),
    ).href,
    code_source_relative: psxCommitment.loader.code_source_relative,
    code_source_sha256: psxCommitment.loader.code_source_sha256,
    class_resource_url: `jar:${pathToFileURL(join(psxRoot, psxCommitment.loader.code_source_relative)).href}!/psx/PsxLoader.class`,
    enabled: null,
  },
];
const languageAssets = [
  {
    relative_path: "Ghidra/Extensions/renamed-psx/data/languages/psx.ldefs",
    sha256: "f".repeat(64),
  },
];
const psxExpected: GhidraPsxStartupExpectation = {
  commitment: psxCommitment,
  installationRoot: psxRoot,
  assets: [
    { relative_path: corePath, file_bytes: 1, sha256: "e".repeat(64) },
    {
      relative_path: psxCommitment.loader.code_source_relative,
      file_bytes: 1,
      sha256: psxCommitment.loader.code_source_sha256,
    },
    { ...languageAssets[0]!, file_bytes: 1 },
  ],
  languageAssets,
  analyzerClasses: ["ghidra.app.plugin.core.analysis.MipsPreAnalyzer"],
};
const psxSession = () => {
  const agreement = psxFixtureAgreement({
    commitment: psxCommitment,
    runId: expected.runId,
    profileDigest: expected.profileDigest,
    selectedClasses: classes,
    languageAssets,
  });
  return {
    ...session("PSX:LE:32:default"),
    target: {
      ...session().target,
      language_id: "PSX:LE:32:default",
      image_base: "0x80000000",
      sha256: psxCommitment.source_sha256,
    },
    psx_import: agreement,
  };
};
const psxOptions = (value = psxSession()) => ({
  ...expected,
  expectedLanguageId: "PSX:LE:32:default",
  targetSha256: psxCommitment.source_sha256,
  psxImport: psxExpected,
  psxBeforeRecordSha256: value.psx_import.before_record_sha256,
  psxOriginalEvidence: {
    record: psxFixtureOriginalRecord(
      value.psx_import.before.commitment,
      value.psx_import.before.provenance.metadata_preservation,
    ),
    sha256:
      value.psx_import.before.provenance.metadata_preservation
        .original_record_sha256,
  },
});
const observationLeaves = (value: unknown, path: string[] = []): string[][] => {
  if (value !== null && typeof value === "object")
    return Object.entries(value).flatMap(([key, child]) =>
      observationLeaves(child, [...path, key]),
    );
  return [path];
};
const mutateLeaf = (value: unknown, path: string[]): void => {
  let parent = value as Record<string, unknown>;
  for (const key of path.slice(0, -1))
    parent = parent[key] as Record<string, unknown>;
  const key = path.at(-1)!;
  const leaf = parent[key];
  parent[key] =
    typeof leaf === "string"
      ? `${leaf}unexpected`
      : typeof leaf === "number"
        ? leaf + 1
        : typeof leaf === "boolean"
          ? !leaf
          : true;
};
describe("strict independently observed PSX startup agreement", () => {
  it("requires fixed original evidence and independently binds its exact digest, identity and full rows", () => {
    const value = psxSession();
    const options = psxOptions(value);
    const { psxOriginalEvidence: _original, ...missing } = options;
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), missing).ok,
    ).toBe(false);
    for (const path of observationLeaves(options.psxOriginalEvidence.record)) {
      const changed = structuredClone(options.psxOriginalEvidence);
      mutateLeaf(changed.record, path);
      expect(
        parseGhidraSessionInfo(jsonValueSchema.parse(value), {
          ...options,
          psxOriginalEvidence: changed,
        }).ok,
      ).toBe(false);
    }
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), {
        ...options,
        psxOriginalEvidence: {
          ...options.psxOriginalEvidence,
          sha256: "0".repeat(64),
        },
      }).ok,
    ).toBe(false);
  });
  it.each([
    [
      "false operational equality",
      (record: PsxImportObservation) => {
        record.provenance.metadata_preservation.operational_state_matched = false;
      },
    ],
    [
      "incorrect journal delta",
      (record: PsxImportObservation) => {
        record.provenance.metadata_preservation.label_history.removed_before_ordinals =
          [];
      },
    ],
    [
      "invalid long date",
      (record: PsxImportObservation) => {
        record.provenance.metadata_preservation.label_history.after[0]!.modification_time_ms =
          "9223372036854775808";
      },
    ],
    [
      "unavailable with applied links",
      (record: PsxImportObservation) => {
        record.provenance.status = "unavailable";
        record.provenance.reason = "Unavailable";
      },
    ],
  ] as const)("rejects matching forged stages with %s", (_name, mutate) => {
    const value = psxSession();
    const options = psxOptions();
    mutate(value.psx_import.before);
    mutate(value.psx_import.after);
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), options).ok,
    ).toBe(false);
  });
  it("accepts exact before/after observations with URL-aware code sources and unknown analyzer option", () => {
    const value = psxSession();
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), psxOptions(value))
        .ok,
    ).toBe(true);
  });
  it.each(
    observationLeaves(psxSession().psx_import.after).map(
      (path) => [path.join("."), path] as const,
    ),
  )(
    "rejects one changed post-analysis leaf %s with echoed digest intact",
    (_name, path) => {
      const value = psxSession();
      mutateLeaf(value.psx_import.after, [...path]);
      expect(
        parseGhidraSessionInfo(jsonValueSchema.parse(value), psxOptions()).ok,
      ).toBe(false);
    },
  );
  it.each([
    "source.sha256",
    "source.snapshot_path",
    "source.file_bytes",
    "program.image_base",
    "program.ram_size",
    "program.default_address_space",
    "program.executable_path",
    "program.executable_format",
    "program.language_id",
    "loader_selector",
    "loader_class",
    "asset_inventory_digest",
    "advertised_defaults.ram_size.value",
    "advertised_defaults.ram_start.value",
  ])(
    "rejects forged agreement in both stages for %s even when correlation fields match",
    (field) => {
      const value = psxSession();
      for (const record of [value.psx_import.before, value.psx_import.after])
        mutateLeaf(record.observed, field.split("."));
      expect(
        parseGhidraSessionInfo(jsonValueSchema.parse(value), psxOptions()).ok,
      ).toBe(false);
    },
  );
  it("rejects missing metadata, wrong marker hash, extra fields, duplicate classes/assets, and extension-selected MipsPreAnalyzer", () => {
    const value = psxSession();
    const { psx_import: _agreement, ...without } = value;
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(without), psxOptions()).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), {
        ...psxOptions(),
        psxBeforeRecordSha256: "0".repeat(64),
      }).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), expected).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(
        jsonValueSchema.parse({
          ...value,
          psx_import: { ...value.psx_import, extra: true },
        }),
        psxOptions(),
      ).ok,
    ).toBe(false);
    for (const record of [value.psx_import.before, value.psx_import.after])
      record.observed.selected_classes.push(structuredClone(classes[0]!));
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(value), psxOptions()).ok,
    ).toBe(false);
    const changed = psxSession();
    for (const record of [changed.psx_import.before, changed.psx_import.after])
      record.observed.selected_classes[0]!.code_source_relative =
        psxCommitment.loader.code_source_relative;
    expect(
      parseGhidraSessionInfo(jsonValueSchema.parse(changed), psxOptions()).ok,
    ).toBe(false);
  });
});

import { realpath, symlink, writeFile } from "node:fs/promises";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { psxImportBytes } from "../../tests/fixtures/ghidraPsxImport.js";
it("requires the canonical owned snapshot commitment while preserving source alias identity", async () => {
  const root = await createTestTempDirectory("rea-psx-source-alias-");
  const physical = join(root, "owned source 雪");
  const alias = join(root, "owned alias 雪");
  await writeFile(physical, psxImportBytes());
  await symlink(physical, alias);
  const canonical = await realpath(physical);
  const value = psxSession();
  for (const record of [value.psx_import.before, value.psx_import.after]) {
    record.observed.source.snapshot_path = canonical;
    record.observed.program.executable_path = canonical;
  }
  const options = psxOptions(value);
  expect(
    parseGhidraSessionInfo(jsonValueSchema.parse(value), {
      ...options,
      psxImport: {
        ...psxExpected,
        commitment: { ...psxExpected.commitment, source_snapshot_path: alias },
      },
    }).ok,
  ).toBe(false);
  expect(
    parseGhidraSessionInfo(jsonValueSchema.parse(value), {
      ...options,
      psxImport: {
        ...psxExpected,
        commitment: {
          ...psxExpected.commitment,
          source_snapshot_path: await realpath(alias),
        },
      },
    }).ok,
  ).toBe(true);
  expect(await realpath(alias)).toBe(canonical);
});
