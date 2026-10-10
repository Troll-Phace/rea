import { describe, expect, it } from "vitest";
import { parsePsxExeHeader } from "../domain/psxExe.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  createGhidraPsxCommitment,
  ghidraPsxInventoryDigest,
  inspectGhidraPsxLoader,
  inspectGhidraPsxPolicy,
  type GhidraPsxAsset,
  type GhidraPsxInspectionHost,
} from "./GhidraPsxLoader.js";

const root = "/selected/ghidra";
const extension = "Ghidra/Extensions/renamed";
const language = `${extension}/data/languages`;
const assets = () =>
  [
    `${extension}/extension.properties`,
    `${extension}/lib/psx.jar`,
    `${language}/psx.ldefs`,
    `${language}/mips.sla`,
    `${language}/mips.pspec`,
    `${language}/mips.cspec`,
    "Ghidra/Processors/MIPS/lib/MIPS.jar",
  ]
    .sort()
    .map((relative_path) => ({
      relative_path,
      file_bytes: 42,
      sha256: "a".repeat(64),
    }));
const host = (
  entries = assets(),
  overrides: Partial<GhidraPsxInspectionHost> = {},
): GhidraPsxInspectionHost => ({
  inventory: async () => ({ root, assets: entries }),
  readText: async (path) =>
    path.endsWith("extension.properties")
      ? "name=ghidra_psx_ldr\nversion=12.1.4\n"
      : '<language_definitions><!-- <language id="PSX:LE:32:default"/> --><language id="PSX:LE:32:default" slafile="mips.sla" processorspec="mips.pspec"><compiler id="default" spec="mips.cspec"/></language></language_definitions>',
  jarEntries: async (path) =>
    path.endsWith("psx.jar")
      ? [
          "psx/PsxLoader.class",
          "psx/PsxAnalyzer.class",
          "ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class",
        ]
      : ["ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class"],
  ...overrides,
});
const header = (values: Readonly<Record<number, number>> = {}) => {
  const bytes = Buffer.alloc(2048);
  bytes.write("PS-X EXE");
  bytes.writeUInt32LE(0x80010000, 0x10);
  bytes.writeUInt32LE(0x80010000, 0x18);
  bytes.writeUInt32LE(8, 0x1c);
  for (const [offset, value] of Object.entries(values))
    bytes.writeUInt32LE(value, Number(offset));
  const parsed = parsePsxExeHeader(bytes, 4096);
  if (!parsed.ok) throw new Error(parsed.error.reason);
  return parsed.value;
};

describe("PSX static installation eligibility", () => {
  it("accepts renamed extension and duplicate extension MipsPreAnalyzer without claiming runtime selection", async () => {
    const inspected = await inspectGhidraPsxLoader(
      root,
      "12.1.4",
      undefined,
      host(),
    );
    expect(inspected.status).toBe("available");
    if (inspected.status !== "available") throw new Error(inspected.reason);
    expect(inspected.candidate.extension_relative).toBe(extension);
    expect(inspected.candidate.analyzer_classes).toEqual([
      "ghidra.app.plugin.core.analysis.MipsPreAnalyzer",
      "psx.PsxAnalyzer",
    ]);
    expect(inspected.candidate.asset_inventory_digest).toBe(
      ghidraPsxInventoryDigest(assets()),
    );
  });
  it("keeps missing, incompatible, and ambiguous distinct", async () => {
    expect(
      (await inspectGhidraPsxLoader(root, "12.1.4", undefined, host([])))
        .status,
    ).toBe("missing");
    expect(
      (await inspectGhidraPsxLoader(root, "12.2", undefined, host())).status,
    ).toBe("incompatible");
    const duplicate: GhidraPsxAsset = {
      relative_path: "Ghidra/Extensions/another/extension.properties",
      file_bytes: 42,
      sha256: "b".repeat(64),
    };
    expect(
      (
        await inspectGhidraPsxLoader(
          root,
          "12.1.4",
          undefined,
          host([...assets(), duplicate]),
        )
      ).status,
    ).toBe("ambiguous");
    expect(
      (
        await inspectGhidraPsxLoader(
          root,
          "12.1.4",
          undefined,
          host(assets(), { jarEntries: async () => ["psx/PsxLoader.class"] }),
        )
      ).status,
    ).toBe("ambiguous");
  });
  it("refuses incomplete reads and conflicting language definitions", async () => {
    expect(
      (
        await inspectGhidraPsxLoader(
          root,
          "12.1.4",
          undefined,
          host(assets(), {
            readText: async () => {
              throw new Error("unreadable metadata");
            },
          }),
        )
      ).status,
    ).toBe("incompatible");
    expect(
      (
        await inspectGhidraPsxLoader(
          root,
          "12.1.4",
          undefined,
          host(
            assets().filter(
              (asset) => !asset.relative_path.endsWith("mips.sla"),
            ),
          ),
        )
      ).status,
    ).toBe("incompatible");
    const duplicate = {
      relative_path: "Ghidra/Processors/OTHER/data/languages/other.ldefs",
      file_bytes: 1,
      sha256: "c".repeat(64),
    };
    expect(
      (
        await inspectGhidraPsxLoader(
          root,
          "12.1.4",
          undefined,
          host([...assets(), duplicate]),
        )
      ).status,
    ).toBe("ambiguous");
  });
  it("preserves cancellation instead of reporting missing assets", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      inspectGhidraPsxLoader(root, "12.1.4", controller.signal, host()),
    ).rejects.toBeInstanceOf(AnalysisCancelledError);
  });
  it("fingerprints stable ordering and exact delimiter-containing names", () => {
    const values = assets();
    expect(ghidraPsxInventoryDigest(values)).toBe(
      ghidraPsxInventoryDigest([...values].reverse()),
    );
    expect(ghidraPsxInventoryDigest(values)).not.toBe(
      ghidraPsxInventoryDigest(
        values.map((asset, index) =>
          index === 0 ? { ...asset, sha256: "b".repeat(64) } : asset,
        ),
      ),
    );
    expect(
      ghidraPsxInventoryDigest([
        { relative_path: "a\tb\nc\\d", file_bytes: 1, sha256: "a".repeat(64) },
      ]),
    ).not.toBe(
      ghidraPsxInventoryDigest([
        { relative_path: "a", file_bytes: 1, sha256: "a".repeat(64) },
      ]),
    );
  });
});

describe("default-only KSEG0 provider policy", () => {
  it("requires the entire entry instruction, rather than only its first byte", () => {
    expect(
      inspectGhidraPsxPolicy(header({ 0x1c: 5, 0x10: 0x80010004 })),
    ).toContain(
      "complete four-byte initial_pc instruction must lie within payload and KSEG0 2MB RAM",
    );
    expect(
      inspectGhidraPsxPolicy(
        header({ 0x18: 0x801ffffc, 0x10: 0x801ffffc, 0x1c: 4 }),
      ),
    ).toEqual([]);
    expect(
      inspectGhidraPsxPolicy(
        header({ 0x18: 0x801ffffc, 0x10: 0x801ffffc, 0x1c: 5 }),
      ),
    ).not.toEqual([]);
  });
  it.each([
    { 0x18: 0x80010001 },
    { 0x10: 0x80010001 },
    { 0x18: 0xa0010000, 0x10: 0xa0010000 },
    { 0x28: 0x80010004, 0x2c: 8 },
    { 0x28: 0x80200000, 0x2c: 4 },
    { 0x20: 1 },
    { 0x24: 1 },
    { 0x1c: 0 },
  ])("refuses unsupported declarations %j", (values) =>
    expect(inspectGhidraPsxPolicy(header(values))).not.toEqual([]),
  );
  it("does not restrict a zero fill extent, absent stack, GP, or trailing bytes", async () => {
    const declared = header({
      0x28: 0xffffffff,
      0x34: 0xabcdef,
      0x14: 0x80010800,
    });
    expect(inspectGhidraPsxPolicy(declared)).toEqual([]);
    const inspected = await inspectGhidraPsxLoader(
      root,
      "12.1.4",
      undefined,
      host(),
    );
    if (inspected.status !== "available") throw new Error(inspected.reason);
    const commitment = createGhidraPsxCommitment(
      declared,
      inspected.candidate,
      "/owned/source",
      "d".repeat(64),
    );
    expect(commitment.declarations).toMatchObject({
      initial_sp: null,
      stack_offset: "0xabcdef",
      initial_gp: "0x80010800",
      trailing_bytes: 2040,
    });
  });
});
