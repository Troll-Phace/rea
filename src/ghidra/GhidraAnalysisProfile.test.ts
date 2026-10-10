import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveGhidraAnalysisProfile } from "./GhidraAnalysisProfile.js";
import {
  inspectGhidraInstallation,
  type GhidraInstallationHost,
} from "./GhidraInstallation.js";
import * as psx from "./GhidraPsxLoader.js";
import { parsePsxExeHeader } from "../domain/psxExe.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  psxFixtureCommitment,
  psxImportBytes,
} from "../../tests/fixtures/ghidraPsxImport.js";
import { psxImportCommitmentSchema } from "./GhidraImportConfiguration.js";

const identity = { id: "ghidra", name: "Ghidra", version: null };
const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/jdk",
    bits: 64,
    runtime: "jdk",
  }),
};
const installation = inspectGhidraInstallation(
  {
    environment: {},
    installDir: "/ghidra",
    platform: "linux",
    architecture: "x64",
  },
  host,
);
const target: BinaryTarget = {
  kind: "executable",
  format: "ps-x-exe",
  architecture: "mips",
  availableArchitectures: ["mips"],
  path: "/source",
  sha256: "a".repeat(64),
};
const candidate: psx.PsxLoaderCandidate = {
  installation_root: "/ghidra",
  provider_version: "12.1.4",
  extension_manifest: { name: "ghidra_psx_ldr", version: "12.1.4" },
  extension_relative: "Ghidra/Extensions/renamed",
  loader: psxFixtureCommitment().loader,
  assets: [
    {
      relative_path: "Ghidra/Processors/MIPS/lib/MIPS.jar",
      file_bytes: 1,
      sha256: "b".repeat(64),
    },
  ],
  language_assets: [
    {
      relative_path: "Ghidra/Extensions/renamed/data/languages/psx.ldefs",
      sha256: "c".repeat(64),
    },
  ],
  analyzer_classes: ["ghidra.app.plugin.core.analysis.MipsPreAnalyzer"],
  asset_inventory_version: "ghidra-code-data-v1",
  asset_inventory_digest: "d".repeat(64),
};
afterEach(() => vi.restoreAllMocks());
const setup = () => {
  const parsed = parsePsxExeHeader(psxImportBytes());
  if (!parsed.ok) throw new Error(parsed.error.reason);
  vi.spyOn(psx, "readGhidraPsxSource").mockResolvedValue(parsed.value);
  return vi
    .spyOn(psx, "inspectGhidraPsxLoader")
    .mockResolvedValue({ status: "available", candidate });
};
describe("canonical PSX analysis identity", () => {
  it("commits assets/options/policy while omitting launch-time paths and identities", async () => {
    setup();
    const resolved = await resolveGhidraAnalysisProfile(
      target,
      identity,
      installation,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("profile missing");
    const parameters = resolved.value.profile.parameters;
    expect(parameters).toMatchObject({
      psx_import: {
        policy: "psx-kseg0-2m-defaults-v1",
        option_mode: "loader-defaults",
        supplied_loader_options: {},
        expected_ram_base: "0x80000000",
        expected_ram_size: 2097152,
      },
      psx_operation_scope: "inventory-observations-only-v1",
    });
    expect(JSON.stringify(parameters)).not.toContain("source_snapshot_path");
    expect(JSON.stringify(parameters)).not.toContain(target.path);
    expect(
      psxImportCommitmentSchema.safeParse({
        ...(parameters.psx_import as object),
        source_snapshot_path: "/owned/snapshot",
      }).success,
    ).toBe(true);
    expect(
      await resolveGhidraAnalysisProfile(target, identity, installation),
    ).toEqual(resolved);
  });
  it("fresh asset and source changes invalidate canonical identity", async () => {
    const inspect = setup();
    const baseline = await resolveGhidraAnalysisProfile(
      target,
      identity,
      installation,
    );
    inspect.mockResolvedValue({
      status: "available",
      candidate: { ...candidate, asset_inventory_digest: "e".repeat(64) },
    });
    const changed = await resolveGhidraAnalysisProfile(
      target,
      identity,
      installation,
    );
    expect(changed.ok && changed.value.profile?.digest).not.toBe(
      baseline.ok && baseline.value.profile?.digest,
    );
    const changedSource = await resolveGhidraAnalysisProfile(
      { ...target, sha256: "f".repeat(64) },
      identity,
      installation,
    );
    expect(changedSource.ok && changedSource.value.profile?.digest).not.toBe(
      changed.ok && changed.value.profile?.digest,
    );
    expect(inspect).toHaveBeenCalledTimes(3);
  });
  it("retains typed policy diagnostics and declines candidate inspection on unsupported layout", async () => {
    const inspect = setup();
    const parsed = parsePsxExeHeader(psxImportBytes({ 0x20: 1 }));
    if (!parsed.ok) throw new Error(parsed.error.reason);
    vi.spyOn(psx, "readGhidraPsxSource").mockResolvedValue(parsed.value);
    const result = await resolveGhidraAnalysisProfile(
      target,
      identity,
      installation,
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unexpected acceptance");
    expect(result.error).toMatchObject({
      diagnostics: {
        psx_import_policy: {
          policy: "psx-kseg0-2m-defaults-v1",
          declarations: { declaredDataAddress: 1 },
        },
      },
    });
    expect(inspect).not.toHaveBeenCalled();
  });
  it("keeps DOS/native profiles independent of missing PSX assets", async () => {
    const inspect = setup();
    inspect.mockResolvedValue({
      status: "missing",
      reason: "no loader",
      diagnostics: {},
    });
    for (const format of ["dos-mz", "dos-com", "elf"] as const) {
      const result = await resolveGhidraAnalysisProfile(
        {
          ...target,
          format,
          architecture: "x86",
          availableArchitectures: ["x86"],
        },
        identity,
        installation,
      );
      expect(result.ok && result.value.profile?.parameters).not.toHaveProperty(
        "psx_import",
      );
      expect(result.ok).toBe(true);
    }
    expect(inspect).not.toHaveBeenCalled();
  });
});
