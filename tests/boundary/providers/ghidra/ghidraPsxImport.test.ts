import { cp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import {
  createGhidraPsxCommitment,
  inspectGhidraPsxLoader,
  readGhidraPsxSource,
  validateGhidraPsxLaunch,
} from "../../../../src/ghidra/GhidraPsxLoader.js";
import { createGhidraTargetSnapshot } from "../../../../src/ghidra/GhidraTargetSnapshot.js";
import {
  createPsxInstallationFixture,
  createPsxRecordingProvider,
  psxFixtureJar,
  psxFixtureSha256,
  psxImportBytes,
} from "../../../fixtures/ghidraPsxImport.js";

const targetFor = (path: string, bytes = psxImportBytes()): BinaryTarget => ({
  path,
  sha256: psxFixtureSha256(bytes),
  kind: "executable",
  format: "ps-x-exe",
  architecture: "mips",
  availableArchitectures: ["mips"],
});

describe("PSX filesystem admission and immutable import boundary (simulated provider)", () => {
  it("discovers a renamed extension and distinct core/extension analyzer resources", async () => {
    const fixture = await createPsxInstallationFixture();
    const inspected = await inspectGhidraPsxLoader(
      fixture.installationRoot,
      "12.1.4",
    );
    if (inspected.status !== "available") throw new Error(inspected.reason);
    expect(inspected.candidate.loader).toMatchObject({
      selector: "PsxLoader",
      class_name: "psx.PsxLoader",
      code_source_relative: "Ghidra/Extensions/renamed-psx/lib/psx.jar",
    });
    expect(inspected.candidate.language_assets).toHaveLength(5);
    expect(inspected.candidate.assets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relative_path: "Ghidra/Processors/MIPS/lib/MIPS.jar",
        }),
        expect.objectContaining({
          relative_path: "Ghidra/Processors/MIPS/data/core.sinc",
        }),
      ]),
    );
    const host = createPsxRecordingProvider(fixture);
    const profile = await host.provider.resolveAnalysisProfile(
      targetFor(fixture.source),
    );
    if (!profile.ok) throw profile.error;
    expect(profile.value.profile?.parameters).toMatchObject({
      psx_operation_scope: "inventory-and-load-image-v1",
      psx_import: {
        supplied_loader_options: {},
        option_mode: "loader-defaults",
        expected_ram_base: "0x80000000",
        expected_ram_size: 2097152,
      },
    });
    expect(profile.value.profile?.parameters.psx_import).not.toHaveProperty(
      "source_snapshot_path",
    );
    expect(host.counts().clients).toBe(0);
  });

  it.each([
    "missing manifest",
    "duplicate manifest",
    "duplicate loader",
    "missing language asset",
    "incompatible manifest",
  ] as const)("refuses %s before provider allocation", async (condition) => {
    const fixture = await createPsxInstallationFixture();
    switch (condition) {
      case "missing manifest":
        await rm(join(fixture.extension, "extension.properties"));
        break;
      case "duplicate manifest":
        await cp(
          fixture.extension,
          join(fixture.installationRoot, "Ghidra/Extensions/second"),
          { recursive: true },
        );
        break;
      case "duplicate loader":
        await fixture.write(
          "Ghidra/Features/Other/lib/other.jar",
          await psxFixtureJar(["psx/PsxLoader.class"]),
        );
        break;
      case "missing language asset":
        await rm(join(fixture.languages, "mips32le.sla"));
        break;
      case "incompatible manifest":
        await writeFile(
          join(fixture.extension, "extension.properties"),
          "name=ghidra_psx_ldr\nversion=0.0.0\n",
        );
        break;
    }
    const host = createPsxRecordingProvider(fixture);
    expect(host.provider.inspectAvailability().status).toBe("available");
    const result = await host.provider.resolveAnalysisProfile(
      targetFor(fixture.source),
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "ProviderAdapterError" },
    });
    expect(host.counts()).toEqual({ clients: 0, closes: 0 });
  });
});

describe("PSX resource identity and policy boundaries", () => {
  it("refuses a resource symlink escaping the selected installation", async () => {
    const fixture = await createPsxInstallationFixture();
    const outside = join(fixture.root, "outside.sinc");
    await writeFile(outside, "outside installation");
    await symlink(outside, join(fixture.languages, "escape.sinc"));
    expect(
      await inspectGhidraPsxLoader(fixture.installationRoot, "12.1.4"),
    ).toMatchObject({
      status: "incompatible",
      reason: expect.stringContaining("escapes installation"),
    });
  });

  it.skipIf(process.platform === "win32")(
    "preserves POSIX backslash, tab and newline resource identities",
    async () => {
      const fixture = await createPsxInstallationFixture();
      const relativePath =
        "Ghidra/Processors/MIPS/data/source\\identity\tline\n.sinc";
      await fixture.write(relativePath, "odd named resource\n");
      const inspected = await inspectGhidraPsxLoader(
        fixture.installationRoot,
        "12.1.4",
      );
      if (inspected.status !== "available") throw new Error(inspected.reason);
      expect(inspected.candidate.assets).toContainEqual({
        relative_path: relativePath,
        file_bytes: 19,
        sha256: psxFixtureSha256(Buffer.from("odd named resource\n")),
      });
      const host = createPsxRecordingProvider(fixture);
      const profile = await host.provider.resolveAnalysisProfile(
        targetFor(fixture.source),
      );
      if (!profile.ok) throw profile.error;
      expect(profile.value.profile?.parameters.psx_asset_inventory).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ relative_path: relativePath }),
        ]),
      );
    },
  );

  it("validates the owned snapshot then detects source or asset changes without reusing an old profile", async () => {
    const fixture = await createPsxInstallationFixture();
    const inspected = await inspectGhidraPsxLoader(
      fixture.installationRoot,
      "12.1.4",
    );
    if (inspected.status !== "available") throw new Error(inspected.reason);
    const digest = psxFixtureSha256(psxImportBytes());
    const header = await readGhidraPsxSource(fixture.source, digest);
    const commitment = createGhidraPsxCommitment(
      header,
      inspected.candidate,
      fixture.source,
      digest,
    );
    const snapshot = await createGhidraTargetSnapshot(
      fixture.source,
      fixture.root,
      digest,
      { platform: "linux" },
    );
    const validated = await validateGhidraPsxLaunch(
      commitment,
      fixture.installationRoot,
      "12.1.4",
      snapshot.path,
    );
    if (!validated.ok) throw validated.error;
    await writeFile(fixture.source, psxImportBytes({}, 16));
    await expect(readFile(snapshot.path)).resolves.toEqual(psxImportBytes());
    await expect(
      readGhidraPsxSource(fixture.source, digest),
    ).rejects.toMatchObject({ _tag: "AnalysisArtifactChangedError" });
    await writeFile(fixture.coreData, "changed core resource\n");
    expect(
      await validateGhidraPsxLaunch(
        commitment,
        fixture.installationRoot,
        "12.1.4",
        snapshot.path,
      ),
    ).toMatchObject({
      ok: false,
      error: {
        message: expect.stringContaining("changed after profile resolution"),
      },
    });
    const fresh = await inspectGhidraPsxLoader(
      fixture.installationRoot,
      "12.1.4",
    );
    if (fresh.status !== "available") throw new Error(fresh.reason);
    expect(fresh.candidate.asset_inventory_digest).not.toBe(
      inspected.candidate.asset_inventory_digest,
    );
  });

  it.each([
    ["alternate bank", { 0x10: 0xa0010000, 0x18: 0xa0010000 }],
    ["crossing RAM end", { 0x10: 0x801ffffc, 0x18: 0x801ffffc }],
    ["overlapping fill", { 0x28: 0x80010010, 0x2c: 4 }],
    ["declared data", { 0x20: 0x80010800 }],
    ["unaligned payload", { 0x18: 0x80010001 }],
    ["entry instruction crosses payload", { 0x10: 0x800107fc, 0x1c: 0x7fe }],
  ] as const)(
    "refuses policy %s from original header bytes before client creation",
    async (_name, fields) => {
      const fixture = await createPsxInstallationFixture();
      const bytes = psxImportBytes(fields);
      await writeFile(fixture.source, bytes);
      const host = createPsxRecordingProvider(fixture);
      expect(
        await host.provider.resolveAnalysisProfile(
          targetFor(fixture.source, bytes),
        ),
      ).toMatchObject({
        ok: false,
        error: {
          _tag: "ProviderAdapterError",
          diagnostics: {
            psx_import_policy: { policy: "psx-kseg0-2m-defaults-v1" },
          },
        },
      });
      expect(host.counts().clients).toBe(0);
    },
  );
});
