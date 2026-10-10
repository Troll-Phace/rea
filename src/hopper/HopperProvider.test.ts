import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import { silentLogger } from "../logger.js";
import { hopperLoaderArgsForTarget } from "./HopperAnalysisProfile.js";
import { resolveHopperMachOImage } from "./HopperMachOImage.js";
import { HopperProvider } from "./HopperProvider.js";

describe("Hopper provider capabilities", () => {
  it("declines DOS MZ targets with a provider-specific support reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/legacy.exe",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
});

it.each(["darwin", "linux", "win32"] as const)(
  "refuses PSX on %s instead of deriving a Hopper MIPS loader",
  (platform) => {
    const config = parseConfig({});
    if (!config.ok) throw config.error;
    const provider = new HopperProvider(
      config.value,
      silentLogger,
      {},
      platform,
    );
    const target = {
      path: "/tmp/original.psx",
      sha256: "a".repeat(64),
      kind: "executable" as const,
      format: "ps-x-exe" as const,
      architecture: "mips" as const,
      availableArchitectures: ["mips" as const],
    };
    expect(provider.inspectTargetSupport(target)).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason:
        "PS-X EXE is recognized, but PSX analysis is not supported by this REA provider.",
      diagnostics: { architecture: "mips" },
    });
    expect(hopperLoaderArgsForTarget(target)).toMatchObject({
      ok: false,
      error: { _tag: "ProviderAdapterError" },
    });
  },
);

it("rejects a MIPS FAT64 selection before attempting to open a source", async () => {
  const target = {
    path: "/nonexistent/unsupported-mips",
    sha256: "a".repeat(64),
    kind: "executable" as const,
    format: "ps-x-exe" as const,
    architecture: "mips" as const,
    availableArchitectures: ["mips" as const],
  };
  expect(await resolveHopperMachOImage(target)).toMatchObject({
    ok: false,
    error: {
      reason: "Hopper FAT64 selection requires an x86 or ARM architecture",
    },
  });
});
