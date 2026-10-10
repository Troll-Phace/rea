import { readFile, writeFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import type { NativeLoadImageObservation } from "../../../../src/domain/native/nativeLoadImage.js";
import { psxLoadImageSchema } from "../../../../src/domain/native/nativeLoadImage.js";
import { err, ok } from "../../../../src/domain/result.js";
import { GhidraSessionError } from "../../../../src/ghidra/GhidraSessionError.js";
import { createGhidraTargetSnapshot } from "../../../../src/ghidra/GhidraTargetSnapshot.js";
import {
  createPsxInstallationFixture,
  createPsxRecordingProvider,
  psxAppliedLoadImageObservation,
  psxFixtureSha256,
  psxImportBytes,
} from "../../../fixtures/ghidraPsxImport.js";

const setup = async (
  mutate?: (observation: NativeLoadImageObservation) => void,
) => {
  const fixture = await createPsxInstallationFixture();
  const bytes = psxImportBytes();
  const target: BinaryTarget = {
    path: fixture.source,
    sha256: psxFixtureSha256(bytes),
    kind: "executable",
    format: "ps-x-exe",
    architecture: "mips",
    availableArchitectures: ["mips"],
  };
  const snapshot = await createGhidraTargetSnapshot(
    fixture.source,
    fixture.root,
    target.sha256!,
    { platform: "linux" },
  );
  const observation = psxAppliedLoadImageObservation(bytes);
  mutate?.(observation);
  const recording = createPsxRecordingProvider(fixture, {
    loadImage: () => structuredClone(observation),
    snapshot: async () => ok(await readFile(snapshot.path)),
  });
  const profile = await recording.provider.resolveAnalysisProfile(target);
  if (!profile.ok) throw profile.error;
  const client = recording.provider.createClient(
    target,
    profile.value.profile ?? undefined,
  );
  return { fixture, bytes, snapshot, client, recording };
};

describe("PSX attestation over a real immutable filesystem snapshot (simulated bridge)", () => {
  it("returns malformed producer observations as a typed output error", async () => {
    const fixture = await setup((observation) => {
      Object.assign(observation, { unexpected_wire_field: true });
    });
    try {
      expect(
        await fixture.client.execute("inspect_native_load_image", {}),
      ).toMatchObject({ ok: false, error: { _tag: "AnalysisOutputError" } });
    } finally {
      const closed = await fixture.client.close();
      if (!closed.ok) throw closed.error;
    }
  });

  it("uses admitted snapshot bytes after the caller source changes", async () => {
    const fixture = await setup();
    try {
      await writeFile(fixture.fixture.source, psxImportBytes({}, 16));
      const result = await fixture.client.execute(
        "inspect_native_load_image",
        {},
      );
      if (!result.ok) throw result.error;
      const image = psxLoadImageSchema.parse(result.value.result);
      expect(image.status).toBe("verified");
      expect(image.target_sha256).toBe(psxFixtureSha256(fixture.bytes));
      expect(image.trailing_bytes).toBe(0);
      expect(await readFile(fixture.snapshot.path)).toEqual(fixture.bytes);
    } finally {
      const closed = await fixture.client.close();
      if (!closed.ok) throw closed.error;
    }
  });

  it("returns an adapter error when owned snapshot bytes change", async () => {
    const fixture = await setup();
    try {
      const changed = Buffer.from(fixture.bytes);
      changed[0x900] = 1;
      await writeFile(fixture.snapshot.path, changed);
      expect(
        await fixture.client.execute("inspect_native_load_image", {}),
      ).toMatchObject({
        ok: false,
        error: {
          _tag: "ProviderAdapterError",
          diagnostics: {
            reason: expect.stringMatching(/digest|SHA|snapshot/iu),
          },
        },
      });
    } finally {
      const closed = await fixture.client.close();
      if (!closed.ok) throw closed.error;
    }
  });
});

describe("PSX contradictory source and provenance observations (simulated bridge)", () => {
  it.each([
    [
      "source offset with unchanged mapped hash",
      (observation: NativeLoadImageObservation) => {
        observation.mappings[0]!.file_offset = 0x801;
      },
      "mapping[0].file_offset",
    ],
    [
      "original FileBytes digest",
      (observation: NativeLoadImageObservation) => {
        observation.source_files[0]!.original_sha256 = "e".repeat(64);
      },
      "original_file_sha256",
    ],
    [
      "forged duplicate-preserving journal delta",
      (observation: NativeLoadImageObservation) => {
        observation.psx!.provenance.metadata_preservation.label_history.removed_before_ordinals =
          [0];
      },
      "provenance.label_history_delta",
    ],
    [
      "new unrelated-address journal row",
      (observation: NativeLoadImageObservation) => {
        observation.psx!.provenance.metadata_preservation.label_history.after[1]!.address =
          "0x80000020";
      },
      "provenance.label_history_scope",
    ],
    [
      "contradictory operational hash",
      (observation: NativeLoadImageObservation) => {
        observation.psx!.provenance.metadata_preservation.adapted_operational_state_sha256 =
          "e".repeat(64);
      },
      "provenance.operational_state",
    ],
  ] as const)(
    "rejects %s through production provider attestation",
    async (_name, mutate, checkName) => {
      const fixture = await setup(mutate);
      try {
        const result = await fixture.client.execute(
          "inspect_native_load_image",
          {},
        );
        if (!result.ok) throw result.error;
        const image = psxLoadImageSchema.parse(result.value.result);
        expect(image.status).toBe("mismatch");
        expect(image.checks).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ name: checkName, status: "mismatch" }),
          ]),
        );
        expect(image.observations.mappings[0]!.sha256).toBe(
          psxFixtureSha256(fixture.bytes.subarray(0x800, 0x1000)),
        );
      } finally {
        const closed = await fixture.client.close();
        if (!closed.ok) throw closed.error;
      }
    },
  );
});

describe("PSX snapshot acquisition cancellation (simulated bridge)", () => {
  it("preserves cancelled snapshot acquisition as a typed cancellation", async () => {
    const fixture = await createPsxInstallationFixture();
    const recording = createPsxRecordingProvider(fixture, {
      loadImage: psxAppliedLoadImageObservation,
      snapshot: async () =>
        err(
          new GhidraSessionError(
            "cancelled",
            "Synthetic cancellation at snapshot acquisition",
          ),
        ),
    });
    const target: BinaryTarget = {
      path: fixture.source,
      sha256: psxFixtureSha256(psxImportBytes()),
      kind: "executable",
      format: "ps-x-exe",
      architecture: "mips",
      availableArchitectures: ["mips"],
    };
    const profile = await recording.provider.resolveAnalysisProfile(target);
    if (!profile.ok) throw profile.error;
    const client = recording.provider.createClient(
      target,
      profile.value.profile ?? undefined,
    );
    try {
      expect(
        await client.execute("inspect_native_load_image", {}),
      ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
    } finally {
      const closed = await client.close();
      if (!closed.ok) throw closed.error;
    }
    expect(recording.counts().closes).toBe(1);
  });
});
