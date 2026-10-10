import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect, it } from "vitest";

import { inventoryArtifact } from "../../../src/artifacts/inventory/ArtifactInventory.js";
import { classifyAndHashRoot } from "../../../src/artifacts/inventory/classify.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { readWithoutFifoWriter } from "../../fixtures/fifoInput.js";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";

it.skipIf(process.platform === "win32")(
  "rejects a FIFO artifact root without waiting for a writer",
  async () => {
    const root = await createTestTempDirectory("rea-artifact-root-fifo-");
    const fifoPath = join(root, "input.asar");
    await promisify(execFile)("mkfifo", [fifoPath]);

    const outcome = await readWithoutFifoWriter(fifoPath, () =>
      inventoryArtifact(fifoPath).then(
        () => undefined,
        (cause: unknown) => cause,
      ),
    );
    expect(outcome.state).toBe("completed");
    if (outcome.state !== "completed")
      throw new Error("Artifact inventory waited for a FIFO writer");
    expect(outcome.result).toMatchObject({
      reason: "format",
      message: `Artifact root is not a regular file: ${fifoPath}`,
    });
  },
);

it("rejects a root path replaced between its initial stat and open", async () => {
  const root = await createTestTempDirectory("rea-artifact-root-replaced-");
  const path = join(root, "input.bin");
  const replacement = join(root, "replacement.bin");
  await writeFile(path, "first bytes\n");
  const expectedMetadata = await lstat(path);
  await writeFile(replacement, "different bytes\n");
  await rm(path);
  await rename(replacement, path);

  await expect(
    classifyAndHashRoot(path, false, expectedMetadata),
  ).rejects.toMatchObject({
    reason: "integrity",
    message: `Root artifact changed before inventory: ${path}`,
  });
});

it("inventories structural PSX identity independently of target admission policy", async () => {
  const root = await createTestTempDirectory("rea-artifact-psx-");
  const bytes = Buffer.alloc(0x800 + 0x3000);
  Buffer.from([0x50, 0x53, 0x2d, 0x58, 0x20, 0x45, 0x58, 0x45]).copy(bytes);
  bytes.writeUInt32LE(0x80010000, 0x18);
  bytes.writeUInt32LE(0x3000, 0x1c);
  // PC zero is structurally valid but outside the payload: admission must refuse it.
  const path = join(root, "program.js");
  await writeFile(path, bytes);
  expect(await parseBinaryTarget(path)).toMatchObject({
    ok: false,
    error: {
      reason: expect.stringContaining(
        "unsupported by the initial import policy",
      ),
    },
  });
  const inventory = await inventoryArtifact(path);
  const digest = createHash("sha256").update(bytes).digest("hex");
  expect(inventory.nodes).toEqual([
    expect.objectContaining({
      format: "ps-x-exe",
      sha256: digest,
      size: bytes.length,
    }),
  ]);
  expect(inventory.occurrences).toEqual([
    expect.objectContaining({ hash_status: "verified" }),
  ]);
  expect(await readFile(path)).toEqual(bytes);

  await writeFile(path, bytes.subarray(0, bytes.length - 1));
  const malformed = await inventoryArtifact(path);
  expect(malformed.nodes).toEqual([
    expect.objectContaining({
      format: "unknown",
      size: bytes.length - 1,
      sha256: createHash("sha256")
        .update(bytes.subarray(0, bytes.length - 1))
        .digest("hex"),
    }),
  ]);
});
