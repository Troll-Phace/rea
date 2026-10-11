import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { CATALOG_IDENTITY } from "../dist/catalogIdentity.js";

import { exec } from "./lib/verify-package-core.mjs";
import { verifyPackedBridge } from "./verify-packed-bridge.mjs";

/** Required shipped PSX runtime paths; no engine installation is needed. */
export const psxPackageResources = Object.freeze([
  "scripts/rea.mjs",
  "dist/main.js",
  "dist/identity.js",
  "dist/generatedPackageMetadata.js",
  "dist/catalogIdentity.js",
  "dist/cli.js",
  "dist/cliOutput.js",
  "dist/cli/streamedJsonOutput.js",
  "dist/contracts/toolContracts.js",
  "dist/ghidra/GhidraProviderClient.js",
  "dist/ghidra/GhidraLauncher.js",
  "dist/ghidra/GhidraPsxLoader.js",
  "dist/ghidra/GhidraPsxLoadImageValues.js",
  "bridge/ghidra/ReaGhidraBridge.java",
  "bridge/ghidra/ReaGhidraPreparePsx.java",
  "bridge/ghidra/ReaGhidraPsxImport.java",
  "bridge/ghidra/ReaGhidraPsxProvenance.java",
  "skills/reverse-engineer-anything/SKILL.md",
  "skills/reverse-engineer-anything/references/native-and-artifacts.md",
  "skills/reverse-engineer-anything/references/evidence-workflows.md",
]);

/** Reject missing production resources and explicitly excluded local artifacts. */
export function assertPsxPackageContents(packedFiles) {
  for (const resource of psxPackageResources)
    if (!packedFiles.includes(`package/${resource}`))
      throw new Error(`package omitted package/${resource}`);
  for (const path of packedFiles) {
    if (!path) continue;
    if (
      !path.startsWith("package/") ||
      path.split("/").some((component) => component === "..") ||
      path.startsWith("package/build/") ||
      /(?:^|\/)(?:psx-local|skill-src|tests|\.cache|\.agent-runtime|ROMs|extracted|snapshots|evidence|ghidra_psx_ldr)(?:\/|$)/u.test(
        path,
      ) ||
      /(?:^|\/)probe-[^/]+/u.test(path) ||
      // This package ships JS/source bridges and the explicit Windows addon;
      // provider projects, disc/executable inputs and loader bytecode are excluded.
      /\.(?:gpr|rep|iso|cue|exe|bin|tgz|jar|class|pyc)(?:\/|$)/iu.test(path) ||
      path.includes("__pycache__")
    )
      throw new Error(`package included excluded artifact: ${path}`);
  }
}

/** Create a tarball and assert production packaging constraints. */
export async function verifyPackagePack({
  root,
  workspace,
  environment,
  execute = exec,
}) {
  const packDirectory = join(workspace, "pack");
  await mkdir(packDirectory);
  const tarball = join(
    packDirectory,
    (
      await execute(
        "npm",
        ["pack", "--silent", "--pack-destination", packDirectory],
        {
          cwd: root,
          ...(environment === undefined ? {} : { env: environment }),
        },
      )
    ).stdout.trim(),
  );
  const packedFiles = (
    await execute("tar", ["-tf", tarball], { env: environment })
  ).stdout.split("\n");
  const packedManifest = JSON.parse(
    (
      await execute("tar", ["-xOf", tarball, "package/package.json"], {
        env: environment,
      })
    ).stdout,
  );
  if (
    packedManifest.scripts?.postinstall !== undefined ||
    packedManifest.dependencies?.["node-pty"] !== undefined ||
    packedManifest.dependencies?.["@lydell/node-pty"] !== "1.1.0"
  )
    throw new Error("package retained a lifecycle-dependent PTY installation");
  if (
    packedManifest.bin?.rea !== "scripts/rea.mjs" ||
    packedManifest.bin?.["rea-agents"] !== "scripts/rea.mjs"
  )
    throw new Error("package did not expose both rea command entry points");
  if (packedManifest.mcpName !== "io.github.morluto/rea")
    throw new Error("package did not retain its MCP Registry ownership marker");
  if (packedFiles.some((path) => path.startsWith("package/skill-src/")))
    throw new Error(
      "package included authored skill sources instead of only the generated bundle",
    );
  if (packedFiles.some((path) => path.startsWith("package/.cache/")))
    throw new Error("package included development cache or test metadata");
  const skill = (
    await execute(
      "tar",
      ["-xOf", tarball, "package/skills/reverse-engineer-anything/SKILL.md"],
      { env: environment },
    )
  ).stdout;
  if (
    !skill.includes(
      `  tool_count: ${String(CATALOG_IDENTITY.counts.mcp_tools)}\n`,
    ) ||
    skill.includes("  catalog_digest:")
  )
    throw new Error(
      "packaged skill metadata did not match the catalog shipped in the package",
    );
  if (
    packedFiles.some(
      (path) => path.includes("__pycache__") || path.endsWith(".pyc"),
    )
  ) {
    throw new Error("package contained generated Python bytecode");
  }
  assertPsxPackageContents(packedFiles);
  await verifyPackedBridge({ workspace, tarball, packedFiles });
  return { tarball, packedFiles, packedManifest };
}
