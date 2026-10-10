import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const digestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const identitySchema = z.looseObject({
  className: z.string(),
  name: z.string(),
  codeSource: z.string(),
  classResource: z.string(),
  classResources: z.array(z.string()),
});
const regionSchema = z.looseObject({
  start: z.string(),
  size: z.number(),
  covered: z.boolean(),
  blockAtStart: z.string().nullable(),
  initializedAtStart: z.boolean().nullable(),
  mappedSha256: digestSchema.nullable(),
});
const fileBytesSchema = z.object({
  filename: z.string(),
  fileOffset: z.number(),
  size: z.number(),
  originalSha256: digestSchema,
});
// Preserve the producer's additional observations; validate every gate-bearing field once.
const observerSchema = z.looseObject({
  stage: z.enum(["before-analysis", "after-analysis"]),
  ghidraVersion: z.string(),
  javaHome: z.string(),
  javaVersion: z.string(),
  fixture: z.string(),
  programName: z.string(),
  executablePath: z.string(),
  executableFormat: z.string(),
  language: z.string(),
  compiler: z.string(),
  imageBase: z.string(),
  extensionSearchRoots: z.array(z.string()),
  runtimeLoaderCandidates: z.array(identitySchema),
  selectorResolution: identitySchema,
  matchingLanguageDefinitions: z.array(
    z.looseObject({
      ldefs: z.string(),
      id: z.string(),
      slafile: z.string(),
      processorspec: z.string(),
    }),
  ),
  defaultOptions: z.array(
    z.object({
      name: z.string(),
      type: z.string(),
      commandLine: z.string(),
      value: z.string(),
    }),
  ),
  loadSpecs: z.array(
    z.looseObject({
      languageCompiler: z.string(),
      preferred: z.boolean(),
      complete: z.boolean(),
      imageBase: z.number(),
    }),
  ),
  analysisOptions: z.array(
    z.looseObject({ name: z.string(), type: z.string(), value: z.unknown() }),
  ),
  programInfo: z.array(z.object({ name: z.string(), value: z.unknown() })),
  addressSpaces: z.array(
    z.looseObject({
      name: z.string(),
      size: z.number(),
      type: z.number(),
      overlay: z.boolean(),
      min: z.string(),
      max: z.string(),
    }),
  ),
  blocks: z.array(
    z.looseObject({
      name: z.string(),
      start: z.string(),
      end: z.string(),
      size: z.number(),
      initialized: z.boolean(),
      read: z.boolean(),
      write: z.boolean(),
      execute: z.boolean(),
      mapped: z.boolean(),
      overlay: z.boolean(),
      sources: z.array(
        z.looseObject({
          start: z.string(),
          end: z.string(),
          length: z.number(),
          fileBytesOffset: z.number(),
          fileBytes: fileBytesSchema.nullable(),
          originalFileOffset: z.number().nullable(),
          sourceOriginalSha256: digestSchema.nullable(),
        }),
      ),
    }),
  ),
  fileBytes: z.array(fileBytesSchema),
  externalEntries: z.array(z.string()),
  entryInstruction: z.string().nullable(),
  registerContexts: z.array(
    z.object({
      address: z.string(),
      register: z.string(),
      valueHex: z.string().nullable(),
    }),
  ),
  payload: regionSchema,
  fill: regionSchema,
  afterPayload: regionSchema,
  trailing: z.object({
    fileOffsetsExamined: z.string(),
    sourceBackedMappingFound: z.boolean(),
    mappingStatus: z.string(),
  }),
  analysisClassIdentities: z.array(
    z.object({
      className: z.string(),
      name: z.string(),
      codeSource: z.string().nullable(),
      classResources: z.array(z.string()),
      enabledOption: z.unknown(),
    }),
  ),
  limitations: z.array(z.string()),
});
/** @typedef {z.infer<typeof observerSchema>} ObserverFacts */
/**
 * Bind logs from one settled import to its two read-only observer outputs.
 * RAM overrides are intentionally absent; effective defaults are observed program facts.
 * No process or workspace lifecycle is owned here. Failure throws with the retained producer evidence.
 * @param {{output: string, beforePath: string, afterPath: string,
 * fixture: {path: string, expected: {variant: string}, sha256: string, payloadSha256: string},
 * installation: import("../../src/ghidra/GhidraInstallation.js").AvailableGhidraInstallation,
 * inventory: {path: string, sha256: string}, installExtensionRoot: string, workspace: string}} input
 * @returns {Promise<{before: ObserverFacts, after: ObserverFacts, loaderLogs: string[], languageLogs: string[], actualLoaderJarSha256: string,
 * effectiveOptions: {imageBase: string, ramSizeProgramInfo: {name: string, value: unknown}, interpretation: string},
 * analysisClasses: Array<z.infer<typeof observerSchema>["analysisClassIdentities"][number] & {jarSha256: string | null}>, identityBinding: string}>}
 */
export async function attestPsxLoaderObservations(input) {
  const {
    output,
    beforePath,
    afterPath,
    fixture,
    installation,
    inventory,
    installExtensionRoot,
    workspace,
  } = input;
  const { loaderLogs, languageLogs } = importSelectionLogs(output);
  const before = observerSchema.parse(
    JSON.parse(await readFile(beforePath, "utf8")),
  );
  const after = observerSchema.parse(
    JSON.parse(await readFile(afterPath, "utf8")),
  );
  for (const facts of [before, after]) {
    assert.equal(facts.runtimeLoaderCandidates.length, 1);
    assert.equal(facts.matchingLanguageDefinitions.length, 1);
    const selected = facts.selectorResolution;
    assert.equal(selected.className, "psx.PsxLoader");
    assert.equal(selected.classResources.length, 1);
    const selectedJar = await realpath(fileURLToPath(selected.codeSource));
    assert.equal(selectedJar, inventory.path);
    assert.equal(await hash(selectedJar), inventory.sha256);
    assert.equal(facts.executableFormat, loaderLogs[0]);
    assert.equal(selected.name, loaderLogs[0]);
    assert.equal(`${facts.language}:${facts.compiler}`, languageLogs[0]);
    assert.equal(facts.fixture, fixture.path);
    assert.equal(
      facts.stage,
      facts === before ? "before-analysis" : "after-analysis",
    );
    assert.equal(
      facts.programInfo.find((option) => option.name === "Executable SHA256")
        ?.value,
      fixture.sha256,
    );
    assert.equal(
      await realpath(facts.executablePath),
      await realpath(fixture.path),
    );
    assert.equal(facts.programName, `${fixture.expected.variant}.exe`);
    assert.equal(facts.payload.mappedSha256, fixture.payloadSha256);
    assert.ok(
      facts.externalEntries.includes("ram:80010000"),
      "Declared entry missing",
    );
    assert.equal(facts.ghidraVersion, installation.providerVersion);
    assert.equal(facts.javaHome, installation.javaHome);
    for (const root of facts.extensionSearchRoots)
      assert.ok(
        root === installExtensionRoot || root.startsWith(workspace),
        "Unexpected extension root",
      );
  }
  assert.equal(after.imageBase, "ram:80000000", "RAM base not effective");
  const ramSize = after.programInfo.find(
    (option) => option.name === "PSX RAM Size",
  );
  assert.ok(ramSize && ramSize.value === 0x200000, "RAM size not effective");
  const analysisClasses = await Promise.all(
    after.analysisClassIdentities.map(async (identity) => ({
      ...identity,
      jarSha256:
        identity.codeSource === null
          ? null
          : await hash(fileURLToPath(identity.codeSource)),
    })),
  );
  return {
    before,
    after,
    loaderLogs,
    languageLogs,
    actualLoaderJarSha256: inventory.sha256,
    effectiveOptions: {
      imageBase: after.imageBase,
      ramSizeProgramInfo: ramSize,
      interpretation:
        "Observed defaults/program state; importer option objects are not retained",
    },
    analysisClasses,
    identityBinding:
      "same-process import logs + unique runtime selector/code-source/resource + pre-import JAR digest",
  };
}
async function hash(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

/** Parse the pinned headless producer log format, including logger suffixes. */
function importSelectionLogs(output) {
  assert.ok(
    output.includes("REPORT: Import succeeded"),
    "No import success record",
  );
  assert.ok(
    !/^(?:ERROR|FATAL)\b|REPORT: Import failed/gmu.test(output),
    "Headless error/failure record",
  );
  for (const stage of ["before-analysis", "after-analysis"])
    assert.ok(
      output.includes(`REA_PSX_LOADER_PROBE_COMPLETE ${stage}`),
      "Missing observer completion",
    );
  const loaderLogs = [
    ...output.matchAll(/Using Loader:\s*([^\r\n]+?) \(ProgramLoader\)\s*$/gmu),
  ].map((match) => match[1].trim());
  const languageLogs = [
    ...output.matchAll(
      /Using Language\/Compiler:\s*([^\r\n]+?) \(ProgramLoader\)\s*$/gmu,
    ),
  ].map((match) => match[1].trim());
  assert.equal(loaderLogs.length, 1);
  assert.equal(languageLogs.length, 1);
  assert.ok(
    !loaderLogs[0].includes("Raw Binary"),
    "Raw binary fallback is forbidden",
  );
  return { loaderLogs, languageLogs };
}
