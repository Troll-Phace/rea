import { createHash } from "node:crypto";
import {
  lstat,
  open,
  readdir,
  readFile,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  inspectPsxExePolicy,
  parsePsxExeHeader,
  type PsxExeHeader,
} from "../domain/psxExe.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  psxImportCommitmentSchema,
  type PsxImportCommitment,
} from "./GhidraImportConfiguration.js";

/** Complete analysis resource inventory, preserving installation-relative identity. */
export interface GhidraPsxAsset {
  readonly relative_path: string;
  readonly file_bytes: number;
  readonly sha256: string;
}
export interface PsxLoaderCandidate {
  readonly installation_root: string;
  readonly provider_version: string;
  readonly extension_manifest: Readonly<Record<string, string>>;
  readonly extension_relative: string;
  readonly loader: PsxImportCommitment["loader"];
  readonly language_assets: readonly {
    readonly relative_path: string;
    readonly sha256: string;
  }[];
  readonly analyzer_classes: readonly string[];
  readonly assets: readonly GhidraPsxAsset[];
  readonly asset_inventory_version: "ghidra-code-data-v1";
  readonly asset_inventory_digest: string;
}
export type PsxLoaderInspection =
  | { readonly status: "available"; readonly candidate: PsxLoaderCandidate }
  | {
      readonly status: "missing" | "incompatible" | "ambiguous";
      readonly reason: string;
      readonly diagnostics: Readonly<Record<string, JsonValue>>;
    };
/** I/O seam retains filesystem/hash responsibility in the production boundary. */
export interface GhidraPsxInspectionHost {
  inventory(
    root: string,
    signal?: AbortSignal,
  ): Promise<{
    readonly root: string;
    readonly assets: readonly GhidraPsxAsset[];
  }>;
  readText(path: string): Promise<string>;
  jarEntries(path: string, signal?: AbortSignal): Promise<readonly string[]>;
}
const abort = (signal?: AbortSignal): void => {
  if (signal?.aborted === true) throw new AnalysisCancelledError("open_binary");
};
/** Shared Java/TS digest encoding: sorted base64(UTF-8 path) TAB length TAB sha256 LF, UTF-8. */
export const ghidraPsxInventoryDigest = (
  assets: readonly GhidraPsxAsset[],
): string =>
  createHash("sha256")
    .update(
      [...assets]
        .sort((a, b) =>
          a.relative_path < b.relative_path
            ? -1
            : a.relative_path > b.relative_path
              ? 1
              : 0,
        )
        .map(
          (asset) =>
            `${Buffer.from(asset.relative_path, "utf8").toString("base64")}\t${asset.file_bytes}\t${asset.sha256}\n`,
        )
        .join(""),
    )
    .digest("hex");

const hashOpenFile = async (
  path: string,
  file: FileHandle,
  signal?: AbortSignal,
): Promise<{ file_bytes: number; sha256: string }> => {
  abort(signal);
  const before = await file.stat();
  if (!before.isFile()) throw new Error(`Not a regular resource: ${path}`);
  const namedBefore = await realpath(path);
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of file.createReadStream({
    autoClose: false,
    start: 0,
  })) {
    abort(signal);
    hash.update(chunk);
    bytes += (chunk as Buffer).length;
  }
  const after = await file.stat();
  const named = await lstat(await realpath(path));
  if (
    bytes !== before.size ||
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    before.ctimeMs !== after.ctimeMs ||
    named.dev !== after.dev ||
    named.ino !== after.ino ||
    (await realpath(path)) !== namedBefore
  )
    throw new Error(`Resource changed during inspection: ${path}`);
  return { file_bytes: bytes, sha256: hash.digest("hex") };
};
const hashStableFile = async (
  path: string,
  signal?: AbortSignal,
): Promise<{ file_bytes: number; sha256: string }> => {
  abort(signal);
  const file = await open(path, "r");
  try {
    return await hashOpenFile(path, file, signal);
  } finally {
    await file.close();
  }
};
const assetPath = (path: string): boolean =>
  (path.endsWith(".jar") && path.split("/").includes("lib")) ||
  path.split("/").includes("data") ||
  /(?:^|\/)(?:extension\.properties|Module\.manifest)$/u.test(path);
const inventory = async (selectedRoot: string, signal?: AbortSignal) => {
  const root = await realpath(selectedRoot);
  const assets: GhidraPsxAsset[] = [];
  const visited = new Set<string>();
  const walk = async (directory: string): Promise<void> => {
    abort(signal);
    const actual = await realpath(directory);
    const local = relative(root, actual);
    if (local.startsWith("..") || isAbsolute(local))
      throw new Error(`Asset symlink escapes installation: ${directory}`);
    if (visited.has(actual))
      throw new Error(`Aliased asset directory: ${directory}`);
    visited.add(actual);
    const before = await lstat(actual);
    for (const name of (await readdir(directory)).sort()) {
      const path = join(directory, name);
      const resolved = await realpath(path);
      const local = relative(root, resolved);
      if (local.startsWith("..") || isAbsolute(local))
        throw new Error(`Asset symlink escapes installation: ${path}`);
      const stat = await lstat(resolved);
      if (stat.isDirectory()) {
        if (
          relative(root, path).split("/").includes("data") ||
          !["docs", "doc", "src", "os", "build", ".git", "cache"].includes(name)
        )
          await walk(path);
      } else if (stat.isFile()) {
        const relative_path = relative(root, path);
        if (assetPath(relative_path))
          assets.push({
            relative_path,
            ...(await hashStableFile(path, signal)),
          });
      } else throw new Error(`Nonregular installation resource: ${path}`);
    }
    const after = await lstat(actual);
    if (before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs)
      throw new Error(`Directory changed during enumeration: ${directory}`);
  };
  await walk(join(root, "Ghidra"));
  assets.sort((a, b) =>
    a.relative_path < b.relative_path
      ? -1
      : a.relative_path > b.relative_path
        ? 1
        : 0,
  );
  return { root, assets };
};
const productionHost: GhidraPsxInspectionHost = {
  inventory,
  readText: (path) => readFile(path, "utf8"),
  jarEntries: async (path, signal) => {
    const reader = new ZipArtifactReader(path, "zip");
    const entries: string[] = [];
    try {
      for await (const entry of reader.entries(signal)) {
        if (entry.kind === "file" && !entry.encrypted) entries.push(entry.path);
      }
    } finally {
      await reader.close();
    }
    return entries;
  },
};
const properties = (text: string): Record<string, string> => {
  const result: Record<string, string> = {};
  for (const line of text.split(/\r?\n/u)) {
    if (/^\s*[#!]/u.test(line)) continue;
    const index = line.indexOf("=");
    if (index < 0) continue;
    const key = line.slice(0, index).trim();
    if (Object.hasOwn(result, key))
      throw new Error(`Duplicate manifest property: ${key}`);
    result[key] = line.slice(index + 1).trim();
  }
  return result;
};
/** Parse the XML language definition's language/attribute structure, never text-match comments. */
const languageDefinitions = (
  text: string,
): { id: string; resources: string[] }[] => {
  const result: { id: string; resources: string[] }[] = [];
  const stack: string[] = [];
  let current: { id: string; resources: string[] } | undefined;
  const tokens =
    text.match(/<\?[^?]*\?>|<!--[\s\S]*?-->|<[^>]*>|[^<]+/gu) ?? [];
  if (tokens.join("") !== text) throw new Error("Malformed language XML");
  for (const token of tokens) {
    if (
      !token.startsWith("<") ||
      token.startsWith("<?") ||
      token.startsWith("<!--")
    )
      continue;
    const close = /^<\/([\w.-]+)\s*>$/u.exec(token);
    if (close !== null) {
      if (stack.pop() !== close[1]) throw new Error("Unbalanced language XML");
      if (close[1] === "language") current = undefined;
      continue;
    }
    const tag =
      /^<([\w.-]+)((?:\s+[\w.-]+\s*=\s*(?:"[^"<]*"|'[^'<]*'))*)\s*(\/?)>$/u.exec(
        token,
      );
    if (tag === null)
      throw new Error("Unsupported or malformed language XML declaration");
    const attrs: Record<string, string> = {};
    for (const match of tag[2]!.matchAll(
      /([\w.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/gu,
    )) {
      const key = match[1]!;
      if (Object.hasOwn(attrs, key)) throw new Error("Duplicate XML attribute");
      const value = match[2] ?? match[3]!;
      if (value.includes("&"))
        throw new Error(
          "Entity-based language resource selection is unmodeled",
        );
      attrs[key] = value;
    }
    if (tag[1] === "language") {
      if (current !== undefined || stack.join("/") !== "language_definitions")
        throw new Error("Unmodeled language XML structure");
      current = {
        id: attrs.id ?? "",
        resources: [attrs.slafile ?? "", attrs.processorspec ?? ""],
      };
      result.push(current);
    }
    if (
      tag[1] === "compiler" &&
      current !== undefined &&
      attrs.id === "default"
    )
      current.resources.push(attrs.spec ?? "");
    if (tag[3] !== "/") stack.push(tag[1]!);
  }
  if (stack.length !== 0) throw new Error("Unclosed language XML");
  return result;
};

/** Fresh, complete static eligibility; runtime class selection is checked separately. */
export const inspectGhidraPsxLoader = async (
  root: string,
  version: string,
  signal?: AbortSignal,
  host: GhidraPsxInspectionHost = productionHost,
): Promise<PsxLoaderInspection> => {
  const rejected = (
    status: "missing" | "incompatible" | "ambiguous",
    reason: string,
  ): PsxLoaderInspection => ({
    status,
    reason,
    diagnostics: { installation_root: root, reason },
  });
  try {
    abort(signal);
    const observed = await host.inventory(root, signal);
    const assets = [...observed.assets].sort((a, b) =>
      a.relative_path < b.relative_path
        ? -1
        : a.relative_path > b.relative_path
          ? 1
          : 0,
    );
    if (
      new Set(assets.map((asset) => asset.relative_path)).size !== assets.length
    )
      return rejected("ambiguous", "Duplicate analysis asset identities");
    const manifests: { path: string; values: Record<string, string> }[] = [];
    for (const asset of assets.filter((asset) =>
      asset.relative_path.endsWith("/extension.properties"),
    )) {
      const values = properties(
        await host.readText(join(observed.root, asset.relative_path)),
      );
      if (values.name === "ghidra_psx_ldr")
        manifests.push({ path: asset.relative_path, values });
    }
    if (manifests.length === 0)
      return rejected(
        "missing",
        "Install the PSX loader extension in the selected Ghidra installation; user GUI extensions are isolated.",
      );
    if (manifests.length !== 1)
      return rejected(
        "ambiguous",
        "Multiple PSX extension manifests in the selected installation",
      );
    const manifest = manifests[0]!;
    if (manifest.values.version !== version)
      return rejected(
        "incompatible",
        `PSX extension version ${manifest.values.version ?? "missing"} does not match Ghidra ${version}`,
      );
    const loaderJars: GhidraPsxAsset[] = [];
    const analyzerClasses = new Set<string>();
    let coreMipsPreAnalyzer = false;
    for (const jar of assets.filter((asset) =>
      asset.relative_path.endsWith(".jar"),
    )) {
      abort(signal);
      const entries = await host.jarEntries(
        join(observed.root, jar.relative_path),
        signal,
      );
      for (const entry of entries)
        if (
          /^(?:psx\/[^/]*Analyzer|ghidra\/app\/plugin\/core\/analysis\/Mips[^/]*Analyzer)\.class$/u.test(
            entry,
          )
        )
          analyzerClasses.add(entry.slice(0, -6).replaceAll("/", "."));
      if (
        jar.relative_path === "Ghidra/Processors/MIPS/lib/MIPS.jar" &&
        entries.includes(
          "ghidra/app/plugin/core/analysis/MipsPreAnalyzer.class",
        )
      )
        coreMipsPreAnalyzer = true;
      const count = entries.filter(
        (entry) => entry === "psx/PsxLoader.class",
      ).length;
      if (count > 1)
        return rejected(
          "ambiguous",
          "Duplicate PSX loader resources in one archive",
        );
      if (count === 1) loaderJars.push(jar);
    }
    if (loaderJars.length === 0)
      return rejected(
        "incompatible",
        "PSX extension manifest has no loader class resource",
      );
    if (loaderJars.length !== 1)
      return rejected("ambiguous", "Multiple PSX loader class resources");
    if (!coreMipsPreAnalyzer)
      return rejected(
        "incompatible",
        "Required core MipsPreAnalyzer resource is missing from Ghidra/Processors/MIPS/lib/MIPS.jar",
      );
    const extension = dirname(manifest.path);
    const loaderJar = loaderJars[0]!;
    if (!loaderJar.relative_path.startsWith(`${extension}/`))
      return rejected(
        "incompatible",
        "PSX loader code source is outside its extension",
      );
    const definitions: { asset: GhidraPsxAsset; resources: string[] }[] = [];
    for (const asset of assets.filter((asset) =>
      asset.relative_path.endsWith(".ldefs"),
    ))
      for (const definition of languageDefinitions(
        await host.readText(join(observed.root, asset.relative_path)),
      ))
        if (definition.id === "PSX:LE:32:default")
          definitions.push({ asset, resources: definition.resources });
    if (definitions.length !== 1)
      return rejected(
        definitions.length > 1 ? "ambiguous" : "incompatible",
        "Expected one PSX:LE:32:default language definition",
      );
    const definition = definitions[0]!;
    if (
      !definition.asset.relative_path.startsWith(`${extension}/`) ||
      definition.resources.length !== 3
    )
      return rejected(
        "incompatible",
        "PSX language/compiler selection is unmodeled",
      );
    for (const name of definition.resources) {
      const path = join(dirname(definition.asset.relative_path), name);
      if (!name || !assets.some((asset) => asset.relative_path === path))
        return rejected(
          "incompatible",
          `Missing selected language resource ${path}`,
        );
    }
    // Include all language resources in this directory, covering specification includes.
    const language_assets = assets
      .filter((asset) =>
        asset.relative_path.startsWith(
          `${dirname(definition.asset.relative_path)}/`,
        ),
      )
      .map(({ relative_path, sha256 }) => ({ relative_path, sha256 }));
    return {
      status: "available",
      candidate: {
        installation_root: observed.root,
        provider_version: version,
        extension_manifest: manifest.values,
        extension_relative: extension,
        loader: {
          selector: "PsxLoader",
          class_name: "psx.PsxLoader",
          display_name: "PSX Executables Loader",
          code_source_relative: loaderJar.relative_path,
          code_source_sha256: loaderJar.sha256,
        },
        language_assets,
        analyzer_classes: [...analyzerClasses].sort(),
        assets,
        asset_inventory_version: "ghidra-code-data-v1",
        asset_inventory_digest: ghidraPsxInventoryDigest(assets),
      },
    };
  } catch (cause) {
    if (signal?.aborted === true || cause instanceof AnalysisCancelledError)
      throw new AnalysisCancelledError("open_binary", { cause });
    if (
      cause instanceof Error &&
      "code" in cause &&
      (cause.code === "EACCES" || cause.code === "EPERM")
    )
      throw new AnalysisAccessDeniedError("open_binary", root, cause.code, {
        cause,
      });
    return rejected(
      "incompatible",
      `Cannot completely inspect PSX assets: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

/** Narrow provider policy, preserving the pure format parser's classification. */
export const inspectGhidraPsxPolicy = (
  header: PsxExeHeader,
): readonly string[] => {
  const base = 0x80000000,
    end = 0x801fffff;
  const pure = inspectPsxExePolicy(header);
  const reasons =
    pure.status === "eligible"
      ? []
      : pure.reasons.map((reason) => reason.reason);
  const payload = header.payloadExtent;
  if (header.payloadAddress % 4 !== 0)
    reasons.push("payload_address must be four-byte aligned");
  if (payload !== null && (payload.start < base || payload.endInclusive > end))
    reasons.push("payload range must be within 0x80000000..0x801fffff");
  if (
    payload === null ||
    header.initialPc < payload.start ||
    header.initialPc + 3 > payload.endInclusive ||
    header.initialPc < base ||
    header.initialPc + 3 > end
  )
    reasons.push(
      "complete four-byte initial_pc instruction must lie within payload and KSEG0 2MB RAM",
    );
  const fill = header.fillExtent;
  if (fill !== null && (fill.start < base || fill.endInclusive > end))
    reasons.push("nonempty fill range must be within 0x80000000..0x801fffff");
  if (
    fill !== null &&
    payload !== null &&
    fill.start <= payload.endInclusive &&
    payload.start <= fill.endInclusive
  )
    reasons.push("fill range must be disjoint from payload");
  if (header.declaredDataAddress !== 0 || header.declaredDataBytes !== 0)
    reasons.push(
      "data_address and data_bytes must both be zero under psx-kseg0-2m-defaults-v1",
    );
  return reasons;
};
/** Bounded header read and streamed source identity; no payload buffering. */
export const readGhidraPsxSource = async (
  path: string,
  sha256: string,
  signal?: AbortSignal,
): Promise<PsxExeHeader> => {
  abort(signal);
  const file = await open(path, "r").catch((cause: unknown) => {
    if (
      cause instanceof Error &&
      "code" in cause &&
      (cause.code === "EACCES" || cause.code === "EPERM")
    )
      throw new AnalysisAccessDeniedError("open_binary", path, cause.code, {
        cause,
      });
    throw cause;
  });
  try {
    const before = await file.stat();
    const bytes = Buffer.alloc(2048);
    const read = await file.read(bytes, 0, 2048, 0);
    const parsed = parsePsxExeHeader(
      bytes.subarray(0, read.bytesRead),
      before.size,
    );
    if (!parsed.ok)
      throw new AnalysisArtifactChangedError(
        "open_binary",
        path,
        parsed.error.reason,
      );
    const observed = await hashOpenFile(path, file, signal);
    const after = await file.stat();
    if (
      observed.sha256 !== sha256 ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      throw new AnalysisArtifactChangedError(
        "open_binary",
        path,
        "PSX source no longer matches resolved SHA-256/header identity",
      );
    return parsed.value;
  } catch (cause) {
    if (signal?.aborted === true)
      throw new AnalysisCancelledError("open_binary", { cause });
    if (
      cause instanceof Error &&
      "code" in cause &&
      (cause.code === "EACCES" || cause.code === "EPERM")
    )
      throw new AnalysisAccessDeniedError("open_binary", path, cause.code, {
        cause,
      });
    throw cause;
  } finally {
    await file.close();
  }
};
export const createGhidraPsxCommitment = (
  header: PsxExeHeader,
  candidate: PsxLoaderCandidate,
  path: string,
  sha256: string,
): PsxImportCommitment => {
  const hex = (value: number) => `0x${value.toString(16)}`;
  return psxImportCommitmentSchema.parse({
    schema_version: 1,
    policy: "psx-kseg0-2m-defaults-v1",
    source_snapshot_path: path,
    source_sha256: sha256,
    declarations: {
      file_bytes: header.fileBytes,
      payload_file_offset: 2048,
      payload_address: hex(header.payloadAddress),
      payload_bytes: header.payloadBytes,
      trailing_bytes: header.trailingBytes,
      initial_pc: hex(header.initialPc),
      initial_gp: hex(header.initialGp),
      data_address: hex(header.declaredDataAddress),
      data_bytes: header.declaredDataBytes,
      fill_address: hex(header.fillAddress),
      fill_bytes: header.fillBytes,
      stack_base: hex(header.stackBase),
      stack_offset: hex(header.stackOffset),
      initial_sp: header.initialSp === null ? null : hex(header.initialSp),
    },
    loader: candidate.loader,
    language_id: "PSX:LE:32:default",
    compiler_spec_id: "default",
    option_mode: "loader-defaults",
    supplied_loader_options: {},
    expected_ram_base: "0x80000000",
    expected_ram_size: 2097152,
    asset_inventory_version: candidate.asset_inventory_version,
    asset_inventory_digest: candidate.asset_inventory_digest,
  });
};
/** Verify the owned snapshot and fresh assets before allocating the provider process. */
export const validateGhidraPsxLaunch = async (
  configuration: PsxImportCommitment,
  root: string,
  version: string,
  path: string,
  signal?: AbortSignal,
): Promise<Result<PsxLoaderCandidate, Error>> => {
  const header = await readGhidraPsxSource(
    path,
    configuration.source_sha256,
    signal,
  );
  const reasons = inspectGhidraPsxPolicy(header);
  if (reasons.length > 0) return err(new Error(reasons.join("; ")));
  const inspected = await inspectGhidraPsxLoader(root, version, signal);
  if (inspected.status !== "available") return err(new Error(inspected.reason));
  const actual = createGhidraPsxCommitment(
    header,
    inspected.candidate,
    path,
    configuration.source_sha256,
  );
  if (
    JSON.stringify(actual) !==
    JSON.stringify({ ...configuration, source_snapshot_path: path })
  )
    return err(
      new Error(
        "PSX import source declarations or installed assets changed after profile resolution",
      ),
    );
  return ok(inspected.candidate);
};
