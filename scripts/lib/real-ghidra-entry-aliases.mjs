import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parseBinaryTarget } from "../../dist/application/BinaryTargetResolver.js";

/** Verify imported entry aliases through CLI/MCP without admitting interior labels. */
export async function verifyGhidraEntryAliases({
  call,
  reject,
  target,
  entrypoint,
  env,
}) {
  const exec = promisify(execFile);
  const compiler = process.env.REA_CC ?? "cc";
  const workspace = await mkdtemp(join(tmpdir(), "rea-ghidra-entry-aliases-"));
  const source = fileURLToPath(
    new URL("../../tests/conformance/ghidra/entry-aliases.c", import.meta.url),
  );
  const darwinRelocatable = process.platform === "darwin";
  const path = join(
    workspace,
    darwinRelocatable ? "entry-aliases.o" : "entry-aliases",
  );
  const compilerArguments = [
    ...(darwinRelocatable ? ["--target=aarch64-linux-gnu", "-c"] : []),
    "-O0",
    "-g",
    "-fno-inline",
    source,
    "-o",
    path,
  ];
  const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
  try {
    const sourceBytes = await readFile(source);
    await exec(compiler, compilerArguments, {
      env,
      timeout: 30000,
    });
    const bytes = await readFile(path);
    const parsed = await parseBinaryTarget(path);
    if (!parsed.ok) throw parsed.error;
    const generatedTarget = parsed.value;
    assert.equal(generatedTarget.kind, "executable");
    assert.equal(generatedTarget.sha256, sha256(bytes));
    if (darwinRelocatable) {
      assert.ok(bytes.length >= 64);
      assert.equal(bytes.subarray(0, 4).toString("hex"), "7f454c46");
      assert.equal(bytes[4], 2);
      assert.equal(bytes[5], 1);
      assert.equal(bytes.readUInt16LE(16), 1);
      assert.equal(bytes.readUInt16LE(18), 183);
      assert.equal(generatedTarget.format, "elf");
      assert.equal(generatedTarget.architecture, "arm64");
    }
    const prefix = generatedTarget.format === "mach-o" ? "_" : "";
    await call("close_binary");
    await call("open_binary", { path, provider_id: "ghidra" });
    const names = await call("list_names");
    const alias = names.find(
      ({ value }) => value === `${prefix}rea_entry_alias`,
    );
    assert.ok(alias, "Fixture entry alias was not imported");
    assert.equal(
      alias.symbol.primary,
      false,
      "The regression must exercise a secondary entry symbol",
    );
    assert.equal(alias.symbol.source, "imported");
    const canonical = (await call("list_procedures")).find(
      ({ address }) => address === alias.address,
    );
    assert.ok(canonical, "Fixture alias is not at a function entry");
    const xrefsSelectors = [];
    for (const value of [
      canonical.value,
      alias.value,
      `${prefix}rea_xrefs_data`,
      `${prefix}rea_xrefs_unreferenced`,
    ]) {
      const symbol = names.find((item) => item.value === value);
      assert.ok(symbol, `Missing xrefs selector ${value}`);
      const expected = await call("xrefs", { address: symbol.address });
      if (value === `${prefix}rea_xrefs_unreferenced`)
        assert.deepEqual(expected, []);
      else assert.ok(expected.length > 0, `Missing references for ${value}`);
      xrefsSelectors.push({ symbol, expected });
    }
    for (const procedure of [
      alias.value,
      "dead",
      canonical.value,
      alias.address,
    ]) {
      assert.equal(
        await call("procedure_address", { procedure }),
        alias.address,
      );
      assert.equal(
        (await call("analyze_function", { procedure })).procedure.address,
        alias.address,
      );
      assert.equal(
        await call("procedure_pseudo_code", { procedure }),
        await call("procedure_pseudo_code", { procedure: alias.address }),
      );
    }
    // Leaf and qualified forms of the primary name must not duplicate a match.
    const aliasInfo = await call("procedure_info", { procedure: alias.value });
    assert.equal(aliasInfo.entrypoint, alias.address);
    const interior = names.find(
      ({ value }) => value === `${prefix}rea_interior`,
    );
    assert.ok(interior);
    assert.equal(interior.symbol.source, "imported");
    assert.notEqual(interior.address, alias.address);
    assert.ok(
      aliasInfo.body.ranges.some(
        ({ start, end }) =>
          BigInt(start) <= BigInt(interior.address) &&
          BigInt(interior.address) <= BigInt(end),
      ),
      "Interior label must belong to the observed canonical function body",
    );
    const failure = await reject("procedure_address", {
      procedure: interior.value,
    });
    assert.equal(failure.code, "invalid_request");
    assert.match(
      JSON.stringify(failure.details.issues),
      /Unknown Ghidra procedure name or address/u,
    );
    assert.equal(
      await call("procedure_address", { procedure: interior.address }),
      alias.address,
      "Explicit interior addresses keep their existing containment semantics",
    );
    const edited = await call("annotate_native_function", {
      procedure: alias.value,
      comment: "Selected by imported entry alias",
    });
    assert.equal(edited.annotations.address, alias.address);
    assert.equal(
      edited.annotations.comment,
      "Selected by imported entry alias",
    );
    assert.equal(
      await call("procedure_address", { procedure: alias.value }),
      alias.address,
    );
    await call("close_binary");
    const { stdout } = await exec(
      process.execPath,
      [
        entrypoint,
        "function",
        path,
        alias.value,
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    assert.equal(
      JSON.parse(stdout).normalized_result.procedure.address,
      alias.address,
    );
    for (const { symbol, expected } of xrefsSelectors) {
      for (const selector of [
        [symbol.value],
        ["--address", symbol.value],
        [symbol.address],
      ]) {
        const { stdout } = await exec(
          process.execPath,
          [
            entrypoint,
            "xrefs",
            path,
            ...selector,
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
        );
        const evidence = JSON.parse(stdout);
        assert.deepEqual(evidence.normalized_result, expected);
        assert.equal(evidence.parameters.address, selector.at(-1));
      }
    }
    await assert.rejects(
      exec(
        process.execPath,
        [
          entrypoint,
          "xrefs",
          path,
          "rea_missing_symbol",
          "--provider",
          "ghidra",
          "--json",
        ],
        { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
      ),
      (error) => {
        const failure = JSON.parse(error.stdout);
        assert.equal(failure.code, "invalid_request");
        assert.equal(failure.details.operation, "xrefs");
        assert.match(
          JSON.stringify(failure.details.issues),
          /Unknown analyzed symbol name.*rea_missing_symbol/u,
        );
        return true;
      },
    );
    assert.deepEqual(await readFile(path), bytes);
    assert.deepEqual(await readFile(source), sourceBytes);
    await call("open_binary", { path: target.path, provider_id: "ghidra" });
    return {
      scope: darwinRelocatable
        ? "darwin-auxiliary-aarch64-elf-relocatable"
        : "native-auxiliary-entry-alias-fixture",
      format: generatedTarget.format,
      architecture: generatedTarget.architecture,
      relocatable:
        generatedTarget.format === "elf" && bytes.readUInt16LE(16) === 1,
      compiler: { command: compiler, arguments: compilerArguments },
      source_sha256: sha256(sourceBytes),
      generated_sha256: sha256(bytes),
      ...(darwinRelocatable
        ? {
            object_sha256: sha256(bytes),
            main_host_controls:
              "Mach-O controls remain separate from this auxiliary ELF subcase",
            macho_named_nonentry_verified: false,
            linux_native_host_verified: false,
          }
        : {}),
      symbol_names: {
        canonical: canonical.value,
        alias: alias.value,
        interior: interior.value,
        hexadecimal_entry: "dead",
        referenced_data: `${prefix}rea_xrefs_data`,
        unreferenced_data: `${prefix}rea_xrefs_unreferenced`,
      },
      observed_addresses: {
        canonical: alias.address,
        interior: interior.address,
      },
      checks: {
        imported_secondary_alias: true,
        entry_selector_agreement: true,
        body_containment: true,
        interior_name_rejected: true,
        explicit_interior_containment: true,
        annotation_by_alias: true,
        cli_mcp_xrefs: true,
        missing_name_rejected: true,
        source_bytes_unchanged: true,
        original_target_reopened: true,
      },
    };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
