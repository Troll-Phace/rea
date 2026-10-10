import assert from "node:assert/strict";

// Explicit independent oracle from the saved P4 contract. No production decoder,
// fixture builder, mnemonic classification or parser constructs these expectations.
export const psxInstructionFlowOracle = Object.freeze({
  entry: "0x80010000",
  leaf: "0x80010080",
  data: "0x80010100",
  words: [
    ["0x80010000", "f0ffbd27"],
    ["0x80010004", "0c00bfaf"],
    ["0x80010008", "2040000c"],
    ["0x8001000c", "07000424"],
    ["0x80010010", "03008010"],
    ["0x80010014", "09000524"],
    ["0x80010018", "0a400008"],
    ["0x8001001c", "0b000624"],
    ["0x80010020", "0d000624"],
    ["0x80010024", "00000000"],
    ["0x80010028", "0180083c"],
    ["0x8001002c", "00010825"],
    ["0x80010030", "00000991"],
    ["0x80010034", "09f82003"],
    ["0x80010038", "0f000724"],
    ["0x8001003c", "0c00bf8f"],
    ["0x80010040", "1000bd27"],
    ["0x80010044", "0800e003"],
    ["0x80010048", "03000224"],
    ["0x80010080", "0800e003"],
    ["0x80010084", "01008224"],
  ],
  transfers: [
    ["0x80010008", "call", false, false, ["0x80010080"], "0x8001000c"],
    ["0x80010010", "jump", true, false, ["0x80010020"], "0x80010014"],
    ["0x80010018", "jump", false, false, ["0x80010028"], "0x8001001c"],
    ["0x80010034", "call", false, true, [], "0x80010038"],
    // P4-R1: Listing TERMINATOR computed=false is independent of register-return intent.
    ["0x80010044", "return", false, false, [], "0x80010048"],
    ["0x80010080", "return", false, false, [], "0x80010084"],
  ],
  dataSources: ["0x80010028", "0x8001002c", "0x80010030"],
});

/** Check original source bytes independently before any provider resource exists. */
export function assertPsxInstructionFlowFixture(
  bytes,
  oracle = psxInstructionFlowOracle,
) {
  for (const [address, expectedHex] of oracle.words) {
    const offset = 0x800 + Number(BigInt(address) - 0x80010000n);
    assert.equal(
      bytes.subarray(offset, offset + 4).toString("hex"),
      expectedHex,
      "Generated source disagrees with independent oracle",
    );
  }
  const expectedString = "REA-PSX-P4\0";
  const dataOffset = 0x800 + Number(BigInt(oracle.data) - 0x80010000n);
  const end = dataOffset + Buffer.byteLength(expectedString, "ascii");
  assert.equal(
    bytes.subarray(dataOffset, end).toString("ascii"),
    expectedString,
    "Generated source string must include its real NUL terminator",
  );
  assert.equal(
    bytes.subarray(end, end + 5).toString("hex"),
    "7f80feff55",
    "Independent sentinel must immediately follow the terminated string",
  );
}

/** Reusable by direct production and future public callers; records belong to caller. */
export async function verifyPsxInstructionFlow({
  call,
  oracle = psxInstructionFlowOracle,
  stage = "decoder",
}) {
  assert.equal(typeof call, "function", "A named call function is required");
  assert.ok(
    ["decoder", "operations"].includes(stage),
    "Unknown operation verification stage",
  );
  assert.ok(
    Array.isArray(oracle.words) && Array.isArray(oracle.transfers),
    "Explicit fixture oracle is required",
  );
  const image = await call("inspect_native_load_image", {});
  assert.equal(
    image.status,
    "verified",
    "Source-backed image failed independent attestation",
  );
  assert.equal(image.coverage.complete, true);
  const slots = new Set(oracle.transfers.map((row) => row[5]));
  const transfers = new Map(oracle.transfers.map((row) => [row[0], row]));
  for (const [address, bytes] of oracle.words) {
    const instruction = await call("inspect_native_instruction", { address });
    assert.equal(instruction.address, address);
    assert.equal(instruction.status, "decoded", `${address} not decoded`);
    assert.equal(
      instruction.bytes,
      bytes,
      `${address} bytes disagree with original words`,
    );
    assert.equal(instruction.length, 4);
    const transfer = transfers.get(address);
    assert.deepEqual(
      instruction.delay_slots,
      {
        is_in_delay_slot: slots.has(address),
        depth: transfer ? 1 : 0,
        addresses: transfer ? [transfer[5]] : [],
      },
      `${address} measured delay-slot facts disagree`,
    );
    assert.equal(
      instruction.flow.kind,
      transfer?.[1] ?? "fallthrough",
      `${address} flow kind`,
    );
    assert.equal(
      instruction.flow.conditional,
      transfer?.[2] ?? false,
      `${address} Listing flow.conditional`,
    );
    assert.equal(
      instruction.flow.computed,
      transfer?.[3] ?? false,
      `${address} Listing flow.computed`,
    );
    if (transfer)
      assert.deepEqual(
        instruction.flow.direct_destinations,
        transfer[4],
        `${address} destinations`,
      );
    assert.ok(
      instruction.flow.classification_evidence.some(
        (fact) => fact.source === "ghidra-listing-flow-type",
      ),
      `${address} lacks Listing classification evidence`,
    );
    if (transfer?.[1] === "return") {
      assert.ok(
        instruction.flow.classification_evidence.some(
          (fact) =>
            fact.source === "ghidra-listing-flow-type" &&
            fact.value === "TERMINATOR",
        ),
        `${address} lacks Listing TERMINATOR evidence for decoded return`,
      );
      assert.ok(
        instruction.flow.classification_evidence.some(
          (fact) =>
            fact.source === "ghidra-instruction-pcode" &&
            fact.value === "RETURN",
        ),
        `${address} lacks exact decoded p-code RETURN evidence`,
      );
    }
  }
  const direct = await call("resolve_native_call_targets", {
    address: "0x80010008",
  });
  assert.equal(direct.status, "direct");
  assert.equal(direct.mechanism, "direct");
  assert.deepEqual(
    direct.targets.map((target) => target.address),
    [oracle.leaf],
  );
  const indirect = await call("resolve_native_call_targets", {
    address: "0x80010034",
  });
  assert.equal(indirect.status, "unresolved");
  assert.equal(indirect.mechanism, "computed");
  assert.deepEqual(indirect.targets, []);
  for (const address of [
    "0x80010010",
    "0x80010018",
    "0x80010044",
    "0x80010080",
  ])
    assert.equal(
      (await call("resolve_native_call_targets", { address })).status,
      "not-call",
    );
  for (const [address, status] of [
    ["0x80010001", "not-instruction-boundary"],
    [oracle.data, "data"],
    ["0x90000000", "outside-memory"],
  ]) {
    const instruction = await call("inspect_native_instruction", { address });
    assert.equal(
      instruction.status,
      status,
      `${address} Listing classification`,
    );
    assert.equal(instruction.bytes, null);
    assert.equal(instruction.flow.kind, "unavailable");
    assert.deepEqual(instruction.delay_slots, {
      is_in_delay_slot: null,
      depth: null,
      addresses: null,
    });
    assert.equal(
      (await call("resolve_native_call_targets", { address })).status,
      "unavailable",
    );
  }
  const inventory = await call("list_procedures", {});
  for (const address of [oracle.entry, oracle.leaf])
    assert.ok(
      inventory.some((item) => item.address === address),
      `Missing function ${address}`,
    );
  const strings = await call("list_strings", {});
  assert.ok(
    strings.some(
      (item) => item.address === oracle.data && item.value === "REA-PSX-P4",
    ),
    "Analyzer did not define the original data/string",
  );
  const outgoing = await call("procedure_references", {
    procedure: oracle.entry,
    direction: "outgoing",
  });
  const dataReferences = outgoing.references.filter(
    (edge) =>
      edge.target_address === oracle.data &&
      oracle.dataSources.includes(edge.source_address) &&
      edge.kind.data,
  );
  assert.ok(
    dataReferences.length > 0,
    "Missing actual address-materialization/data reference",
  );
  const entry = await functionObservations(call, oracle.entry, "0x80010048");
  const leaf = await functionObservations(call, oracle.leaf, "0x80010084");
  for (const [address, owner] of [
    ["0x8001000c", oracle.entry],
    ["0x80010001", oracle.entry],
    ["0x80010048", oracle.entry],
    ["0x80010084", oracle.leaf],
  ]) {
    const containing = await call("resolve_containing_procedure", { address });
    assert.equal(containing.found, true, `${address} tail/interior ownership`);
    assert.equal(containing.procedure.address, owner);
    assert.equal(
      await call("procedure_address", { procedure: address }),
      owner,
    );
  }
  const facts = {
    stage,
    compared_words: oracle.words.length,
    transfers: oracle.transfers.length,
    data_reference_sources: dataReferences.map((edge) => edge.source_address),
    decoded_return_addresses: ["0x80010044", "0x80010080"],
    unresolved_call: indirect.call_site,
    observed_tail_slots: ["0x80010048", "0x80010084"],
  };
  if (stage === "decoder") return facts;
  assert.equal(stage, "operations");
  await verifyOperations(call, oracle, { entry, leaf, outgoing });
  return { ...facts, operation_matrix: "passed" };
}

async function functionObservations(call, procedure, tail) {
  assert.equal(await call("procedure_address", { procedure }), procedure);
  const info = await call("procedure_info", { procedure });
  assert.equal(info.entrypoint, procedure);
  assert.ok(
    info.body.available &&
      info.body.ranges.some(
        (range) =>
          BigInt(range.start) <= BigInt(tail) &&
          BigInt(range.end) >= BigInt(tail),
      ),
    `${procedure} AddressSet lacks actual tail slot`,
  );
  const listing = await call("read_function_instructions", { procedure });
  assert.equal(listing.procedure.address, procedure);
  assert.deepEqual(listing.procedure.body, info.body);
  assert.ok(
    listing.instructions.some((line) => line.startsWith(`${tail}: `)),
    `${procedure} listing excludes tail slot`,
  );
  return { info, listing };
}

async function verifyOperations(call, oracle, { entry, leaf, outgoing }) {
  for (const [procedure, observation] of [
    [oracle.entry, entry],
    [oracle.leaf, leaf],
  ]) {
    const assembly = await call("procedure_assembly", { procedure });
    assert.equal(typeof assembly, "string");
    assert.ok(assembly.includes(procedure) && assembly.trim().length > 0);
    const pseudocode = await call("procedure_pseudo_code", { procedure });
    meaningfulC(pseudocode, procedure);
    const dossier = await call("analyze_function", { procedure });
    assert.equal(dossier.procedure.address, procedure);
    assert.deepEqual(dossier.procedure.body, observation.info.body);
    meaningfulC(dossier.pseudocode, procedure);
    assert.deepEqual(dossier.assembly, observation.listing.instructions);
    assert.ok(dossier.basic_blocks.length > 0);
    const direction = procedure === oracle.entry ? "outgoing" : "incoming";
    const references = await call("procedure_references", {
      procedure,
      direction,
    });
    assertCallEdge(references.references, oracle);
    assertCallEdge(dossier[`${direction}_references`], oracle);
    if (procedure === oracle.entry) {
      assert.ok(
        Array.isArray(references.unresolved_calls),
        `procedure_references(${procedure}, outgoing) must expose an unresolved_calls array for required site 0x80010034`,
      );
      assert.ok(
        references.unresolved_calls.some(
          (site) => site.address === "0x80010034",
        ),
        `procedure_references(${procedure}, outgoing) lacks required unresolved call site 0x80010034`,
      );
      assert.ok(
        Array.isArray(dossier.limitations) &&
          dossier.limitations.some((text) =>
            /unresolved.*(?:computed|indirect).*target.*(?:reference|edge)/iu.test(
              text,
            ),
          ),
        `analyze_function(${procedure}) lacks unresolved computed/indirect flow disclosure about absent target/reference edges`,
      );
      assert.ok(
        dossier.callees.some((identity) => identity.address === oracle.leaf),
      );
      assert.ok(
        dossier.referenced_strings.some(
          (item) =>
            item.address === oracle.data &&
            oracle.dataSources.includes(item.source_address),
        ),
      );
    } else
      assert.ok(
        dossier.callers.some((identity) => identity.address === oracle.entry),
      );
  }
  assert.ok(
    (await call("procedure_callees", { procedure: oracle.entry })).includes(
      oracle.leaf,
    ),
  );
  assert.ok(
    (await call("procedure_callers", { procedure: oracle.leaf })).includes(
      oracle.entry,
    ),
  );
  assert.ok(
    (await call("xrefs", { address: oracle.leaf })).includes("0x80010008"),
  );
  assert.ok(
    (await call("xrefs", { address: oracle.data })).some((source) =>
      oracle.dataSources.includes(source),
    ),
  );
  for (const procedure of ["0x8001000c", "0x80010001"]) {
    assert.equal(
      (await call("procedure_info", { procedure })).entrypoint,
      oracle.entry,
    );
    assert.deepEqual(
      await call("read_function_instructions", { procedure }),
      entry.listing,
    );
    meaningfulC(await call("procedure_pseudo_code", { procedure }), procedure);
    assert.equal(
      (await call("analyze_function", { procedure })).procedure.address,
      oracle.entry,
    );
    assert.ok(
      (await call("procedure_assembly", { procedure })).includes(oracle.entry),
    );
  }
  assert.deepEqual(
    await call("procedure_info", { procedure: oracle.entry }),
    entry.info,
    "Read operations changed function body observations",
  );
  assert.deepEqual(
    await call("procedure_references", {
      procedure: oracle.entry,
      direction: "outgoing",
    }),
    outgoing,
    "Read operations changed reference observations",
  );
}
function assertCallEdge(edges, oracle) {
  assert.ok(
    edges.some(
      (edge) =>
        edge.source_address === "0x80010008" &&
        edge.target_address === oracle.leaf &&
        edge.kind.call &&
        edge.source_procedure?.address === oracle.entry &&
        edge.target_procedure?.address === oracle.leaf,
    ),
    "Direct call edge/identities absent",
  );
}
function meaningfulC(text, procedure) {
  assert.equal(
    typeof text,
    "string",
    `${procedure} native decompiler returned no C`,
  );
  assert.ok(
    text.trim().length > 0 && /\{[\s\S]*\}/u.test(text),
    `${procedure} native decompiler output lacks a function body`,
  );
}

/** Always attempt independent capture/postchecks and every close; retain unresolved owners. */
export async function settlePsxVerification({
  primary,
  capture = [],
  postchecks = [],
  resources = [],
  cleanup = [],
}) {
  const failures = [];
  if (primary !== undefined)
    failures.push({ stage: "primary", error: primary });
  for (const [stage, actions] of [
    ["capture", capture],
    ["postcheck", postchecks],
  ])
    for (const action of actions)
      try {
        await action();
      } catch (error) {
        failures.push({ stage, error });
      }
  const unresolved = [];
  for (const resource of resources) {
    let closed = false;
    for (let attempt = 0; attempt < 2 && !closed; attempt++)
      try {
        await resource.close();
        closed = true;
      } catch (error) {
        failures.push({
          stage: "close",
          owner: resource.owner,
          attempt: attempt + 1,
          error,
        });
      }
    if (!closed) unresolved.push(resource.owner);
  }
  // Exact roots may only be released once all owned resources are settled.
  if (unresolved.length === 0)
    for (const action of cleanup)
      try {
        await action();
      } catch (error) {
        failures.push({ stage: "cleanup", error });
      }
  return {
    ok: failures.length === 0 && unresolved.length === 0,
    failures,
    unresolved,
  };
}
