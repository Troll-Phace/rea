import { createHash } from "node:crypto";
import { open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { functionDossierSchema } from "../../../../src/domain/hopperValues.js";
import { jsonValueSchema } from "../../../../src/domain/jsonValue.js";
import { parseGhidraFunctionResult } from "../../../../src/ghidra/GhidraFunctionValues.js";
import type { GhidraOperation } from "../../../../src/ghidra/GhidraClient.js";
import { psxSimulatedOperation } from "../../../fixtures/ghidraPsxImport.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

type Action = () => Promise<void>;
interface Settlement {
  ok: boolean;
  failures: { stage: string; error: unknown; owner?: string }[];
  unresolved: string[];
}
interface Helper {
  assertPsxInstructionFlowFixture: (bytes: Buffer) => void;
  settlePsxVerification: (options: {
    primary?: unknown;
    capture?: Action[];
    postchecks?: Action[];
    resources?: { owner: string; close: Action }[];
    cleanup?: Action[];
  }) => Promise<Settlement>;
  verifyPsxInstructionFlow: (options: {
    call: (
      operation: string,
      parameters: Record<string, unknown>,
    ) => Promise<unknown>;
    stage?: string;
    oracle?: Record<string, unknown>;
  }) => Promise<unknown>;
}
const helperPath = new URL(
  "../../../../scripts/lib/real-ghidra-psx-instruction-flow.mjs",
  import.meta.url,
).href;
const helper: Helper = await import(helperPath);
const fixturePath = new URL(
  "../../../conformance/ghidra/psx-exe-fixture.mjs",
  import.meta.url,
).href;
const { buildPsxExeFixture } = (await import(fixturePath)) as {
  buildPsxExeFixture: (options: { variant: string }) => { bytes: Buffer };
};

// These cases cross a real filesystem boundary. Close/capture failures are
// controlled lifecycle seams; none claims a simulated positive native run.
describe("PSX operation verifier ownership and independent failure capture", () => {
  it("preserves the primary mismatch and attempts every independent postcheck/close", async () => {
    const root = await createTestTempDirectory("rea-psx-operation-failure-");
    const path = join(root, "evidence.json");
    await writeFile(path, '{"observed":"mismatch"}');
    const handle = await open(path, "r");
    const primary = new Error("native semantic mismatch");
    const captureError = new Error("first capture unavailable");
    const postcheckError = new Error("source changed");
    const events: string[] = [];
    const result = await helper.settlePsxVerification({
      primary,
      capture: [
        async () => {
          throw captureError;
        },
        async () => {
          events.push("second-capture");
          expect(await handle.readFile("utf8")).toContain("mismatch");
        },
      ],
      postchecks: [
        async () => {
          throw postcheckError;
        },
        async () => {
          events.push("assets");
        },
      ],
      resources: [
        {
          owner: path,
          close: async () => {
            events.push("close");
            await handle.close();
          },
        },
      ],
      cleanup: [
        async () => {
          events.push("cleanup");
          await rm(path);
        },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.failures.map((item) => item.error)).toEqual([
      primary,
      captureError,
      postcheckError,
    ]);
    expect(events).toEqual(["second-capture", "assets", "close", "cleanup"]);
    expect(result.unresolved).toEqual([]);
    await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains an exact resource and its root after two failed closes", async () => {
    const root = await createTestTempDirectory("rea-psx-operation-retain-");
    const path = join(root, "retained.json");
    await writeFile(path, "retained original evidence");
    const handle = await open(path, "r");
    let attempts = 0;
    let cleanupCalled = false;
    try {
      const result = await helper.settlePsxVerification({
        resources: [
          {
            owner: root,
            close: async () => {
              attempts++;
              throw new Error("owned close failed");
            },
          },
        ],
        cleanup: [
          async () => {
            cleanupCalled = true;
            await rm(path);
          },
        ],
      });
      expect(result.ok).toBe(false);
      expect(result.unresolved).toEqual([root]);
      expect(attempts).toBe(2);
      expect(cleanupCalled).toBe(false);
      expect(await handle.readFile("utf8")).toBe("retained original evidence");
      expect((await stat(path)).isFile()).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("retries a failed close, closes independent owners and records the initial failure", async () => {
    const root = await createTestTempDirectory("rea-psx-operation-retry-");
    const path = join(root, "capture.json");
    await writeFile(path, "immutable");
    const handle = await open(path, "r");
    let attempts = 0;
    let peerClosed = false;
    const closeError = new Error("transient close failure");
    const result = await helper.settlePsxVerification({
      resources: [
        {
          owner: path,
          close: async () => {
            attempts++;
            if (attempts === 1) throw closeError;
            await handle.close();
          },
        },
        {
          owner: "independent-session",
          close: async () => {
            peerClosed = true;
          },
        },
      ],
      cleanup: [
        async () => {
          await rm(path);
        },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.error).toBe(closeError);
    expect(result.unresolved).toEqual([]);
    expect(attempts).toBe(2);
    expect(peerClosed).toBe(true);
    await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("records cleanup failure without suppressing a later independent cleanup", async () => {
    const root = await createTestTempDirectory("rea-psx-operation-cleanup-");
    const retained = join(root, "retained.json");
    const released = join(root, "released.json");
    await writeFile(retained, "retained");
    await writeFile(released, "released");
    const result = await helper.settlePsxVerification({
      cleanup: [
        async () => {
          throw new Error("root release failed");
        },
        async () => {
          await rm(released);
        },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.failures.map((item) => item.stage)).toEqual(["cleanup"]);
    expect(await readFile(retained, "utf8")).toBe("retained");
    await expect(stat(released)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("PSX independent oracle and pre-allocation refusal", () => {
  it("preserves all three existing fixture variants byte-identically", async () => {
    const expected = {
      baseline:
        "be3485b5a1ffb508a0ba1a39d77f1c0b5f383ed0e0df351b84fc2c29d799716a",
      "declared-registers-fill":
        "fb38aeaa649f3b90993bf6151dffc42da00cba2087344255bc6e60d9442ab3d1",
      "trailing-bytes":
        "53fea47eea51911150080df66d2d1acc852d64a7fe39d3777cdcbcd54b155595",
    };
    for (const [variant, hash] of Object.entries(expected)) {
      expect(
        createHash("sha256")
          .update(buildPsxExeFixture({ variant }).bytes)
          .digest("hex"),
      ).toBe(hash);
    }
  });

  it("preflights the actual terminated string and rejects missing NUL or shifted sentinel", () => {
    const bytes = buildPsxExeFixture({ variant: "instruction-flow" }).bytes;
    const expected = Buffer.from("REA-PSX-P4\0", "ascii");
    expect(expected.byteLength).toBe(11);
    expect(bytes.subarray(0x900, 0x900 + expected.byteLength)).toEqual(
      expected,
    );
    helper.assertPsxInstructionFlowFixture(bytes);
    const missingNul = Buffer.from(bytes);
    missingNul[0x900 + expected.byteLength - 1] = 0x7f;
    expect(() => helper.assertPsxInstructionFlowFixture(missingNul)).toThrow(
      /NUL terminator/u,
    );
    const shiftedSentinel = Buffer.from(bytes);
    shiftedSentinel[0x900 + expected.byteLength] = 0;
    expect(() =>
      helper.assertPsxInstructionFlowFixture(shiftedSentinel),
    ).toThrow(/sentinel/u);
  });

  it("uses actual runner-to-helper wiring and captures the first contradictory decoder observation", async () => {
    const root = await createTestTempDirectory("rea-psx-operation-oracle-");
    const captured = join(root, "raw.json");
    const script = new URL(
      "../../../../scripts/verify-real-ghidra-psx-operations.mjs",
      import.meta.url,
    ).href;
    const runner = (await import(script)) as {
      verifyOperationMatrix: Helper["verifyPsxInstructionFlow"];
    };
    const calls: string[] = [];
    await expect(
      runner.verifyOperationMatrix({
        call: async (operation, parameters) => {
          calls.push(operation);
          if (operation === "inspect_native_load_image")
            return { status: "verified", coverage: { complete: true } };
          if (operation !== "inspect_native_instruction")
            throw new Error("Unmodeled command");
          const observation = {
            address: parameters.address,
            status: "decoded",
            bytes: "00000000",
            length: 4,
          };
          await writeFile(captured, JSON.stringify(observation));
          return observation;
        },
      }),
    ).rejects.toThrow(/bytes disagree/u);
    expect(calls).toEqual([
      "inspect_native_load_image",
      "inspect_native_instruction",
    ]);
    expect(JSON.parse(await readFile(captured, "utf8"))).toMatchObject({
      address: "0x80010000",
      bytes: "00000000",
    });
  });

  it("forwards the named operation stage before any dispatch", async () => {
    const script = new URL(
      "../../../../scripts/verify-real-ghidra-psx-operations.mjs",
      import.meta.url,
    ).href;
    const runner = (await import(script)) as {
      verifyOperationMatrix: Helper["verifyPsxInstructionFlow"];
    };
    let dispatched = false;
    await expect(
      runner.verifyOperationMatrix({
        stage: "invalid",
        call: async () => {
          dispatched = true;
          throw new Error("Unmodeled command");
        },
      }),
    ).rejects.toThrow(/verification stage/u);
    expect(dispatched).toBe(false);
  });

  it("rejects caller targets before reading prerequisites or allocating an owned workspace", async () => {
    const script = new URL(
      "../../../../scripts/verify-real-ghidra-psx-operations.mjs",
      import.meta.url,
    ).href;
    const { preflightPsxOperations } = (await import(script)) as {
      preflightPsxOperations: (args: string[], env: object) => Promise<unknown>;
    };
    await expect(
      preflightPsxOperations(["/caller/game.exe"], {}),
    ).rejects.toThrow(/no target path/u);
  });
});

// Literal protocol facts exercise only the bounded R1 assertion. A sentinel
// stops immediately after that instruction, never reporting simulated G1 success.
const literalReturn = () => ({
  address: "0x80010044",
  status: "decoded",
  bytes: "0800e003",
  length: 4,
  delay_slots: { is_in_delay_slot: false, depth: 1, addresses: ["0x80010048"] },
  flow: {
    kind: "return",
    conditional: false,
    computed: false,
    direct_destinations: [],
    classification_evidence: [
      { source: "ghidra-listing-flow-type", value: "TERMINATOR" },
      { source: "ghidra-instruction-pcode", value: "RETURN" },
    ],
  },
});
const returnOracle = {
  words: [["0x80010044", "0800e003"]],
  transfers: [["0x80010044", "return", false, false, [], "0x80010048"]],
};
const recordedPartial = async (
  instruction: ReturnType<typeof literalReturn>,
  oracle = returnOracle,
) => {
  const reached: { operation: string; address: unknown }[] = [];
  let failure: unknown;
  try {
    await helper.verifyPsxInstructionFlow({
      oracle,
      call: async (operation, parameters) => {
        reached.push({ operation, address: parameters.address });
        if (operation === "inspect_native_load_image")
          return { status: "verified", coverage: { complete: true } };
        if (operation === "inspect_native_instruction") return instruction;
        throw new Error("intentional partial-sequence sentinel");
      },
    });
  } catch (error) {
    failure = error;
  }
  return { reached, failure };
};
describe("P4-R1 simulated partial instruction comparisons", () => {
  it("accepts literal Listing TERMINATOR/computed false and p-code RETURN before the exact next request", async () => {
    const result = await recordedPartial(literalReturn());
    expect(result.failure).toMatchObject({
      message: "intentional partial-sequence sentinel",
    });
    expect(result.reached).toEqual([
      { operation: "inspect_native_load_image", address: undefined },
      { operation: "inspect_native_instruction", address: "0x80010044" },
      { operation: "resolve_native_call_targets", address: "0x80010008" },
    ]);
  });

  it.each([
    ["computed true", "0x80010044 Listing flow.computed"],
    ["missing RETURN", "0x80010044 lacks exact decoded p-code RETURN evidence"],
    ["missing Listing", "0x80010044 lacks Listing classification evidence"],
    [
      "wrong Listing",
      "0x80010044 lacks Listing TERMINATOR evidence for decoded return",
    ],
  ])(
    "rejects %s at the observed instruction with a property-specific diagnostic",
    async (mutation, diagnostic) => {
      const instruction = literalReturn();
      if (mutation === "computed true") instruction.flow.computed = true;
      if (mutation === "missing RETURN")
        instruction.flow.classification_evidence =
          instruction.flow.classification_evidence.filter(
            (fact) => fact.source !== "ghidra-instruction-pcode",
          );
      if (mutation === "missing Listing")
        instruction.flow.classification_evidence =
          instruction.flow.classification_evidence.filter(
            (fact) => fact.source !== "ghidra-listing-flow-type",
          );
      if (mutation === "wrong Listing")
        instruction.flow.classification_evidence[0]!.value = "COMPUTED_JUMP";
      const result = await recordedPartial(instruction);
      expect(result.failure).toMatchObject({
        message: expect.stringContaining(diagnostic!),
      });
      expect(result.reached.at(-1)).toEqual({
        operation: "inspect_native_instruction",
        address: "0x80010044",
      });
    },
  );

  it("keeps the literal computed-call positive control independent from return flags", async () => {
    const instruction = {
      address: "0x80010034",
      status: "decoded",
      bytes: "09f82003",
      length: 4,
      delay_slots: {
        is_in_delay_slot: false,
        depth: 1,
        addresses: ["0x80010038"],
      },
      flow: {
        kind: "call",
        conditional: false,
        computed: true,
        direct_destinations: [],
        classification_evidence: [
          { source: "ghidra-listing-flow-type", value: "COMPUTED_CALL" },
        ],
      },
    };
    const result = await recordedPartial(instruction, {
      words: [["0x80010034", "09f82003"]],
      transfers: [["0x80010034", "call", false, true, [], "0x80010038"]],
    });
    expect(result.failure).toMatchObject({
      message: "intentional partial-sequence sentinel",
    });
    expect(result.reached.at(-1)).toEqual({
      operation: "resolve_native_call_targets",
      address: "0x80010008",
    });
  });
});

// Complete normalized entry dossier from run-oEckNl, report SHA256
// 9aad3a560caef2281c1a8b29b07ecb09e14484d6d6219117c36615a815b2e767.
// No transport/runtime metadata or local report reads at test execution.
// The measured shape is literal; the named production schema owns its parsing.
const recordedEntryDossier = functionDossierSchema.parse(
  JSON.parse(
    String.raw`{"procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true},"signature":"undefined start()","locals":[{"description":"undefined4 local_4 @ Stack[-0x4]:4","provenance":"ghidra-function-database"}]},"pseudocode":"\nundefined4 start(void)\n\n{\n  code *in_t9;\n  \n  FUN_80010080();\n  (*in_t9)();\n  return 3;\n}\n\n","assembly":["0x80010000: addiu sp, sp, -0x10","0x80010004: sw ra, 0xc(sp)","0x80010008: jal 0x80010080","0x8001000c: _li a0, 0x7","0x80010010: beq a0, zero, 0x80010020","0x80010014: _li a1, 0x9","0x80010018: j 0x80010028","0x8001001c: _li a2, 0xb","0x80010020: li a2, 0xd","0x80010024: nop","0x80010028: lui t0, 0x8001","0x8001002c: addiu t0, t0, 0x100","0x80010030: lbu t1, 0x0(t0)","0x80010034: jalr t9","0x80010038: _li a3, 0xf","0x8001003c: lw ra, 0xc(sp)","0x80010040: addiu sp, sp, 0x10","0x80010044: jr ra","0x80010048: _li v0, 0x3"],"comments":[],"callers":[],"callees":[{"address":"0x80010080","name":"FUN_80010080","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010080","end":"0x80010087"}],"total_bytes":8,"span_bytes":8,"non_contiguous":false,"contains_entry":true}}],"incoming_references":[],"outgoing_references":[{"source_address":"0x80010004","target_address":"stack:0xfffffffffffffffc","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":null,"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"WRITE","flow":false,"call":false,"jump":false,"data":true,"read":false,"write":true,"indirect":false,"computed":false,"conditional":false,"terminal":false,"primary":true,"operand_index":1,"external":false}},{"source_address":"0x80010008","target_address":"0x80010080","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":{"address":"0x80010080","name":"FUN_80010080","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010080","end":"0x80010087"}],"total_bytes":8,"span_bytes":8,"non_contiguous":false,"contains_entry":true}},"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"UNCONDITIONAL_CALL","flow":true,"call":true,"jump":false,"data":false,"read":false,"write":false,"indirect":false,"computed":false,"conditional":false,"terminal":false,"primary":true,"operand_index":0,"external":false}},{"source_address":"0x80010010","target_address":"0x80010020","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"CONDITIONAL_JUMP","flow":true,"call":false,"jump":true,"data":false,"read":false,"write":false,"indirect":false,"computed":false,"conditional":true,"terminal":false,"primary":true,"operand_index":2,"external":false}},{"source_address":"0x80010018","target_address":"0x80010028","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"UNCONDITIONAL_JUMP","flow":true,"call":false,"jump":true,"data":false,"read":false,"write":false,"indirect":false,"computed":false,"conditional":false,"terminal":false,"primary":true,"operand_index":0,"external":false}},{"source_address":"0x80010030","target_address":"0x80010100","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":null,"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"READ","flow":false,"call":false,"jump":false,"data":true,"read":true,"write":false,"indirect":false,"computed":false,"conditional":false,"terminal":false,"primary":true,"operand_index":1,"external":false}},{"source_address":"0x8001003c","target_address":"stack:0xfffffffffffffffc","source_procedure":{"address":"0x80010000","name":"start","classification":{"external":false,"thunk":false,"thunk_target":null,"provenance":"ghidra-function-manager"},"body":{"available":true,"provenance":"ghidra-function-body-address-set","ranges":[{"start":"0x80010000","end":"0x8001004b"}],"total_bytes":76,"span_bytes":76,"non_contiguous":false,"contains_entry":true}},"target_procedure":null,"kind":{"available":true,"provenance":"ghidra-reference-manager","type":"READ","flow":false,"call":false,"jump":false,"data":true,"read":true,"write":false,"indirect":false,"computed":false,"conditional":false,"terminal":false,"primary":true,"operand_index":1,"external":false}}],"referenced_strings":[{"address":"0x80010100","value":"REA-PSX-P4","source_address":"0x80010030"}],"referenced_names":[{"address":"0x80010020","value":"LAB_80010020","source_address":"0x80010010"},{"address":"0x80010028","value":"LAB_80010028","source_address":"0x80010018"},{"address":"0x80010080","value":"FUN_80010080","source_address":"0x80010008"},{"address":"0x80010100","value":"s_REA-PSX-P4_80010100","source_address":"0x80010030"}],"basic_blocks":[{"start":"0x80010000","end":"0x80010018","successors":["0x80010018","0x80010020"]},{"start":"0x80010018","end":"0x80010020","successors":["0x80010028"]},{"start":"0x80010020","end":"0x80010028","successors":["0x80010028"]},{"start":"0x80010028","end":"0x8001004c","successors":[]}],"native_api":{"available":true,"provenance":"ghidra-high-function","signature_source":"default","calling_convention":"__stdcall","return_type":{"ordinal":null,"name":null,"data_type":"undefined4","size_bytes":4,"storage":"v0:4","confidence":"low","evidence":[{"kind":"signature-source","source":"ghidra-function-manager","detail":"Function signature source is default."},{"kind":"decompiler-type","source":"ghidra-high-function","detail":"HighFunction recovered data type undefined4."}],"decompiler_artifacts":["recovered-signature","register-or-stack-storage"],"role":"return"},"parameters":[],"jump_tables":[],"pseudocode":{"classification":"decompiler-generated-non-source","compilable":false},"decompiler_artifacts":["recovered-signature","register-and-stack-variables","compiler-generated-control-flow","pointer-arithmetic","pseudocode"],"limitations":["Types and calling conventions are Ghidra decompiler observations, not source declarations.","Register variables, compiler-generated blocks, and pointer arithmetic remain decompiler artifacts.","Pseudocode is neither original source nor guaranteed to compile."]},"native_value_flow":{"available":true,"provenance":"ghidra-high-pcode","operations":[{"id":"0x80010008#7","address":"0x80010008","sequence":7,"opcode":"CALL","is_dead":true,"block_membership":"member","inputs":[{"kind":"address","size_bytes":8,"location":"0x80010080","constant_hex":null}],"output":null},{"id":"0x80010008#61","address":"0x80010008","sequence":61,"opcode":"INDIRECT","is_dead":true,"block_membership":"member","inputs":[{"kind":"register","size_bytes":4,"location":"register:0x64","constant_hex":null},{"kind":"constant","size_bytes":4,"location":null,"constant_hex":"7"}],"output":{"kind":"register","size_bytes":4,"location":"register:0x64","constant_hex":null}},{"id":"0x80010034#27","address":"0x80010034","sequence":27,"opcode":"CALLIND","is_dead":true,"block_membership":"member","inputs":[{"kind":"register","size_bytes":4,"location":"register:0x64","constant_hex":null}],"output":null},{"id":"0x80010044#38","address":"0x80010044","sequence":38,"opcode":"COPY","is_dead":true,"block_membership":"member","inputs":[{"kind":"constant","size_bytes":4,"location":null,"constant_hex":"3"}],"output":{"kind":"register","size_bytes":4,"location":"register:0x8","constant_hex":null}},{"id":"0x80010044#39","address":"0x80010044","sequence":39,"opcode":"RETURN","is_dead":true,"block_membership":"member","inputs":[{"kind":"constant","size_bytes":4,"location":null,"constant_hex":"0"},{"kind":"register","size_bytes":4,"location":"register:0x8","constant_hex":null}],"output":null}],"def_use":[{"definition":"0x80010008#61","use":"0x80010034#27","input_index":0},{"definition":"0x80010044#38","use":"0x80010044#39","input_index":1}],"effects":[{"operation":"0x80010008#7","kind":"direct_call","operand_input":0,"value_input":null},{"operation":"0x80010034#27","kind":"indirect_call","operand_input":0,"value_input":null}],"parameters":[],"parameter_uses":[],"truncated":false,"omitted_operations_lower_bound":0,"known_omitted_inputs":0,"known_omitted_edges":0,"limitations":["High p-code is decompiler-derived, not original source or runtime behavior. is_dead preserves the Java AST flag; decoded block members can retain that flag, so block_membership separately reports actual syntax-tree membership.","Def-use links do not cross function boundaries and may omit memory aliasing, call side effects, or unresolved indirect flow.","Memory read/write effects include stack and temporary memory operations; they do not identify persistent state or business meaning.","Operation, input, and def-use limits can truncate large functions; inspect truncation, omitted lower bounds, and known omitted counts before drawing conclusions.","Known omitted-edge counts cover links omitted from retained operations; omitted operations may contain additional uncounted links."]},"limitations":["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]}`,
  ),
);
const recordedPrefixRequests: {
  operation: string;
  parameters: Record<string, unknown>;
}[] = [
  {
    operation: "inspect_native_load_image",
    parameters: {},
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010000",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010004",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010008",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x8001000c",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010010",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010014",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010018",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x8001001c",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010020",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010024",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010028",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x8001002c",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010030",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010034",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010038",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x8001003c",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010040",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010044",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010048",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010080",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010084",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010008",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010034",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010010",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010018",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010044",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010080",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010001",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010001",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x80010100",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x80010100",
    },
  },
  {
    operation: "inspect_native_instruction",
    parameters: {
      address: "0x90000000",
    },
  },
  {
    operation: "resolve_native_call_targets",
    parameters: {
      address: "0x90000000",
    },
  },
  {
    operation: "list_procedures",
    parameters: {},
  },
  {
    operation: "list_strings",
    parameters: {},
  },
  {
    operation: "procedure_references",
    parameters: {
      procedure: "0x80010000",
      direction: "outgoing",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "procedure_info",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "read_function_instructions",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x80010080",
    },
  },
  {
    operation: "procedure_info",
    parameters: {
      procedure: "0x80010080",
    },
  },
  {
    operation: "read_function_instructions",
    parameters: {
      procedure: "0x80010080",
    },
  },
  {
    operation: "resolve_containing_procedure",
    parameters: {
      address: "0x8001000c",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x8001000c",
    },
  },
  {
    operation: "resolve_containing_procedure",
    parameters: {
      address: "0x80010001",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x80010001",
    },
  },
  {
    operation: "resolve_containing_procedure",
    parameters: {
      address: "0x80010048",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x80010048",
    },
  },
  {
    operation: "resolve_containing_procedure",
    parameters: {
      address: "0x80010084",
    },
  },
  {
    operation: "procedure_address",
    parameters: {
      procedure: "0x80010084",
    },
  },
  {
    operation: "procedure_assembly",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "procedure_pseudo_code",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "analyze_function",
    parameters: {
      procedure: "0x80010000",
    },
  },
  {
    operation: "procedure_references",
    parameters: {
      procedure: "0x80010000",
      direction: "outgoing",
    },
  },
];
const recordedEntryReferences = () => ({
  procedure: {
    address: "0x80010000",
    name: "start",
    classification: recordedEntryDossier.procedure.classification,
    body: recordedEntryDossier.procedure.body,
  },
  direction: "outgoing",
  references: structuredClone(recordedEntryDossier.outgoing_references),
  reference_kinds_available: true,
  unresolved_calls: [
    {
      address: "0x80010034",
      reason:
        "Instruction decoder identifies a call but ReferenceManager supplies no call destination",
    },
  ],
});

type DossierMutation =
  | "none"
  | "empty reference sites"
  | "missing reference sites"
  | "missing disclosure";
const recordedDossierPrefix = async (mutation: DossierMutation) => {
  const dossier = structuredClone(recordedEntryDossier);
  if (mutation === "missing disclosure")
    dossier.limitations = dossier.limitations.filter(
      (text) => !text.startsWith("Unresolved computed or indirect flows"),
    );
  const reached: { operation: string; parameters: Record<string, unknown> }[] =
    [];
  const sentinel = new Error("intentional unmeasured leaf assembly sentinel");
  const script = new URL(
    "../../../../scripts/verify-real-ghidra-psx-operations.mjs",
    import.meta.url,
  ).href;
  const runner = (await import(script)) as {
    verifyOperationMatrix: Helper["verifyPsxInstructionFlow"];
  };
  let failure: unknown;
  try {
    await runner.verifyOperationMatrix({
      stage: "operations",
      call: async (operation, parameters) => {
        const request = { operation, parameters };
        const index = reached.length;
        reached.push(request);
        if (index === recordedPrefixRequests.length) {
          expect(request).toEqual({
            operation: "procedure_assembly",
            parameters: { procedure: "0x80010080" },
          });
          throw sentinel;
        }
        expect(request).toEqual(recordedPrefixRequests[index]);
        // Explicit focused recording seam for preceding G1 facts, never native success.
        // These responses come from an independent literal simulation, not the verifier oracle.
        if (operation === "inspect_native_load_image")
          return { status: "verified", coverage: { complete: true } };
        if (operation === "list_procedures")
          return [{ address: "0x80010000" }, { address: "0x80010080" }];
        if (operation === "list_strings")
          return [{ address: "0x80010100", value: "REA-PSX-P4" }];
        if (operation === "procedure_references") {
          const reference: Record<string, unknown> = recordedEntryReferences();
          // The earlier G1 read remains intact; these mutations target the G2 assertion.
          if (index === recordedPrefixRequests.length - 1) {
            if (mutation === "empty reference sites")
              reference.unresolved_calls = [];
            if (mutation === "missing reference sites")
              delete reference.unresolved_calls;
          }
          return reference;
        }
        if (operation === "analyze_function") return dossier;
        if (
          operation === "read_function_instructions" &&
          parameters.procedure === "0x80010000"
        )
          return {
            procedure: { address: "0x80010000", body: dossier.procedure.body },
            instructions: dossier.assembly,
          };
        return psxSimulatedOperation(operation as GhidraOperation, parameters);
      },
    });
  } catch (error) {
    failure = error;
  }
  return { failure, sentinel, reached };
};

describe("P4-R5 captured optional dossier contract and partial runner replay", () => {
  it("parses the complete measured dossier without inventing optional unresolved_calls", () => {
    expect(functionDossierSchema.parse(recordedEntryDossier)).toEqual(
      recordedEntryDossier,
    );
    expect(recordedEntryDossier).not.toHaveProperty("unresolved_calls");
    expect(recordedEntryDossier.native_api?.available).toBe(true);
    expect(recordedEntryDossier.native_value_flow?.available).toBe(true);
  });

  it("keeps an empty unresolved reference array schema-valid while requiring the fixture-specific site separately", () => {
    const reference = recordedEntryReferences();
    reference.unresolved_calls = [];
    expect(
      parseGhidraFunctionResult(
        "procedure_references",
        jsonValueSchema.parse(reference),
      ).ok,
    ).toBe(true);
  });

  it("reaches the exact unmeasured leaf request with the optional-field-absent dossier", async () => {
    const replay = await recordedDossierPrefix("none");
    expect(replay.failure).toBe(replay.sentinel);
    expect(replay.reached).toHaveLength(recordedPrefixRequests.length + 1);
    expect(replay.reached.at(-1)).toEqual({
      operation: "procedure_assembly",
      parameters: { procedure: "0x80010080" },
    });
  });

  it.each([
    [
      "empty reference sites",
      "procedure_references(0x80010000, outgoing) lacks required unresolved call site 0x80010034",
    ],
    [
      "missing reference sites",
      "procedure_references(0x80010000, outgoing) must expose an unresolved_calls array for required site 0x80010034",
    ],
    [
      "missing disclosure",
      "analyze_function(0x80010000) lacks unresolved computed/indirect flow disclosure about absent target/reference edges",
    ],
  ] as const)(
    "rejects %s at its intended contract assertion",
    async (mutation, diagnostic) => {
      const replay = await recordedDossierPrefix(mutation);
      expect(replay.failure).toMatchObject({
        name: "AssertionError",
        message: expect.stringContaining(diagnostic),
      });
      expect(replay.failure).not.toBeInstanceOf(TypeError);
      expect(replay.reached.at(-1)).toEqual({
        operation: "procedure_references",
        parameters: { procedure: "0x80010000", direction: "outgoing" },
      });
    },
  );
});
