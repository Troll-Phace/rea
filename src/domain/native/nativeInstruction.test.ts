import { describe, expect, it } from "vitest";
import { nativeInstructionSchema } from "./nativeInstruction.js";

const instruction = () => ({
  address: "code:100",
  status: "decoded",
  procedure: null,
  architecture: "fixture",
  mode: "default",
  bytes: "00",
  length: 1,
  mnemonic: "fixture",
  raw_disassembly: "fixture",
  operands: [],
  flow: {
    kind: "fallthrough",
    conditional: false,
    computed: false,
    direct_destinations: [],
  },
  references: [],
  limitations: [],
});

describe("optional neutral delay-slot evidence", () => {
  it("retains older captures without inventing slot observations", () => {
    expect(nativeInstructionSchema.parse(instruction())).not.toHaveProperty(
      "delay_slots",
    );
  });

  it.each([
    { is_in_delay_slot: null, depth: null, addresses: null },
    { is_in_delay_slot: false, depth: 0, addresses: [] },
    { is_in_delay_slot: true, depth: 0, addresses: [] },
    { is_in_delay_slot: null, depth: 2, addresses: null },
    { is_in_delay_slot: false, depth: 2, addresses: ["code:101", "code:102"] },
  ])("preserves independent membership, depth and coverage %j", (slots) => {
    expect(
      nativeInstructionSchema.parse({ ...instruction(), delay_slots: slots })
        .delay_slots,
    ).toEqual(slots);
  });

  it.each([
    { is_in_delay_slot: false, depth: -1, addresses: null },
    { is_in_delay_slot: false, depth: 0.5, addresses: null },
    {
      is_in_delay_slot: false,
      depth: Number.MAX_SAFE_INTEGER + 1,
      addresses: null,
    },
    { is_in_delay_slot: false, depth: null, addresses: [] },
    { is_in_delay_slot: false, depth: 0, addresses: ["code:101"] },
    { is_in_delay_slot: false, depth: 2, addresses: ["code:101"] },
    { is_in_delay_slot: false, depth: 2, addresses: ["code:101", "code:101"] },
    { is_in_delay_slot: false, depth: 0, addresses: [], inferred_order: true },
    { depth: 0, addresses: [] },
  ])("rejects contradictory or malformed complete coverage %j", (slots) => {
    expect(
      nativeInstructionSchema.safeParse({
        ...instruction(),
        delay_slots: slots,
      }).success,
    ).toBe(false);
  });

  it.each([
    "not-instruction-boundary",
    "data",
    "undecodable",
    "outside-memory",
  ])(
    "retains all unknowns for %s and rejects asserted slot facts",
    (status) => {
      const value = {
        ...instruction(),
        status,
        bytes: null,
        length: null,
        mnemonic: null,
        raw_disassembly: null,
        flow: { ...instruction().flow, kind: "unavailable" },
      };
      const slots = { is_in_delay_slot: null, depth: null, addresses: null };
      expect(
        nativeInstructionSchema.parse({ ...value, delay_slots: slots })
          .delay_slots,
      ).toEqual(slots);
      expect(
        nativeInstructionSchema.safeParse({
          ...value,
          delay_slots: { is_in_delay_slot: false, depth: 0, addresses: [] },
        }).success,
      ).toBe(false);
    },
  );
});
