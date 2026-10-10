import { describe, expect, it } from "vitest";

import {
  hasPsxExeSignature,
  inspectPsxExePolicy,
  parsePsxExeHeader,
} from "./psxExe.js";

const fixture = (payloadBytes = 16): Buffer => {
  const bytes = Buffer.alloc(0x800 + payloadBytes);
  Buffer.from([0x50, 0x53, 0x2d, 0x58, 0x20, 0x45, 0x58, 0x45]).copy(bytes);
  bytes.writeUInt32LE(0x80120000, 0x10);
  bytes.writeUInt32LE(0x80120000, 0x18);
  bytes.writeUInt32LE(payloadBytes, 0x1c);
  return bytes;
};
const header = (bytes: Buffer, fileSize = bytes.length) => {
  const parsed = parsePsxExeHeader(bytes, fileSize);
  if (!parsed.ok) throw new Error(parsed.error.reason);
  return parsed.value;
};
const code = (bytes: Buffer, fileSize = bytes.length) => {
  const parsed = parsePsxExeHeader(bytes, fileSize);
  return parsed.ok ? null : parsed.error.code;
};

describe("PS-X EXE source declarations", () => {
  it("requires the exact eight bytes, including high bits", () => {
    expect(hasPsxExeSignature(fixture())).toBe(true);
    for (let index = 0; index < 8; index += 1) {
      for (const difference of [1, 0x80]) {
        const bytes = fixture();
        bytes[index] = (bytes[index] ?? 0) ^ difference;
        expect(hasPsxExeSignature(bytes)).toBe(false);
        expect(code(bytes)).toBe("signature");
      }
    }
    expect(code(fixture().subarray(0, 7))).toBe("signature");
  });
  it.each([8, 55, 2047])(
    "rejects a %i-byte exact-signature header",
    (length) => {
      expect(code(fixture().subarray(0, length))).toBe("header_truncated");
    },
  );
  it("preserves empty payloads structurally without inventing an extent", () => {
    const parsed = header(fixture(0));
    expect(parsed).toMatchObject({
      payloadBytes: 0,
      payloadExtent: null,
      fillExtent: null,
      initialSp: null,
    });
    expect(inspectPsxExePolicy(parsed)).toEqual({
      status: "unsupported",
      reasons: [
        { code: "empty_payload", reason: "the declared payload is empty" },
      ],
    });
  });
  it("distinguishes payload, trailing bytes and a truncated payload", () => {
    expect(header(fixture())).toMatchObject({
      headerBytes: 2048,
      payloadFileOffset: 2048,
      payloadBytes: 16,
      trailingBytes: 0,
    });
    expect(
      header(Buffer.concat([fixture(), Buffer.from([1, 2, 3])])).trailingBytes,
    ).toBe(3);
    expect(code(fixture().subarray(0, 0x80f))).toBe("payload_truncated");
  });
  it("validates a bounded prefix against the actual larger file", () => {
    const bytes = fixture(4096);
    expect(header(bytes.subarray(0, 4096), bytes.length)).toMatchObject({
      fileBytes: 6144,
      payloadBytes: 4096,
      trailingBytes: 0,
    });
    expect(code(bytes.subarray(0, 4096))).toBe("payload_truncated");
  });
  it.each([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 2047])(
    "rejects unsafe or inconsistent file length %s",
    (fileSize) => {
      expect(code(fixture(), fileSize)).toBe("file_size");
    },
  );
  it("retains high-bit PC, GP and raw data declarations without interpretation", () => {
    const bytes = fixture();
    bytes.writeUInt32LE(0xffffffff, 0x14);
    bytes.writeUInt32LE(0xfffffffe, 0x20);
    bytes.writeUInt32LE(0xffffffff, 0x24);
    expect(header(bytes)).toMatchObject({
      initialPc: 0x80120000,
      initialGp: 0xffffffff,
      payloadAddress: 0x80120000,
      declaredDataAddress: 0xfffffffe,
      declaredDataBytes: 0xffffffff,
    });
  });
  it("accepts the last unsigned payload byte and rejects one-byte wraparound", () => {
    const bytes = fixture();
    bytes.writeUInt32LE(0xfffffff0, 0x18);
    bytes.writeUInt32LE(0xfffffff0, 0x10);
    expect(header(bytes).payloadExtent).toEqual({
      start: 0xfffffff0,
      size: 16,
      endInclusive: 0xffffffff,
    });
    bytes.writeUInt32LE(0xfffffff1, 0x18);
    expect(code(bytes)).toBe("payload_address_overflow");
  });
  it("keeps zero fill declarations and checks nonzero fill intervals", () => {
    const bytes = fixture();
    bytes.writeUInt32LE(0xffffffff, 0x28);
    expect(header(bytes)).toMatchObject({
      fillAddress: 0xffffffff,
      fillExtent: null,
    });
    bytes.writeUInt32LE(1, 0x2c);
    expect(header(bytes).fillExtent).toEqual({
      start: 0xffffffff,
      size: 1,
      endInclusive: 0xffffffff,
    });
    bytes.writeUInt32LE(2, 0x2c);
    expect(code(bytes)).toBe("fill_address_overflow");
  });
  it("checks stack sums without assigning an SP when the base is zero", () => {
    const bytes = fixture();
    bytes.writeUInt32LE(0xffffffff, 0x34);
    expect(header(bytes)).toMatchObject({
      stackBase: 0,
      stackOffset: 0xffffffff,
      initialSp: null,
    });
    bytes.writeUInt32LE(0xfffffff0, 0x30);
    bytes.writeUInt32LE(15, 0x34);
    expect(header(bytes).initialSp).toBe(0xffffffff);
    bytes.writeUInt32LE(16, 0x34);
    expect(code(bytes)).toBe("stack_address_overflow");
  });
});

describe("PS-X EXE initial header policy", () => {
  it.each([
    [0x80120000, []],
    [0x8012000c, []],
    [0x80120010, ["entry_outside_payload"]],
    [0x8011fffc, ["entry_outside_payload"]],
    [0x80120001, ["unaligned_entry"]],
    [0x80120011, ["unaligned_entry", "entry_outside_payload"]],
  ] as const)("evaluates PC %s after structural parsing", (pc, expected) => {
    const bytes = fixture();
    bytes.writeUInt32LE(pc, 0x10);
    const parsed = header(bytes);
    expect(parsed.initialPc).toBe(pc);
    const policy = inspectPsxExePolicy(parsed);
    expect(
      policy.status === "eligible"
        ? []
        : policy.reasons.map((reason) => reason.code),
    ).toEqual(expected);
  });
  it("reports every applicable reason in stable order without redundant outside-empty reason", () => {
    const bytes = fixture(0);
    bytes.writeUInt32LE(1, 0x10);
    expect(inspectPsxExePolicy(header(bytes))).toMatchObject({
      status: "unsupported",
      reasons: [{ code: "empty_payload" }, { code: "unaligned_entry" }],
    });
  });
});
