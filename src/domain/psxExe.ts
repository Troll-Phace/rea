import { err, ok, type Result } from "./result.js";

/** An unsigned, nonempty address interval declared by a PS-X EXE header. */
export interface PsxAddressExtent {
  readonly start: number;
  readonly size: number;
  readonly endInclusive: number;
}

/** Source declarations only; eligibility and provider support are separate. */
export interface PsxExeHeader {
  readonly headerBytes: 0x800;
  readonly fileBytes: number;
  readonly payloadFileOffset: 0x800;
  readonly payloadBytes: number;
  readonly trailingBytes: number;
  readonly initialPc: number;
  readonly initialGp: number;
  readonly payloadAddress: number;
  readonly payloadExtent: PsxAddressExtent | null;
  readonly declaredDataAddress: number;
  readonly declaredDataBytes: number;
  readonly fillAddress: number;
  readonly fillBytes: number;
  readonly fillExtent: PsxAddressExtent | null;
  readonly stackBase: number;
  readonly stackOffset: number;
  readonly initialSp: number | null;
}

export type PsxExeParseError = {
  readonly kind: "malformed";
  readonly code:
    | "signature"
    | "file_size"
    | "header_truncated"
    | "payload_truncated"
    | "payload_address_overflow"
    | "fill_address_overflow"
    | "stack_address_overflow";
  readonly reason: string;
};

export type PsxExePolicyReason = {
  readonly code: "empty_payload" | "unaligned_entry" | "entry_outside_payload";
  readonly reason: string;
};

export type PsxExePolicy =
  | { readonly status: "eligible" }
  | {
      readonly status: "unsupported";
      readonly reasons: readonly PsxExePolicyReason[];
    };

const signature = Buffer.from([0x50, 0x53, 0x2d, 0x58, 0x20, 0x45, 0x58, 0x45]);

/** Compare exact signature bytes without lossy text decoding. */
export const hasPsxExeSignature = (bytes: Buffer): boolean =>
  bytes.length >= signature.length &&
  bytes.subarray(0, signature.length).equals(signature);

/** Parse a fixed header against the actual file length, without reading payload. */
export const parsePsxExeHeader = (
  bytes: Buffer,
  fileSize = bytes.length,
): Result<PsxExeHeader, PsxExeParseError> => {
  const malformed = (code: PsxExeParseError["code"], reason: string) =>
    err({ kind: "malformed" as const, code, reason });
  if (!hasPsxExeSignature(bytes))
    return malformed("signature", "the exact PS-X EXE signature is missing");
  if (
    !Number.isSafeInteger(fileSize) ||
    fileSize < 0 ||
    fileSize < bytes.length
  )
    return malformed(
      "file_size",
      "file length must be a nonnegative safe integer at least as large as the supplied bytes",
    );
  if (bytes.length < 0x800 || fileSize < 0x800)
    return malformed(
      "header_truncated",
      "the fixed PS-X EXE header needs 2048 bytes",
    );
  const initialPc = bytes.readUInt32LE(0x10);
  const initialGp = bytes.readUInt32LE(0x14);
  const payloadAddress = bytes.readUInt32LE(0x18);
  const payloadBytes = bytes.readUInt32LE(0x1c);
  if (0x800 + payloadBytes > fileSize)
    return malformed(
      "payload_truncated",
      "the declared PS-X EXE payload extends beyond the file",
    );
  const extent = (start: number, size: number): PsxAddressExtent | null =>
    size === 0 ? null : { start, size, endInclusive: start + size - 1 };
  const payloadExtent = extent(payloadAddress, payloadBytes);
  if (payloadExtent !== null && payloadExtent.endInclusive > 0xffffffff)
    return malformed(
      "payload_address_overflow",
      "the declared payload address interval exceeds 0xffffffff",
    );
  const fillAddress = bytes.readUInt32LE(0x28);
  const fillBytes = bytes.readUInt32LE(0x2c);
  const fillExtent = extent(fillAddress, fillBytes);
  if (fillExtent !== null && fillExtent.endInclusive > 0xffffffff)
    return malformed(
      "fill_address_overflow",
      "the declared fill address interval exceeds 0xffffffff",
    );
  const stackBase = bytes.readUInt32LE(0x30);
  const stackOffset = bytes.readUInt32LE(0x34);
  const initialSp = stackBase === 0 ? null : stackBase + stackOffset;
  if (initialSp !== null && initialSp > 0xffffffff)
    return malformed(
      "stack_address_overflow",
      "the declared initial stack address exceeds 0xffffffff",
    );
  return ok({
    headerBytes: 0x800,
    fileBytes: fileSize,
    payloadFileOffset: 0x800,
    payloadBytes,
    trailingBytes: fileSize - 0x800 - payloadBytes,
    initialPc,
    initialGp,
    payloadAddress,
    payloadExtent,
    declaredDataAddress: bytes.readUInt32LE(0x20),
    declaredDataBytes: bytes.readUInt32LE(0x24),
    fillAddress,
    fillBytes,
    fillExtent,
    stackBase,
    stackOffset,
    initialSp,
  });
};

/** Evaluate initial admission policy without losing structurally valid facts. */
export const inspectPsxExePolicy = (header: PsxExeHeader): PsxExePolicy => {
  const reasons: PsxExePolicyReason[] = [];
  if (header.payloadBytes === 0)
    reasons.push({
      code: "empty_payload",
      reason: "the declared payload is empty",
    });
  if (header.initialPc % 4 !== 0)
    reasons.push({
      code: "unaligned_entry",
      reason: "the declared entry PC is not four-byte aligned",
    });
  if (
    header.payloadExtent !== null &&
    (header.initialPc < header.payloadExtent.start ||
      header.initialPc > header.payloadExtent.endInclusive)
  )
    reasons.push({
      code: "entry_outside_payload",
      reason: "the declared entry PC is outside the payload address interval",
    });
  return reasons.length === 0
    ? { status: "eligible" }
    : { status: "unsupported", reasons };
};
