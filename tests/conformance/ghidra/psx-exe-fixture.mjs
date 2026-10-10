/** Original synthetic PS-X EXE bytes; this builder does not use REA's parser. */
export function buildPsxExeFixture({ variant = "baseline" } = {}) {
  if (
    !["baseline", "declared-registers-fill", "trailing-bytes"].includes(variant)
  )
    throw new TypeError(`Unknown PSX fixture variant: ${variant}`);
  const declared = variant === "declared-registers-fill";
  const trailing = variant === "trailing-bytes";
  const bytes = Buffer.alloc(trailing ? 0x1010 : 0x1000);
  Buffer.from([0x50, 0x53, 0x2d, 0x58, 0x20, 0x45, 0x58, 0x45]).copy(bytes);
  const fields = {
    initialPc: 0x80010000,
    initialGp: declared ? 0x80010800 : 0,
    payloadAddress: 0x80010000,
    payloadBytes: 0x800,
    declaredDataAddress: 0,
    declaredDataBytes: 0,
    fillAddress: declared ? 0x80011000 : 0,
    fillBytes: declared ? 0x20 : 0,
    stackBase: declared ? 0x801fff00 : 0,
    stackOffset: declared ? 0x80 : 0,
  };
  Object.values(fields).forEach((value, index) =>
    bytes.writeUInt32LE(value, 0x10 + index * 4),
  );
  const codeWords = [
    [0x00, 0x27bdfff0],
    [0x04, 0xafbf000c],
    [0x08, 0x0c004010],
    [0x0c, 0x24040007],
    [0x10, 0x3c088001],
    [0x14, 0x25080100],
    [0x18, 0x91090000],
    [0x1c, 0x8fbf000c],
    [0x20, 0x27bd0010],
    [0x24, 0x03e00008],
    [0x28, 0],
    [0x40, 0x03e00008],
    [0x44, 0x24820001],
  ];
  for (const [offset, word] of codeWords)
    bytes.writeUInt32LE(word, 0x800 + offset);
  const data = "5245412d5053582d5031007f80feff55";
  Buffer.from(data, "hex").copy(bytes, 0x900);
  const trailingHex = trailing ? "50312d545241494cdeadbeef007f80ff" : "";
  Buffer.from(trailingHex, "hex").copy(bytes, 0x1000);
  return {
    bytes,
    expected: {
      variant,
      ...fields,
      headerBytes: 0x800,
      fileBytes: bytes.length,
      payloadFileOffset: 0x800,
      payloadFileEndExclusive: 0x1000,
      payloadEndInclusive: 0x800107ff,
      initialSp: declared ? 0x801fff80 : null,
      fillEndInclusive: declared ? 0x8001101f : null,
      trailingBytes: trailing ? 0x10 : 0,
      trailingHex,
      codeWords: codeWords.map(([offset, word]) => ({
        fileOffset: 0x800 + offset,
        address: 0x80010000 + offset,
        word,
      })),
      data: { fileOffset: 0x900, address: 0x80010100, hex: data },
    },
  };
}
