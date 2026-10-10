import { z } from "zod";

/** Exact instruction location within the active analysis program. */
export const nativeInstructionInputSchema = z.strictObject({
  address: z.string().min(1),
  document: z.string().optional(),
});
const reference = z.strictObject({
  target_address: z.string(),
  type: z.string(),
  call: z.boolean(),
  jump: z.boolean(),
  indirect: z.boolean(),
  computed: z.boolean(),
  operand_index: z.number().int(),
});
const delaySlots = z
  .union([
    z.strictObject({
      is_in_delay_slot: z.boolean().nullable(),
      depth: z.null(),
      addresses: z.null(),
    }),
    z.strictObject({
      is_in_delay_slot: z.boolean().nullable(),
      depth: z.literal(0),
      addresses: z.array(z.string()).length(0).nullable(),
    }),
    z.strictObject({
      is_in_delay_slot: z.boolean().nullable(),
      depth: z.number().int().positive().safe(),
      addresses: z.array(z.string()).nullable(),
    }),
  ])
  .superRefine((value, context) => {
    if (value.addresses === null) return;
    if (
      value.addresses.length !== value.depth ||
      new Set(value.addresses).size !== value.addresses.length
    )
      context.addIssue({
        code: "custom",
        message:
          "Delay-slot addresses must be unique and cover the observed depth",
      });
  });
/** Provider-decoded facts for one instruction; operand tokens preserve their native ordering. */
export const nativeInstructionSchema = z
  .strictObject({
    address: z.string(),
    status: z.enum([
      "decoded",
      "not-instruction-boundary",
      "data",
      "undecodable",
      "outside-memory",
    ]),
    procedure: z.string().nullable(),
    architecture: z.string(),
    mode: z.string(),
    bytes: z.string().nullable(),
    length: z.number().int().positive().nullable(),
    mnemonic: z.string().nullable(),
    raw_disassembly: z.string().nullable(),
    operands: z.array(
      z.strictObject({
        index: z.number().int().nonnegative(),
        raw: z.string(),
        provider_type: z.number().int(),
        components: z.array(
          z.strictObject({
            kind: z.enum(["register", "immediate", "address", "unknown"]),
            text: z.string(),
            value: z.string().nullable(),
            bit_width: z.number().int().nonnegative().nullable(),
          }),
        ),
        memory_addressing: z.literal("unavailable"),
      }),
    ),
    flow: z.strictObject({
      kind: z.enum([
        "call",
        "jump",
        "return",
        "fallthrough",
        "terminal",
        "unavailable",
      ]),
      conditional: z.boolean(),
      computed: z.boolean(),
      direct_destinations: z.array(z.string()),
      classification_evidence: z
        .array(
          z.strictObject({
            source: z.string().min(1),
            value: z.string().min(1),
          }),
        )
        .optional()
        .describe(
          "Observed provider facts used to classify flow; older captures or other providers may omit them.",
        ),
    }),
    references: z.array(reference),
    delay_slots: delaySlots
      .optional()
      .describe(
        "Observed slot membership, owned depth and complete ordered addresses; null is unknown, zero depth and an empty list are observed absence. Older captures may omit this object.",
      ),
    limitations: z.array(z.string()),
  })
  .superRefine((value, context) => {
    if (
      value.status !== "decoded" &&
      value.delay_slots !== undefined &&
      (value.delay_slots.is_in_delay_slot !== null ||
        value.delay_slots.depth !== null ||
        value.delay_slots.addresses !== null)
    )
      context.addIssue({
        code: "custom",
        path: ["delay_slots"],
        message: "Nondecoded instructions cannot establish delay-slot facts",
      });
  });

/** Static target resolution preserves provider references as evidence, never runtime certainty. */
export const nativeCallTargetsSchema = z.strictObject({
  call_site: z.string(),
  procedure: z.string().nullable(),
  status: z.enum([
    "direct",
    "resolved-indirect",
    "ambiguous",
    "unresolved",
    "not-call",
    "unavailable",
  ]),
  mechanism: z.enum(["direct", "computed", "indirect", "unavailable"]),
  targets: z.array(
    z.strictObject({
      address: z.string(),
      procedure: z.string().nullable(),
      status: z.enum(["direct", "resolved-indirect", "candidate"]),
      basis: z.literal("provider-reference"),
      references: z.array(reference),
    }),
  ),
  limitations: z.array(z.string()),
});
