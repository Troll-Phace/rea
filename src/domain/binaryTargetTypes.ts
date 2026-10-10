/** Provider-neutral CPU families detected from supported executable headers. */
export type BinaryArchitecture = "x86" | "x86_64" | "arm" | "arm64" | "mips";

interface BinaryTargetIdentity {
  readonly path: string;
  readonly sourcePath?: string;
  /** Info.plist of the app bundle the target was resolved from. */
  readonly bundleInfoPlist?: string;
  readonly sha256: string;
}

type NonExecutableMetadata = {
  readonly architecture?: never;
  readonly availableArchitectures?: never;
  readonly executableRole?: never;
  readonly managed?: never;
};

type ExecutableTarget<Architecture extends BinaryArchitecture> =
  BinaryTargetIdentity & {
    readonly kind: "executable";
    readonly architecture: Architecture;
    readonly availableArchitectures: readonly Architecture[];
  };

/**
 * Canonical local target identity and provider-neutral file classification.
 * Each variant carries only metadata established for that exact file kind.
 */
export type BinaryTarget =
  | (ExecutableTarget<Exclude<BinaryArchitecture, "mips">> & {
      readonly format: "mach-o" | "elf" | "dos-mz" | "dos-com";
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget<"mips"> & {
      readonly format: "ps-x-exe";
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget<Exclude<BinaryArchitecture, "mips">> & {
      readonly format: "pe";
      /** Provider-neutral PE image role observed from COFF characteristics. */
      readonly executableRole:
        | "application"
        | "shared-library"
        | "non-executable";
      /** Whether the PE declares a non-empty CLI header data-directory entry. */
      readonly managed: boolean;
    })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "database";
        readonly format: "analysis-database";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "archive";
        readonly format:
          | "zip"
          | "ipa"
          | "apk"
          | "msix"
          | "appx"
          | "asar"
          | "dmg"
          | "pkg";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "artifact";
        readonly format: "plist" | "javascript" | "source-map";
      });
