import type {
  AnalysisProfileResolution,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  AnalysisCancelledError,
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { type AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";

import { jsonValueSchema } from "../domain/jsonValue.js";
import {
  createGhidraPsxCommitment,
  inspectGhidraPsxLoader,
  inspectGhidraPsxPolicy,
  readGhidraPsxSource,
  type GhidraPsxInspectionHost,
} from "./GhidraPsxLoader.js";
import { GHIDRA_FUNCTION_OPERATIONS } from "./GhidraFunctionValues.js";

/** Resolve version-bound, deterministic semantics before Ghidra imports a target. */
export const resolveGhidraAnalysisProfile = async (
  target: BinaryTarget,
  identity: ProviderIdentity,
  installation: GhidraInstallationInspection,
  signal?: AbortSignal,
  psxHost?: GhidraPsxInspectionHost,
): Promise<Result<AnalysisProfileResolution, AnalysisError>> => {
  if (signal?.aborted === true)
    return Promise.resolve(err(new AnalysisCancelledError("open_binary")));
  if (target.kind !== "executable")
    return Promise.resolve(ok({ profile: null }));
  if (installation.status === "unavailable")
    return Promise.resolve(
      err(new ProviderAdapterError(identity.id, "resolve_analysis_profile")),
    );
  const provider = { ...identity, version: installation.providerVersion };
  if (target.format === "ps-x-exe") {
    try {
      if (
        !["darwin", "linux"].includes(installation.platform) ||
        target.architecture !== "mips"
      )
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            diagnostics: {
              psx_loader: {
                status: "incompatible",
                reason:
                  "PSX imports require macOS/Linux and PS-X EXE MIPS identity",
              },
            },
          }),
        );
      const header = await readGhidraPsxSource(
        target.path,
        target.sha256,
        signal,
      );
      const reasons = inspectGhidraPsxPolicy(header);
      if (reasons.length > 0)
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            diagnostics: {
              psx_import_policy: {
                policy: "psx-kseg0-2m-defaults-v1",
                reason: reasons.join("; "),
                declarations: jsonValueSchema.parse(header),
              },
            },
          }),
        );
      const inspected = await inspectGhidraPsxLoader(
        installation.installDir,
        installation.providerVersion,
        signal,
        psxHost,
      );
      if (inspected.status !== "available")
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            diagnostics: {
              psx_loader: {
                status: inspected.status,
                reason: inspected.reason,
                ...inspected.diagnostics,
              },
            },
          }),
        );
      const { source_snapshot_path: _transportPath, ...commitment } =
        createGhidraPsxCommitment(
          header,
          inspected.candidate,
          target.path,
          target.sha256,
        );
      return ok({
        profile: createAnalysisProfile(provider, {
          target_kind: target.kind,
          target_format: target.format,
          architecture: target.architecture,
          import_mode: "ephemeral-source-immutable",
          analyzer_preset: "ghidra-default",
          process_launch: "inspected-jvm-launch-support-v1",
          psx_import: jsonValueSchema.parse(commitment),
          psx_extension_manifest: jsonValueSchema.parse(
            inspected.candidate.extension_manifest,
          ),
          psx_asset_inventory: jsonValueSchema.parse(
            inspected.candidate.assets,
          ),
          psx_language_assets: jsonValueSchema.parse(
            inspected.candidate.language_assets,
          ),
          psx_analyzer_classes: [...inspected.candidate.analyzer_classes],
          psx_operation_scope: "inventory-observations-only-v1",
          startup_agreement: "psx-observed-import-v1",
          instruction_flow_evidence: "unavailable-pending-psx-semantics-v1",
          unavailable_function_operations: [...GHIDRA_FUNCTION_OPERATIONS],
          load_image_evidence:
            "unsupported-with-observations-no-source-backed-coverage-v1",
        }),
      });
    } catch (cause) {
      if (
        cause instanceof AnalysisCancelledError ||
        cause instanceof AnalysisArtifactChangedError ||
        cause instanceof AnalysisAccessDeniedError
      )
        return err(cause);
      return err(
        new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
          cause,
        }),
      );
    }
  }
  const dosMz = target.format === "dos-mz";
  const dosCom = target.format === "dos-com";
  const dos = dosMz || dosCom;
  return Promise.resolve(
    ok({
      profile: createAnalysisProfile(provider, {
        target_kind: target.kind,
        target_format: target.format,
        architecture: target.architecture ?? null,
        available_architectures: [
          ...(target.availableArchitectures ?? []),
        ].sort(),
        import_mode: "ephemeral-source-immutable",
        annotation_policy: "atomic-function-entry-metadata-v1",
        load_image_observations: "source-mappings-entry-context-v2",
        function_body_evidence: "complete-inclusive-ranges-v1",
        function_references: "complete-body-and-entry-reference-manager-v2",
        location_resolution: "explicit-address-exact-entry-symbol-first-v3",
        instruction_flow_evidence: "decoded-return-pcode-v1",
        process_launch:
          installation.platform === "win32"
            ? "official-headless-script-v1"
            : "inspected-jvm-launch-support-v1",
        ...(dos
          ? {
              load_image_evidence: dosCom
                ? "independent-com-mapping-context-v1"
                : "independent-mz-mapping-relocations-v1",
            }
          : {}),
        jump_table_evidence: "typed-case-default-blocks-v1",
        decompiler_jump_loads: true,
        loader: dosMz
          ? "MzLoader"
          : dosCom
            ? "BinaryLoader"
            : "auto-from-header",
        language_id: dos ? "x86:LE:16:Real Mode" : "auto-from-header",
        compiler_spec_id: dos ? "default" : "auto-default",
        ...(dos
          ? {
              load_segment: "0x1000",
              address_coordinates: "linear-byte-offset",
            }
          : {}),
        ...(dosCom
          ? {
              entry_offset: "0x100",
              register_context: {
                CS: "0x1000",
                DS: "0x1000",
                ES: "0x1000",
                SS: "0x1000",
              },
              entry_seed: "external-entry-and-function-before-analysis-v1",
            }
          : {}),
        analyzer_preset: "ghidra-default",
      }),
    }),
  );
};
