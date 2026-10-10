//@category REA Verification
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import java.nio.file.*;

/** Observes the actual production preparation preScript after it returns. No adaptation. */
public class ReaPsxPreparationTransactionProbe extends GhidraScript {
    private final Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private JsonObject obj(Object... pairs) {
        JsonObject result = new JsonObject(); for (int i = 0; i < pairs.length; i += 2) result.add((String)pairs[i], gson.toJsonTree(pairs[i + 1])); return result;
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs(); Path output = args.length == 2 ? Path.of(args[1]) : null;
        JsonObject ownership = null;
        try {
            if (args.length != 2 || currentProgram == null || !isRunningHeadless()) throw new IllegalArgumentException("Expected headless descriptorPath outputPath");
            ownership = obj("policy", "exclusive-top-level-v1", "script_transaction_observed", currentProgram.getCurrentTransactionInfo() != null,
                "wrapper_released", false, "setup_transaction_performed", false, "setup_finalized", true,
                "before_adaptation_active", null, "after_adaptation_active", null, "outcome", null);
            try { end(true); }
            catch (Exception failure) { throw ReaGhidraPsxProvenance.failureAt(currentProgram, "observer-wrapper-release", failure); }
            ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "observer-wrapper-release");
            ownership.addProperty("wrapper_released", true); ownership.addProperty("before_adaptation_active", false);
            Path descriptorPath = Path.of(args[0]); JsonObject descriptor = ReaGhidraPsxImport.readDescriptor(descriptorPath);
            JsonObject declarations = ReaGhidraPsxImport.verifiedDeclarations(descriptor, monitor);
            if (!declarations.get("payload_address").getAsString().equals("0x80010000") || declarations.get("payload_bytes").getAsLong() != 2048 || declarations.get("file_bytes").getAsLong() > 4112) throw new IllegalArgumentException("Observer accepts only generated synthetic profile");
            JsonObject agreement = ReaGhidraPsxImport.agreement(descriptorPath, descriptor, currentProgram, monitor);
            JsonObject before = agreement.getAsJsonObject("before"), after = agreement.getAsJsonObject("after"), provenance = before.getAsJsonObject("provenance");
            if (!provenance.get("status").getAsString().equals("applied")) throw new IllegalStateException("Production preparation did not apply source provenance");
            JsonObject metadata = provenance.getAsJsonObject("metadata_preservation");
            String afterHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, monitor);
            if (!afterHash.equals(metadata.get("adapted_state_sha256").getAsString())) throw new IllegalStateException("Production preparation's returned state differs from retained adaptation");
            JsonObject image = ReaGhidraPsxProvenance.observe(currentProgram, monitor);
            image.add("psx", ReaGhidraPsxProvenance.psxObservation(currentProgram, provenance, declarations, monitor));
            ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "production-wrapper-final-observation");
            ownership.addProperty("after_adaptation_active", false); ownership.addProperty("outcome", "committed");
            String beforeHash = metadata.get("original_state_sha256").getAsString();
            JsonObject report = obj("schema_version", 2, "mode", "production-wrapper", "ok", true, "evidence_complete", true, "transaction_ownership", ownership,
                "before", before, "after", after, "load_image", image,
                "preservation", obj("operational_state_matched", metadata.get("operational_state_matched"), "before_sha256", beforeHash, "after_sha256", afterHash,
                    "journal_disposition", metadata.getAsJsonObject("label_history").get("program_journal")),
                "rollback", obj("exercised", false, "matched", true, "before_sha256", beforeHash, "after_sha256", beforeHash));
            Files.writeString(output, gson.toJson(report), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            println("REA_PSX_PROVENANCE_PROBE_COMPLETE production-wrapper");
        } catch (Exception failure) {
            if (output != null) try {
                Files.writeString(output, gson.toJson(obj("schema_version", 2, "mode", "production-wrapper", "ok", false, "evidence_complete", false,
                    "transaction_ownership", ownership, "failure", ReaGhidraPsxProvenance.failureDetails(failure, "production-wrapper-observation"))), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            } catch (Exception reporting) { failure.addSuppressed(reporting); }
            throw failure;
        }
    }
}
