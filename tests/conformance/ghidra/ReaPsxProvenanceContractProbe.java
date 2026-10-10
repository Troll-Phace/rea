//@category REA Verification
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Test-only adaptation/rollback probe of generated synthetic disposable imports. Never packaged. */
public class ReaPsxProvenanceContractProbe extends GhidraScript {
    private final Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private JsonObject ownership;
    private byte[] faultRecordBytes;
    private JsonObject faultObservation;
    private boolean faultFired;
    private JsonObject obj(Object... pairs) {
        JsonObject result = new JsonObject(); for (int i = 0; i < pairs.length; i += 2) result.add((String)pairs[i], gson.toJsonTree(pairs[i + 1])); return result;
    }
    private String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private void write(Path path, JsonObject report, String mode) throws Exception {
        report.addProperty("ok", true); report.addProperty("evidence_complete", true);
        report.add("transaction_ownership", ownership);
        Files.writeString(path, gson.toJson(report), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        println("REA_PSX_PROVENANCE_PROBE_COMPLETE " + mode);
    }
    @Override protected void run() throws Exception {
        Path output = getScriptArgs().length == 3 ? Path.of(getScriptArgs()[1]) : null;
        try { executeProbe(); }
        catch (Exception failure) {
            if (output != null) try {
                Files.writeString(output, gson.toJson(obj("schema_version", 2, "mode", getScriptArgs()[2], "ok", false, "evidence_complete", false,
                    "transaction_ownership", ownership, "failure", ReaGhidraPsxProvenance.failureDetails(failure, "probe-reporting"),
                    "fault", obj("fired_after_rebind", faultFired, "observation_at_fault", faultObservation),
                    "original_record_before", faultRecordBytes == null ? null : obj("bytes_base64", Base64.getEncoder().encodeToString(faultRecordBytes), "sha256", hash(faultRecordBytes)))), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            } catch (Exception reporting) { failure.addSuppressed(reporting); }
            throw failure;
        }
    }
    private void executeProbe() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || currentProgram == null || !isRunningHeadless() || !Set.of("baseline", "split", "journal-multiplicity", "unsupported-data", "rollback", "original-record-tamper", "active-transaction").contains(args[2])) throw new IllegalArgumentException("Expected headless descriptorPath outputPath baseline|split|journal-multiplicity|unsupported-data|rollback|original-record-tamper|active-transaction");
        Path descriptorPath = Path.of(args[0]), outputPath = Path.of(args[1]); String mode = args[2];
        boolean setup = mode.equals("split") || mode.equals("unsupported-data") || mode.equals("journal-multiplicity");
        ownership = obj("policy", "exclusive-top-level-v1", "script_transaction_observed", currentProgram.getCurrentTransactionInfo() != null,
            "wrapper_released", false, "setup_transaction_performed", setup, "setup_finalized", !setup,
            "before_adaptation_active", null, "after_adaptation_active", null, "outcome", null);
        try { end(true); }
        catch (Exception failure) { throw ReaGhidraPsxProvenance.failureAt(currentProgram, "wrapper-release", failure); }
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "wrapper-release"); ownership.addProperty("wrapper_released", true);
        JsonObject descriptor = ReaGhidraPsxImport.readDescriptor(descriptorPath), commitment = ReaGhidraPsxImport.validateCommitment(descriptor);
        JsonObject declarations = ReaGhidraPsxImport.verifiedDeclarations(descriptor, monitor);
        // The source-owned lane's deliberately finite synthetic shape. No AC3/game import is admitted.
        if (!declarations.get("payload_address").getAsString().equals("0x80010000") || !declarations.get("initial_pc").getAsString().equals("0x80010000") || declarations.get("payload_bytes").getAsLong() != 2048 || declarations.get("file_bytes").getAsLong() > 4112) throw new IllegalArgumentException("Probe accepts only the generated 2 KiB synthetic payload profile");
        Address entry = toAddr(0x80010000L);
        if (setup) {
            int transaction = currentProgram.startTransaction("Synthetic PSX provenance probe setup"); boolean commit = false;
            Exception setupFailure = null;
            try {
                if (mode.equals("split")) {
                    MemoryBlock original = currentProgram.getMemory().getBlock(entry);
                    currentProgram.getMemory().split(original, entry.addNoWrap(1024));
                    currentProgram.getMemory().getBlock(entry.addNoWrap(1024)).setName("synthetic_second_payload");
                } else if (mode.equals("unsupported-data")) currentProgram.getListing().createData(entry.addNoWrap(1024), new ByteDataType());
                else {
                    Symbol affected = currentProgram.getSymbolTable().createLabel(entry.addNoWrap(1024), "rea_probe_history", SourceType.USER_DEFINED);
                    affected.setName("rea_probe_history_renamed", SourceType.USER_DEFINED);
                    affected.setName("rea_probe_history", SourceType.USER_DEFINED);
                    currentProgram.getSymbolTable().createLabel(toAddr(0x80011010L), "rea_probe_outside_history", SourceType.USER_DEFINED);
                }
                commit = true;
            } catch (Exception failure) { setupFailure = failure; }
            boolean finalized = false;
            try { finalized = currentProgram.endTransaction(transaction, commit); }
            catch (Exception close) { if (setupFailure == null) setupFailure = close; else setupFailure.addSuppressed(close); }
            try { ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "setup-finalization"); }
            catch (Exception close) { if (setupFailure == null) setupFailure = close; else setupFailure.addSuppressed(close); }
            if (setupFailure != null) throw ReaGhidraPsxProvenance.failureAt(currentProgram, "probe-setup", setupFailure);
            if (!commit || !finalized) throw ReaGhidraPsxProvenance.failureAt(currentProgram, "probe-setup", new IllegalStateException("Synthetic setup did not commit finally"));
            ownership.addProperty("setup_finalized", true);
        }
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "probe-baseline");
        String beforeHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, monitor);
        JsonObject original = ReaGhidraPsxProvenance.observe(currentProgram, monitor);
        JsonArray originalJournal = ReaGhidraPsxProvenance.labelHistory(currentProgram, monitor);
        JsonObject rollback = obj("exercised", false, "matched", true, "before_sha256", beforeHash, "after_sha256", beforeHash);
        ownership.addProperty("before_adaptation_active", currentProgram.getCurrentTransactionInfo() != null);
        if (mode.equals("active-transaction")) {
            int transaction = currentProgram.startTransaction("Synthetic caller-owned refusal transaction");
            ownership.addProperty("before_adaptation_active", true); Exception expected = null, refusalFailure = null; boolean afterActive = false; boolean closed = false;
            try {
                try { ReaGhidraPsxProvenance.adapt(currentProgram, descriptorPath, descriptor, declarations, monitor); }
                catch (ReaGhidraPsxProvenance.PreparationException failure) {
                    if (!failure.stage.equals("pre-entry-ownership")) throw failure; expected = failure;
                }
                afterActive = currentProgram.getCurrentTransactionInfo() != null;
            } catch (Exception failure) { refusalFailure = failure; }
            try { closed = currentProgram.endTransaction(transaction, true); }
            catch (Exception close) {
                if (refusalFailure == null) refusalFailure = close; else refusalFailure.addSuppressed(close);
                if (expected != null) refusalFailure.addSuppressed(expected);
            }
            try { ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "active-refusal-owned-close"); }
            catch (Exception close) { if (refusalFailure == null) refusalFailure = close; else refusalFailure.addSuppressed(close); }
            if (refusalFailure != null) throw ReaGhidraPsxProvenance.failureAt(currentProgram, "active-refusal-owned-close", refusalFailure);
            String afterHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, monitor);
            JsonObject afterObservation = ReaGhidraPsxProvenance.observe(currentProgram, monitor); JsonArray afterJournal = ReaGhidraPsxProvenance.labelHistory(currentProgram, monitor);
            boolean originalPresent = Files.exists(ReaGhidraPsxImport.originalRecordPath(descriptorPath), LinkOption.NOFOLLOW_LINKS);
            boolean beforePresent = Files.exists(descriptorPath.resolveSibling("psx-import-before.json"), LinkOption.NOFOLLOW_LINKS);
            if (expected == null || !afterActive || !closed || originalPresent || beforePresent || !beforeHash.equals(afterHash) || !original.equals(afterObservation)) throw new IllegalStateException("Active-owner refusal did not preserve original state without evidence publication");
            ownership.addProperty("after_adaptation_active", afterActive); ownership.addProperty("outcome", "rejected-active-transaction");
            write(outputPath, obj("schema_version", 2, "mode", mode, "before", null, "after", null, "load_image", null,
                "preservation", obj("operational_state_matched", true, "before_sha256", beforeHash, "after_sha256", afterHash, "journal_disposition", "unchanged"), "rollback", rollback,
                "failure", obj("expected", true, "kind", "active-transaction", "name", expected.getClass().getName(), "message", expected.getMessage(), "marker_emitted", false, "before_record_present", false),
                "active_transaction", obj("rejected", true, "original_record_present", originalPresent, "before_record_present", beforePresent, "owned_close_return", closed, "final_active", currentProgram.getCurrentTransactionInfo() != null,
                    "before_sha256", beforeHash, "after_sha256", afterHash, "observations_before", original, "observations_after", afterObservation, "label_history_before", originalJournal, "label_history_after", afterJournal)), mode);
            return;
        }
        if (mode.equals("rollback") || mode.equals("original-record-tamper")) {
            final byte[][] originalRecordBytes = {null}; final boolean[] fired = {false}; final JsonObject[] observationAtFault = {null};
            TaskMonitor fault = new TaskMonitorAdapter() {
                @Override public void checkCancelled() throws CancelledException {
                    if (!fired[0]) {
                        MemoryBlock block = currentProgram.getMemory().getBlock(entry);
                        if (block != null && block.getSourceInfos().stream().anyMatch(source -> source.getFileBytes().isPresent())) {
                            fired[0] = true;
                            faultFired = true;
                            try {
                                observationAtFault[0] = ReaGhidraPsxProvenance.observe(currentProgram, TaskMonitor.DUMMY);
                                faultObservation = observationAtFault[0];
                                Path fixed = ReaGhidraPsxImport.originalRecordPath(descriptorPath);
                                originalRecordBytes[0] = Files.readAllBytes(fixed);
                                faultRecordBytes = originalRecordBytes[0];
                                if (mode.equals("original-record-tamper")) Files.writeString(fixed, "{}\n", StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
                            } catch (Exception failure) { throw new IllegalStateException("Synthetic original-record fault failed", failure); }
                            if (mode.equals("rollback")) throw new CancelledException("Synthetic cancellation after payload block removal/rebind");
                        }
                    }
                    monitor.checkCancelled();
                }
            };
            Exception expected = null;
            try { ReaGhidraPsxProvenance.adapt(currentProgram, descriptorPath, descriptor, declarations, fault); }
            catch (Exception failure) {
                Exception primary = failure instanceof ReaGhidraPsxProvenance.PreparationException && failure.getCause() instanceof Exception cause ? cause : failure;
                if ((mode.equals("rollback") && primary instanceof CancelledException) || (mode.equals("original-record-tamper") && primary instanceof ReaGhidraPsxProvenance.OriginalRecordException)) {
                    if (failure.getSuppressed().length != 0 || primary.getSuppressed().length != 0) throw failure;
                    expected = primary;
                }
                else throw failure;
            }
            if (expected == null || !fired[0] || originalRecordBytes[0] == null) throw new IllegalStateException("Controlled failure after actual payload rebind was not exercised");
            if (expected.getSuppressed().length != 0) throw expected;
            String rollbackHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, TaskMonitor.DUMMY);
            JsonObject restored = ReaGhidraPsxProvenance.observe(currentProgram, TaskMonitor.DUMMY);
            JsonArray restoredJournal = ReaGhidraPsxProvenance.labelHistory(currentProgram, TaskMonitor.DUMMY);
            boolean matched = beforeHash.equals(rollbackHash) && original.equals(restored);
            boolean beforeRecordPresent = Files.exists(descriptorPath.resolveSibling("psx-import-before.json"), LinkOption.NOFOLLOW_LINKS);
            if (!matched || beforeRecordPresent || !restored.getAsJsonArray("source_files").isEmpty()) throw new IllegalStateException("Failure did not roll back full original state/source before readiness");
            ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "probe-rollback-final-state");
            ownership.addProperty("after_adaptation_active", false); ownership.addProperty("outcome", "rolled-back");
            rollback = obj("exercised", true, "matched", true, "before_sha256", beforeHash, "after_sha256", rollbackHash, "original_observation_matched", true,
                "observations_before", original, "observations_after", restored, "label_history_before", originalJournal, "label_history_after", restoredJournal);
            write(outputPath, obj("schema_version", 2, "mode", mode, "before", null, "after", null, "load_image", null,
                "preservation", obj("operational_state_matched", true, "before_sha256", beforeHash, "after_sha256", rollbackHash, "journal_disposition", "unchanged"), "rollback", rollback,
                "failure", obj("expected", true, "kind", mode.equals("rollback") ? "cancelled" : "original-record-invalid", "name", expected.getClass().getName(), "message", expected.getMessage(), "marker_emitted", false, "before_record_present", beforeRecordPresent, "fired_after_rebind", fired[0], "observation_at_fault", observationAtFault[0]),
                "original_record_before", obj("bytes_base64", Base64.getEncoder().encodeToString(originalRecordBytes[0]), "sha256", hash(originalRecordBytes[0]))), mode);
            return;
        }
        String marker = ReaGhidraPsxImport.prepare(descriptorPath, currentProgram, monitor);
        JsonObject agreement = ReaGhidraPsxImport.agreement(descriptorPath, descriptor, currentProgram, monitor);
        JsonObject before = agreement.getAsJsonObject("before"), after = agreement.getAsJsonObject("after");
        JsonObject metadata = before.getAsJsonObject("provenance").getAsJsonObject("metadata_preservation");
        String afterHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, monitor);
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "probe-adapted-final-state");
        ownership.addProperty("after_adaptation_active", false); ownership.addProperty("outcome", before.getAsJsonObject("provenance").get("status").getAsString().equals("applied") ? "committed" : "unavailable");
        if (!beforeHash.equals(metadata.get("original_state_sha256").getAsString()) || !afterHash.equals(metadata.get("adapted_state_sha256").getAsString())) throw new IllegalStateException("Probe state fingerprints disagree with metadata observations");
        JsonObject image = ReaGhidraPsxProvenance.observe(currentProgram, monitor);
        image.add("psx", ReaGhidraPsxProvenance.psxObservation(currentProgram, before.getAsJsonObject("provenance"), declarations, monitor));
        write(outputPath, obj("schema_version", 2, "mode", mode, "before", before, "after", after, "load_image", image,
            "preservation", obj("operational_state_matched", metadata.get("operational_state_matched"), "before_sha256", beforeHash, "after_sha256", afterHash, "journal_disposition", metadata.getAsJsonObject("label_history").get("program_journal")), "rollback", rollback), mode);
        println(marker);
    }
}
