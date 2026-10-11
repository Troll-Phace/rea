//@category REA Verification
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
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
    private static final Set<String> BOOKMARK_MODES = Set.of("bookmarks", "bookmarks-split", "bookmarks-cancel-parking", "bookmarks-cancel-rebind", "bookmarks-cancel-return", "bookmarks-unsupported-data");
    private boolean bookmarkMode(String mode) { return BOOKMARK_MODES.contains(mode); }
    private JsonArray ordered(List<JsonObject> rows) { rows.sort(Comparator.comparing(gson::toJson)); JsonArray result = new JsonArray(); rows.forEach(result::add); return result; }
    private String bookmarkAddress(Address at) { return "0x" + Long.toUnsignedString(at.getOffset(), 16); }
    private JsonObject bookmarkState() {
        List<JsonObject> rows = new ArrayList<>(), types = new ArrayList<>(); BookmarkManager manager = currentProgram.getBookmarkManager();
        var iterator = manager.getBookmarksIterator();
        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next(); rows.add(obj("id", Long.toUnsignedString(bookmark.getId()), "address", bookmarkAddress(bookmark.getAddress()),
                "address_space", bookmark.getAddress().getAddressSpace().getName(), "type_id", bookmark.getType().getTypeId(), "type", bookmark.getTypeString(), "category", bookmark.getCategory(), "comment", bookmark.getComment()));
        }
        for (BookmarkType type : manager.getBookmarkTypes()) {
            if (type.getIcon() != null) throw new IllegalStateException("Opaque bookmark icon outside representable native probe state");
            types.add(obj("id", type.getTypeId(), "name", type.getTypeString(), "defined", manager.isDefinedType(type.getTypeString()), "has_bookmarks", type.hasBookmarks(),
                "priority", type.getMarkerPriority(), "color_argb", type.getMarkerColor() == null ? null : type.getMarkerColor().getRGB(), "icon", null));
        }
        return obj("records", ordered(rows), "types", ordered(types));
    }
    private void seedBookmarks(Address entry) throws Exception {
        BookmarkManager manager = currentProgram.getBookmarkManager();
        manager.setBookmark(entry, BookmarkType.NOTE, "rea_probe_first", "original first 雪");
        manager.setBookmark(entry, BookmarkType.NOTE, "rea_probe_second", "distinct category");
        manager.setBookmark(entry, BookmarkType.ERROR, "rea_probe_first", "distinct type");
        manager.setBookmark(entry.addNoWrap(2047), BookmarkType.WARNING, "rea_probe_last", "original last");
        manager.setBookmark(entry.addNoWrap(1024), BookmarkType.INFO, "rea_probe_middle", "split boundary");
        manager.setBookmark(entry.subtract(1), BookmarkType.NOTE, "rea_probe_outside_before", "unaffected preceding address");
        manager.setBookmark(entry.addNoWrap(2048), BookmarkType.NOTE, "rea_probe_outside_after", "unaffected succeeding address");
    }
    private JsonObject completeState(Address entry) throws Exception {
        // Test-only capture readback supplements independent identity/type rows.
        var capture = ReaGhidraPsxProvenance.class.getDeclaredMethod("capture", Program.class, AddressSet.class, TaskMonitor.class);
        capture.setAccessible(true); Object state = capture.invoke(null, currentProgram, new AddressSet(entry, entry.addNoWrap(2047)), TaskMonitor.DUMMY);
        var manifest = state.getClass().getDeclaredField("manifest"); manifest.setAccessible(true); return ((JsonObject)manifest.get(state)).deepCopy();
    }
    private JsonObject operationalState(JsonObject state) { JsonObject copy = state.deepCopy(); copy.remove("label_history"); return copy; }
    private boolean payloadLinked(Address entry) throws Exception {
        Address next = entry, end = entry.addNoWrap(2047);
        while (next.compareTo(end) <= 0) {
            MemoryBlock block = currentProgram.getMemory().getBlock(next);
            if (block == null || !block.getStart().equals(next) || block.getEnd().compareTo(end) > 0 || block.getSourceInfos().size() != 1) return false;
            var source = block.getSourceInfos().get(0);
            if (source.getFileBytes().isEmpty() || source.getFileBytesOffset() != 2048 + next.subtract(entry)) return false;
            if (block.getEnd().equals(end)) return true;
            next = block.getEnd().addNoWrap(1);
        }
        return false;
    }
    private boolean parkedBookmarks(JsonObject before, JsonObject current) {
        if (!before.get("types").equals(current.get("types")) || before.getAsJsonArray("records").size() != current.getAsJsonArray("records").size()) return false;
        Map<String, JsonObject> rows = new HashMap<>(); for (JsonElement value : current.getAsJsonArray("records")) { JsonObject row = value.getAsJsonObject(); if (rows.put(row.get("id").getAsString(), row) != null) return false; }
        Long delta = null; boolean moved = false;
        for (JsonElement value : before.getAsJsonArray("records")) {
            JsonObject original = value.getAsJsonObject(), actual = rows.get(original.get("id").getAsString()); if (actual == null) return false;
            long at = Long.parseUnsignedLong(original.get("address").getAsString().substring(2), 16);
            if (!original.get("address_space").getAsString().equals(currentProgram.getAddressFactory().getDefaultAddressSpace().getName()) || at < 0x80010000L || at > 0x800107ffL) { if (!original.equals(actual)) return false; continue; }
            JsonObject expected = original.deepCopy(); expected.add("address", actual.get("address")); if (!expected.equals(actual)) return false;
            long parked = Long.parseUnsignedLong(actual.get("address").getAsString().substring(2), 16);
            if (parked >= 0x80010000L && parked <= 0x800107ffL) return false;
            long displacement = parked - at; if (delta != null && delta.longValue() != displacement) return false; delta = displacement; moved = true;
        }
        return moved;
    }
    private final class BookmarkRun extends TaskMonitorAdapter {
        final String mode; final Path descriptor; final Address entry; final JsonObject before, fullBefore; final JsonArray checkpoints = new JsonArray();
        final Set<String> observed = new HashSet<>(); byte[] originalRecord; boolean cancelled;
        BookmarkRun(String mode, Path descriptor, Address entry) throws Exception {
            this.mode = mode; this.descriptor = descriptor; this.entry = entry; before = bookmarkState(); fullBefore = completeState(entry);
        }
        @Override public void checkCancelled() throws CancelledException {
            try {
                Path fixed = ReaGhidraPsxImport.originalRecordPath(descriptor);
                if (originalRecord == null && Files.exists(fixed, LinkOption.NOFOLLOW_LINKS)) originalRecord = Files.readAllBytes(fixed);
                JsonObject current = bookmarkState(); boolean parked = parkedBookmarks(before, current), linked = payloadLinked(entry);
                String boundary = parked ? (linked ? "rebind" : "parking") : linked && before.equals(current) && observed.contains("rebind") ? "return" : null;
                if (boundary != null && observed.add(boundary)) {
                    if (currentProgram.getCurrentTransactionInfo() == null) throw new IllegalStateException("Observed bookmark mutation outside owned transaction");
                    JsonObject image = ReaGhidraPsxProvenance.observe(currentProgram, TaskMonitor.DUMMY);
                    checkpoints.add(obj("boundary", boundary, "bookmark_identity", current, "load_image", image, "transaction_active", true));
                    if (mode.equals("bookmarks-cancel-" + boundary)) {
                        cancelled = true; faultFired = true; faultObservation = image; faultRecordBytes = originalRecord;
                        throw new CancelledException("Controlled bookmark cancellation after " + boundary);
                    }
                }
            } catch (CancelledException failure) { throw failure; }
            catch (Exception failure) { throw new IllegalStateException("Independent bookmark production-boundary observation failed", failure); }
            monitor.checkCancelled();
        }
        JsonObject finish(boolean unchanged) throws Exception {
            JsonObject after = bookmarkState(), fullAfter = completeState(entry);
            if (!before.equals(after) || !(unchanged ? fullBefore.equals(fullAfter) : operationalState(fullBefore).equals(operationalState(fullAfter)))) throw new IllegalStateException("Production adaptation did not preserve complete bookmark identity/type/operational state");
            Path fixed = ReaGhidraPsxImport.originalRecordPath(descriptor); if (originalRecord == null) originalRecord = Files.readAllBytes(fixed);
            if (!Arrays.equals(originalRecord, Files.readAllBytes(fixed))) throw new IllegalStateException("Original evidence bytes changed during bookmark adaptation");
            return obj("schema_version", 1, "production_adaptation", true, "before", before, "after", after, "full_state_before", fullBefore, "full_state_after", fullAfter,
                "identity_and_type_matched", true, "checkpoints", checkpoints, "original_record_before", obj("bytes_base64", Base64.getEncoder().encodeToString(originalRecord), "sha256", hash(originalRecord)));
        }
    }
    private void bookmarkCancellation(Path output, Path descriptorPath, JsonObject descriptor, JsonObject declarations, Address entry,
        String mode, String beforeHash, JsonObject original, JsonArray journal, BookmarkRun bookmarks) throws Exception {
        Exception expected = null;
        try { ReaGhidraPsxProvenance.adapt(currentProgram, descriptorPath, descriptor, declarations, bookmarks); }
        catch (Exception failure) {
            Exception primary = failure instanceof ReaGhidraPsxProvenance.PreparationException && failure.getCause() instanceof Exception cause ? cause : failure;
            if (!(primary instanceof CancelledException) || !bookmarks.cancelled || failure.getSuppressed().length != 0 || primary.getSuppressed().length != 0) throw failure;
            expected = primary;
        }
        if (expected == null || faultRecordBytes == null) throw new IllegalStateException("Requested actual bookmark cancellation boundary was not exercised");
        String afterHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, TaskMonitor.DUMMY);
        JsonObject restored = ReaGhidraPsxProvenance.observe(currentProgram, TaskMonitor.DUMMY); JsonArray restoredJournal = ReaGhidraPsxProvenance.labelHistory(currentProgram, TaskMonitor.DUMMY);
        boolean beforeRecord = Files.exists(descriptorPath.resolveSibling("psx-import-before.json"), LinkOption.NOFOLLOW_LINKS);
        if (!beforeHash.equals(afterHash) || !original.equals(restored) || beforeRecord || !restored.getAsJsonArray("source_files").isEmpty()) throw new IllegalStateException("Bookmark cancellation did not finalize exact original state/provenance rollback");
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "bookmark-rollback-final-state");
        ownership.addProperty("after_adaptation_active", false); ownership.addProperty("outcome", "rolled-back");
        write(output, obj("schema_version", 2, "mode", mode, "before", null, "after", null, "load_image", null,
            "preservation", obj("operational_state_matched", true, "before_sha256", beforeHash, "after_sha256", afterHash, "journal_disposition", "unchanged"),
            "rollback", obj("exercised", true, "matched", true, "before_sha256", beforeHash, "after_sha256", afterHash, "original_observation_matched", true,
                "observations_before", original, "observations_after", restored, "label_history_before", journal, "label_history_after", restoredJournal),
            "failure", obj("expected", true, "kind", "cancelled", "name", expected.getClass().getName(), "message", expected.getMessage(), "marker_emitted", false, "before_record_present", beforeRecord,
                "fired_after_rebind", !mode.equals("bookmarks-cancel-parking"), "observation_at_fault", faultObservation), "bookmark_preservation", bookmarks.finish(true)), mode);
    }
    private void executeProbe() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || currentProgram == null || !isRunningHeadless() || !(Set.of("baseline", "split", "journal-multiplicity", "unsupported-data", "rollback", "original-record-tamper", "active-transaction").contains(args[2]) || bookmarkMode(args[2]))) throw new IllegalArgumentException("Expected headless descriptorPath outputPath baseline|split|journal-multiplicity|unsupported-data|rollback|original-record-tamper|active-transaction|bookmarks|bookmarks-split|bookmarks-cancel-parking|bookmarks-cancel-rebind|bookmarks-cancel-return|bookmarks-unsupported-data");
        Path descriptorPath = Path.of(args[0]), outputPath = Path.of(args[1]); String mode = args[2];
        boolean setup = mode.equals("split") || mode.equals("unsupported-data") || mode.equals("journal-multiplicity") || bookmarkMode(mode);
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
                if (mode.equals("split") || mode.equals("bookmarks-split")) {
                    MemoryBlock original = currentProgram.getMemory().getBlock(entry);
                    currentProgram.getMemory().split(original, entry.addNoWrap(1024));
                    currentProgram.getMemory().getBlock(entry.addNoWrap(1024)).setName("synthetic_second_payload");
                } else if (mode.equals("unsupported-data") || mode.equals("bookmarks-unsupported-data")) currentProgram.getListing().createData(entry.addNoWrap(1024), new ByteDataType());
                else if (mode.equals("journal-multiplicity")) {
                    Symbol affected = currentProgram.getSymbolTable().createLabel(entry.addNoWrap(1024), "rea_probe_history", SourceType.USER_DEFINED);
                    affected.setName("rea_probe_history_renamed", SourceType.USER_DEFINED);
                    affected.setName("rea_probe_history", SourceType.USER_DEFINED);
                    currentProgram.getSymbolTable().createLabel(toAddr(0x80011010L), "rea_probe_outside_history", SourceType.USER_DEFINED);
                }
                if (bookmarkMode(mode)) seedBookmarks(entry);
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
        BookmarkRun bookmarks = bookmarkMode(mode) ? new BookmarkRun(mode, descriptorPath, entry) : null;
        JsonObject original = ReaGhidraPsxProvenance.observe(currentProgram, monitor);
        JsonArray originalJournal = ReaGhidraPsxProvenance.labelHistory(currentProgram, monitor);
        JsonObject rollback = obj("exercised", false, "matched", true, "before_sha256", beforeHash, "after_sha256", beforeHash);
        ownership.addProperty("before_adaptation_active", currentProgram.getCurrentTransactionInfo() != null);
        if (mode.startsWith("bookmarks-cancel-")) {
            bookmarkCancellation(outputPath, descriptorPath, descriptor, declarations, entry, mode, beforeHash, original, originalJournal, bookmarks); return;
        }
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
        String marker = ReaGhidraPsxImport.prepare(descriptorPath, currentProgram, bookmarks == null ? monitor : bookmarks);
        JsonObject agreement = ReaGhidraPsxImport.agreement(descriptorPath, descriptor, currentProgram, monitor);
        JsonObject before = agreement.getAsJsonObject("before"), after = agreement.getAsJsonObject("after");
        JsonObject metadata = before.getAsJsonObject("provenance").getAsJsonObject("metadata_preservation");
        String afterHash = ReaGhidraPsxProvenance.stateDigest(currentProgram, declarations, monitor);
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "probe-adapted-final-state");
        ownership.addProperty("after_adaptation_active", false); ownership.addProperty("outcome", before.getAsJsonObject("provenance").get("status").getAsString().equals("applied") ? "committed" : "unavailable");
        if (!beforeHash.equals(metadata.get("original_state_sha256").getAsString()) || !afterHash.equals(metadata.get("adapted_state_sha256").getAsString())) throw new IllegalStateException("Probe state fingerprints disagree with metadata observations");
        JsonObject image = ReaGhidraPsxProvenance.observe(currentProgram, monitor);
        image.add("psx", ReaGhidraPsxProvenance.psxObservation(currentProgram, before.getAsJsonObject("provenance"), declarations, monitor));
        JsonObject report = obj("schema_version", 2, "mode", mode, "before", before, "after", after, "load_image", image,
            "preservation", obj("operational_state_matched", metadata.get("operational_state_matched"), "before_sha256", beforeHash, "after_sha256", afterHash, "journal_disposition", metadata.getAsJsonObject("label_history").get("program_journal")), "rollback", rollback);
        if (bookmarks != null) report.add("bookmark_preservation", bookmarks.finish(mode.equals("bookmarks-unsupported-data")));
        write(outputPath, report, mode);
        println(marker);
    }
}
