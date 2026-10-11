import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.bookmark.BookmarkDBManager;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.nio.channels.SeekableByteChannel;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;

/**
 * PSX-only preparation of REA's disposable database; never modifies source bytes.
 * Public API evidence (also checked in the installed 12.1.4 SoftwareModeling-src.zip):
 * https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/Memory.java
 * https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/ProgramContext.java
 * removeBlock deletes address metadata, requiring explicit capture/restoration:
 * https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/mem/MemoryMapDB.java
 * Sole transaction ownership/final completion follow the public DomainObject contract:
 * https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/DomainObject.java
 * This is deliberately not a general database copier. Unsupported affected state
 * is rejected before mutation; any attempted restoration discrepancy rolls back.
 */
public final class ReaGhidraPsxProvenance {
    public static final String METHOD = "rea-psx-filebytes-rebind-v2";
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private ReaGhidraPsxProvenance() {}
    private static JsonObject obj(Object... pairs) {
        JsonObject result = new JsonObject();
        for (int i = 0; i < pairs.length; i += 2) result.add((String)pairs[i], GSON.toJsonTree(pairs[i + 1]));
        return result;
    }
    /** A same-call diagnostic payload, never a process-global last-error cache. */
    public static final class PreparationException extends Exception {
        public final String stage;
        public final JsonObject diagnostics;
        PreparationException(String stage, Exception cause, JsonObject diagnostics) {
            super("PSX preparation failed at " + stage + ": " + cause.getMessage(), cause);
            this.stage = stage; this.diagnostics = diagnostics;
        }
    }
    public static JsonObject transactionDiagnostics(Program program) {
        var transaction = program.getCurrentTransactionInfo();
        return transaction == null ? obj("active", false, "id", null, "description", null, "status", null, "open_subtransactions", null) :
            obj("active", true, "id", Long.toString(transaction.getID()), "description", transaction.getDescription(),
                "status", transaction.getStatus().toString(), "open_subtransactions", transaction.getOpenSubTransactions());
    }
    public static void requireNoTransaction(Program program, String stage) throws PreparationException {
        try {
            if (program.getCurrentTransactionInfo() != null) throw new PreparationException(stage,
                new IllegalStateException("An existing Program transaction is not owned by PSX preparation"), obj("checkpoint", stage, "transaction", transactionDiagnostics(program)));
        } catch (PreparationException failure) { throw failure; }
        catch (Exception failure) { throw failed(program, stage, failure, null, null, null); }
    }
    public static PreparationException failureAt(Program program, String stage, Exception failure) {
        return failed(program, stage, failure, null, null, null);
    }
    private static JsonObject exceptionValue(Throwable failure) {
        JsonArray suppressed = new JsonArray(); for (Throwable item : failure.getSuppressed()) suppressed.add(exceptionValue(item));
        return obj("name", failure.getClass().getName(), "message", failure.getMessage(), "suppressed", suppressed,
            "cause", failure.getCause() == null ? null : exceptionValue(failure.getCause()));
    }
    public static JsonObject failureDetails(Exception failure, String fallbackStage) {
        PreparationException prepared = failure instanceof PreparationException value ? value : null;
        JsonObject result = exceptionValue(failure);
        result.addProperty("stage", prepared == null ? fallbackStage : prepared.stage);
        result.add("available_diagnostics", prepared == null ? obj("checkpoint", fallbackStage, "unavailable_reason", "Failure occurred outside adaptation diagnostics") : prepared.diagnostics);
        return result;
    }
    private static PreparationException failed(Program program, String stage, Exception cause, State originalState, AddressSet affected, JsonObject originalObservation) {
        JsonObject diagnostics = obj("checkpoint", stage, "transaction", null, "differing_manifest_categories", null,
            "before_sha256", originalState == null ? null : uncheckedManifestHash(originalState.manifest), "after_sha256", null,
            "label_history_before", originalState == null ? null : originalState.journal, "label_history_after", null,
            "source_observation_before", originalObservation == null ? null : sourceProjection(originalObservation), "source_observation_after", null);
        JsonObject unavailable = new JsonObject();
        if (originalState == null) unavailable.addProperty("original_manifest", "Original enumerated state is unavailable at this checkpoint");
        if (originalObservation == null) unavailable.addProperty("source_observation_before", "Original source observation is unavailable at this checkpoint");
        try { diagnostics.add("transaction", transactionDiagnostics(program)); } catch (Exception error) { unavailable.add("transaction", exceptionValue(error)); }
        if (originalState != null && affected != null) try {
            State current = capture(program, affected, TaskMonitor.DUMMY); JsonArray differences = new JsonArray();
            for (String key : new TreeSet<>(STATE_KEYS)) if (!Objects.equals(originalState.manifest.get(key), current.manifest.get(key))) differences.add(key);
            diagnostics.add("differing_manifest_categories", differences); diagnostics.addProperty("after_sha256", manifestHash(current.manifest));
            diagnostics.add("label_history_after", current.journal);
        } catch (Exception error) { unavailable.add("current_manifest", exceptionValue(error)); }
        else unavailable.addProperty("current_manifest", "Original enumerated state is unavailable at this checkpoint");
        try { diagnostics.add("source_observation_after", sourceProjection(observe(program, TaskMonitor.DUMMY))); }
        catch (Exception error) { unavailable.add("source_observation_after", exceptionValue(error)); }
        diagnostics.add("unavailable", unavailable); return new PreparationException(stage, cause, diagnostics);
    }
    private static String uncheckedManifestHash(JsonObject manifest) {
        try { return manifestHash(manifest); } catch (Exception failure) { throw new IllegalStateException("Enumerated-state hashing failed", failure); }
    }
    private static JsonObject sourceProjection(JsonObject observation) {
        return obj("source_files", observation.get("source_files"), "mappings", observation.get("mappings"));
    }
    public static String address(Program program, Address value) {
        String hex = "0x" + Long.toUnsignedString(value.getOffset(), 16);
        if (value.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) return hex;
        // Match the bridge's lossless encoded-space coordinate convention.
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getAddressSpace().getName().getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int c = Byte.toUnsignedInt(b);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '~') encoded.append((char)c);
            else encoded.append(String.format("%%%02X", c));
        }
        return encoded + ":" + hex;
    }
    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String hashFileBytes(FileBytes file, boolean modified, TaskMonitor monitor) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); byte[] chunk = new byte[65536];
        for (long at = 0; at < file.getSize();) {
            monitor.checkCancelled(); int count = (int)Math.min(chunk.length, file.getSize() - at);
            int read = modified ? file.getModifiedBytes(at, chunk, 0, count) : file.getOriginalBytes(at, chunk, 0, count);
            if (read != count) throw new IOException("Incomplete FileBytes read");
            hash.update(chunk, 0, read); at += read;
        }
        return HexFormat.of().formatHex(hash.digest());
    }
    private static String hashMemory(Program program, Address start, long length, TaskMonitor monitor) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); byte[] chunk = new byte[65536];
        for (long at = 0; at < length;) {
            monitor.checkCancelled(); int count = (int)Math.min(chunk.length, length - at);
            int read = program.getMemory().getBytes(start.addNoWrap(at), chunk, 0, count);
            if (read != count) throw new IOException("Incomplete memory read");
            hash.update(chunk, 0, read); at += read;
        }
        return HexFormat.of().formatHex(hash.digest());
    }
    /** Shared fresh API observation used by the bridge and the preparation record. */
    public static JsonObject observe(Program program, TaskMonitor monitor) throws Exception {
        JsonObject result = obj("executable_format", program.getExecutableFormat(), "language_id", program.getLanguageID().getIdAsString(),
            "compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().getIdAsString(), "image_base", address(program, program.getImageBase()),
            "default_address_space", program.getAddressFactory().getDefaultAddressSpace().getName());
        List<FileBytes> files = program.getMemory().getAllFileBytes(); JsonArray sources = new JsonArray(), mappings = new JsonArray();
        for (FileBytes file : files) sources.add(obj("name", file.getFilename(), "size", file.getSize(),
            "original_sha256", hashFileBytes(file, false, monitor), "modified_sha256", hashFileBytes(file, true, monitor)));
        for (MemoryBlock block : program.getMemory().getBlocks()) for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            monitor.checkCancelled(); FileBytes file = source.getFileBytes().orElse(null); int index = file == null ? -1 : files.indexOf(file);
            mappings.add(obj("block", block.getName(), "start", address(program, source.getMinAddress()), "end", address(program, source.getMaxAddress()),
                "address_space", source.getMinAddress().getAddressSpace().getName(), "initialized", block.isInitialized(), "loaded", block.isLoaded(),
                "overlay", block.isOverlay(), "length", source.getLength(), "source_file_index", index < 0 ? null : index,
                // An unbacked block's source offset is never header arithmetic.
                "file_offset", file == null || source.getFileBytesOffset() < 0 ? null : source.getFileBytesOffset(),
                "sha256", block.isInitialized() ? hashMemory(program, source.getMinAddress(), source.getLength(), monitor) : null));
        }
        result.add("source_files", sources); result.add("mappings", mappings); JsonArray relocations = new JsonArray();
        var relocationIterator = program.getRelocationTable().getRelocations();
        while (relocationIterator.hasNext()) {
            monitor.checkCancelled(); var relocation = relocationIterator.next(); Address at = relocation.getAddress(); byte[] original = relocation.getBytes();
            String memory = null;
            if (original != null && original.length > 0) {
                byte[] bytes = new byte[original.length]; if (program.getMemory().getBytes(at, bytes) == bytes.length) memory = HexFormat.of().formatHex(bytes);
            }
            relocations.add(obj("address", address(program, at), "segment", at instanceof SegmentedAddress s ? s.getSegment() : null,
                "offset", at instanceof SegmentedAddress s ? s.getSegmentOffset() : null, "status", relocation.getStatus().toString(), "type", relocation.getType(),
                "values", relocation.getValues() == null ? new long[0] : relocation.getValues(),
                "original_bytes_hex", original == null ? null : HexFormat.of().formatHex(original), "memory_bytes_hex", memory));
        }
        result.add("relocations", relocations); List<Address> entries = new ArrayList<>();
        var entryIterator = program.getSymbolTable().getExternalEntryPointIterator(); while (entryIterator.hasNext()) entries.add(entryIterator.next()); entries.sort(Address::compareTo);
        JsonArray points = new JsonArray(), contexts = new JsonArray(); boolean psx = program.getLanguageID().getIdAsString().equals("PSX:LE:32:default");
        for (Address entry : entries) {
            monitor.checkCancelled(); points.add(address(program, entry)); JsonArray registers = new JsonArray();
            for (String name : psx ? new String[]{"gp", "sp"} : new String[]{"CS", "DS", "ES", "SS"}) {
                Register register = program.getRegister(name); if (register == null && !psx) continue;
                var value = register == null ? null : program.getProgramContext().getValue(register, entry, false);
                registers.add(obj("name", name, "value_hex", value == null ? null : "0x" + value.toString(16)));
            }
            contexts.add(obj("address", address(program, entry), "registers", registers));
        }
        result.add("entry_points", points); result.add("entry_context", contexts); return result;
    }
    public static JsonObject psxObservation(Program program, JsonObject provenance, JsonObject declarations, TaskMonitor monitor) throws Exception {
        Address pc = program.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(declarations.get("initial_pc").getAsString().substring(2), 16));
        Instruction instruction = program.getListing().getInstructionAt(pc);
        String status = !program.getMemory().contains(pc) ? "unmapped" : instruction == null ? "not-instruction" : "instruction";
        return obj("schema_version", 2, "provenance", provenance.deepCopy(), "current_label_history", labelHistory(program, monitor), "entry_instruction", obj("address", address(program, pc), "status", status,
            "length", instruction == null ? null : instruction.getLength()));
    }
    private record BlockState(String name, Address start, long size, boolean read, boolean write, boolean execute, boolean vol, boolean artificial, String comment, String sourceName) {}
    private record FragmentState(String tree, String name, AddressSet addresses) {}
    private record ContextState(Address start, Address end, RegisterValue value) {}
    private record SymbolState(Address address, String name, SourceType source, SymbolType type, boolean primary) {}
    private record FunctionState(Address entry, String name, SourceType source, AddressSet body, int purge) {}
    private record ReferenceState(Address from, Address to, RefType type, SourceType source, int operand, boolean primary) {}
    private record BookmarkState(long id, Address address, long typeId, String type, String category, String comment) {}
    private static final class State {
        final List<BlockState> blocks = new ArrayList<>(); final List<ContextState> contexts = new ArrayList<>();
        final List<SymbolState> symbols = new ArrayList<>(); final List<FunctionState> functions = new ArrayList<>(); final List<ReferenceState> references = new ArrayList<>();
        final List<Address> entries = new ArrayList<>(); final AddressSet instructions = new AddressSet(), instructionStarts = new AddressSet();
        final List<FragmentState> fragments = new ArrayList<>();
        final List<BookmarkState> bookmarks = new ArrayList<>(); JsonArray bookmarkTypes;
        final Map<String, List<String>> treeOrders = new TreeMap<>();
        final JsonObject manifest = new JsonObject(); JsonArray journal; String unavailable;
        void refuse(String reason) { if (unavailable == null) unavailable = reason; }
    }
    private static JsonObject prototypeState(InstructionPrototype prototype) {
        JsonArray operands = new JsonArray();
        for (int operand = 0; operand < prototype.getNumOperands(); operand++) {
            Mask mask = prototype.getOperandValueMask(operand);
            operands.add(obj("index", operand, "value_mask", mask == null ? null : HexFormat.of().formatHex(mask.getBytes()), "separator", prototype.getSeparator(operand)));
        }
        Mask instructionMask = prototype.getInstructionMask();
        return obj("implementation", prototype.getClass().getName(), "language_id", prototype.getLanguage().getLanguageID().getIdAsString(), "length", prototype.getLength(),
            "instruction_mask", instructionMask == null ? null : HexFormat.of().formatHex(instructionMask.getBytes()), "operand_count", prototype.getNumOperands(), "operands", operands,
            "has_delay_slots", prototype.hasDelaySlots(), "delay_slot_bytes", prototype.getDelaySlotByteCount(), "in_delay_slot", prototype.isInDelaySlot(),
            "crossbuild_dependency", prototype.hasCrossBuildDependency(), "next2_dependency", prototype.hasNext2Dependency());
    }
    private static final Set<String> STATE_KEYS = Set.of("blocks", "context", "default_context", "default_disassembly_context", "symbols", "label_history", "functions", "instructions", "data", "references", "entries", "bookmarks", "comments", "property_maps", "trees", "source_maps", "equates", "relocations");
    public static JsonArray labelHistory(Program program, TaskMonitor monitor) throws Exception {
        JsonArray rows = new JsonArray(); var iterator = program.getSymbolTable().getLabelHistory();
        while (iterator.hasNext()) {
            monitor.checkCancelled(); LabelHistory item = iterator.next();
            if (item == null || item.getAddress() == null) throw new IllegalStateException("Incomplete label-history enumeration");
            java.util.Date date = item.getModificationDate();
            rows.add(obj("ordinal", rows.size(), "address", address(program, item.getAddress()), "label", item.getLabelString(), "action", item.getActionID(),
                "user", item.getUserName(), "modification_time_ms", date == null ? null : Long.toString(date.getTime())));
        }
        return rows;
    }
    private static JsonObject journalValue(JsonObject row) { return obj("address", row.get("address"), "label", row.get("label"), "action", row.get("action").getAsInt(), "user", row.get("user"), "modification_time_ms", row.get("modification_time_ms")); }
    private static JsonArray journalMultiset(JsonArray rows) { List<JsonObject> values = new ArrayList<>(); for (JsonElement row : rows) values.add(journalValue(row.getAsJsonObject())); return ordered(values); }
    private record JournalDelta(JsonArray removed, JsonArray added) {}
    private static JournalDelta journalDelta(JsonArray before, JsonArray after) {
        boolean[] matched = new boolean[after.size()]; JsonArray removed = new JsonArray(), added = new JsonArray();
        Map<String, ArrayDeque<Integer>> candidates = new HashMap<>();
        for (int next = 0; next < after.size(); next++) candidates.computeIfAbsent(GSON.toJson(journalValue(after.get(next).getAsJsonObject())), ignored -> new ArrayDeque<>()).add(next);
        for (int old = 0; old < before.size(); old++) {
            ArrayDeque<Integer> available = candidates.get(GSON.toJson(journalValue(before.get(old).getAsJsonObject())));
            if (available == null || available.isEmpty()) removed.add(old); else matched[available.removeFirst()] = true;
        }
        for (int next = 0; next < after.size(); next++) if (!matched[next]) added.add(next);
        return new JournalDelta(removed, added);
    }
    private static JsonObject operational(JsonObject manifest) {
        if (!manifest.keySet().equals(STATE_KEYS)) throw new IllegalStateException("Unexpected or missing preservation category");
        JsonObject result = manifest.deepCopy(); result.remove("label_history"); return result;
    }
    private static String manifestHash(JsonObject manifest) throws Exception { return digest(GSON.toJson(manifest).getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
    private static JsonArray outsideJournal(Program program, JsonArray journal, AddressSet affected) {
        JsonArray result = new JsonArray(); for (JsonElement element : journal) {
            JsonObject row = element.getAsJsonObject(); Address at = parseProviderAddress(program, row.get("address").getAsString());
            if (!affected.contains(at)) result.add(row.deepCopy());
        }
        return journalMultiset(result);
    }
    private static Address parseProviderAddress(Program program, String value) {
        // Journal coordinates originate at the single format-aware API boundary above.
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            String prefix = address(program, space.getMinAddress()); prefix = prefix.substring(0, prefix.lastIndexOf("0x"));
            if (value.startsWith(prefix + "0x")) {
                try { return space.getAddress(Long.parseUnsignedLong(value.substring(prefix.length() + 2), 16)); }
                catch (RuntimeException invalid) { throw new IllegalArgumentException("Invalid journal address coordinate", invalid); }
            }
        }
        throw new IllegalArgumentException("Unrecognized journal address space");
    }
    @FunctionalInterface private interface Restoration { void run() throws Exception; }
    private static void restoreOperation(Program program, TaskMonitor monitor, String kind, AddressSet targets,
            List<SymbolState> symbols, List<JsonObject> generated, Restoration operation) throws Exception {
        JsonArray before = labelHistory(program, monitor); operation.run(); JsonArray after = labelHistory(program, monitor);
        JournalDelta delta = journalDelta(before, after);
        for (JsonElement ordinal : delta.added) {
            JsonObject row = after.get(ordinal.getAsInt()).getAsJsonObject(); Address at = parseProviderAddress(program, row.get("address").getAsString());
            boolean measured = symbols.stream().anyMatch(symbol -> symbol.address.equals(at) && Objects.equals(symbol.name, row.get("label").isJsonNull() ? null : row.get("label").getAsString()));
            generated.add(obj("operation", kind, "target_correlated", targets.contains(at), "measured_symbol", measured, "row", journalValue(row)));
        }
    }
    private static void validateJournalTransition(Program program, State original, State adapted, AddressSet affected, List<JsonObject> generated) {
        if (!outsideJournal(program, original.journal, affected).equals(outsideJournal(program, adapted.journal, affected))) throw new IllegalStateException("Label history outside payload changed");
        JournalDelta delta = journalDelta(original.journal, adapted.journal); boolean[] consumed = new boolean[generated.size()];
        for (JsonElement ordinal : delta.added) {
            JsonObject row = adapted.journal.get(ordinal.getAsInt()).getAsJsonObject(); Address at = parseProviderAddress(program, row.get("address").getAsString());
            if (!affected.contains(at) || row.get("action").getAsInt() != LabelHistory.ADD) throw new IllegalStateException("Unexpected surviving generated label-history action/address: " + row);
            boolean correlated = false;
            for (int index = 0; index < generated.size(); index++) {
                JsonObject event = generated.get(index);
                if (!consumed[index] && event.get("target_correlated").getAsBoolean() && event.get("measured_symbol").getAsBoolean() && event.get("row").equals(journalValue(row))) { consumed[index] = true; correlated = true; break; }
            }
            if (!correlated) throw new IllegalStateException("Generated label-history row was not observed at a measured restoration target: " + row + "; operations=" + generated);
        }
        for (JsonElement ordinal : delta.removed) if (!affected.contains(parseProviderAddress(program, original.journal.get(ordinal.getAsInt()).getAsJsonObject().get("address").getAsString()))) throw new IllegalStateException("Original outside-payload label history was lost");
    }
    private static JsonObject metadata(State original, State adapted, String originalRecordHash) throws Exception {
        JsonObject oldOperational = operational(original.manifest), newOperational = operational(adapted.manifest);
        if (!oldOperational.equals(newOperational)) throw new IllegalStateException("Rebind did not preserve enumerated operational state: " + different(oldOperational, newOperational));
        JournalDelta delta = journalDelta(original.journal, adapted.journal);
        return obj("comparison", "exact-enumerated-state-except-label-history-v1", "original_state_sha256", manifestHash(original.manifest), "adapted_state_sha256", manifestHash(adapted.manifest),
            "original_operational_state_sha256", manifestHash(oldOperational), "adapted_operational_state_sha256", manifestHash(newOperational), "operational_state_matched", true,
            "original_record_sha256", originalRecordHash, "label_history", obj("scope", "complete-program-label-history", "before", original.journal, "after", adapted.journal,
                "removed_before_ordinals", delta.removed, "added_after_ordinals", delta.added, "program_journal", delta.removed.isEmpty() && delta.added.isEmpty() ? "unchanged" : "recreated-at-payload-addresses"));
    }
    private static JsonArray ordered(List<JsonObject> rows) {
        rows.sort(Comparator.comparing(GSON::toJson)); JsonArray result = new JsonArray(); rows.forEach(result::add); return result;
    }
    private static JsonArray ranges(Program program, AddressSetView set) {
        JsonArray result = new JsonArray(); for (AddressRange range : set.getAddressRanges()) result.add(obj("start", address(program, range.getMinAddress()), "end", address(program, range.getMaxAddress()))); return result;
    }
    private static JsonArray bookmarkTypes(Program program, State state, TaskMonitor monitor) throws Exception {
        BookmarkManager manager = program.getBookmarkManager(); List<JsonObject> rows = new ArrayList<>();
        Set<Long> ids = new HashSet<>(); Set<String> names = new HashSet<>();
        for (BookmarkType type : manager.getBookmarkTypes()) {
            monitor.checkCancelled();
            if (!ids.add((long)type.getTypeId()) || !names.add(type.getTypeString())) throw new IllegalStateException("Ambiguous bookmark type identity");
            if (type.getIcon() != null) state.refuse("Opaque bookmark marker icon cannot be completely represented for preservation");
            rows.add(obj("id", type.getTypeId(), "name", type.getTypeString(), "defined", manager.isDefinedType(type.getTypeString()),
                "has_bookmarks", type.hasBookmarks(), "priority", type.getMarkerPriority(), "color_argb", type.getMarkerColor() == null ? null : type.getMarkerColor().getRGB(),
                "icon", type.getIcon() == null ? null : obj("unavailable_value_class", type.getIcon().getClass().getName())));
        }
        for (BookmarkState bookmark : state.bookmarks) {
            boolean represented = rows.stream().anyMatch(row -> row.get("id").getAsLong() == bookmark.typeId && Objects.equals(row.get("name").getAsString(), bookmark.type));
            if (!represented) throw new IllegalStateException("Bookmark type identity missing from complete enumeration");
        }
        return ordered(rows);
    }
    /** A checked empty interval in the payload's actual address space, never a reserved scratch address. */
    private static Address bookmarkParking(Program program, AddressSet affected, TaskMonitor monitor) throws Exception {
        AddressSpace space = affected.getMinAddress().getAddressSpace();
        if (!space.equals(program.getAddressFactory().getDefaultAddressSpace()) || !space.equals(affected.getMaxAddress().getAddressSpace()) || affected.getNumAddressRanges() != 1)
            throw new IllegalStateException("Bookmark parking address-space ambiguity");
        AddressSet free = new AddressSet(space.getMinAddress(), space.getMaxAddress()); free.delete(affected); free.delete(program.getMemory());
        var iterator = program.getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) { monitor.checkCancelled(); Address at = iterator.next().getAddress(); free.delete(at, at); }
        for (AddressRange range : free.getAddressRanges()) {
            monitor.checkCancelled();
            if (range.getLength() >= affected.getNumAddresses()) {
                Address at = range.getMinAddress(); validateBookmarkParking(program, affected, at, monitor); return at;
            }
        }
        throw new IllegalStateException("No complete disjoint empty bookmark parking interval");
    }
    private static void validateBookmarkParking(Program program, AddressSet affected, Address at, TaskMonitor monitor) throws Exception {
        if (!at.getAddressSpace().equals(affected.getMinAddress().getAddressSpace())) throw new IllegalStateException("Bookmark parking address-space ambiguity");
        AddressSet interval;
        try { interval = new AddressSet(at, at.addNoWrap(affected.getNumAddresses() - 1)); }
        catch (AddressOverflowException overflow) { throw new IllegalStateException("Bookmark parking interval overflow", overflow); }
        if (interval.intersects(affected) || interval.intersects(program.getMemory())) throw new IllegalStateException("Bookmark parking overlaps payload or mapped memory");
        var iterator = program.getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) { monitor.checkCancelled(); if (interval.contains(iterator.next().getAddress())) throw new IllegalStateException("Bookmark parking destination occupied"); }
    }
    /** Resolve each original key and independently enumerate all live keys; no bookmark is recreated. */
    private static void verifyBookmarks(Program program, State original, AddressSet affected, Address destination, TaskMonitor monitor) throws Exception {
        BookmarkManager manager = program.getBookmarkManager(); Set<Long> expected = new HashSet<>();
        for (BookmarkState saved : original.bookmarks) {
            monitor.checkCancelled();
            if (!expected.add(saved.id)) throw new IllegalStateException("Duplicate captured bookmark identity");
            Bookmark current = manager.getBookmark(saved.id);
            Address at = affected.contains(saved.address) ? destination.addNoWrap(saved.address.subtract(affected.getMinAddress())) : saved.address;
            if (current == null || !current.getAddress().equals(at) || current.getType().getTypeId() != saved.typeId || !Objects.equals(current.getTypeString(), saved.type) ||
                !Objects.equals(current.getCategory(), saved.category) || !Objects.equals(current.getComment(), saved.comment)) throw new IllegalStateException("Bookmark identity/offset/type/category/comment changed");
        }
        Set<Long> actual = new HashSet<>(); var iterator = manager.getBookmarksIterator();
        while (iterator.hasNext()) { monitor.checkCancelled(); if (!actual.add(iterator.next().getId())) throw new IllegalStateException("Duplicate live bookmark identity"); }
        if (!actual.equals(expected)) throw new IllegalStateException("Unexpected generated or missing bookmark identity");
        State currentTypes = new State(); JsonArray types = bookmarkTypes(program, currentTypes, monitor);
        if (currentTypes.unavailable != null || !types.equals(original.bookmarkTypes)) throw new IllegalStateException("Bookmark type state changed or became unsupported");
    }
    /** Full logical manifest, including unaffected state. Provenance fields alone are excluded. */
    private static State capture(Program program, AddressSet affected, TaskMonitor monitor) throws Exception {
        State state = new State(); List<JsonObject> rows = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            monitor.checkCancelled(); boolean intersects = affected.intersects(block.getStart(), block.getEnd());
            rows.add(obj("name", block.getName(), "start", address(program, block.getStart()), "end", address(program, block.getEnd()), "size", block.getSize(),
                "initialized", block.isInitialized(), "loaded", block.isLoaded(), "mapped", block.isMapped(), "overlay", block.isOverlay(),
                "read", block.isRead(), "write", block.isWrite(), "execute", block.isExecute(), "volatile", block.isVolatile(), "artificial", block.isArtificial(),
                "comment", block.getComment(), "source_name", block.getSourceName(), "sha256", block.isInitialized() ? hashMemory(program, block.getStart(), block.getSize(), monitor) : null));
            if (intersects) state.blocks.add(new BlockState(block.getName(), block.getStart(), block.getSize(), block.isRead(), block.isWrite(), block.isExecute(), block.isVolatile(), block.isArtificial(), block.getComment(), block.getSourceName()));
        }
        state.manifest.add("blocks", ordered(rows)); rows = new ArrayList<>();
        List<Register> registers = new ArrayList<>(program.getProgramContext().getRegisters()); registers.sort(Comparator.comparing(Register::getName));
        for (Register register : registers) {
            monitor.checkCancelled(); if (!register.equals(register.getBaseRegister())) continue;
            for (AddressRange range : program.getProgramContext().getRegisterValueAddressRanges(register)) {
                RegisterValue value = program.getProgramContext().getNonDefaultValue(register, range.getMinAddress());
                if (value == null) throw new IllegalStateException("Enumerated register range has no non-default value");
                rows.add(obj("name", register.getName(), "start", address(program, range.getMinAddress()), "end", address(program, range.getMaxAddress()), "mask_value", HexFormat.of().formatHex(value.toBytes())));
                AddressSet intersection = affected.intersectRange(range.getMinAddress(), range.getMaxAddress());
                for (AddressRange part : intersection.getAddressRanges()) state.contexts.add(new ContextState(part.getMinAddress(), part.getMaxAddress(), value));
            }
        }
        state.manifest.add("context", ordered(rows)); rows = new ArrayList<>();
        for (Register register : registers) {
            if (!register.equals(register.getBaseRegister())) continue;
            for (AddressRange range : program.getProgramContext().getDefaultRegisterValueAddressRanges(register)) {
                monitor.checkCancelled(); RegisterValue value = program.getProgramContext().getDefaultValue(register, range.getMinAddress());
                if (value == null) throw new IllegalStateException("Enumerated default context range has no value");
                rows.add(obj("name", register.getName(), "start", address(program, range.getMinAddress()), "end", address(program, range.getMaxAddress()), "mask_value", HexFormat.of().formatHex(value.toBytes())));
            }
        }
        state.manifest.add("default_context", ordered(rows));
        RegisterValue defaultDisassembly = program.getProgramContext().getDefaultDisassemblyContext();
        state.manifest.add("default_disassembly_context", GSON.toJsonTree(defaultDisassembly == null ? null : HexFormat.of().formatHex(defaultDisassembly.toBytes())));
        rows = new ArrayList<>();
        var symbols = program.getSymbolTable().getAllSymbols(false);
        while (symbols.hasNext()) {
            monitor.checkCancelled(); Symbol symbol = symbols.next(); Address at = symbol.getAddress();
            rows.add(obj("address", address(program, at), "name", symbol.getName(), "namespace", symbol.getParentNamespace().getName(true), "source", symbol.getSource().toString(),
                "type", symbol.getSymbolType().toString(), "primary", symbol.isPrimary(), "pinned", symbol.isPinned()));
            if (affected.contains(at)) {
                if (!symbol.isGlobal() || symbol.isPinned() || (symbol.getSymbolType() != SymbolType.LABEL && symbol.getSymbolType() != SymbolType.FUNCTION)) state.refuse("Affected symbol namespace/type/pinning is outside plain loader state");
                state.symbols.add(new SymbolState(at, symbol.getName(), symbol.getSource(), symbol.getSymbolType(), symbol.isPrimary()));
            }
        }
        state.manifest.add("symbols", ordered(rows)); rows = new ArrayList<>();
        state.journal = labelHistory(program, monitor);
        state.manifest.add("label_history", journalMultiset(state.journal)); rows = new ArrayList<>();
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled(); Function function = functions.next(); boolean intersects = function.getBody().intersects(affected);
            rows.add(obj("entry", address(program, function.getEntryPoint()), "name", function.getName(), "source", function.getSymbol().getSource().toString(),
                "body", ranges(program, function.getBody()), "signature", function.getSignature().toString(), "signature_source", function.getSignatureSource().toString(),
                "purge", function.getStackPurgeSize(), "comment", function.getComment(), "repeatable_comment", function.getRepeatableComment(), "inline", function.isInline(),
                "noreturn", function.hasNoReturn(), "varargs", function.hasVarArgs(), "custom_storage", function.hasCustomVariableStorage(), "convention", function.getCallingConventionName(),
                "thunk", function.isThunk(), "call_fixup", function.getCallFixup(), "tags", function.getTags().stream().map(FunctionTag::getName).sorted().toList(),
                "locals", Arrays.stream(function.getLocalVariables()).map(Object::toString).toList(), "return_storage", function.getReturn().getVariableStorage().toString()));
            if (intersects) {
                if (!affected.contains(function.getEntryPoint()) || !affected.contains(function.getBody()) || !function.getSymbol().isGlobal() || function.getSignatureSource() != SourceType.DEFAULT ||
                    function.getParameterCount() != 0 || function.getLocalVariables().length != 0 || function.hasCustomVariableStorage() || function.isThunk() || function.hasVarArgs() || function.isInline() || function.hasNoReturn() ||
                    function.getCallFixup() != null || function.getComment() != null || function.getRepeatableComment() != null || !function.getTags().isEmpty() || !ghidra.program.model.data.Undefined.isUndefined(function.getReturnType())) state.refuse("Affected function has non-plain storage/prototype/body/metadata");
                state.functions.add(new FunctionState(function.getEntryPoint(), function.getName(), function.getSymbol().getSource(), new AddressSet(function.getBody()), function.getStackPurgeSize()));
            }
        }
        state.manifest.add("functions", ordered(rows)); rows = new ArrayList<>();
        var instructions = program.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled(); Instruction instruction = instructions.next(); Address at = instruction.getAddress();
            rows.add(obj("address", address(program, at), "length", instruction.getLength(), "prototype", prototypeState(instruction.getPrototype()), "text", instruction.toString(),
                "flow_override", instruction.getFlowOverride().toString(), "fallthrough_override", instruction.isFallThroughOverridden(), "length_override", instruction.isLengthOverridden(),
                "fallthrough", instruction.getFallThrough() == null ? null : address(program, instruction.getFallThrough()), "delay_depth", instruction.getDelaySlotDepth()));
            if (affected.intersects(instruction.getMinAddress(), instruction.getMaxAddress())) {
                if (!affected.contains(instruction.getMinAddress(), instruction.getMaxAddress()) || instruction.getFlowOverride() != FlowOverride.NONE || instruction.isFallThroughOverridden() || instruction.isLengthOverridden()) state.refuse("Affected instruction has unsupported boundaries/overrides");
                state.instructions.add(instruction.getMinAddress(), instruction.getMaxAddress());
                state.instructionStarts.add(instruction.getAddress());
            }
        }
        state.manifest.add("instructions", ordered(rows)); rows = new ArrayList<>();
        var data = program.getListing().getDefinedData(true);
        while (data.hasNext()) {
            monitor.checkCancelled(); Data item = data.next(); rows.add(obj("address", address(program, item.getAddress()), "length", item.getLength(), "type", item.getDataType().getPathName(), "text", item.toString()));
            if (affected.intersects(item.getMinAddress(), item.getMaxAddress())) state.refuse("Affected data definitions cannot be preserved by plain loader restoration");
        }
        state.manifest.add("data", ordered(rows)); rows = new ArrayList<>();
        // Enumerating every source captures incoming edges as well as outgoing ones.
        var sources = program.getReferenceManager().getReferenceSourceIterator(program.getAddressFactory().getAddressSet(), true);
        while (sources.hasNext()) {
            monitor.checkCancelled(); for (Reference reference : program.getReferenceManager().getReferencesFrom(sources.next())) {
                rows.add(obj("from", address(program, reference.getFromAddress()), "to", address(program, reference.getToAddress()), "type", reference.getReferenceType().toString(),
                    "source", reference.getSource().toString(), "operand", reference.getOperandIndex(), "primary", reference.isPrimary(), "symbol", reference.getSymbolID() == -1 ? null : program.getSymbolTable().getSymbol(reference.getSymbolID()).getName(true)));
                if (affected.contains(reference.getFromAddress()) || affected.contains(reference.getToAddress())) {
                    if (!reference.isMemoryReference() || reference.isOffsetReference() || reference.isShiftedReference() || reference.getSymbolID() != -1) state.refuse("Affected reference kind/symbol association is outside plain memory references");
                    state.references.add(new ReferenceState(reference.getFromAddress(), reference.getToAddress(), reference.getReferenceType(), reference.getSource(), reference.getOperandIndex(), reference.isPrimary()));
                }
            }
        }
        state.manifest.add("references", ordered(rows)); rows = new ArrayList<>();
        var entries = program.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) { Address at = entries.next(); rows.add(obj("address", address(program, at))); if (affected.contains(at)) state.entries.add(at); }
        state.manifest.add("entries", ordered(rows)); rows = new ArrayList<>();
        var bookmarks = program.getBookmarkManager().getBookmarksIterator();
        Set<Long> bookmarkIds = new HashSet<>();
        while (bookmarks.hasNext()) {
            monitor.checkCancelled(); Bookmark bookmark = bookmarks.next();
            if (!bookmarkIds.add(bookmark.getId())) throw new IllegalStateException("Duplicate bookmark identity during capture");
            state.bookmarks.add(new BookmarkState(bookmark.getId(), bookmark.getAddress(), bookmark.getType().getTypeId(), bookmark.getTypeString(), bookmark.getCategory(), bookmark.getComment()));
            rows.add(obj("id", Long.toUnsignedString(bookmark.getId()), "address", address(program, bookmark.getAddress()), "type_id", bookmark.getType().getTypeId(),
                "type", bookmark.getTypeString(), "category", bookmark.getCategory(), "comment", bookmark.getComment()));
        }
        state.bookmarkTypes = bookmarkTypes(program, state, monitor);
        state.manifest.add("bookmarks", obj("records", ordered(rows), "types", state.bookmarkTypes)); rows = new ArrayList<>();
        var comments = program.getListing().getCommentAddressIterator(program.getAddressFactory().getAddressSet(), true);
        while (comments.hasNext()) {
            monitor.checkCancelled(); Address at = comments.next(); for (CommentType type : CommentType.values()) {
                String comment = program.getListing().getComment(type, at); if (comment != null) rows.add(obj("address", address(program, at), "type", type.toString(), "value", comment));
            }
            if (affected.contains(at)) state.refuse("Affected listing comments cannot be restored by plain loader adaptation");
        }
        state.manifest.add("comments", ordered(rows)); rows = new ArrayList<>();
        var properties = program.getUsrPropertyManager().propertyManagers();
        while (properties.hasNext()) {
            monitor.checkCancelled(); String name = properties.next(); var map = program.getUsrPropertyManager().getPropertyMap(name);
            JsonArray values = new JsonArray(); var locations = map.getPropertyIterator();
            while (locations.hasNext()) {
                monitor.checkCancelled(); Address at = locations.next(); Object value = map.get(at);
                if (value == null || value instanceof Number || value instanceof Boolean || value instanceof String) values.add(obj("address", address(program, at), "value", value));
                else {
                    // Arbitrary Saveable object state has no format-neutral exact value contract.
                    state.refuse("User property value class cannot be completely represented for preservation");
                    values.add(obj("address", address(program, at), "unavailable_value_class", value.getClass().getName()));
                }
            }
            rows.add(obj("name", name, "class", map.getClass().getName(), "size", map.getSize(), "values", values));
            if (map.intersects(affected)) state.refuse("Affected user properties cannot be restored by plain loader adaptation");
        }
        state.manifest.add("property_maps", ordered(rows)); rows = new ArrayList<>();
        for (String tree : new TreeSet<>(Arrays.asList(program.getListing().getTreeNames()))) {
            ProgramModule root = program.getListing().getRootModule(tree);
            captureTree(program, root, root, tree, affected, state, rows, new HashSet<>(), monitor);
            state.treeOrders.put(tree, Arrays.stream(root.getChildren()).map(Group::getName).toList());
        }
        state.manifest.add("trees", ordered(rows)); rows = new ArrayList<>();
        for (var source : program.getSourceFileManager().getAllSourceFiles()) {
            monitor.checkCancelled();
            for (var entry : program.getSourceFileManager().getSourceMapEntries(source)) {
                rows.add(obj("source_path", source.getPath(), "source_uri", source.getUri().toString(), "id_type", source.getIdType().toString(), "id", HexFormat.of().formatHex(source.getIdentifier()),
                    "line", entry.getLineNumber(), "base", address(program, entry.getBaseAddress()), "length", entry.getLength()));
                if (affected.contains(entry.getBaseAddress()) || (entry.getRange() != null && affected.intersects(entry.getRange().getMinAddress(), entry.getRange().getMaxAddress()))) state.refuse("Affected source-map metadata cannot be restored by plain loader adaptation");
            }
        }
        state.manifest.add("source_maps", ordered(rows)); rows = new ArrayList<>();
        var equates = program.getEquateTable().getEquateAddresses();
        while (equates.hasNext()) {
            monitor.checkCancelled(); Address at = equates.next(); rows.add(obj("address", address(program, at), "equates", program.getEquateTable().getEquates(at).stream().map(item -> item.getName() + ":" + item.getValue()).sorted().toList()));
            if (affected.contains(at)) state.refuse("Affected equates cannot be restored by plain loader adaptation");
        }
        state.manifest.add("equates", ordered(rows));
        JsonObject observation = observe(program, monitor); state.manifest.add("relocations", observation.get("relocations"));
        var relocations = program.getRelocationTable().getRelocations(); while (relocations.hasNext()) if (affected.contains(relocations.next().getAddress())) state.refuse("Affected relocation records cannot be restored by plain loader adaptation");
        return state;
    }
    private static void captureTree(Program program, ProgramModule root, Group group, String tree, AddressSet affected,
            State state, List<JsonObject> rows, Set<String> visited, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled(); if (!visited.add(group.getName())) return;
        JsonObject row = obj("tree", tree, "name", group.getName(), "comment", group.getComment(), "parents", Arrays.stream(group.getParentNames()).sorted().toList());
        if (group instanceof ProgramModule module) {
            row.add("children", GSON.toJsonTree(Arrays.stream(module.getChildren()).map(Group::getName).toList()));
            for (Group child : module.getChildren()) captureTree(program, root, child, tree, affected, state, rows, visited, monitor);
        } else if (group instanceof ProgramFragment fragment) {
            row.add("ranges", ranges(program, fragment));
            if (fragment.intersects(affected)) {
                if (fragment.getNumParents() != 1 || !fragment.getParents()[0].equals(root) || fragment.getComment() != null || !affected.contains(fragment)) state.refuse("Affected program tree fragment ownership is outside ordinary root payload fragments");
                state.fragments.add(new FragmentState(tree, fragment.getName(), new AddressSet(fragment)));
            }
        } else state.refuse("Unmodeled program tree group");
        rows.add(row);
    }
    public static String stateDigest(Program program, JsonObject declarations, TaskMonitor monitor) throws Exception {
        return manifestHash(capture(program, affected(program, declarations), monitor).manifest);
    }
    private static AddressSet affected(Program program, JsonObject declaration) throws Exception {
        long start = Long.parseUnsignedLong(declaration.get("payload_address").getAsString().substring(2), 16), length = declaration.get("payload_bytes").getAsLong();
        if (length < 1 || start < 0x80000000L || start + length > 0x80200000L) throw new IllegalArgumentException("Payload is outside admitted default RAM");
        Address first = program.getAddressFactory().getDefaultAddressSpace().getAddress(start); return new AddressSet(first, first.addNoWrap(length - 1));
    }
    public static JsonObject adapt(Program program, Path descriptorPath, JsonObject descriptor, JsonObject declarations, TaskMonitor monitor) throws Exception {
        requireNoTransaction(program, "pre-entry-ownership");
        try { return adaptExclusive(program, descriptorPath, descriptor, declarations, monitor); }
        catch (PreparationException failure) { throw failure; }
        catch (Exception failure) { throw failed(program, "preflight", failure, null, null, null); }
    }
    private static JsonObject adaptExclusive(Program program, Path descriptorPath, JsonObject descriptor, JsonObject declarations, TaskMonitor monitor) throws Exception {
        JsonObject commitment = ReaGhidraPsxImport.validateCommitment(descriptor);
        Path snapshot = Path.of(commitment.get("source_snapshot_path").getAsString()); String sourceHash = commitment.get("source_sha256").getAsString();
        AddressSet affected = affected(program, declarations); JsonObject original = observe(program, monitor);
        JsonObject before = obj("source_files", original.get("source_files"), "mappings", original.get("mappings"), "entry_points", original.get("entry_points"), "entry_context", original.get("entry_context"));
        JsonObject record = obj("method", METHOD, "status", "unavailable", "reason", "Preflight incomplete", "source_sha256", sourceHash,
            "source_file_bytes", declarations.get("file_bytes").getAsLong(), "before", before, "rebound_ranges", new JsonArray());
        State captured = capture(program, affected, monitor); String refusal = captured.unavailable;
        JsonObject originalEvidence = obj("schema_version", 1, "commitment", obj("run_id", descriptor.get("run_id"), "profile_digest", descriptor.get("profile_digest"), "source_sha256", descriptor.get("target_sha256")),
            "state_sha256", manifestHash(captured.manifest), "operational_state_sha256", manifestHash(operational(captured.manifest)), "label_history", captured.journal);
        requireNoTransaction(program, "original-record-publication");
        String originalRecordHash = ReaGhidraPsxImport.publishOriginalRecord(descriptorPath, originalEvidence);
        ReaGhidraPsxImport.OriginalRecord published = ReaGhidraPsxImport.readOriginalRecord(descriptorPath, serializedRecordBytes(originalEvidence));
        if (!originalRecordHash.equals(published.sha256()) || !originalEvidence.equals(published.value())) throw new OriginalRecordException("Original evidence publication changed exact bytes or contents");
        if (!program.getMemory().getAllFileBytes().isEmpty()) refusal = "Original import already has FileBytes; this rebind supports the demonstrated empty-source state only";
        List<MemoryBlock> blocks = new ArrayList<>(); Address next = affected.getMinAddress();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isOverlay()) { if (block.getStart().getOffset() <= affected.getMaxAddress().getOffset() && block.getEnd().getOffset() >= affected.getMinAddress().getOffset()) refusal = "Overlay intersects payload coordinates"; continue; }
            if (!affected.intersects(block.getStart(), block.getEnd())) continue;
            if (!affected.contains(block.getStart(), block.getEnd()) || !block.isInitialized() || !block.isLoaded() || block.isMapped() || !block.getStart().equals(next)) refusal = "Payload requires complete nonoverlapping initialized ordinary blocks wholly inside its boundary";
            if (block.getSourceInfos().size() != 1 || block.getSourceInfos().get(0).getFileBytes().isPresent() || block.getSourceInfos().get(0).getMappedRange().isPresent()) refusal = "Payload has unsupported mixed or mapped source intervals";
            blocks.add(block); next = block.getEnd().addNoWrap(1);
        }
        if (!next.equals(affected.getMaxAddress().addNoWrap(1)) || blocks.isEmpty()) refusal = "Payload coverage is incomplete";
        boolean moveBookmarks = captured.bookmarks.stream().anyMatch(bookmark -> affected.contains(bookmark.address));
        BookmarkDBManager bookmarkManager = program.getBookmarkManager() instanceof BookmarkDBManager manager ? manager : null;
        Address parking = null;
        if (refusal == null && moveBookmarks) {
            if (bookmarkManager == null) refusal = "Affected bookmark identity requires the supported database bookmark manager";
            else {
                try { parking = bookmarkParking(program, affected, monitor); }
                catch (IllegalStateException unsupported) { refusal = unsupported.getMessage(); }
            }
        }
        if (refusal != null) {
            State unchanged = capture(program, affected, monitor);
            if (!captured.manifest.equals(unchanged.manifest) || !original.equals(observe(program, monitor))) throw new IllegalStateException("Unavailable preflight changed original state");
            record.addProperty("reason", refusal); record.add("metadata_preservation", metadata(captured, unchanged, originalRecordHash));
            validateOriginalRecord(descriptorPath, descriptor, record);
            requireNoTransaction(program, "unavailable-completion"); return record;
        }
        // Byte agreement is a precondition, never the lineage proof. Reject rather than repair.
        try (SeekableByteChannel file = Files.newByteChannel(snapshot, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] expected = new byte[65536], actual = new byte[65536];
            for (MemoryBlock block : blocks) for (long offset = 0; offset < block.getSize();) {
                monitor.checkCancelled(); int count = (int)Math.min(expected.length, block.getSize() - offset);
                long coordinate = 2048 + block.getStart().subtract(affected.getMinAddress()) + offset; file.position(coordinate); ByteBuffer buffer = ByteBuffer.wrap(expected, 0, count);
                while (buffer.hasRemaining()) if (file.read(buffer) < 0) throw new IOException("Snapshot payload read truncated");
                if (program.getMemory().getBytes(block.getStart().addNoWrap(offset), actual, 0, count) != count || !Arrays.equals(Arrays.copyOf(expected, count), Arrays.copyOf(actual, count))) throw new IllegalStateException("Original loader payload differs from immutable source; refusing silent repair");
                offset += count;
            }
        }
        requireNoTransaction(program, "pre-start-ownership");
        int transaction = program.startTransaction("REA PSX source provenance rebind");
        boolean intendedCommit = false; Exception failure = null; State inTransactionState = null; JsonObject inTransactionObservation = null;
        try {
            if (moveBookmarks) {
                if (program.getBookmarkManager() != bookmarkManager) throw new IllegalStateException("Bookmark manager changed before parking");
                verifyBookmarks(program, captured, affected, affected.getMinAddress(), monitor);
                validateBookmarkParking(program, affected, parking, monitor);
                bookmarkManager.moveAddressRange(affected.getMinAddress(), parking, affected.getNumAddresses(), monitor);
                monitor.checkCancelled();
                verifyBookmarks(program, captured, affected, parking, monitor);
            }
            FileBytes file;
            try (InputStream stream = Files.newInputStream(snapshot, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                file = program.getMemory().createFileBytes(snapshot.getFileName().toString(), 0, declarations.get("file_bytes").getAsLong(), stream, monitor);
            }
            if (!hashFileBytes(file, false, monitor).equals(sourceHash) || !hashFileBytes(file, true, monitor).equals(sourceHash)) throw new IllegalStateException("New FileBytes differs from immutable source");
            for (MemoryBlock block : blocks) program.getMemory().removeBlock(block, monitor);
            JsonArray afterRemoval = labelHistory(program, monitor);
            if (!outsideJournal(program, captured.journal, affected).equals(outsideJournal(program, afterRemoval, affected))) throw new IllegalStateException("Block removal changed outside-payload label history");
            List<JsonObject> generated = new ArrayList<>();
            JsonArray rebound = new JsonArray();
            for (BlockState block : captured.blocks) {
                long fileOffset = 2048 + block.start.subtract(affected.getMinAddress()); MemoryBlock restored = program.getMemory().createInitializedBlock(block.name, block.start, file, fileOffset, block.size, false);
                restored.setRead(block.read); restored.setWrite(block.write); restored.setExecute(block.execute); restored.setVolatile(block.vol); restored.setArtificial(block.artificial); restored.setComment(block.comment); restored.setSourceName(block.sourceName);
                String measured = hashMemory(program, block.start, block.size, monitor), previous = null;
                for (JsonElement element : original.getAsJsonArray("mappings")) {
                    JsonObject row = element.getAsJsonObject(); if (row.get("start").getAsString().equals(address(program, block.start)) && row.get("length").getAsLong() == block.size) previous = row.get("sha256").getAsString();
                }
                if (previous == null || !previous.equals(measured)) throw new IllegalStateException("Rebound payload differs from the true original observation");
                rebound.add(obj("start", address(program, block.start), "end", address(program, block.start.addNoWrap(block.size - 1)), "length", block.size, "file_offset", fileOffset,
                    "source_file_index", program.getMemory().getAllFileBytes().indexOf(file), "before_sha256", previous, "after_sha256", measured));
            }
            monitor.checkCancelled();
            for (FragmentState originalFragment : captured.fragments) {
                ProgramFragment fragment = program.getListing().getFragment(originalFragment.tree, originalFragment.name);
                if (fragment == null) fragment = program.getListing().getRootModule(originalFragment.tree).createFragment(originalFragment.name);
                for (AddressRange range : originalFragment.addresses.getAddressRanges()) fragment.move(range.getMinAddress(), range.getMaxAddress());
            }
            Set<String> generatedBlockNames = new HashSet<>(); for (BlockState block : captured.blocks) generatedBlockNames.add(block.name);
            for (Map.Entry<String, List<String>> tree : captured.treeOrders.entrySet()) {
                ProgramModule root = program.getListing().getRootModule(tree.getKey());
                for (Group child : root.getChildren()) if (!tree.getValue().contains(child.getName())) {
                    if (!(child instanceof ProgramFragment fragment) || !fragment.isEmpty() || fragment.getNumParents() != 1 || !fragment.getParents()[0].equals(root) || !generatedBlockNames.contains(child.getName())) throw new IllegalStateException("Unexpected generated tree ownership during restoration");
                    if (!root.removeChild(child.getName())) throw new IllegalStateException("Owned empty generated fragment was not removed");
                }
                for (int index = 0; index < tree.getValue().size(); index++) root.moveChild(tree.getValue().get(index), index);
            }
            for (ContextState context : captured.contexts) program.getProgramContext().setRegisterValue(context.start, context.end, context.value);
            // Restrict the disassembler to the exact previously defined instruction extents.
            if (!captured.instructionStarts.isEmpty()) {
                DisassembleCommand command = new DisassembleCommand(captured.instructionStarts, captured.instructions, false);
                command.enableCodeAnalysis(false);
                restoreOperation(program, monitor, "redisassembly", captured.instructionStarts, captured.symbols, generated, () -> {
                    if (!command.applyTo(program, monitor)) throw new IllegalStateException("Restoring measured instruction units failed: " + command.getStatusMsg());
                });
            }
            for (FunctionState function : captured.functions) {
                restoreOperation(program, monitor, "function-creation", new AddressSet(function.entry), captured.symbols, generated, () -> {
                    Function restored = program.getFunctionManager().createFunction(function.name, function.entry, function.body, function.source); restored.setStackPurgeSize(function.purge);
                });
            }
            for (SymbolState symbol : captured.symbols) {
                Symbol restored = program.getSymbolTable().getSymbol(symbol.name, symbol.address, program.getGlobalNamespace());
                if (restored == null && symbol.type == SymbolType.LABEL) {
                    restoreOperation(program, monitor, "label-creation", new AddressSet(symbol.address), captured.symbols, generated, () -> program.getSymbolTable().createLabel(symbol.address, symbol.name, symbol.source));
                    restored = program.getSymbolTable().getSymbol(symbol.name, symbol.address, program.getGlobalNamespace());
                }
                if (restored == null || restored.getSource() != symbol.source || restored.getSymbolType() != symbol.type) throw new IllegalStateException("Symbol identity could not be restored");
                if (symbol.primary) {
                    Symbol primary = restored; restoreOperation(program, monitor, "primary-selection", new AddressSet(symbol.address), captured.symbols, generated, () -> primary.setPrimary());
                }
            }
            for (Address at : captured.entries) program.getSymbolTable().addExternalEntryPoint(at);
            // Remove redisassembly's newly produced edges, then restore measured edges exactly.
            var refs = program.getReferenceManager().getReferenceSourceIterator(program.getAddressFactory().getAddressSet(), true); List<Reference> remove = new ArrayList<>();
            while (refs.hasNext()) for (Reference reference : program.getReferenceManager().getReferencesFrom(refs.next())) if (affected.contains(reference.getFromAddress()) || affected.contains(reference.getToAddress())) remove.add(reference);
            for (Reference reference : remove) program.getReferenceManager().delete(reference);
            for (ReferenceState reference : captured.references) {
                Reference restored = program.getReferenceManager().addMemoryReference(reference.from, reference.to, reference.type, reference.source, reference.operand); program.getReferenceManager().setPrimary(restored, reference.primary);
            }
            if (moveBookmarks) {
                if (program.getBookmarkManager() != bookmarkManager) throw new IllegalStateException("Bookmark manager changed before return");
                // Exact all-key verification also proves absence of newly generated records in either range.
                verifyBookmarks(program, captured, affected, parking, monitor);
                bookmarkManager.moveAddressRange(parking, affected.getMinAddress(), affected.getNumAddresses(), monitor);
                monitor.checkCancelled();
                verifyBookmarks(program, captured, affected, affected.getMinAddress(), monitor);
            }
            monitor.checkCancelled(); State restored = capture(program, affected, monitor);
            validateJournalTransition(program, captured, restored, affected, generated);
            JsonObject preservation = metadata(captured, restored, originalRecordHash);
            JsonObject fresh = observe(program, monitor); int index = program.getMemory().getAllFileBytes().indexOf(file);
            long coverage = 0;
            for (JsonElement element : fresh.getAsJsonArray("mappings")) {
                JsonObject mapping = element.getAsJsonObject(); if (mapping.get("source_file_index").isJsonNull() || mapping.get("source_file_index").getAsInt() != index) continue;
                long start = Long.parseUnsignedLong(mapping.get("start").getAsString().substring(2), 16), length = mapping.get("length").getAsLong();
                if (mapping.get("file_offset").getAsLong() != 2048 + start - affected.getMinAddress().getOffset() || !affected.contains(program.getAddressFactory().getDefaultAddressSpace().getAddress(start), program.getAddressFactory().getDefaultAddressSpace().getAddress(start + length - 1))) throw new IllegalStateException("Actual FileBytes source interval differs from committed payload");
                coverage += length;
            }
            if (coverage != declarations.get("payload_bytes").getAsLong()) throw new IllegalStateException("Actual FileBytes payload coverage is incomplete");
            record.addProperty("status", "applied"); record.add("reason", JsonNull.INSTANCE); record.add("rebound_ranges", rebound);
            record.add("metadata_preservation", preservation);
            validateOriginalRecord(descriptorPath, descriptor, record);
            ReaGhidraPsxImport.OriginalRecord confirmed = ReaGhidraPsxImport.readOriginalRecord(descriptorPath, serializedRecordBytes(originalEvidence));
            if (!Objects.equals(published.attributes().fileKey(), confirmed.attributes().fileKey()) || !published.attributes().creationTime().equals(confirmed.attributes().creationTime())) throw new OriginalRecordException("Original evidence file identity changed before commit");
            inTransactionState = restored; inTransactionObservation = fresh; intendedCommit = true;
        } catch (Exception error) { failure = error; }
        boolean finalCommit = false; Exception closeFailure = null;
        // Exactly one close, using only the ID returned by our own start. Never
        // end an ID found through read-only TransactionInfo diagnostics.
        try { finalCommit = program.endTransaction(transaction, intendedCommit); }
        catch (Exception error) { closeFailure = error; }
        if (closeFailure != null) {
            if (failure == null) failure = closeFailure; else failure.addSuppressed(closeFailure);
            throw failed(program, "final-transaction-close", failure, captured, affected, original);
        }
        try { requireNoTransaction(program, "transaction-not-finalized"); }
        catch (PreparationException closure) {
            if (failure == null) failure = closure; else failure.addSuppressed(closure);
            throw failed(program, "transaction-not-finalized", failure, captured, affected, original);
        }
        if (!intendedCommit) {
            if (finalCommit) {
                Exception discrepancy = new IllegalStateException("Rollback close unexpectedly reported committed completion");
                if (failure == null) failure = discrepancy; else failure.addSuppressed(discrepancy);
            }
            try {
                // A cancelled monitor must not prevent inspection of rollback ownership.
                State rollback = capture(program, affected, TaskMonitor.DUMMY);
                if (!captured.manifest.equals(rollback.manifest) || !original.equals(observe(program, TaskMonitor.DUMMY))) throw new IllegalStateException("Rollback did not restore original state and provenance");
                requireNoTransaction(program, "rollback-comparison");
            } catch (Exception rollback) { if (failure != null) failure.addSuppressed(rollback); else failure = rollback; }
            throw failed(program, failure != null && failure.getSuppressed().length > 0 ? "full-rollback-comparison" : "mutation",
                failure == null ? new IllegalStateException("Rebind transaction failed") : failure, captured, affected, original);
        }
        if (!finalCommit) throw failed(program, "final-transaction-close", new IllegalStateException("Owned transaction did not report final committed completion"), captured, affected, original);
        try {
            State postcommit = capture(program, affected, TaskMonitor.DUMMY);
            JsonObject postcommitObservation = observe(program, TaskMonitor.DUMMY);
            if (!inTransactionState.manifest.equals(postcommit.manifest) || !inTransactionObservation.equals(postcommitObservation)) throw new IllegalStateException("Postcommit state/source observations differ from checked adapted state");
            validateOriginalRecord(descriptorPath, descriptor, record);
            requireNoTransaction(program, "postcommit-validation");
        } catch (Exception error) { throw failed(program, "postcommit-validation", error, captured, affected, original); }
        return record;
    }
    /** Validate retained startup evidence before it is reused by a fresh agreement. */
    public static void validateRecord(JsonObject record, JsonObject commitment) {
        keys(record, "method", "status", "reason", "source_sha256", "source_file_bytes", "before", "rebound_ranges", "metadata_preservation");
        if (!string(record.get("method")).equals(METHOD) || !string(record.get("source_sha256")).equals(commitment.get("source_sha256").getAsString()) ||
            integer(record.get("source_file_bytes")) != commitment.getAsJsonObject("declarations").get("file_bytes").getAsLong()) throw new IllegalArgumentException("Provenance source/method correlation failed");
        sha(record.get("source_sha256"));
        JsonObject before = record.getAsJsonObject("before"); keys(before, "source_files", "mappings", "entry_points", "entry_context");
        for (JsonElement element : list(before.get("source_files"))) {
            JsonObject row = element.getAsJsonObject(); keys(row, "name", "size", "original_sha256", "modified_sha256"); string(row.get("name")); integer(row.get("size")); sha(row.get("original_sha256")); sha(row.get("modified_sha256"));
        }
        for (JsonElement element : list(before.get("mappings"))) {
            JsonObject row = element.getAsJsonObject(); keys(row, "block", "start", "end", "address_space", "initialized", "loaded", "overlay", "length", "source_file_index", "file_offset", "sha256");
            for (String field : List.of("block", "start", "end", "address_space")) string(row.get(field));
            for (String field : List.of("initialized", "loaded", "overlay")) if (!row.get(field).isJsonPrimitive() || !row.get(field).getAsJsonPrimitive().isBoolean()) throw new IllegalArgumentException("Invalid retained mapping boolean");
            integer(row.get("length")); for (String field : List.of("source_file_index", "file_offset")) if (!row.get(field).isJsonNull()) integer(row.get(field));
            if (!row.get("sha256").isJsonNull()) sha(row.get("sha256"));
        }
        for (JsonElement element : list(before.get("entry_points"))) string(element);
        for (JsonElement element : list(before.get("entry_context"))) {
            JsonObject row = element.getAsJsonObject(); keys(row, "address", "registers"); string(row.get("address"));
            for (JsonElement value : list(row.get("registers"))) { JsonObject register = value.getAsJsonObject(); keys(register, "name", "value_hex"); string(register.get("name")); if (!register.get("value_hex").isJsonNull()) string(register.get("value_hex")); }
        }
        JsonArray rebound = list(record.get("rebound_ranges"));
        for (JsonElement element : rebound) {
            JsonObject row = element.getAsJsonObject(); keys(row, "start", "end", "length", "file_offset", "source_file_index", "before_sha256", "after_sha256");
            for (String field : List.of("start", "end")) if (!string(row.get(field)).matches("0x(?:0|[1-9a-f][0-9a-f]{0,7})")) throw new IllegalArgumentException("Invalid rebound address");
            for (String field : List.of("length", "file_offset", "source_file_index")) integer(row.get(field)); sha(row.get("before_sha256")); sha(row.get("after_sha256"));
        }
        String status = string(record.get("status"));
        if (status.equals("applied")) {
            if (!record.get("reason").isJsonNull() || rebound.isEmpty()) throw new IllegalArgumentException("Applied provenance record is incomplete");
        } else if (status.equals("unavailable")) {
            if (string(record.get("reason")).isBlank() || !rebound.isEmpty()) throw new IllegalArgumentException("Unavailable provenance record is inconsistent");
        } else throw new IllegalArgumentException("Unknown provenance status");
        validateMetadata(record.getAsJsonObject("metadata_preservation"), commitment, status);
    }
    private static void validateJournal(JsonArray rows) {
        for (int ordinal = 0; ordinal < rows.size(); ordinal++) {
            JsonObject row = rows.get(ordinal).getAsJsonObject(); keys(row, "ordinal", "address", "label", "action", "user", "modification_time_ms");
            if (integer(row.get("ordinal")) != ordinal || string(row.get("address")).isEmpty()) throw new IllegalArgumentException("Invalid label-history ordinal/address");
            for (String field : List.of("label", "user")) if (!row.get(field).isJsonNull()) string(row.get(field));
            JsonElement action = row.get("action");
            if (!action.isJsonPrimitive() || !action.getAsJsonPrimitive().isNumber()) throw new IllegalArgumentException("Invalid label-history action type");
            long numeric = action.getAsBigDecimal().longValueExact(); if (numeric < -128 || numeric > 127) throw new IllegalArgumentException("Invalid label-history byte action");
            if (!row.get("modification_time_ms").isJsonNull()) {
                String date = string(row.get("modification_time_ms"));
                if (!date.matches("(?:0|-?[1-9][0-9]*)")) throw new IllegalArgumentException("Noncanonical label-history date");
                Long.parseLong(date);
            }
        }
    }
    private static boolean payloadJournalRow(JsonObject row, JsonObject commitment) {
        String value = string(row.get("address")); if (!value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,7})")) return false;
        long at = Long.parseUnsignedLong(value.substring(2), 16), start = Long.parseUnsignedLong(commitment.getAsJsonObject("declarations").get("payload_address").getAsString().substring(2), 16);
        return at >= start && at < start + commitment.getAsJsonObject("declarations").get("payload_bytes").getAsLong();
    }
    private static void validateMetadata(JsonObject metadata, JsonObject commitment, String status) {
        keys(metadata, "comparison", "original_state_sha256", "adapted_state_sha256", "original_operational_state_sha256", "adapted_operational_state_sha256", "operational_state_matched", "original_record_sha256", "label_history");
        if (!string(metadata.get("comparison")).equals("exact-enumerated-state-except-label-history-v1")) throw new IllegalArgumentException("Unrecognized operational preservation comparison");
        for (String field : List.of("original_state_sha256", "adapted_state_sha256", "original_operational_state_sha256", "adapted_operational_state_sha256", "original_record_sha256")) sha(metadata.get(field));
        if (!metadata.get("operational_state_matched").isJsonPrimitive() || !metadata.get("operational_state_matched").getAsJsonPrimitive().isBoolean() || !metadata.get("operational_state_matched").getAsBoolean() ||
            !metadata.get("original_operational_state_sha256").equals(metadata.get("adapted_operational_state_sha256"))) throw new IllegalArgumentException("Operational preservation disagreement");
        JsonObject journal = metadata.getAsJsonObject("label_history"); keys(journal, "scope", "before", "after", "removed_before_ordinals", "added_after_ordinals", "program_journal");
        if (!string(journal.get("scope")).equals("complete-program-label-history")) throw new IllegalArgumentException("Invalid retained journal scope");
        JsonArray before = list(journal.get("before")), after = list(journal.get("after")); validateJournal(before); validateJournal(after);
        JournalDelta delta = journalDelta(before, after);
        if (!delta.removed.equals(list(journal.get("removed_before_ordinals"))) || !delta.added.equals(list(journal.get("added_after_ordinals")))) throw new IllegalArgumentException("Retained journal difference ordinals disagree");
        boolean unchanged = delta.removed.isEmpty() && delta.added.isEmpty();
        if (metadata.get("original_state_sha256").equals(metadata.get("adapted_state_sha256")) != unchanged) throw new IllegalArgumentException("Complete state hash identity disagrees with journal multiset identity");
        if (!string(journal.get("program_journal")).equals(unchanged ? "unchanged" : "recreated-at-payload-addresses")) throw new IllegalArgumentException("Retained journal disposition disagrees");
        JsonArray beforeOutside = new JsonArray(), afterOutside = new JsonArray();
        for (JsonElement element : before) if (!payloadJournalRow(element.getAsJsonObject(), commitment)) beforeOutside.add(element);
        for (JsonElement element : after) if (!payloadJournalRow(element.getAsJsonObject(), commitment)) afterOutside.add(element);
        if (!journalMultiset(beforeOutside).equals(journalMultiset(afterOutside))) throw new IllegalArgumentException("Retained outside-payload journal changed");
        for (JsonElement ordinal : delta.added) if (!payloadJournalRow(after.get(ordinal.getAsInt()).getAsJsonObject(), commitment) || after.get(ordinal.getAsInt()).getAsJsonObject().get("action").getAsInt() != LabelHistory.ADD) throw new IllegalArgumentException("Unexpected retained generated journal action/address");
        if (status.equals("unavailable") && (!unchanged || !metadata.get("original_state_sha256").equals(metadata.get("adapted_state_sha256")))) throw new IllegalArgumentException("Unavailable preparation changed complete state");
    }
    public static final class OriginalRecordException extends IOException {
        public OriginalRecordException(String message) { super(message); }
        public OriginalRecordException(String message, Throwable cause) { super(message, cause); }
    }
    public static void validateOriginalRecord(Path descriptorPath, JsonObject descriptor, JsonObject provenance) throws Exception {
        try {
            JsonObject metadata = provenance.getAsJsonObject("metadata_preservation");
            JsonObject expected = obj("schema_version", 1, "commitment", obj("run_id", descriptor.get("run_id"), "profile_digest", descriptor.get("profile_digest"), "source_sha256", descriptor.get("target_sha256")),
                "state_sha256", metadata.get("original_state_sha256"), "operational_state_sha256", metadata.get("original_operational_state_sha256"), "label_history", metadata.getAsJsonObject("label_history").get("before"));
            ReaGhidraPsxImport.OriginalRecord record = ReaGhidraPsxImport.readOriginalRecord(descriptorPath, serializedRecordBytes(expected)); JsonObject value = record.value();
            keys(value, "schema_version", "commitment", "state_sha256", "operational_state_sha256", "label_history");
            JsonObject correlation = value.getAsJsonObject("commitment"); keys(correlation, "run_id", "profile_digest", "source_sha256");
            validateJournal(list(value.get("label_history")));
            if (integer(value.get("schema_version")) != 1 || !record.sha256().equals(string(metadata.get("original_record_sha256"))) ||
                !correlation.equals(obj("run_id", descriptor.get("run_id"), "profile_digest", descriptor.get("profile_digest"), "source_sha256", descriptor.get("target_sha256"))) ||
                !value.get("state_sha256").equals(metadata.get("original_state_sha256")) || !value.get("operational_state_sha256").equals(metadata.get("original_operational_state_sha256")) ||
                !value.get("label_history").equals(metadata.getAsJsonObject("label_history").get("before"))) throw new OriginalRecordException("Original evidence exact-byte digest/state/journal/correlation disagreement");
        } catch (OriginalRecordException failure) { throw failure; }
        catch (Exception failure) { throw new OriginalRecordException("Original evidence file missing, unreadable or malformed", failure); }
    }
    private static int serializedRecordBytes(JsonObject record) { return (GSON.toJson(record) + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8).length; }
    private static void keys(JsonObject object, String... expected) { if (object == null || !object.keySet().equals(Set.of(expected))) throw new IllegalArgumentException("Invalid provenance object fields"); }
    private static String string(JsonElement value) { if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) throw new IllegalArgumentException("Invalid provenance string"); return value.getAsString(); }
    private static long integer(JsonElement value) {
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) throw new IllegalArgumentException("Invalid provenance number");
        long result = value.getAsBigDecimal().longValueExact(); if (result < 0 || result > 9007199254740991L) throw new IllegalArgumentException("Invalid provenance integer range"); return result;
    }
    private static void sha(JsonElement value) { if (!string(value).matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid provenance digest"); }
    private static JsonArray list(JsonElement value) { if (value == null || !value.isJsonArray()) throw new IllegalArgumentException("Invalid provenance array"); return value.getAsJsonArray(); }
    private static String different(JsonObject before, JsonObject after) {
        List<String> categories = new ArrayList<>(); for (String key : before.keySet()) if (!Objects.equals(before.get(key), after.get(key))) categories.add(key); return String.join(", ", categories);
    }
}
