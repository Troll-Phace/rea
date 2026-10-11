//@category REA Verification
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.bookmark.BookmarkDBManager;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Synthetic metadata feasibility only. No production guard removal or game inputs. */
public class ReaPsxBookmarkPreservationProbe extends GhidraScript {
    private final Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private final JsonArray stages = new JsonArray();
    private ProgramDB witness;
    private JsonObject declarations, before, after, imported;
    private String mode, stage = "admission", failureStage;
    private Path source;
    private byte[] originalBytes;
    private AddressSet payload;
    private Address parking;
    private boolean mutationStarted, committed, finalized, released, injected;
    private int transaction = -1;
    private final Set<String> negatives = Set.of("occupied-destination", "insufficient-range", "overflow", "unsupported-manager",
        "unexpected-original", "unexpected-parking", "cancel-parking", "fail-parking", "cancel-replacement", "fail-replacement",
        "cancel-return", "fail-return", "commit-finalization", "rollback-finalization");
    private JsonObject obj(Object... pairs) {
        JsonObject value = new JsonObject(); for (int i = 0; i < pairs.length; i += 2) value.add((String)pairs[i], gson.toJsonTree(pairs[i + 1])); return value;
    }
    private String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private void require(boolean condition, String reason) { if (!condition) throw new IllegalStateException(reason); }
    private JsonArray ordered(List<JsonObject> rows) { rows.sort(Comparator.comparing(gson::toJson)); JsonArray result = new JsonArray(); rows.forEach(result::add); return result; }
    private String coordinate(Address at) { return at.toString(true); }
    private JsonObject bookmarkState() {
        List<JsonObject> rows = new ArrayList<>(), types = new ArrayList<>();
        BookmarkManager manager = witness.getBookmarkManager();
        var iterator = manager.getBookmarksIterator();
        while (iterator.hasNext()) {
            Bookmark b = iterator.next(); rows.add(obj("id", Long.toUnsignedString(b.getId()), "address", coordinate(b.getAddress()),
                "type_id", b.getType().getTypeId(), "type", b.getTypeString(), "category", b.getCategory(), "comment", b.getComment()));
        }
        for (BookmarkType t : manager.getBookmarkTypes()) { require(t.getIcon() == null, "Opaque bookmark marker icon outside this headless feasibility scope"); types.add(obj("id", t.getTypeId(), "name", t.getTypeString(),
            "defined", manager.isDefinedType(t.getTypeString()), "has_bookmarks", t.hasBookmarks(), "priority", t.getMarkerPriority(),
            "color_argb", t.getMarkerColor() == null ? null : t.getMarkerColor().getRGB(),
            "icon", null)); }
        return obj("bookmarks", ordered(rows), "types", ordered(types));
    }
    private JsonObject state() throws Exception {
        // Test-only named seam into the unchanged copied helper. It supplements
        // independent ID/type observations; neither hashes nor this seam alone are the oracle.
        var capture = ReaGhidraPsxProvenance.class.getDeclaredMethod("capture", Program.class, AddressSet.class, TaskMonitor.class);
        capture.setAccessible(true); Object captured = capture.invoke(null, witness, payload, TaskMonitor.DUMMY);
        var manifest = captured.getClass().getDeclaredField("manifest"); manifest.setAccessible(true);
        JsonObject full = ((JsonObject)manifest.get(captured)).deepCopy();
        return obj("bookmark_identity", bookmarkState(), "complete_enumerated_state", full, "complete_enumerated_state_sha256", ReaGhidraPsxProvenance.stateDigest(witness, declarations, TaskMonitor.DUMMY),
            "observation", ReaGhidraPsxProvenance.observe(witness, TaskMonitor.DUMMY));
    }
    private void checkpoint(String next) {
        stage = next; stages.add(obj("stage", stage, "bookmark_identity", bookmarkState(), "transaction_active", witness.getCurrentTransactionInfo() != null));
    }
    private AddressSet freeAddresses(AddressSetView admitted) {
        AddressSet free = new AddressSet(admitted); free.delete(payload); free.delete(witness.getMemory());
        var bookmarks = witness.getBookmarkManager().getBookmarksIterator();
        while (bookmarks.hasNext()) { Address at = bookmarks.next().getAddress(); free.delete(at, at); }
        return free;
    }
    private Address findParking(AddressSetView admitted) {
        long length = payload.getNumAddresses();
        for (AddressRange range : freeAddresses(admitted).getAddressRanges()) {
            if (range.getLength() >= length) { Address at = range.getMinAddress(); validateParking(at); return at; }
        }
        throw new IllegalStateException("No complete disjoint empty parking interval");
    }
    private void validateParking(Address at) {
        try {
            require(at.getAddressSpace().equals(payload.getMinAddress().getAddressSpace()), "Parking address-space ambiguity");
            Address end = at.addNoWrap(payload.getNumAddresses() - 1);
            AddressSet interval = new AddressSet(at, end);
            require(!interval.intersects(payload) && !interval.intersects(witness.getMemory()), "Parking overlaps payload or mapped memory");
            var bookmarks = witness.getBookmarkManager().getBookmarksIterator();
            while (bookmarks.hasNext()) require(!interval.contains(bookmarks.next().getAddress()), "Parking destination occupied by bookmark");
        } catch (AddressOverflowException e) { throw new IllegalStateException("Parking interval overflow", e); }
    }
    private void verifyMoved(JsonObject original, Address from, Address to) {
        BookmarkManager manager = witness.getBookmarkManager();
        Set<String> expectedIds = new HashSet<>();
        for (JsonElement row : original.getAsJsonArray("bookmarks")) {
            JsonObject r = row.getAsJsonObject(); long id = Long.parseUnsignedLong(r.get("id").getAsString()); Bookmark b = manager.getBookmark(id);
            require(b != null, "Original bookmark ID disappeared"); expectedIds.add(r.get("id").getAsString());
            Address originalAt = witness.getAddressFactory().getAddress(r.get("address").getAsString());
            require(originalAt != null, "Original bookmark coordinate unresolved");
            Address expected = payload.contains(originalAt) ? to.add(originalAt.subtract(payload.getMinAddress())) : originalAt;
            if (from.equals(parking)) expected = originalAt;
            require(b.getAddress().equals(expected) && b.getType().getTypeId() == r.get("type_id").getAsInt() && b.getTypeString().equals(r.get("type").getAsString()) &&
                b.getCategory().equals(r.get("category").getAsString()) && b.getComment().equals(r.get("comment").getAsString()), "Bookmark identity/offset/type/category/comment changed");
        }
        JsonObject current = bookmarkState();
        require(current.getAsJsonArray("bookmarks").size() == expectedIds.size(), "Unexpected generated bookmark");
        require(current.get("types").equals(original.get("types")), "Bookmark type state changed");
    }
    private void fault(String boundary) throws Exception {
        if (mode.equals("cancel-" + boundary)) { injected = true; throw new CancelledException("Controlled cancellation at " + boundary); }
        if (mode.equals("fail-" + boundary)) { injected = true; throw new IOException("Controlled failure at " + boundary); }
    }
    private boolean expectedFailure(Exception e) {
        if (!negatives.contains(mode)) return false;
        if (mode.equals("rollback-finalization")) return injected && e instanceof IOException && e.getMessage().equals("Controlled mutation failure requiring rollback") &&
            e.getSuppressed().length == 1 && e.getSuppressed()[0] instanceof IOException && e.getSuppressed()[0].getMessage().equals("Controlled rollback finalization-call boundary failure");
        if (e.getSuppressed().length != 0) return false;
        if (mode.startsWith("cancel-")) return injected && e instanceof CancelledException && e.getMessage().equals("Controlled cancellation at " + mode.substring(7));
        if (mode.startsWith("fail-")) return injected && e instanceof IOException && e.getMessage().equals("Controlled failure at " + mode.substring(5));
        if (mode.equals("commit-finalization")) return injected && e instanceof IOException && e.getMessage().equals("Controlled commit finalization-call boundary failure");
        return e instanceof IllegalStateException && e.getMessage().equals(switch (mode) {
            case "occupied-destination" -> "Parking destination occupied by bookmark";
            case "insufficient-range" -> "No complete disjoint empty parking interval";
            case "overflow" -> "Parking interval overflow";
            case "unsupported-manager" -> "Unsupported bookmark manager";
            case "unexpected-original", "unexpected-parking" -> "Unexpected generated bookmark";
            default -> "not an expected failure";
        });
    }
    private void setup() throws Exception {
        originalBytes = Files.readAllBytes(source);
        require(originalBytes.length == 4096 && Arrays.equals(Arrays.copyOf(originalBytes, 8), new byte[]{80,83,45,88,32,69,88,69}), "Only original generated 4 KiB PS-X EXE is admitted");
        ByteBuffer header = ByteBuffer.wrap(originalBytes).order(ByteOrder.LITTLE_ENDIAN);
        require(header.getInt(16) == 0x80010000 && header.getInt(24) == 0x80010000 && header.getInt(28) == 2048, "Only generated 2 KiB payload profile is admitted");
        require(currentProgram.getLanguageID().getIdAsString().equals("PSX:LE:32:default"), "Actual PSX import language mismatch");
        Address importedStart = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x80010000L); byte[] importedPayload = new byte[2048];
        require(currentProgram.getMemory().getBytes(importedStart, importedPayload) == importedPayload.length && Arrays.equals(importedPayload, Arrays.copyOfRange(originalBytes, 2048, 4096)), "Actual loader import payload mismatch");
        imported = obj("language_id", currentProgram.getLanguageID().getIdAsString(), "compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            "executable_format", currentProgram.getExecutableFormat(), "examined_payload_bytes", importedPayload.length, "payload_sha256", hash(importedPayload));
        var compilerSpecId = currentProgram.getCompilerSpec().getCompilerSpecID();
        witness = new ProgramDB("REA synthetic bookmark metadata witness", currentProgram.getLanguage(), currentProgram.getLanguage().getCompilerSpecByID(compilerSpecId), this);
        require(witness.getLanguageID().equals(currentProgram.getLanguageID()) && witness.getCompilerSpec().getCompilerSpecID().equals(compilerSpecId), "Witness language/compiler identity mismatch");
        Address start = witness.getAddressFactory().getDefaultAddressSpace().getAddress(0x80010000L); payload = new AddressSet(start, start.addNoWrap(2047));
        declarations = obj("payload_address", "0x80010000", "payload_bytes", 2048);
        int setup = witness.startTransaction("Owned synthetic bookmark setup"); boolean commit = false;
        try {
            byte[] bytes = Arrays.copyOfRange(originalBytes, 2048, 4096);
            if (mode.equals("split")) {
                witness.getMemory().createInitializedBlock("payload-left", start, new ByteArrayInputStream(bytes, 0, 1024), 1024, monitor, false);
                witness.getMemory().createInitializedBlock("payload-right", start.addNoWrap(1024), new ByteArrayInputStream(bytes, 1024, 1024), 1024, monitor, false);
            } else witness.getMemory().createInitializedBlock("payload", start, new ByteArrayInputStream(bytes), 2048, monitor, false);
            if (Set.of("adjacent", "outside", "multiple", "boundaries").contains(mode)) {
                witness.getMemory().createInitializedBlock("neighbor-before", start.subtract(16), new ByteArrayInputStream(new byte[16]), 16, monitor, false);
                witness.getMemory().createInitializedBlock("neighbor-after", start.addNoWrap(2048), new ByteArrayInputStream(new byte[16]), 16, monitor, false);
            }
            BookmarkManager manager = witness.getBookmarkManager();
            if (!mode.equals("zero")) manager.setBookmark(start, BookmarkType.NOTE, "first", "original first 雪");
            if (!Set.of("zero", "one").contains(mode)) {
                manager.setBookmark(start, BookmarkType.NOTE, "second", "distinct category");
                manager.setBookmark(start, BookmarkType.ERROR, "first", "distinct type");
                manager.setBookmark(payload.getMaxAddress(), BookmarkType.WARNING, "last", "original last");
                manager.setBookmark(start.addNoWrap(1024), BookmarkType.INFO, "middle", "split boundary");
            }
            if (!Set.of("zero", "one").contains(mode)) {
                manager.setBookmark(start.subtract(1), BookmarkType.NOTE, "outside-before", "unaffected preceding address");
                manager.setBookmark(start.addNoWrap(2048), BookmarkType.NOTE, "outside-after", "unaffected succeeding address");
            }
            parking = findParking(new AddressSet(start.getAddressSpace().getMinAddress(), start.getAddressSpace().getMaxAddress()));
            if (mode.equals("occupied-destination")) manager.setBookmark(parking, BookmarkType.NOTE, "occupied", "do not overwrite");
            commit = true;
        } finally { require(witness.endTransaction(setup, commit) == commit, "Setup transaction did not finalize as intended"); }
        ReaGhidraPsxProvenance.requireNoTransaction(witness, "synthetic-setup-finalized");
        before = state(); checkpoint("before");
    }
    private void execute() throws Exception {
        BookmarkManager selected = witness.getBookmarkManager();
        if (mode.equals("unsupported-manager")) selected = (BookmarkManager)java.lang.reflect.Proxy.newProxyInstance(BookmarkManager.class.getClassLoader(), new Class<?>[]{BookmarkManager.class},
            (proxy, method, args) -> method.invoke(witness.getBookmarkManager(), args));
        BookmarkDBManager manager = selected instanceof BookmarkDBManager actual ? actual : null;
        require(manager != null, "Unsupported bookmark manager");
        if (mode.equals("insufficient-range")) findParking(new AddressSet(parking, parking));
        if (mode.equals("overflow")) validateParking(payload.getMinAddress().getAddressSpace().getMaxAddress());
        validateParking(parking); checkpoint("destination-validated");
        transaction = witness.startTransaction("Owned bookmark-only parking and payload replacement"); mutationStarted = true;
        Exception primary = null;
        try {
            long half = payload.getNumAddresses() / 2;
            manager.moveAddressRange(payload.getMinAddress(), parking, half, monitor); checkpoint("parking-partial"); fault("parking");
            manager.moveAddressRange(payload.getMinAddress().addNoWrap(half), parking.addNoWrap(half), payload.getNumAddresses() - half, monitor);
            verifyMoved(before.getAsJsonObject("bookmark_identity"), payload.getMinAddress(), parking); checkpoint("parked");
            List<MemoryBlock> blocks = new ArrayList<>();
            for (MemoryBlock block : witness.getMemory().getBlocks()) if (payload.intersects(block.getStart(), block.getEnd())) blocks.add(block);
            Map<String, List<String>> treeOrders = new TreeMap<>();
            for (String name : witness.getListing().getTreeNames()) {
                List<String> order = new ArrayList<>();
                for (Group child : witness.getListing().getRootModule(name).getChildren()) {
                    require(child instanceof ProgramFragment, "Unexpected non-flat synthetic Program tree"); order.add(child.getName());
                }
                treeOrders.put(name, order);
            }
            record SavedBlock(String name, Address start, long size, boolean read, boolean write, boolean execute, boolean vol, boolean artificial, String comment, String sourceName) {}
            List<SavedBlock> saved = new ArrayList<>();
            for (MemoryBlock block : blocks) { require(payload.contains(block.getStart(), block.getEnd()), "Replacement block straddles payload");
                saved.add(new SavedBlock(block.getName(), block.getStart(), block.getSize(), block.isRead(), block.isWrite(), block.isExecute(), block.isVolatile(), block.isArtificial(), block.getComment(), block.getSourceName())); }
            FileBytes sourceBytes = witness.getMemory().createFileBytes(source.getFileName().toString(), 0, originalBytes.length, new ByteArrayInputStream(originalBytes), monitor);
            for (MemoryBlock block : blocks) witness.getMemory().removeBlock(block, monitor);
            checkpoint("blocks-removed"); fault("replacement");
            for (SavedBlock b : saved) {
                MemoryBlock restored = witness.getMemory().createInitializedBlock(b.name(), b.start(), sourceBytes, 2048 + b.start().subtract(payload.getMinAddress()), b.size(), false);
                restored.setRead(b.read()); restored.setWrite(b.write()); restored.setExecute(b.execute()); restored.setVolatile(b.vol()); restored.setArtificial(b.artificial()); restored.setComment(b.comment()); restored.setSourceName(b.sourceName());
            }
            for (Map.Entry<String, List<String>> tree : treeOrders.entrySet()) {
                ProgramModule root = witness.getListing().getRootModule(tree.getKey());
                require(root.getChildren().length == tree.getValue().size(), "Unexpected generated tree fragment");
                for (int i = 0; i < tree.getValue().size(); i++) root.moveChild(tree.getValue().get(i), i);
            }
            checkpoint("blocks-replaced");
            if (mode.equals("rollback-finalization")) throw new IOException("Controlled mutation failure requiring rollback");
            if (mode.equals("unexpected-original")) witness.getBookmarkManager().setBookmark(payload.getMinAddress(), BookmarkType.NOTE, "unexpected", "new producer record");
            if (mode.equals("unexpected-parking")) witness.getBookmarkManager().setBookmark(parking.addNoWrap(1), BookmarkType.NOTE, "unexpected", "new parking record");
            verifyMoved(before.getAsJsonObject("bookmark_identity"), payload.getMinAddress(), parking); checkpoint("return-validated");
            manager.moveAddressRange(parking, payload.getMinAddress(), half, monitor); checkpoint("return-partial"); fault("return");
            manager.moveAddressRange(parking.addNoWrap(half), payload.getMinAddress().addNoWrap(half), payload.getNumAddresses() - half, monitor);
            verifyMoved(before.getAsJsonObject("bookmark_identity"), parking, payload.getMinAddress()); checkpoint("returned");
            require(before.get("bookmark_identity").equals(bookmarkState()), "Complete bookmark/type identity differs after return");
            require(before.get("complete_enumerated_state").equals(state().get("complete_enumerated_state")), "Complete enumerated preserved manifest differs");
            require(before.get("complete_enumerated_state_sha256").getAsString().equals(ReaGhidraPsxProvenance.stateDigest(witness, declarations, monitor)), "Complete enumerated preserved state differs");
            verifySourceBacked();
        } catch (Exception e) { primary = e; failureStage = stage; }
        if (Set.of("commit-finalization", "rollback-finalization").contains(mode)) {
            injected = true; IOException closeBoundary = new IOException("Controlled " + (primary == null ? "commit" : "rollback") + " finalization-call boundary failure");
            if (primary == null) { primary = closeBoundary; failureStage = "finalization-boundary-failed"; } else primary.addSuppressed(closeBoundary);
            checkpoint("finalization-boundary-failed");
        }
        boolean intent = primary == null;
        try { committed = witness.endTransaction(transaction, intent); finalized = witness.getCurrentTransactionInfo() == null; transaction = -1;
            require(finalized && committed == intent, "Owned transaction finalization contradicted requested outcome");
        } catch (Exception e) { if (primary == null) primary = e; else primary.addSuppressed(e); }
        after = state(); checkpoint(committed ? "committed" : "rolled-back");
        if (!intent) try { require(finalized && before.equals(after), "Rollback did not restore exact original full state/IDs/source observations"); }
        catch (Exception e) { if (primary != null) primary.addSuppressed(e); else primary = e; }
        if (primary != null) throw primary;
    }
    private void verifySourceBacked() throws Exception {
        byte[] actual = new byte[2048]; require(witness.getMemory().getBytes(payload.getMinAddress(), actual) == actual.length && Arrays.equals(actual, Arrays.copyOfRange(originalBytes, 2048, 4096)), "Mapped source payload disagreement");
        require(witness.getMemory().getAllFileBytes().size() == 1, "Source-backed replacement has ambiguous FileBytes");
        FileBytes file = witness.getMemory().getAllFileBytes().get(0); byte[] stored = new byte[originalBytes.length];
        require(file.getOriginalBytes(0, stored) == stored.length && Arrays.equals(stored, originalBytes), "FileBytes differs from exact synthetic source");
        long coverage = 0;
        for (MemoryBlock block : witness.getMemory().getBlocks()) if (payload.contains(block.getStart(), block.getEnd())) {
            require(block.getSourceInfos().size() == 1, "Mixed source intervals"); MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
            require(info.getFileBytes().isPresent() && info.getFileBytes().get().equals(file) && info.getFileBytesOffset() == 2048 + block.getStart().subtract(payload.getMinAddress()), "Source offset/identity disagreement"); coverage += block.getSize();
        }
        require(coverage == 2048, "Incomplete source-backed coverage");
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs(); Path output = args.length == 4 ? Path.of(args[1]) : null;
        Exception failure = null; boolean expected = false; JsonObject report = new JsonObject();
        try {
            require(args.length == 4 && isRunningHeadless() && currentProgram != null, "Expected source output scenario sourceSha256 in synthetic headless import");
            source = Path.of(args[0]); mode = args[2];
            require(negatives.contains(mode) || Set.of("zero", "one", "multiple", "boundaries", "adjacent", "split", "outside").contains(mode), "Unknown bookmark feasibility scenario");
            end(true); ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "script-wrapper-release");
            setup(); require(hash(originalBytes).equals(args[3]), "Independent source identity disagreement");
            try { execute(); } catch (Exception e) {
                failure = e; expected = expectedFailure(e);
                if (expected) { if (after == null) after = state(); require(before.equals(after), "Expected refusal/failure changed original state"); require(!committed, "Failure unexpectedly committed"); }
            }
            require(failure == null ? !negatives.contains(mode) && committed && finalized : expected, "Scenario did not establish its declared expectation");
            require(Arrays.equals(originalBytes, Files.readAllBytes(source)), "Original synthetic source changed");
            report = obj("schema_version", 1, "scenario", mode, "scope", "isolated-synthetic-ProgramDB-bookmark-metadata-feasibility",
                "mocked", false, "source", obj("path", source.toString(), "sha256", hash(originalBytes), "after_sha256", hash(Files.readAllBytes(source)), "file_bytes", originalBytes.length),
                "actual_import", imported, "parking", coordinate(parking), "before", before, "after", after, "stages", stages,
                "supplementary_manifest_seam", "test-only reflection of copied ReaGhidraPsxProvenance.capture/State.manifest; independent bookmark IDs/types and explicit provenance observations remain required",
                "transaction", obj("started", mutationStarted, "finalized", mutationStarted ? finalized : witness.getCurrentTransactionInfo() == null, "committed", committed),
                "expected_failure", expected, "injected_failure", injected, "failure", failure == null ? null : ReaGhidraPsxProvenance.failureDetails(failure, failureStage == null ? stage : failureStage),
                "finalization_control", Set.of("commit-finalization", "rollback-finalization").contains(mode) ? "injected-caller-boundary-failure-with-actual-finalized-rollback; not a Ghidra internal close failure" : null,
                "ok", true, "evidence_complete", true);
        } catch (Exception e) { if (failure != null && failure != e) e.addSuppressed(failure); failure = e; report = obj("schema_version", 1, "scenario", mode, "ok", false, "evidence_complete", false, "stages", stages, "before", before, "after", after, "failure", ReaGhidraPsxProvenance.failureDetails(e, stage)); }
        finally {
            if (witness != null) {
                try {
                    if (transaction != -1) { witness.endTransaction(transaction, false); transaction = -1; }
                    ReaGhidraPsxProvenance.requireNoTransaction(witness, "witness-release"); witness.release(this); released = witness.isClosed(); require(released, "Owned ProgramDB consumer was not released");
                } catch (Exception cleanup) { if (failure != null) failure.addSuppressed(cleanup); else failure = cleanup; report.addProperty("ok", false); report.addProperty("evidence_complete", false); report.add("cleanup_failure", ReaGhidraPsxProvenance.failureDetails(cleanup, "witness-release")); }
            }
            report.addProperty("owned_program_released", released);
            if (output != null) Files.writeString(output, gson.toJson(report), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
        if (!report.get("ok").getAsBoolean()) throw failure == null ? new IllegalStateException("Incomplete bookmark feasibility") : failure;
        println("REA_PSX_BOOKMARK_PROBE_COMPLETE " + mode);
    }
}
