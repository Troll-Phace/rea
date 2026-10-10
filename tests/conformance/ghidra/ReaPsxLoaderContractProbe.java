//@category REA Verification
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.Option;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.classfinder.ClassSearcher;
import java.io.File;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.parsers.DocumentBuilderFactory;

/** Read-only observer of disposable synthetic imports. No program setters are used. */
public class ReaPsxLoaderContractProbe extends GhidraScript {
    private final Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private JsonObject obj(Object... pairs) {
        JsonObject result = new JsonObject();
        for (int i = 0; i < pairs.length; i += 2) result.add((String) pairs[i], gson.toJsonTree(pairs[i + 1]));
        return result;
    }
    private String hex(Address address) { return address == null ? null : address.toString(true); }
    private String hash(FileBytes file) throws Exception { return hash(file, 0, file.getSize()); }
    private String hash(FileBytes file, long start, long size) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] chunk = new byte[65536];
        for (long offset = 0; offset < size;) {
            int count = file.getOriginalBytes(start + offset, chunk, 0, (int) Math.min(chunk.length, size - offset));
            if (count <= 0) throw new IllegalStateException("Incomplete FileBytes enumeration");
            digest.update(chunk, 0, count); offset += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private String hash(Address start, long size) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] chunk = new byte[65536];
        for (long offset = 0; offset < size;) {
            int count = currentProgram.getMemory().getBytes(start.add(offset), chunk, 0, (int) Math.min(chunk.length, size - offset));
            if (count <= 0) throw new IllegalStateException("Incomplete memory enumeration");
            digest.update(chunk, 0, count); offset += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private JsonObject file(FileBytes bytes) throws Exception {
        return obj("filename", bytes.getFilename(), "fileOffset", bytes.getFileOffset(), "size", bytes.getSize(), "originalSha256", hash(bytes));
    }
    private JsonArray analysisOptions() {
        JsonArray array = new JsonArray();
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : new TreeSet<>(options.getOptionNames()))
            array.add(obj("name", name, "type", options.getType(name).toString(), "value", options.getObject(name, null)));
        return array;
    }
    private JsonObject region(long start, long size) throws Exception {
        Address address = toAddr(start);
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        boolean covered = size > 0 && currentProgram.getMemory().contains(address, address.add(size - 1));
        JsonObject result = obj("start", hex(address), "size", size, "covered", covered,
            "blockAtStart", block == null ? null : block.getName(), "initializedAtStart", block == null ? null : block.isInitialized());
        try { result.add("mappedSha256", gson.toJsonTree(covered ? hash(address, size) : null)); }
        catch (Exception error) { result.add("mappedSha256", JsonNull.INSTANCE); result.addProperty("hashUnavailable", error.toString()); }
        return result;
    }
    private JsonArray registers() {
        JsonArray array = new JsonArray();
        for (long value : new long[] {0x80010000L, 0x80010040L, 0x800107ffL, 0x80011000L}) {
            Address address = toAddr(value);
            for (String name : new String[] {"gp", "sp"}) {
                Register register = currentProgram.getRegister(name);
                var observed = register == null ? null : currentProgram.getProgramContext().getValue(register, address, false);
                array.add(obj("address", hex(address), "register", name, "valueHex", observed == null ? null : observed.toString(16)));
            }
        }
        return array;
    }
    private JsonObject identity(Class<? extends Loader> cls) throws Exception {
        Loader loader = cls.getDeclaredConstructor().newInstance();
        List<String> resources = new ArrayList<>();
        var enumeration = cls.getClassLoader().getResources(cls.getName().replace('.', '/') + ".class");
        while (enumeration.hasMoreElements()) resources.add(enumeration.nextElement().toString());
        return obj("className", cls.getName(), "name", loader.getName(),
            "codeSource", cls.getProtectionDomain().getCodeSource() == null ? null : cls.getProtectionDomain().getCodeSource().getLocation().toString(),
            "classResource", cls.getResource(cls.getSimpleName() + ".class").toString(), "classResources", resources);
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("Expected evidence path, fixture path, stage");
        JsonObject report = obj("stage", args[2], "ghidraVersion", Application.getApplicationVersion(),
            "javaVersion", System.getProperty("java.version"), "javaHome", System.getProperty("java.home"),
            "javaRuntime", System.getProperty("java.runtime.name"), "fixture", args[1],
            "programName", currentProgram.getName(), "executablePath", currentProgram.getExecutablePath(),
            "executableFormat", currentProgram.getExecutableFormat(), "language", currentProgram.getLanguageID().toString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(), "imageBase", hex(currentProgram.getImageBase()));
        JsonArray roots = new JsonArray();
        for (var root : Application.getApplicationLayout().getExtensionInstallationDirs()) roots.add(root.getAbsolutePath());
        report.add("extensionSearchRoots", roots);
        JsonArray languages = new JsonArray();
        var xmlFactory = DocumentBuilderFactory.newInstance();
        xmlFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        xmlFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        xmlFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        for (var root : Application.getApplicationLayout().getExtensionInstallationDirs()) {
            Path directory = Path.of(root.getAbsolutePath());
            if (!Files.isDirectory(directory)) continue;
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.filter(value -> value.toString().endsWith(".ldefs")).toList()) {
                    var document = xmlFactory.newDocumentBuilder().parse(path.toFile());
                    var definitions = document.getElementsByTagName("language");
                    for (int index = 0; index < definitions.getLength(); index++) {
                        var language = (org.w3c.dom.Element) definitions.item(index);
                        if (language.getAttribute("id").equals(currentProgram.getLanguageID().toString()))
                            languages.add(obj("ldefs", path.toString(), "id", language.getAttribute("id"),
                                "slafile", language.getAttribute("slafile"), "processorspec", language.getAttribute("processorspec")));
                    }
                }
            }
        }
        report.add("matchingLanguageDefinitions", languages);
        report.add("userSettingsDirectory", gson.toJsonTree(Application.getApplicationLayout().getUserSettingsDir().getAbsolutePath()));
        JsonArray candidates = new JsonArray();
        for (Loader loader : ClassSearcher.getInstances(Loader.class))
            if (loader.getClass().getSimpleName().equals("PsxLoader") || loader.getName().equals("PSX Executables Loader")) candidates.add(identity(loader.getClass()));
        report.add("runtimeLoaderCandidates", candidates);
        Class<? extends Loader> selected = LoaderService.getLoaderClassByName("PsxLoader");
        if (selected == null) throw new IllegalStateException("PsxLoader not resolved");
        report.add("selectorResolution", identity(selected));
        JsonArray specs = new JsonArray(); JsonArray defaults = new JsonArray();
        try (var provider = new FileByteProvider(new File(args[1]), null, AccessMode.READ)) {
            Loader loader = selected.getDeclaredConstructor().newInstance();
            for (LoadSpec spec : loader.findSupportedLoadSpecs(provider)) {
                specs.add(obj("languageCompiler", String.valueOf(spec.getLanguageCompilerSpec()), "preferred", spec.isPreferred(), "complete", spec.isComplete(), "imageBase", spec.getDesiredImageBase()));
                for (Option option : loader.getDefaultOptions(provider, spec, currentProgram, false, false))
                    defaults.add(obj("name", option.getName(), "type", option.getValueClass().getName(), "commandLine", option.getArg(), "value", String.valueOf(option.getValue())));
            }
        }
        report.add("loadSpecs", specs); report.add("defaultOptions", defaults);
        report.add("analysisOptions", analysisOptions());
        JsonArray analysisClasses = new JsonArray();
        for (Analyzer analyzer : ClassSearcher.getInstances(Analyzer.class)) {
            Class<?> cls = analyzer.getClass();
            String codeSource = cls.getProtectionDomain().getCodeSource() == null ? null : cls.getProtectionDomain().getCodeSource().getLocation().toString();
            if ((codeSource != null && codeSource.contains("/Extensions/")) || cls.getName().contains("Mips")) {
                List<String> resources = new ArrayList<>();
                var enumeration = cls.getClassLoader().getResources(cls.getName().replace('.', '/') + ".class");
                while (enumeration.hasMoreElements()) resources.add(enumeration.nextElement().toString());
                analysisClasses.add(obj("className", cls.getName(), "name", analyzer.getName(), "codeSource", codeSource,
                    "classResources", resources, "enabledOption", currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).getObject(analyzer.getName(), null)));
            }
        }
        report.add("analysisClassIdentities", analysisClasses);
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        JsonArray programInfo = new JsonArray();
        for (String name : new TreeSet<>(info.getOptionNames())) programInfo.add(obj("name", name, "value", info.getObject(name, null)));
        report.add("programInfo", programInfo);
        JsonArray spaces = new JsonArray();
        for (AddressSpace space : currentProgram.getAddressFactory().getAddressSpaces())
            spaces.add(obj("name", space.getName(), "size", space.getSize(), "type", space.getType(), "overlay", space.isOverlaySpace(), "min", hex(space.getMinAddress()), "max", hex(space.getMaxAddress())));
        report.add("addressSpaces", spaces);
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonArray sources = new JsonArray();
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) sources.add(obj("start", hex(source.getMinAddress()), "end", hex(source.getMaxAddress()),
                "length", source.getLength(), "description", source.getDescription(), "fileBytesOffset", source.getFileBytesOffset(),
                "fileBytes", source.getFileBytes().isPresent() ? file(source.getFileBytes().get()) : null,
                "originalFileOffset", source.getFileBytes().isPresent() && source.getFileBytesOffset() >= 0 ? source.getFileBytes().get().getFileOffset() + source.getFileBytesOffset() : null,
                "sourceOriginalSha256", source.getFileBytes().isPresent() && source.getFileBytesOffset() >= 0 ? hash(source.getFileBytes().get(), source.getFileBytesOffset(), source.getLength()) : null,
                "mappedRange", source.getMappedRange().isPresent() ? source.getMappedRange().get().toString() : null));
            blocks.add(obj("name", block.getName(), "start", hex(block.getStart()), "end", hex(block.getEnd()), "size", block.getSize(),
                "initialized", block.isInitialized(), "read", block.isRead(), "write", block.isWrite(), "execute", block.isExecute(),
                "mapped", block.isMapped(), "overlay", block.isOverlay(), "sourceName", block.getSourceName(), "sources", sources));
        }
        report.add("blocks", blocks);
        JsonArray files = new JsonArray();
        for (FileBytes bytes : currentProgram.getMemory().getAllFileBytes()) files.add(file(bytes));
        report.add("fileBytes", files);
        JsonArray entries = new JsonArray();
        var iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext()) entries.add(hex(iterator.next()));
        report.add("externalEntries", entries);
        var instruction = currentProgram.getListing().getInstructionAt(toAddr(0x80010000L));
        report.add("entryInstruction", gson.toJsonTree(instruction == null ? null : instruction.toString()));
        report.add("registerContexts", registers());
        report.add("payload", region(0x80010000L, 0x800)); report.add("fill", region(0x80011000L, 0x20));
        report.add("afterPayload", region(0x80010800L, 0x10));
        boolean trailingMapped = false;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) for (MemoryBlockSourceInfo source : block.getSourceInfos())
            if (source.getFileBytes().isPresent()) for (long offset = 0x1000; offset < 0x1010; offset++)
                trailingMapped |= source.containsFileOffset(offset - source.getFileBytes().get().getFileOffset());
        report.add("trailing", obj("fileOffsetsExamined", "0x1000..0x100f", "sourceBackedMappingFound", trailingMapped,
            "mappingStatus", files.isEmpty() ? "unknown_without_FileBytes_provenance" : "examined_source_ranges"));
        report.add("limitations", gson.toJsonTree(List.of("Equal mapped hashes do not establish file provenance", "Uninitialized memory is not observed zero-filled runtime memory", "Fresh default option objects are not retained importer option objects", "No fixture instructions executed", "Analysis result semantics are not Phase 4 acceptance")));
        Files.writeString(Path.of(args[0]), gson.toJson(report));
        println("REA_PSX_LOADER_PROBE_COMPLETE " + args[2]);
    }
}
