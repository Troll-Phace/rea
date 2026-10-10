import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.Strictness;
import ghidra.app.services.Analyzer;
import ghidra.app.util.Option;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderService;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.SleighLanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigDecimal;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** PSX-only observation boundary. It never writes Program state or target bytes. */
public final class ReaGhidraPsxImport {
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private static final String POLICY = "psx-kseg0-2m-defaults-v1";
    private static final String INVENTORY_VERSION = "ghidra-code-data-v1";
    private static final String LANGUAGE = "PSX:LE:32:default";
    private static final String FORMAT = "PSX Executables Loader";
    private static final long RAM_BASE = 0x80000000L;
    private static final long RAM_SIZE = 0x200000L;
    private static final long MAX_SAFE_INTEGER = 9007199254740991L;
    private static final Set<String> DECLARATION_KEYS = Set.of(
        "file_bytes", "payload_file_offset", "payload_address", "payload_bytes", "trailing_bytes",
        "initial_pc", "initial_gp", "data_address", "data_bytes", "fill_address", "fill_bytes",
        "stack_base", "stack_offset", "initial_sp"
    );
    private static final Set<String> OBSERVED_KEYS = Set.of(
        "ghidra_version", "source", "program", "loader_selector", "loader_class", "advertised_defaults",
        "selected_classes", "language_assets", "asset_inventory_version", "asset_inventory_digest"
    );
    private static final Set<String> SKIP_DIRECTORIES = Set.of("docs", "doc", "src", "os", "build", ".git", "cache");

    private ReaGhidraPsxImport() {}

    public static String prepare(Path descriptorPath, Program program, TaskMonitor monitor) throws Exception {
        JsonObject descriptor = readDescriptor(descriptorPath);
        JsonObject commitment = validateCommitment(descriptor);
        Path recordPath = beforePath(descriptorPath);
        if (Files.exists(recordPath, LinkOption.NOFOLLOW_LINKS)) {
            throw invalid("PSX before record already exists");
        }
        JsonObject before = observe("before-analysis", descriptor, commitment, program, monitor);
        byte[] bytes = (GSON.toJson(before) + "\n").getBytes(StandardCharsets.UTF_8);
        Path pending = recordPath.resolveSibling("psx-import-before.json.pending");
        boolean pendingOwned = false;
        try {
            // CREATE_NEW and private permissions apply before any record bytes exist.
            Files.createFile(pending, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            pendingOwned = true;
            Files.write(pending, bytes, StandardOpenOption.WRITE);
            // A non-atomic filesystem is incompatible with this publication contract.
            Files.move(pending, recordPath, StandardCopyOption.ATOMIC_MOVE);
            pendingOwned = false;
        }
        catch (Exception primary) {
            if (pendingOwned) {
                try { Files.deleteIfExists(pending); }
                catch (Exception cleanup) { primary.addSuppressed(cleanup); }
            }
            throw primary;
        }
        return "REA_PSX_IMPORT_BEFORE_COMPLETE " + text(descriptor, "run_id") + " " + hashBytes(bytes);
    }

    public static JsonObject agreement(Path descriptorPath, JsonObject descriptor,
            Program program, TaskMonitor monitor) throws Exception {
        JsonObject commitment = validateCommitment(descriptor);
        Path recordPath = beforePath(descriptorPath);
        requireRegular(recordPath);
        BasicFileAttributes initial = attributes(recordPath);
        byte[] bytes = Files.readAllBytes(recordPath);
        stable(initial, attributes(recordPath), recordPath);
        JsonObject before = object(parseJson(new String(bytes, StandardCharsets.UTF_8)),
            Set.of("schema_version", "stage", "commitment", "observed"));
        validateObservation(before, "before-analysis", descriptor, commitment);
        JsonObject after = observe("after-analysis", descriptor, commitment, program, monitor);
        JsonObject oldFacts = before.getAsJsonObject("observed"), newFacts = after.getAsJsonObject("observed");
        for (String field : List.of("ghidra_version", "source", "loader_selector", "loader_class", "advertised_defaults",
                "selected_classes", "language_assets", "asset_inventory_version", "asset_inventory_digest")) {
            equal(oldFacts.get(field), newFacts.get(field), "Before/after " + field);
        }
        JsonObject result = obj("schema_version", 1, "before_record_sha256", hashBytes(bytes));
        result.add("before", before);
        result.add("after", after);
        return result;
    }

    public static JsonObject readDescriptor(Path path) throws Exception {
        requireRegular(path);
        JsonObject descriptor = parseJson(Files.readString(path, StandardCharsets.UTF_8)).getAsJsonObject();
        Set<String> keys = new HashSet<>(Set.of("transport", "endpoint_path", "token", "run_id",
            "target_path", "target_sha256", "provider_version", "profile_digest", "psx_import"));
        if (descriptor.has("analysis_extensions")) keys.add("analysis_extensions");
        object(descriptor, keys);
        if (descriptor.has("analysis_extensions") &&
            (!descriptor.get("analysis_extensions").isJsonArray() || descriptor.getAsJsonArray("analysis_extensions").size() != 0)) {
            throw invalid("PSX import cannot combine analysis extensions");
        }
        if (!text(descriptor, "transport").equals("unix-socket")) throw invalid("PSX import requires a supported POSIX host");
        text(descriptor, "token"); text(descriptor, "endpoint_path");
        validateCommitment(descriptor);
        return descriptor;
    }

    public static JsonObject validateCommitment(JsonObject descriptor) {
        UUID.fromString(text(descriptor, "run_id"));
        digest(descriptor, "profile_digest"); digest(descriptor, "target_sha256");
        JsonObject expected = object(descriptor.get("psx_import"), Set.of("schema_version", "policy",
            "source_snapshot_path", "source_sha256", "declarations", "loader", "language_id", "compiler_spec_id",
            "option_mode", "supplied_loader_options", "expected_ram_base", "expected_ram_size",
            "asset_inventory_version", "asset_inventory_digest"));
        equal(number(expected, "schema_version"), 1L, "commitment schema version");
        equal(text(expected, "policy"), POLICY, "import policy");
        equal(text(expected, "language_id"), LANGUAGE, "language commitment");
        equal(text(expected, "compiler_spec_id"), "default", "compiler commitment");
        equal(text(expected, "option_mode"), "loader-defaults", "option mode");
        object(expected.get("supplied_loader_options"), Set.of());
        equal(text(expected, "expected_ram_base"), hex(RAM_BASE), "RAM base commitment");
        equal(number(expected, "expected_ram_size"), RAM_SIZE, "RAM size commitment");
        equal(text(expected, "asset_inventory_version"), INVENTORY_VERSION, "inventory version");
        digest(expected, "asset_inventory_digest");
        equal(digest(expected, "source_sha256"), digest(descriptor, "target_sha256"), "source commitment digest");
        Path snapshot = Path.of(text(expected, "source_snapshot_path"));
        Path target = Path.of(text(descriptor, "target_path"));
        if (!snapshot.isAbsolute() || !target.isAbsolute() || !snapshot.normalize().equals(target.normalize())) {
            throw invalid("Snapshot and descriptor must identify the same absolute owned target path");
        }
        JsonObject loader = object(expected.get("loader"), Set.of("selector", "class_name", "display_name", "code_source_relative", "code_source_sha256"));
        equal(text(loader, "selector"), "PsxLoader", "loader selector");
        equal(text(loader, "class_name"), "psx.PsxLoader", "loader class");
        equal(text(loader, "display_name"), FORMAT, "loader display name");
        relative(text(loader, "code_source_relative")); digest(loader, "code_source_sha256");
        validateDeclarations(object(expected.get("declarations"), DECLARATION_KEYS));
        return expected;
    }

    private static JsonObject observe(String stage, JsonObject descriptor, JsonObject expected,
            Program program, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        Path snapshot = Path.of(text(expected, "source_snapshot_path"));
        requireRegular(snapshot);
        Path programPath = Path.of(program.getExecutablePath());
        if (!programPath.isAbsolute() || !Files.isSameFile(snapshot, programPath)) {
            throw invalid("Program executable path differs from the owned snapshot");
        }
        BasicFileAttributes initial = attributes(snapshot);
        JsonObject declarations = readDeclarations(snapshot, initial.size());
        equal(declarations, expected.getAsJsonObject("declarations"), "independent snapshot declarations");
        String sourceHash = hashFile(snapshot, monitor);
        stable(initial, attributes(snapshot), snapshot);
        equal(sourceHash, text(expected, "source_sha256"), "independent snapshot digest");
        Inventory inventory = inventory(monitor);
        equal(inventory.digest, text(expected, "asset_inventory_digest"), "fresh installation inventory");

        Class<? extends Loader> selected = LoaderService.getLoaderClassByName("PsxLoader");
        if (selected == null) throw invalid("PsxLoader selector did not resolve");
        List<Loader> candidates = new ArrayList<>();
        for (Loader loader : ClassSearcher.getInstances(Loader.class)) {
            monitor.checkCancelled();
            if (loader.getClass().getSimpleName().equals("PsxLoader") || loader.getName().equals(FORMAT)) candidates.add(loader);
        }
        if (candidates.size() != 1 || candidates.get(0).getClass() != selected) throw invalid("PSX loader selector is ambiguous");
        Loader loader = selected.getDeclaredConstructor().newInstance();
        equal(selected.getName(), "psx.PsxLoader", "selected loader class");
        equal(loader.getName(), FORMAT, "selected loader display name");
        JsonObject loaderIdentity = classIdentity(selected, "loader", null, inventory, monitor);
        equal(loaderIdentity.get("code_source_relative"), expected.getAsJsonObject("loader").get("code_source_relative"), "loader code source");
        equal(loaderIdentity.get("code_source_sha256"), expected.getAsJsonObject("loader").get("code_source_sha256"), "loader code digest");

        JsonObject defaults = advertisedDefaults(loader, snapshot, program);
        TreeMap<String, JsonObject> classes = new TreeMap<>();
        classes.put(selected.getName(), loaderIdentity);
        boolean coreMips = false;
        for (Analyzer analyzer : ClassSearcher.getInstances(Analyzer.class)) {
            monitor.checkCancelled();
            Class<?> cls = analyzer.getClass();
            URL code = codeSource(cls);
            Path location = codePath(code);
            String rel = inventory.relative(location);
            if (!cls.getName().matches("psx\\.[^.]*Analyzer") &&
                !cls.getName().matches("ghidra\\.app\\.plugin\\.core\\.analysis\\.Mips[^.]*Analyzer")) continue;
            Object enabled = program.getOptions(Program.ANALYSIS_PROPERTIES).getObject(analyzer.getName(), null);
            if (enabled != null && !(enabled instanceof Boolean)) throw invalid("Analyzer enabled option is not boolean: " + analyzer.getName());
            JsonObject identity = classIdentity(cls, "analyzer", (Boolean) enabled, inventory, monitor);
            if (classes.put(cls.getName(), identity) != null) throw invalid("Duplicate analyzer identity: " + cls.getName());
            if (cls.getName().equals("ghidra.app.plugin.core.analysis.MipsPreAnalyzer") &&
                rel.equals("Ghidra/Processors/MIPS/lib/MIPS.jar")) coreMips = true;
        }
        if (!coreMips) throw invalid("Selected core MipsPreAnalyzer was not observed");

        Object ram = program.getOptions(Program.PROGRAM_INFO).getObject("PSX RAM Size", null);
        // The installed loader writes an Integer. Missing, arbitrary strings and
        // lossy floating values cannot establish an effective RAM-size property.
        if (!(ram instanceof Integer) && !(ram instanceof Long)) throw invalid("PSX RAM Size must be an observed integer property");
        JsonArray entries = new JsonArray();
        TreeSet<String> addresses = new TreeSet<>();
        var iterator = program.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            String address = address(iterator.next());
            if (!addresses.add(address)) throw invalid("Duplicate external entry");
        }
        for (String value : addresses) entries.add(value);
        String entry = text(declarations, "initial_pc");
        Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(parseAddress(entry));
        if (!addresses.contains(entry) || !program.getMemory().contains(entryAddress, entryAddress.add(3))) {
            throw invalid("Declared complete entry instruction is not an external entry in mapped memory");
        }
        JsonObject programFacts = obj("executable_path", program.getExecutablePath(), "executable_format", program.getExecutableFormat(),
            "language_id", program.getLanguageID().getIdAsString(), "compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            "image_base", address(program.getImageBase()), "default_address_space", program.getAddressFactory().getDefaultAddressSpace().getName(),
            "ram_size", ((Number) ram).longValue());
        programFacts.add("external_entries", entries);
        JsonObject observed = obj("ghidra_version", Application.getApplicationVersion(), "loader_selector", selected.getSimpleName(),
            "loader_class", selected.getName(), "asset_inventory_version", INVENTORY_VERSION, "asset_inventory_digest", inventory.digest);
        observed.add("source", obj("snapshot_path", snapshot.toRealPath().toString(), "sha256", sourceHash, "file_bytes", initial.size()));
        observed.add("program", programFacts);
        observed.add("advertised_defaults", defaults);
        JsonArray selectedClasses = new JsonArray();
        classes.values().forEach(selectedClasses::add);
        observed.add("selected_classes", selectedClasses);
        observed.add("language_assets", languageAssets(program, inventory, monitor));
        JsonObject result = obj("schema_version", 1, "stage", stage);
        result.add("commitment", correlation(descriptor));
        result.add("observed", observed);
        validateObservation(result, stage, descriptor, expected);
        return result;
    }

    private static JsonObject advertisedDefaults(Loader loader, Path snapshot, Program program) throws Exception {
        JsonObject defaults = new JsonObject();
        try (FileByteProvider provider = new FileByteProvider(snapshot.toFile(), null, java.nio.file.AccessMode.READ)) {
            List<LoadSpec> matches = new ArrayList<>();
            for (LoadSpec spec : loader.findSupportedLoadSpecs(provider)) {
                var pair = spec.getLanguageCompilerSpec();
                if (pair != null && pair.languageID.getIdAsString().equals(LANGUAGE) && pair.compilerSpecID.getIdAsString().equals("default")) matches.add(spec);
            }
            if (matches.size() != 1) throw invalid("PSX supported language/compiler load spec is not unique");
            for (Option option : loader.getDefaultOptions(provider, matches.get(0), program, false, false)) {
                String name = "-loader-ramStart".equals(option.getArg()) ? "ram_start" : "-loader-ramSize".equals(option.getArg()) ? "ram_size" : null;
                if (name == null) continue;
                if (defaults.has(name)) throw invalid("Duplicate advertised RAM option");
                if (option.getValueClass() != String.class || !(option.getValue() instanceof String)) {
                    throw invalid("Advertised RAM default must have java.lang.String class and value");
                }
                defaults.add(name, obj("argument", option.getArg(), "value_class", option.getValueClass().getName(), "value", (String) option.getValue()));
            }
        }
        object(defaults, Set.of("ram_start", "ram_size"));
        return defaults;
    }

    private static JsonObject classIdentity(Class<?> cls, String role, Boolean enabled,
            Inventory inventory, TaskMonitor monitor) throws Exception {
        URL code = codeSource(cls);
        Path codePath = codePath(code);
        String relative = inventory.relative(codePath);
        Asset member = inventory.assets.get(relative);
        if (member == null) throw invalid("Selected class code source is outside the hashed inventory: " + code);
        String resourceName = cls.getName().replace('.', '/') + ".class";
        URL resource = cls.getResource("/" + resourceName);
        if (resource == null || !resource.getProtocol().equals("jar")) throw invalid("Selected class has no modeled JAR resource: " + cls.getName());
        JarURLConnection connection = (JarURLConnection) resource.openConnection();
        connection.setUseCaches(false);
        if (!Files.isSameFile(codePath, codePath(connection.getJarFileURL())) || !connection.getEntryName().equals(resourceName)) {
            throw invalid("Class resource and selected code source disagree: " + cls.getName());
        }
        var resources = cls.getClassLoader().getResources(resourceName);
        Set<String> origins = new HashSet<>();
        while (resources.hasMoreElements()) {
            monitor.checkCancelled();
            URL candidate = resources.nextElement();
            if (!candidate.getProtocol().equals("jar")) throw invalid("Unmodeled duplicate class resource: " + candidate);
            JarURLConnection other = (JarURLConnection) candidate.openConnection();
            other.setUseCaches(false);
            String origin = inventory.relative(codePath(other.getJarFileURL()));
            if (!inventory.assets.containsKey(origin) || !origins.add(origin)) throw invalid("Unmodeled or duplicate class code source: " + candidate);
        }
        // The measured extension also contains MipsPreAnalyzer. Core selection
        // is explicitly permitted; all other duplicate class resources fail.
        boolean coreDuplicate = cls.getName().equals("ghidra.app.plugin.core.analysis.MipsPreAnalyzer") &&
            relative.equals("Ghidra/Processors/MIPS/lib/MIPS.jar") && origins.stream().allMatch(value -> value.equals(relative) || value.startsWith("Ghidra/Extensions/"));
        if (!origins.contains(relative) || (origins.size() != 1 && !coreDuplicate)) throw invalid("Ambiguous selected class resource: " + cls.getName());
        return obj("class_name", cls.getName(), "role", role, "code_source_url", code.toExternalForm(),
            "code_source_relative", relative, "code_source_sha256", member.sha256, "class_resource_url", resource.toExternalForm(), "enabled", enabled);
    }

    private static URL codeSource(Class<?> cls) {
        if (cls.getProtectionDomain().getCodeSource() == null) throw invalid("Missing selected class code source: " + cls.getName());
        return cls.getProtectionDomain().getCodeSource().getLocation();
    }

    private static Path codePath(URL code) throws Exception {
        if (!code.getProtocol().equals("file")) throw invalid("Unmodeled selected class code-source URL: " + code);
        return Path.of(code.toURI()).toRealPath();
    }

    private static JsonArray languageAssets(Program program, Inventory inventory, TaskMonitor monitor) throws Exception {
        if (!(program.getLanguage().getLanguageDescription() instanceof SleighLanguageDescription description)) throw invalid("PSX language is not a modeled Sleigh language");
        String selectedDefs = inventory.relative(Path.of(description.getDefsFile().getAbsolutePath()).toRealPath());
        Element chosen = null;
        String chosenPath = null;
        for (String relative : inventory.assets.keySet()) {
            if (!relative.endsWith(".ldefs")) continue;
            monitor.checkCancelled();
            var document = xmlFactory().newDocumentBuilder().parse(inventory.root.resolve(relative).toFile());
            var definitions = document.getElementsByTagName("language");
            for (int index = 0; index < definitions.getLength(); index++) {
                Element language = (Element) definitions.item(index);
                if (!language.getAttribute("id").equals(LANGUAGE)) continue;
                if (chosen != null) throw invalid("Conflicting PSX language definitions");
                chosen = language; chosenPath = relative;
            }
        }
        if (chosen == null || !selectedDefs.equals(chosenPath)) throw invalid("Selected PSX definition differs from unique inventory definition");
        Path directory = inventory.root.resolve(selectedDefs).getParent();
        Path sla = directory.resolve(chosen.getAttribute("slafile")).normalize();
        Path spec = directory.resolve(chosen.getAttribute("processorspec")).normalize();
        if (!Files.isSameFile(sla, Path.of(description.getSlaFile().getAbsolutePath())) ||
            !Files.isSameFile(spec, Path.of(description.getSpecFile().getAbsolutePath()))) throw invalid("Runtime PSX SLA/processor resources differ from selected definition");
        int compilers = 0;
        var nodes = chosen.getElementsByTagName("compiler");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element compiler = (Element) nodes.item(index);
            if (!compiler.getAttribute("id").equals("default")) continue;
            compilers++;
            String compilerPath = inventory.relative(directory.resolve(compiler.getAttribute("spec")).toRealPath());
            if (!inventory.assets.containsKey(compilerPath)) throw invalid("Default compiler spec is outside inventory");
        }
        if (compilers != 1) throw invalid("Default PSX compiler definition is not unique");
        for (Path path : List.of(sla, spec)) if (!inventory.assets.containsKey(inventory.relative(path.toRealPath()))) throw invalid("Selected language resource is outside inventory");
        String prefix = inventory.relative(directory) + "/";
        JsonArray result = new JsonArray();
        for (Map.Entry<String, Asset> member : inventory.assets.entrySet()) {
            if (member.getKey().startsWith(prefix)) result.add(obj("relative_path", member.getKey(), "sha256", member.getValue().sha256));
        }
        return result;
    }

    private static DocumentBuilderFactory xmlFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
        return factory;
    }

    private record Asset(long bytes, String sha256) {}
    private record Inventory(Path root, TreeMap<String, Asset> assets, String digest) {
        String relative(Path path) throws IOException {
            Path resolved = path.toRealPath();
            if (!resolved.startsWith(root)) throw invalid("Resource escapes the selected installation: " + path);
            return root.relativize(resolved).toString().replace(java.io.File.separatorChar, '/');
        }
    }

    private static Inventory inventory(TaskMonitor monitor) throws Exception {
        Path root = Path.of(Application.getInstallationDirectory().getAbsolutePath()).toRealPath();
        TreeMap<String, Asset> assets = new TreeMap<>();
        visit(root.resolve("Ghidra"), root, assets, new HashSet<>(), monitor);
        if (assets.isEmpty()) throw invalid("Installation resource inventory is empty");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Map.Entry<String, Asset> member : assets.entrySet()) {
            String row = Base64.getEncoder().encodeToString(member.getKey().getBytes(StandardCharsets.UTF_8)) + "\t" +
                member.getValue().bytes + "\t" + member.getValue().sha256 + "\n";
            digest.update(row.getBytes(StandardCharsets.UTF_8));
        }
        return new Inventory(root, assets, HexFormat.of().formatHex(digest.digest()));
    }

    private static void visit(Path path, Path root, TreeMap<String, Asset> assets,
            Set<Path> directories, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        Path real = path.toRealPath();
        if (!real.startsWith(root)) throw invalid("Inventory symlink escapes selected installation: " + path);
        BasicFileAttributes initial = attributes(path);
        if (initial.isDirectory()) {
            if (!directories.add(real)) throw invalid("Inventory contains an aliased directory: " + path);
            boolean insideData = List.of(root.relativize(path).toString().split(java.io.File.separator)).contains("data");
            if (!insideData && SKIP_DIRECTORIES.contains(path.getFileName().toString())) return;
            try (var children = Files.newDirectoryStream(path)) {
                for (Path child : children) visit(child, root, assets, directories, monitor);
            }
            stable(initial, attributes(path), path);
        }
        else if (initial.isRegularFile()) {
            String relative = root.relativize(path).toString().replace(java.io.File.separatorChar, '/');
            List<String> parts = List.of(relative.split("/"));
            String name = path.getFileName().toString();
            boolean included = (name.endsWith(".jar") && parts.contains("lib")) || parts.contains("data") ||
                name.equals("extension.properties") || name.equals("Module.manifest");
            if (included) {
                assets.put(relative, new Asset(initial.size(), hashFile(path, monitor)));
                stable(initial, attributes(path), path);
            }
        }
        else throw invalid("Nonregular resource prevents complete inventory: " + path);
    }

    private static JsonObject readDeclarations(Path snapshot, long size) throws Exception {
        if (size < 2048 || size > MAX_SAFE_INTEGER) throw invalid("PS-X EXE file length is invalid");
        ByteBuffer bytes = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN);
        try (SeekableByteChannel channel = Files.newByteChannel(snapshot, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            while (bytes.hasRemaining()) if (channel.read(bytes) < 0) throw invalid("PS-X EXE header is truncated");
        }
        byte[] magic = "PS-X EXE".getBytes(StandardCharsets.US_ASCII);
        for (int index = 0; index < magic.length; index++) if (bytes.get(index) != magic[index]) throw invalid("Exact PS-X EXE signature is absent");
        long pc = unsigned(bytes, 0x10), gp = unsigned(bytes, 0x14), payload = unsigned(bytes, 0x18), payloadBytes = unsigned(bytes, 0x1c);
        long data = unsigned(bytes, 0x20), dataBytes = unsigned(bytes, 0x24), fill = unsigned(bytes, 0x28), fillBytes = unsigned(bytes, 0x2c);
        long stack = unsigned(bytes, 0x30), offset = unsigned(bytes, 0x34);
        JsonObject result = obj("file_bytes", size, "payload_file_offset", 2048, "payload_address", hex(payload), "payload_bytes", payloadBytes,
            "trailing_bytes", size - 2048 - payloadBytes, "initial_pc", hex(pc), "initial_gp", hex(gp),
            "data_address", hex(data), "data_bytes", dataBytes, "fill_address", hex(fill), "fill_bytes", fillBytes,
            "stack_base", hex(stack), "stack_offset", hex(offset), "initial_sp", stack == 0 ? null : hex(stack + offset));
        validateDeclarations(result);
        return result;
    }

    private static long unsigned(ByteBuffer bytes, int offset) { return Integer.toUnsignedLong(bytes.getInt(offset)); }

    private static void validateDeclarations(JsonObject declaration) {
        object(declaration, DECLARATION_KEYS);
        long fileBytes = number(declaration, "file_bytes"), payloadBytes = number(declaration, "payload_bytes"), fillBytes = number(declaration, "fill_bytes");
        equal(number(declaration, "payload_file_offset"), 2048L, "payload file offset");
        equal(number(declaration, "trailing_bytes"), fileBytes - 2048 - payloadBytes, "trailing file bytes");
        long payload = parseAddress(text(declaration, "payload_address")), pc = parseAddress(text(declaration, "initial_pc"));
        long fill = parseAddress(text(declaration, "fill_address"));
        parseAddress(text(declaration, "initial_gp"));
        long stack = parseAddress(text(declaration, "stack_base")), offset = parseAddress(text(declaration, "stack_offset"));
        JsonElement sp = declaration.get("initial_sp");
        if (stack == 0) { if (!sp.isJsonNull()) throw invalid("Zero stack base requires an unknown declared initial SP"); }
        else {
            if (stack + offset > 0xffffffffL) throw invalid("Declared stack address overflows 32 bits");
            equal(text(declaration, "initial_sp"), hex(stack + offset), "declared initial SP");
        }
        if (payloadBytes == 0 || payload % 4 != 0 || pc % 4 != 0 || !bank(payload, payloadBytes) ||
            !bank(pc, 4) || pc < payload || pc + 4 > payload + payloadBytes) throw invalid("Payload and complete entry instruction violate KSEG0 2 MiB policy");
        if (fillBytes != 0 && (!bank(fill, fillBytes) || (fill < payload + payloadBytes && payload < fill + fillBytes))) {
            throw invalid("Declared fill violates KSEG0 policy or overlaps payload");
        }
        if (parseAddress(text(declaration, "data_address")) != 0 || number(declaration, "data_bytes") != 0) throw invalid("Initial PSX import policy requires zero data declarations");
    }

    private static boolean bank(long start, long bytes) { return start >= RAM_BASE && bytes > 0 && start + bytes <= RAM_BASE + RAM_SIZE; }

    private static void validateObservation(JsonObject record, String stage, JsonObject descriptor, JsonObject expected) throws Exception {
        object(record, Set.of("schema_version", "stage", "commitment", "observed"));
        equal(number(record, "schema_version"), 1L, "observation schema version");
        equal(text(record, "stage"), stage, "observation stage");
        equal(object(record.get("commitment"), Set.of("run_id", "profile_digest", "source_sha256")), correlation(descriptor), "observation correlation");
        JsonObject observed = object(record.get("observed"), OBSERVED_KEYS);
        equal(text(observed, "ghidra_version"), text(descriptor, "provider_version"), "observed Ghidra version");
        JsonObject source = object(observed.get("source"), Set.of("snapshot_path", "sha256", "file_bytes"));
        Path sourcePath = Path.of(text(source, "snapshot_path"));
        if (!sourcePath.isAbsolute() || !Files.isSameFile(sourcePath, Path.of(text(expected, "source_snapshot_path")))) throw invalid("Observed snapshot identity disagrees");
        equal(digest(source, "sha256"), text(expected, "source_sha256"), "observed source digest");
        equal(number(source, "file_bytes"), number(expected.getAsJsonObject("declarations"), "file_bytes"), "observed source size");
        JsonObject program = object(observed.get("program"), Set.of("executable_path", "executable_format", "language_id", "compiler_spec_id", "image_base", "default_address_space", "ram_size", "external_entries"));
        Path executable = Path.of(text(program, "executable_path"));
        if (!executable.isAbsolute() || !Files.isSameFile(sourcePath, executable)) throw invalid("Observed program source identity disagrees");
        equal(text(program, "executable_format"), FORMAT, "observed executable format");
        equal(text(program, "language_id"), LANGUAGE, "observed language");
        equal(text(program, "compiler_spec_id"), "default", "observed compiler");
        equal(text(program, "image_base"), hex(RAM_BASE), "observed image base");
        equal(text(program, "default_address_space"), "ram", "observed default address space");
        equal(number(program, "ram_size"), RAM_SIZE, "observed effective RAM size");
        String previous = null;
        boolean entryFound = false;
        for (JsonElement entry : array(program, "external_entries")) {
            String current = string(entry); parseAddress(current); previous = ordered(previous, current);
            entryFound |= current.equals(text(expected.getAsJsonObject("declarations"), "initial_pc"));
        }
        if (!entryFound) throw invalid("Observed entries omit declared initial PC");
        equal(text(observed, "loader_selector"), "PsxLoader", "observed selector");
        equal(text(observed, "loader_class"), "psx.PsxLoader", "observed loader class");
        JsonObject defaults = object(observed.get("advertised_defaults"), Set.of("ram_start", "ram_size"));
        validateOption(defaults.get("ram_start"), "-loader-ramStart", RAM_BASE);
        validateOption(defaults.get("ram_size"), "-loader-ramSize", RAM_SIZE);
        previous = null; boolean loaderFound = false, mipsFound = false;
        for (JsonElement element : array(observed, "selected_classes")) {
            JsonObject cls = object(element, Set.of("class_name", "role", "code_source_url", "code_source_relative", "code_source_sha256", "class_resource_url", "enabled"));
            String name = text(cls, "class_name"); previous = ordered(previous, name);
            String rel = text(cls, "code_source_relative"); relative(rel); digest(cls, "code_source_sha256");
            URI.create(text(cls, "code_source_url")).toURL(); URI.create(text(cls, "class_resource_url")).toURL();
            String role = text(cls, "role");
            JsonElement enabled = cls.get("enabled");
            if (!enabled.isJsonNull() && (!enabled.isJsonPrimitive() || !enabled.getAsJsonPrimitive().isBoolean())) throw invalid("Analyzer enabled observation must be boolean or unknown");
            if (role.equals("loader")) {
                if (!name.equals("psx.PsxLoader") || !enabled.isJsonNull() || loaderFound) throw invalid("Invalid observed loader identity");
                loaderFound = true;
                equal(rel, text(expected.getAsJsonObject("loader"), "code_source_relative"), "observed loader code source");
                equal(text(cls, "code_source_sha256"), text(expected.getAsJsonObject("loader"), "code_source_sha256"), "observed loader code digest");
            }
            else if (!role.equals("analyzer")) throw invalid("Unknown selected class role");
            mipsFound |= role.equals("analyzer") && name.equals("ghidra.app.plugin.core.analysis.MipsPreAnalyzer") && rel.equals("Ghidra/Processors/MIPS/lib/MIPS.jar");
        }
        if (!loaderFound || !mipsFound) throw invalid("Observation omits loader or core MipsPreAnalyzer");
        previous = null;
        for (JsonElement element : array(observed, "language_assets")) {
            JsonObject asset = object(element, Set.of("relative_path", "sha256"));
            String rel = text(asset, "relative_path"); relative(rel); previous = ordered(previous, rel); digest(asset, "sha256");
        }
        if (previous == null) throw invalid("Observation omits language assets");
        equal(text(observed, "asset_inventory_version"), INVENTORY_VERSION, "observed inventory version");
        equal(digest(observed, "asset_inventory_digest"), text(expected, "asset_inventory_digest"), "observed inventory digest");
    }

    private static void validateOption(JsonElement element, String argument, long value) {
        JsonObject option = object(element, Set.of("argument", "value_class", "value"));
        equal(text(option, "argument"), argument, "advertised option argument");
        equal(text(option, "value_class"), "java.lang.String", "advertised option value class");
        equal(parseAddress(text(option, "value")), value, "advertised option value");
    }

    private static JsonObject correlation(JsonObject descriptor) {
        return obj("run_id", text(descriptor, "run_id"), "profile_digest", digest(descriptor, "profile_digest"), "source_sha256", digest(descriptor, "target_sha256"));
    }

    private static String ordered(String previous, String current) {
        if (previous != null && previous.compareTo(current) >= 0) throw invalid("Observation identities must be sorted and unique");
        return current;
    }

    private static Path beforePath(Path descriptor) throws IOException {
        if (!descriptor.isAbsolute()) throw invalid("PSX descriptor must have an absolute private session path");
        Path parent = descriptor.getParent();
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) throw invalid("PSX private session parent must be a directory");
        return parent.resolve("psx-import-before.json");
    }

    private static BasicFileAttributes attributes(Path path) throws IOException { return Files.readAttributes(path, BasicFileAttributes.class); }

    private static void requireRegular(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw invalid("Expected an owned regular file: " + path);
    }

    private static void stable(BasicFileAttributes before, BasicFileAttributes after, Path path) {
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
            !before.creationTime().equals(after.creationTime()) || !Objects.equals(before.fileKey(), after.fileKey())) throw invalid("Resource changed while being observed: " + path);
    }

    private static String hashFile(Path path, TaskMonitor monitor) throws Exception {
        BasicFileAttributes initial = attributes(path);
        if (!initial.isRegularFile()) throw invalid("Resource is not a regular file: " + path);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long bytes = 0;
        try (var input = Files.newInputStream(path)) {
            byte[] chunk = new byte[65536]; int count;
            while ((count = input.read(chunk)) >= 0) {
                monitor.checkCancelled(); digest.update(chunk, 0, count); bytes += count;
            }
        }
        stable(initial, attributes(path), path);
        if (bytes != initial.size()) throw invalid("Truncated resource hash: " + path);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String hashBytes(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static String hex(long value) { return "0x" + Long.toHexString(value); }
    private static String address(Address address) { return "0x" + address.getOffsetAsBigInteger().toString(16); }

    private static long parseAddress(String value) {
        if (!value.matches("0x(?:0|[1-9a-f][0-9a-f]*)")) throw invalid("Expected canonical lowercase hexadecimal address: " + value);
        try {
            long result = Long.parseLong(value.substring(2), 16);
            if (result > 0xffffffffL) throw invalid("Address exceeds the PSX 32-bit range");
            return result;
        }
        catch (NumberFormatException exception) { throw invalid("Address exceeds the PSX 32-bit range"); }
    }

    private static void relative(String value) {
        if (value.startsWith("/") || value.contains("\\")) throw invalid("Expected installation-relative path");
        for (String part : value.split("/", -1)) if (part.isEmpty() || part.equals(".") || part.equals("..")) throw invalid("Expected installation-relative path");
    }

    private static JsonArray array(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonArray()) throw invalid("Expected JSON array: " + key);
        return value.getAsJsonArray();
    }

    private static JsonObject object(JsonElement value, Set<String> keys) {
        if (value == null || !value.isJsonObject() || !value.getAsJsonObject().keySet().equals(keys)) throw invalid("Unexpected PSX object fields; expected " + keys);
        return value.getAsJsonObject();
    }

    private static String string(JsonElement value) {
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString() || value.getAsString().isEmpty()) throw invalid("Expected nonempty JSON string");
        return value.getAsString();
    }
    private static String text(JsonObject object, String key) { return string(object.get(key)); }
    private static String digest(JsonObject object, String key) {
        String value = text(object, key);
        if (!value.matches("[a-f0-9]{64}")) throw invalid("Expected lowercase SHA-256: " + key);
        return value;
    }
    private static long number(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) throw invalid("Expected nonnegative safe integer: " + key);
        try {
            long result = value.getAsBigDecimal().longValueExact();
            if (result < 0 || result > MAX_SAFE_INTEGER) throw invalid("Expected nonnegative safe integer: " + key);
            return result;
        }
        catch (ArithmeticException exception) { throw invalid("Expected nonnegative safe integer: " + key); }
    }
    private static JsonObject obj(Object... values) {
        JsonObject object = new JsonObject();
        for (int index = 0; index < values.length; index += 2) object.add((String) values[index], GSON.toJsonTree(values[index + 1]));
        return object;
    }
    private static void equal(Object actual, Object expected, String description) {
        if (!Objects.equals(actual, expected)) throw invalid(description + " disagrees with the PSX import commitment");
    }
    private static IllegalArgumentException invalid(String reason) { return new IllegalArgumentException(reason); }

    /** Reject duplicate keys rather than allowing Gson's last-value-wins projection. */
    private static JsonElement parseJson(String input) throws IOException {
        try (JsonReader reader = new JsonReader(new StringReader(input))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement value = readJson(reader);
            if (reader.peek() != JsonToken.END_DOCUMENT) throw invalid("Trailing PSX JSON content");
            return value;
        }
    }
    private static JsonElement readJson(JsonReader reader) throws IOException {
        switch (reader.peek()) {
            case BEGIN_OBJECT: {
                reader.beginObject(); JsonObject object = new JsonObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (object.has(key)) throw invalid("Duplicate PSX JSON field: " + key);
                    object.add(key, readJson(reader));
                }
                reader.endObject(); return object;
            }
            case BEGIN_ARRAY: {
                reader.beginArray(); JsonArray array = new JsonArray();
                while (reader.hasNext()) array.add(readJson(reader));
                reader.endArray(); return array;
            }
            case STRING: return new JsonPrimitive(reader.nextString());
            case NUMBER: return new JsonPrimitive(new BigDecimal(reader.nextString()));
            case BOOLEAN: return new JsonPrimitive(reader.nextBoolean());
            case NULL: reader.nextNull(); return JsonNull.INSTANCE;
            default: throw invalid("Invalid PSX JSON value");
        }
    }
}
