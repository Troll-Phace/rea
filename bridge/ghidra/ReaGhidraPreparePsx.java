// REA's read-only observer after import and before auto-analysis.
// @category REA

import ghidra.app.util.headless.HeadlessScript;
import java.nio.file.Path;

public final class ReaGhidraPreparePsx extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || currentProgram == null) {
            throw new IllegalArgumentException("REA PSX preparation requires one descriptor and an imported program");
        }
        Path descriptor = Path.of(arguments[0]);
        String marker = ReaGhidraPsxImport.prepare(descriptor, currentProgram, monitor);
        // Exceptions produce no marker. Ghidra may continue to its postScript;
        // the bridge independently requires the complete private before record.
        println(marker);
    }
}
