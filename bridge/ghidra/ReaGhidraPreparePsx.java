// REA's owned disposable-database preparation after import, before auto-analysis.
// Payload provenance adaptation changes Program state; executable bytes remain immutable.
// @category REA

import ghidra.app.util.headless.HeadlessScript;
import java.nio.file.Path;

public final class ReaGhidraPreparePsx extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || currentProgram == null || !isRunningHeadless()) {
            throw new IllegalArgumentException("REA PSX preparation requires one descriptor and an imported program");
        }
        // GhidraScript starts this instance's transaction before run(). Release only
        // that owned wrapper; a remaining transaction belongs to somebody else.
        // Public installed APIs: GhidraScript.executeNormal and FlatProgramAPI.end.
        // https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Features/Base/src/main/java/ghidra/program/flatapi/FlatProgramAPI.java
        try { end(true); }
        catch (Exception failure) { throw ReaGhidraPsxProvenance.failureAt(currentProgram, "wrapper-release", failure); }
        ReaGhidraPsxProvenance.requireNoTransaction(currentProgram, "wrapper-release");
        Path descriptor = Path.of(arguments[0]);
        String marker = ReaGhidraPsxImport.prepare(descriptor, currentProgram, monitor);
        // Exceptions produce no marker. Ghidra may continue to its postScript;
        // the bridge independently requires the complete private before record.
        println(marker);
    }
}
