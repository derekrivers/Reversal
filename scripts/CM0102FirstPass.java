// Read-only static export. Does not launch the target executable.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102FirstPass extends GhidraScript {
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(out.resolve("pseudocode"));
        Map<String,Object> root = new LinkedHashMap<>();
        root.put("program", currentProgram.getName());
        root.put("sha256", currentProgram.getExecutableSHA256());
        root.put("language", currentProgram.getLanguageID().toString());
        root.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        root.put("function_count", currentProgram.getFunctionManager().getFunctionCount());
        root.put("function_count_includes_external_symbols", true);
        root.put("evidence_type", "static_analysis_only");
        List<Object> anchors = new ArrayList<>();
        LinkedHashMap<String,Function> candidates = new LinkedHashMap<>();
        int sourcePaths = 0;
        int inventoryCount = 0;
        try (PrintWriter inventory = new PrintWriter(out.resolve("functions.tsv").toFile())) {
            inventory.println("entry\tname\tbody_bytes");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                inventory.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+f.getBody().getNumAddresses());
                inventoryCount++;
            }
        }
        root.put("internal_function_inventory_count", inventoryCount);
        int externalCount = 0;
        for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) externalCount++;
        root.put("external_function_symbol_count", externalCount);
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (!(d.getValue() instanceof String)) continue;
            String s = (String)d.getValue();
            String lower = s.toLowerCase(Locale.ROOT);
            if (lower.contains("\\code\\") && (lower.endsWith(".cpp") || lower.endsWith(".c"))) sourcePaths++;
            boolean selected = lower.endsWith("\\match_eng.cpp") || lower.endsWith("\\match_events.cpp") ||
                lower.endsWith("\\match_pl.cpp") || lower.endsWith("\\tactics.cpp") ||
                lower.endsWith("\\database.cpp") || s.equals("index.dat") || s.equals("player.dat") || s.equals("3.9.68");
            if (!selected) continue;
            Map<String,Object> a = new LinkedHashMap<>();
            a.put("address", d.getAddress().toString()); a.put("string", s);
            List<Object> refs = new ArrayList<>();
            int n = 0;
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
            while (it.hasNext()) {
                Reference r = it.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                Map<String,Object> ref = new LinkedHashMap<>();
                ref.put("from", r.getFromAddress().toString()); ref.put("type", r.getReferenceType().toString());
                if (f != null) {
                    ref.put("function_entry", f.getEntryPoint().toString()); ref.put("function_name", f.getName());
                    if (n < 2) candidates.put(f.getEntryPoint().toString(), f);
                }
                refs.add(ref); n++;
            }
            a.put("references", refs); anchors.add(a);
        }
        root.put("embedded_source_path_count", sourcePaths);
        root.put("anchors", anchors);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        List<Object> exports = new ArrayList<>();
        try {
            int count = 0;
            for (Function f : candidates.values()) {
                if (count++ >= 12) break;
                DecompileResults r = decompiler.decompileFunction(f, 45, monitor);
                Map<String,Object> entry = new LinkedHashMap<>();
                entry.put("entry", f.getEntryPoint().toString());
                entry.put("completed", r.decompileCompleted()); entry.put("error", r.getErrorMessage());
                if (r.decompileCompleted()) {
                    String filename = "pseudocode/"+f.getEntryPoint()+".c";
                    Files.writeString(out.resolve(filename), "/* Ghidra recovered pseudocode; names and types are provisional. */\n"+r.getDecompiledFunction().getC());
                    entry.put("file", filename);
                }
                exports.add(entry);
            }
        } finally { decompiler.dispose(); }
        root.put("decompilations", exports);
        root.put("limitations", Arrays.asList("No target execution or behavioral equivalence testing", "Source path references are investigation anchors, not recovered original function names", "Ghidra function boundaries and types are inferred", "Starter Kit executable patch state is unverified", "This export ran directly in Ghidra because REA native launch failed its process ownership check"));
        try (Writer w = Files.newBufferedWriter(out.resolve("ghidra-first-pass.json"))) {
            new GsonBuilder().setPrettyPrinting().create().toJson(root,w);
        }
        println("CM0102 first-pass export complete: "+out);
    }
}
