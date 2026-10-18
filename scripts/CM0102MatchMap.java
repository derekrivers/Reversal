// Read-only graph, assembly and decompilation export for the pinned CM 01/02 image.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102MatchMap extends GhidraScript {
    LinkedHashMap<String,Function> selected = new LinkedHashMap<>();
    LinkedHashMap<String,Function> decompile = new LinkedHashMap<>();
    String id(Function f) { return f.getEntryPoint().toString(); }
    void add(Function f, boolean code) {
        if (f == null || f.isExternal()) return;
        selected.put(id(f),f);
        if (code) decompile.put(id(f),f);
    }
    Map<String,Object> identity(Function f) {
        Map<String,Object> x = new LinkedHashMap<>();
        x.put("entry",id(f)); x.put("name",f.getName()); x.put("bytes",f.getBody().getNumAddresses());
        x.put("prototype",f.getPrototypeString(false,false)); x.put("external",f.isExternal());
        return x;
    }
    List<Function> directCallees(Function f) {
        LinkedHashMap<String,Function> found = new LinkedHashMap<>();
        for (Instruction instruction : currentProgram.getListing().getInstructions(f.getBody(),true))
            for (Reference reference : instruction.getReferencesFrom())
                if (reference.getReferenceType().isCall()) {
                    Function target = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                    if (target != null) found.put(id(target),target);
                }
        return new ArrayList<>(found.values());
    }
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(out.resolve("pseudocode")); Files.createDirectories(out.resolve("assembly"));
        long centerAddress=getScriptArgs().length>1 ? Long.parseLong(getScriptArgs()[1],16) : 0x006b7f20L;
        Function entry=currentProgram.getFunctionManager().getFunctionAt(toAddr(centerAddress));
        add(entry,true);
        for (Function f : directCallees(entry)) add(f,true);
        ReferenceIterator entryRefs=currentProgram.getReferenceManager().getReferencesTo(entry.getEntryPoint());
        while(entryRefs.hasNext()) {
            Reference r=entryRefs.next();
            if(r.getReferenceType().isCall()) add(currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress()),true);
        }
        // Source-path seeds observed in the earlier export. These are a bounded
        // investigation seed set, not a claim that the entire engine is covered.
        long[] seeds={0x006b7f20L,0x006b98c0L,0x006c0c60L,0x006c4290L,0x006c4470L,0x006c4820L,0x006c4ec0L,0x006c54a0L,0x006c87e0L,0x006cdd50L,0x006ceb90L,0x006d1770L,0x006d47e0L};
        for(long address:seeds) add(currentProgram.getFunctionManager().getFunctionAt(toAddr(address)),false);
        Function random=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x0090cfc0L));
        add(random,true);
        for(Function f:directCallees(random)) { add(f,true); for(Function g:directCallees(f)) add(g,true); }
        if(getScriptArgs().length>2) for(String value:getScriptArgs()[2].split(",")) {
            Function focus=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(value,16)));
            add(focus,true);if(focus!=null) for(Function f:directCallees(focus)) add(f,true);
        }
        Map<String,Object> root=new LinkedHashMap<>();
        root.put("sha256",currentProgram.getExecutableSHA256()); root.put("evidence_type","static_analysis");
        root.put("center_entry",id(entry)); root.put("selected_function_count",selected.size());
        List<Object> functions=new ArrayList<>();
        DecompInterface dc=new DecompInterface(); dc.openProgram(currentProgram);
        try {
            for(Function f:selected.values()) {
                Map<String,Object> item=identity(f); List<Object> calls=new ArrayList<>(); List<Object> dataRefs=new ArrayList<>();
                int unresolved=0;
                try(PrintWriter asm=new PrintWriter(out.resolve("assembly/"+id(f)+".asm").toFile())) {
                    for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)) {
                        asm.println(ins.getAddress()+"  "+ins.toString());
                        if(ins.getFlowType().isCall() && ins.getFlows().length==0) unresolved++;
                        for(Reference r:ins.getReferencesFrom()) {
                            if(r.getReferenceType().isCall()) {
                                Map<String,Object> call=new LinkedHashMap<>();call.put("site",ins.getAddress().toString());call.put("target",r.getToAddress().toString());
                                Function target=currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
                                if(target!=null) call.put("function",identity(target));calls.add(call);
                            } else if(r.getReferenceType().isData()) {
                                Map<String,Object> ref=new LinkedHashMap<>();ref.put("site",ins.getAddress().toString());ref.put("target",r.getToAddress().toString());ref.put("type",r.getReferenceType().toString());
                                Data data=currentProgram.getListing().getDataContaining(r.getToAddress());
                                if(data!=null && data.getValue() instanceof String) ref.put("string",data.getValue());
                                dataRefs.add(ref);
                            }
                        }
                    }
                }
                List<Object> incoming=new ArrayList<>();ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while(refs.hasNext()) {
                    Reference r=refs.next();if(!r.getReferenceType().isCall()) continue;
                    Map<String,Object> ref=new LinkedHashMap<>();ref.put("site",r.getFromAddress().toString());
                    Function caller=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());if(caller!=null) ref.put("caller",identity(caller)); incoming.add(ref);
                }
                item.put("calls",calls);item.put("incoming_entry_call_references",incoming);item.put("data_references",dataRefs);item.put("unresolved_indirect_call_instructions",unresolved);
                item.put("assembly","assembly/"+id(f)+".asm");
                if(decompile.containsKey(id(f))) {
                    DecompileResults r=dc.decompileFunction(f,45,monitor);item.put("decompile_completed",r.decompileCompleted());item.put("decompile_error",r.getErrorMessage());
                    if(r.decompileCompleted()) {String file="pseudocode/"+id(f)+".c";Files.writeString(out.resolve(file),"/* Recovered pseudocode: names, types and calling conventions may be wrong. */\n"+r.getDecompiledFunction().getC());item.put("pseudocode",file);}
                }
                functions.add(item);
            }
        } finally {dc.dispose();}
        root.put("functions",functions);
        root.put("limitations",Arrays.asList("No game execution; static references and inferred function boundaries", "Indirect calls and tail jumps may be absent from direct-call edges", "Incoming references are to observed function entry addresses", "Source-path seed functions are not the complete engine", "Types, prototypes and unsigned/signed expressions require assembly verification"));
        try(Writer writer=Files.newBufferedWriter(out.resolve("match-map.json"))) {new GsonBuilder().setPrettyPrinting().create().toJson(root,writer);}
        println("Exported "+selected.size()+" selected functions, "+decompile.size()+" decompilation requests");
    }
}
