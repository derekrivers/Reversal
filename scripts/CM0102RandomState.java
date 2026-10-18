// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102RandomState extends GhidraScript {
    public void run() throws Exception {
        Path out=Paths.get(getScriptArgs()[0]);Files.createDirectories(out.resolve("pseudocode"));Files.createDirectories(out.resolve("assembly"));
        Map<String,Object> root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());
        long[] addresses={0x00de1f5cL,0x00de1f60L,0x00de2798L,0x00ad6c30L,0x00aa2454L,0x00970a70L};
        List<Object> globals=new ArrayList<>();LinkedHashMap<String,Function> functions=new LinkedHashMap<>();
        for(long n:addresses) {
            var address=toAddr(n);Map<String,Object> item=new LinkedHashMap<>();item.put("address",address.toString());
            item.put("loaded_u32",Integer.toUnsignedLong(currentProgram.getMemory().getInt(address)));
            item.put("loaded_u64_hex",Long.toUnsignedString(currentProgram.getMemory().getLong(address),16));
            List<Object> refs=new ArrayList<>();ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(address);
            while(it.hasNext()) {Reference ref=it.next();Map<String,Object> r=new LinkedHashMap<>();r.put("site",ref.getFromAddress().toString());r.put("type",ref.getReferenceType().toString());
                Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if(f!=null) {r.put("function",f.getEntryPoint().toString());if(ref.getReferenceType().isWrite())functions.put(f.getEntryPoint().toString(),f);}refs.add(r);
            }item.put("references",refs);globals.add(item);
        }
        long[] extras={0x0090d0a0L,0x006b98c0L};
        for(long n:extras){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(n));if(f!=null)functions.put(f.getEntryPoint().toString(),f);}
        root.put("globals",globals);List<Object> exports=new ArrayList<>();DecompInterface dc=new DecompInterface();dc.openProgram(currentProgram);
        try{for(Function f:functions.values()){
            Map<String,Object> x=new LinkedHashMap<>();String entry=f.getEntryPoint().toString();x.put("entry",entry);x.put("bytes",f.getBody().getNumAddresses());
            DecompileResults result=dc.decompileFunction(f,60,monitor);x.put("completed",result.decompileCompleted());x.put("error",result.getErrorMessage());
            if(result.decompileCompleted()){String file="pseudocode/"+entry+".c";Files.writeString(out.resolve(file),result.getDecompiledFunction().getC());x.put("pseudocode",file);}
            try(PrintWriter writer=new PrintWriter(out.resolve("assembly/"+entry+".asm").toFile())){for(Instruction i:currentProgram.getListing().getInstructions(f.getBody(),true))writer.println(i.getAddress()+"  "+i);}
            exports.add(x);
        }}finally{dc.dispose();}
        root.put("exports",exports);root.put("limitations",Arrays.asList("Loaded initial bytes, not observed live game state", "Only references found at exact global addresses are enumerated", "Save/load or pointer aliases may access state without direct references"));
        try(Writer writer=Files.newBufferedWriter(out.resolve("random-state.json"))){new GsonBuilder().setPrettyPrinting().create().toJson(root,writer);}
        println("Exported random-state references and "+functions.size()+" functions");
    }
}
