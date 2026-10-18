// Static control-word instruction inventory; not a runtime control-state trace.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102FloatControlSites extends GhidraScript {
 public void run() throws Exception {
  List<Object>sites=new ArrayList<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)) {
   String m=i.getMnemonicString();if(!Arrays.asList("FLDCW","FSTCW","FNSTCW","FINIT","FNINIT").contains(m))continue;
   Map<String,Object>row=new LinkedHashMap<>();row.put("address",i.getAddress().toString());row.put("mnemonic",m);
   Function f=currentProgram.getFunctionManager().getFunctionContaining(i.getAddress());
   if(f!=null){row.put("function",f.getEntryPoint().toString());List<String>incoming=new ArrayList<>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
    int count=0;while(it.hasNext()){Reference r=it.next();if(r.getReferenceType().isCall()){count++;if(incoming.size()<16)incoming.add(r.getFromAddress().toString());}}row.put("incoming_call_count",count);row.put("first_incoming_calls",incoming);
   }
   List<Object>refs=new ArrayList<>();for(Reference r:i.getReferencesFrom())if(r.getReferenceType().isData()){
    Map<String,Object>ref=new LinkedHashMap<>();ref.put("address",r.getToAddress().toString());
    if(currentProgram.getMemory().contains(r.getToAddress()))ref.put("word",currentProgram.getMemory().getShort(r.getToAddress())&65535);refs.add(ref);
   }row.put("data_refs",refs);sites.add(row);
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("sites",sites);root.put("limitations","Inferred instruction inventory; entry-state/runtime control word is not established by this list.");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");
 }
}
