// Read-only references to commentary loader strings and recovered event globals.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102TraceEventRefs extends GhidraScript {
 public void run() throws Exception {
  List<Object> rows=new ArrayList<>();
  long[] seeds={0x00a15aa0L,0x00a15af0L,0x00a15b38L,0x00a15bacL,0x00a15c3cL};
  List<Long> targets=new ArrayList<>();for(long a:seeds)targets.add(a);
  for(long a=0x00b68788L;a<0x00b6879aL;a++)targets.add(a);
  for(long a:targets){var refs=currentProgram.getReferenceManager().getReferencesTo(toAddr(a));
   while(refs.hasNext()){Reference r=refs.next();Map<String,Object> x=new LinkedHashMap<>();
    x.put("target",toAddr(a).toString());x.put("from",r.getFromAddress().toString());x.put("type",r.getReferenceType().toString());
    Function f=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
    if(f!=null){x.put("function",f.getEntryPoint().toString());x.put("name",f.getName());}
    List<String> context=new ArrayList<>();Instruction ins=currentProgram.getListing().getInstructionAt(r.getFromAddress());
    if(ins!=null){for(int i=0;i<5&&ins.getPrevious()!=null;i++)ins=ins.getPrevious();for(int i=0;i<12&&ins!=null;i++,ins=ins.getNext())context.add(ins.getAddress()+" "+ins);}
    x.put("context",context);rows.add(x);
   }
  }
  List<Object> candidateWrites=new ArrayList<>();
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   String text=ins.toString().toLowerCase().replace(" ","");
   if(text.contains("+0x1a8]")&&text.startsWith("mov")){
    Map<String,Object>x=new LinkedHashMap<>();x.put("instruction",ins.getAddress()+" "+ins);
    Function f=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());if(f!=null)x.put("function",f.getEntryPoint().toString());candidateWrites.add(x);
   }
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("references",rows);root.put("candidate_1a8_moves",candidateWrites);
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root));
  println("Event references: "+rows.size()+", candidate +1a8 moves: "+candidateWrites.size());
 }
}
