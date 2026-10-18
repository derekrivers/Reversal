// Whole-program factual inventory, without bulk decompilation or game bytes.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102Inventory extends GhidraScript {
 public void run()throws Exception {
  Path out=Paths.get(getScriptArgs()[0]);Files.createDirectories(out);
  Map<String,Set<String>> unitsByFunction=new TreeMap<>();List<Object>units=new ArrayList<>();
  for(Data d:currentProgram.getListing().getDefinedData(true)) {
   if(!(d.getValue() instanceof String))continue;
   String path=(String)d.getValue();String lower=path.toLowerCase(Locale.ROOT);
   if(!lower.contains("\\code\\")||!(lower.endsWith(".cpp")||lower.endsWith(".c")))continue;
   String unit=path.substring(path.lastIndexOf('\\')+1);Map<String,Object>row=new LinkedHashMap<>();
   row.put("unit",unit);row.put("original_path",path);row.put("string_address",d.getAddress().toString());List<Object>refs=new ArrayList<>();
   ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
   while(it.hasNext()){Reference r=it.next();Function f=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
    Map<String,Object>x=new LinkedHashMap<>();x.put("site",r.getFromAddress().toString());x.put("reference_type",r.getReferenceType().toString());
    if(f!=null){String id=f.getEntryPoint().toString();x.put("function",id);unitsByFunction.computeIfAbsent(id,k->new TreeSet<>()).add(unit);}
    refs.add(x);
   }row.put("references",refs);units.add(row);
  }
  AddressSet bodies=new AddressSet(),executable=new AddressSet();
  for(var block:currentProgram.getMemory().getBlocks())if(block.isExecute())executable.add(block.getStart(),block.getEnd());
  List<Object>functions=new ArrayList<>();int named=0,sourceAnchored=0,totalCalls=0,unresolved=0;
  for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
   monitor.checkCancelled();String id=f.getEntryPoint().toString();Map<String,Object>row=new LinkedHashMap<>();
   row.put("entry",id);row.put("name",f.getName());row.put("body_bytes",f.getBody().getNumAddresses());row.put("body_min",f.getBody().getMinAddress().toString());row.put("body_max",f.getBody().getMaxAddress().toString());
   boolean working=f.getName().startsWith("cm0102_");row.put("working_research_name",working);if(working)named++;
   Set<String>source=unitsByFunction.getOrDefault(id,Collections.emptySet());row.put("direct_source_units",source);if(!source.isEmpty())sourceAnchored++;
   Set<String>callees=new TreeSet<>();List<String>indirect=new ArrayList<>();int calls=0;
   for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)){
    if(ins.getFlowType().isCall()){calls++;if(ins.getFlows().length==0)indirect.add(ins.getAddress().toString());}
    for(Reference r:ins.getReferencesFrom())if(r.getReferenceType().isCall())callees.add(r.getToAddress().toString());
   }
   row.put("direct_callees",callees);row.put("call_instruction_count",calls);row.put("unresolved_indirect_call_sites",indirect);
   functions.add(row);bodies.add(f.getBody());totalCalls+=calls;unresolved+=indirect.size();
  }
  List<Object>external=new ArrayList<>();for(Function f:currentProgram.getFunctionManager().getExternalFunctions()){
   Map<String,Object>x=new LinkedHashMap<>();x.put("entry",f.getEntryPoint().toString());x.put("name",f.getName());external.add(x);
  }
  Map<String,Object>summary=new LinkedHashMap<>();summary.put("internal_functions",functions.size());summary.put("external_function_symbols",external.size());
  summary.put("source_path_strings",units.size());summary.put("functions_with_direct_source_path_reference",sourceAnchored);summary.put("functions_with_working_research_name",named);
  summary.put("call_instructions",totalCalls);summary.put("unresolved_indirect_call_instructions",unresolved);summary.put("executable_memory_bytes",executable.getNumAddresses());
  summary.put("executable_bytes_in_inferred_function_bodies",bodies.intersect(executable).getNumAddresses());
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("ghidra","12.1.4");root.put("counts",summary);
  root.put("functions",functions);root.put("external_functions",external);root.put("source_units",units);
  root.put("limitations",Arrays.asList("Inventory of Ghidra-inferred function boundaries, not recovered original source", "Direct source-path references are anchors, not exclusive ownership or recovered class names", "Indirect calls, tail jumps, inlining, data-driven dispatch and undiscovered code limit graph completeness", "Executable byte coverage is structural, not semantic or behavioral reconstruction progress", "No pseudocode or executable bytes are included"));
  Files.writeString(out.resolve("program-inventory.json"),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");
  println("Program inventory: "+summary);
 }
}
