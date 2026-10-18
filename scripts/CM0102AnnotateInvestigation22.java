// Apply reviewed investigation-22 working names to checkpoint 21.
// Name-only transaction; the original PE and program types are unchanged.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation22 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String B_PREFLIGHT="03c82ef51e320c9483697b2446ad4421da7e96bd0068532d88f4a26cd5753560";
 private static final String D_PREFLIGHT="239bc3cbef548589d959c9cc123726b5f910d0f48873c4b627aaef94640eb27d";
 private static final Set<String> A=Set.of("0062c3d0","0062c590");
 private static final Set<String> B=Set.of("006ceb90");
 private static final Set<String> D=Set.of("005a8f60","0090d130","00945934");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 22 precondition: "+what);}
 private void collect(String path,Set<String> allowed,String preflight,String preflightKey,boolean scalar,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen "+path);
  if(preflightKey==null)require("checkpoint 21".equals(doc.get("native_baseline").getAsString()),"proposal baseline "+path);
  else require(preflight.equals(doc.get(preflightKey).getAsString()),"proposal preflight "+path);
  JsonArray proposals=doc.getAsJsonArray("proposals");Set<String> local=new HashSet<>();
  for(JsonElement item:proposals){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   require(a.matches("[0-9a-f]{8}")&&allowed.contains(a)&&local.add(a)&&seen.add(a),"proposal address "+a);
   if(!scalar)require("function_name".equals(p.get("kind").getAsString()),"proposal kind "+a);
   String old=p.get(scalar?"old_name":"old").getAsString(),name=p.get(scalar?"new_name":"new").getAsString();
   require(old.equals("FUN_"+a)&&!name.isBlank()&&!name.equals(old),"proposal names "+a);
   var address=toAddr(Long.parseLong(a,16));Function f=currentProgram.getFunctionManager().getFunctionAt(address);
   require(f!=null&&old.equals(f.getName()),"old function "+a);
   require(f.getComment()==null||f.getComment().isBlank(),"old function comment "+a);
   require(currentProgram.getListing().getInstructionAt(address)!=null,"entry instruction "+a);
   JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
  }
  require(local.equals(allowed),"complete proposal set "+path);
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==4,"Use OUTPUT_JSON SCALAR_PROPOSALS SELECTION_PROPOSALS RUNTIME_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function corrected=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x006f09f0L));
  require(corrected!=null&&corrected.getBody().getNumAddresses()==14547,"corrected match body size");
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collect(args[1],A,"",null,true,rows,seen);
  collect(args[2],B,B_PREFLIGHT,"private_preflight_sha256",false,rows,seen);
  collect(args[3],D,D_PREFLIGHT,"preflight_sha256",false,rows,seen);
  require(rows.size()==6,"six reviewed names");
  int tx=currentProgram.startTransaction("Investigation 22 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows)currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get(0).getAsString(),16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",22);
  receipt.addProperty("scope","Six reviewed working names only; one bounded execution validation and six other static local contracts. Existing __ftol name unchanged. No prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-scalar-22-annotations-proposal.json");sources.add("match-selection-22-annotations.json");sources.add("match-runtime-22-annotations-proposal.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 22: "+rows.size()+" working names");
 }
}
