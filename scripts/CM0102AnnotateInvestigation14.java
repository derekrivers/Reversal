// Apply independently reviewed investigation-14 working names to a preserved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation14 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Set<String> A=Set.of("00713fc0");
 private static final Set<String> B=Set.of("0054d8a0","0054da00","0054db50","0054e630","0054e780","0054e880","0054f030","0054fc10","0054fd60","0054feb0","00550230","00550380","005504d0","005505c0","00550710","00550860");
 private static final Set<String> C=Set.of("007f6af0","007f6be0","007f6cd0","007f6e30","007f6f20");
 private JsonObject read(String path) throws Exception {return JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();}
 private String sha(JsonObject row){return row.has("sha256")?row.get("sha256").getAsString():row.get("specimen_sha256").getAsString();}
 private String value(JsonObject row,String first,String second){return row.has(first)?row.get(first).getAsString():row.get(second).getAsString();}
 private void collect(JsonObject proposal,String arrayName,Set<String> allowed,List<JsonArray> rows,Set<String> seen) throws Exception {
  if(!SHA.equals(sha(proposal)))throw new Exception("Proposal specimen mismatch");
  Set<String> local=new HashSet<>();
  for(JsonElement item:proposal.getAsJsonArray(arrayName)){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   if(!a.matches("[0-9a-f]{8}")||!allowed.contains(a)||!local.add(a)||!seen.add(a))throw new Exception("Unexpected proposal site: "+a);
   if(p.has("kind")&&!"function_name".equals(p.get("kind").getAsString()))throw new Exception("Unexpected annotation kind: "+a);
   String old=value(p,"old_name","old"),name=value(p,"new_name","new");
   if(!old.equals("FUN_"+a)||name.isBlank()||name.equals(old))throw new Exception("Invalid name proposal: "+a);
   var address=toAddr(Long.parseLong(a,16));Function f=currentProgram.getFunctionManager().getFunctionAt(address);
   if(f==null||!old.equals(f.getName()))throw new Exception("Old function mismatch: "+a);
   if(f.getComment()!=null&&!f.getComment().isBlank())throw new Exception("Unexpected old function comment: "+a);
   if(currentProgram.getListing().getInstructionAt(address)==null)throw new Exception("Missing entry instruction: "+a);
   JsonArray r=new JsonArray();r.add(a);r.add(old);r.add(name);rows.add(r);
  }
  if(!local.equals(allowed))throw new Exception("Incomplete proposal set: "+arrayName);
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=4)throw new Exception("Use OUTPUT_JSON MATCH_PROPOSAL DB_PROPOSAL SCOUT_PROPOSAL");
  if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collect(read(args[1]),"functions",A,rows,seen);
  collect(read(args[2]),"proposals",B,rows,seen);
  collect(read(args[3]),"proposals",C,rows,seen);
  int tx=currentProgram.startTransaction("Investigation 14 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows){String a=row.get(0).getAsString();currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(a,16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);}
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",14);
  receipt.addProperty("scope","Twenty-two reviewed static working names only; no behavior oracle, prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-dispatch-14-annotations.json");sources.add("db-wrapper-family-14-annotations.json");sources.add("scouting-boundary-14-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 14: "+rows.size()+" working names");
 }
}
