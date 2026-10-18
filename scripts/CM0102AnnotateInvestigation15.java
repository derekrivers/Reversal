// Apply nine independently reviewed investigation-15 working names.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation15 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Set<String> A=Set.of("00714d40");
 private static final Set<String> B=Set.of("0054dc90","0054e9a0","0054f150","0054ffd0");
 private static final Set<String> C=Set.of("007f6760","007f6aa0","008041c0","00804450");
 private JsonObject read(String path) throws Exception {return JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();}
 private void add(JsonObject p,Set<String> allowed,List<JsonArray> rows,Set<String> seen) throws Exception {
  String a=p.get("address").getAsString().toLowerCase();
  if(!a.matches("[0-9a-f]{8}")||!allowed.contains(a)||!seen.add(a))throw new Exception("Unexpected proposal site: "+a);
  String old=p.has("old_name")?p.get("old_name").getAsString():p.get("old").getAsString();
  String name=p.has("new_name")?p.get("new_name").getAsString():p.get("new").getAsString();
  String kind=p.get("kind").getAsString();
  if(!kind.equals("function_name")&&!kind.equals("function-name-only"))throw new Exception("Invalid annotation kind: "+a);
  if(!old.equals("FUN_"+a)||name.isBlank()||name.equals(old))throw new Exception("Invalid name proposal: "+a);
  var address=toAddr(Long.parseLong(a,16));Function f=currentProgram.getFunctionManager().getFunctionAt(address);
  if(f==null||!old.equals(f.getName()))throw new Exception("Old function mismatch: "+a);
  if(f.getComment()!=null&&!f.getComment().isBlank())throw new Exception("Unexpected old function comment: "+a);
  if(currentProgram.getListing().getInstructionAt(address)==null)throw new Exception("Missing entry instruction: "+a);
  JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
 }
 private void collect(JsonObject doc,Set<String> allowed,List<JsonArray> rows,Set<String> seen) throws Exception {
  if(!SHA.equals(doc.get("specimen_sha256").getAsString()))throw new Exception("Proposal specimen mismatch");
  Set<String> local=new HashSet<>();
  for(JsonElement item:doc.getAsJsonArray("proposals")){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   if(!local.add(a))throw new Exception("Duplicate proposal: "+a);
   add(p,allowed,rows,seen);
  }
  if(!local.equals(allowed))throw new Exception("Incomplete proposal set");
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=4)throw new Exception("Use OUTPUT_JSON MATCH_FINDINGS DB_PROPOSAL SCOUT_PROPOSAL");
  if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  JsonObject a=read(args[1]);if(!SHA.equals(a.get("specimen_sha256").getAsString()))throw new Exception("Match specimen mismatch");
  add(a.getAsJsonObject("annotation_proposal"),A,rows,seen);
  if(seen.size()!=1)throw new Exception("Incomplete match proposal");
  collect(read(args[2]),B,rows,seen);collect(read(args[3]),C,rows,seen);
  if(rows.size()!=9)throw new Exception("Unexpected proposal count");
  int tx=currentProgram.startTransaction("Investigation 15 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows){String address=row.get(0).getAsString();currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);}
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",15);
  receipt.addProperty("scope","Nine reviewed static working names only; no behavior oracle, prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-dependency-15-findings.json");sources.add("db-field-readers-15-annotations.json");sources.add("scouting-lifecycle-15-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 15: "+rows.size()+" working names");
 }
}
