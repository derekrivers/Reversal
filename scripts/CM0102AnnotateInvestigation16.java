// Apply independently reviewed investigation-16 working names to a preserved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation16 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String PREFLIGHT="2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc";
 private static final String UNWIND_PREFLIGHT="12d10d6ba68468a8b44f3756f7ac638758fa82523cb7685df16db742548cb93d";
 private static final Set<String> A=Set.of("007109f0");
 private static final Set<String> B=Set.of("00945bfe","00932c30");
 private static final Set<String> C=Set.of("007b7690","00813140");
 private static final Set<String> U=Set.of("005a53c0","00682300","00944c94");
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
 private void collect(JsonObject doc,Set<String> allowed,String preflight,List<JsonArray> rows,Set<String> seen) throws Exception {
  if(!SHA.equals(doc.get("specimen_sha256").getAsString()))throw new Exception("Proposal specimen mismatch");
  if(!preflight.equals(doc.get("private_preflight_sha256").getAsString()))throw new Exception("Proposal preflight mismatch");
  Set<String> local=new HashSet<>();
  for(JsonElement item:doc.getAsJsonArray("proposals")){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   if(!local.add(a))throw new Exception("Duplicate proposal: "+a);
   add(p,allowed,rows,seen);
  }
  if(!local.equals(allowed))throw new Exception("Incomplete proposal set");
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=5)throw new Exception("Use OUTPUT_JSON MATCH_FINDINGS DB_PROPOSAL SCOUT_PROPOSAL UNWIND_PROPOSAL");
  if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  JsonObject a=read(args[1]);if(!SHA.equals(a.get("specimen_sha256").getAsString()))throw new Exception("Match specimen mismatch");
  JsonObject ap=a.getAsJsonObject("annotation_proposal");
  if(!PREFLIGHT.equals(ap.get("preflight_sha256").getAsString()))throw new Exception("Match preflight mismatch");
  add(ap,A,rows,seen);
  if(seen.size()!=1)throw new Exception("Incomplete match proposal");
  collect(read(args[2]),B,PREFLIGHT,rows,seen);
  collect(read(args[3]),C,PREFLIGHT,rows,seen);
  collect(read(args[4]),U,UNWIND_PREFLIGHT,rows,seen);
  if(rows.size()!=8)throw new Exception("Unexpected proposal count");
  int tx=currentProgram.startTransaction("Investigation 16 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows){String address=row.get(0).getAsString();currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);}
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",16);
  receipt.addProperty("scope","Eight reviewed static working names only; no behavior oracle, prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-core-16-findings.json");sources.add("db-stream-16-annotations.json");sources.add("scout-copy-16-annotations.json");sources.add("unwind-targets-16-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 16: "+rows.size()+" working names");
 }
}
