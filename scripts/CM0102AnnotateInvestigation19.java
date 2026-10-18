// Apply independently reviewed investigation-19 working names to checkpoint 18.
// This script changes names only.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation19 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String PREFLIGHT="a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78";
 private static final Set<String> A=Set.of("006cd770","006cd490");
 private static final Set<String> B=Set.of("0094fded");
 private static final Set<String> C=Set.of("0094633b","009452ca","00948b90","009498eb","00949942");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 19 precondition: "+what);}
 private void collect(String path,Set<String> allowed,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen");
  require(PREFLIGHT.equals(doc.get("private_preflight_sha256").getAsString()),"proposal preflight");
  Set<String> local=new HashSet<>();
  for(JsonElement item:doc.getAsJsonArray("proposals")){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   require(a.matches("[0-9a-f]{8}")&&allowed.contains(a)&&local.add(a)&&seen.add(a),"proposal address "+a);
   require("function_name".equals(p.get("kind").getAsString()),"proposal kind "+a);
   String old=p.get("old").getAsString(),name=p.get("new").getAsString();
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
  String[] args=getScriptArgs();require(args.length==4,"Use OUTPUT_JSON MATCH_PROPOSALS DB_PROPOSALS CLEANUP_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function corrected=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x006f09f0L));
  require(corrected!=null&&corrected.getBody().getNumAddresses()==14547,"corrected match body size");
  for(long v:new long[]{0x006f1639L,0x006f163eL,0x006f1640L,0x006f1645L,0x006f1647L,0x006f164cL})
   require(corrected.getBody().contains(toAddr(v)),"corrected match case "+Long.toHexString(v));
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collect(args[1],A,rows,seen);collect(args[2],B,rows,seen);collect(args[3],C,rows,seen);
  require(rows.size()==8,"eight reviewed names");
  int tx=currentProgram.startTransaction("Investigation 19 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows)currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get(0).getAsString(),16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",19);
  receipt.addProperty("scope","Eight reviewed static working names only; no behavior oracle, prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-action-19-annotations.json");sources.add("db-runtime-19-annotations.json");sources.add("cleanup-runtime-19-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 19: "+rows.size()+" working names");
 }
}
