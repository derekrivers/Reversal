// Apply independently reviewed investigation-21 working names to checkpoint 19.
// This script changes names only.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation21 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String A_PREFLIGHT="02f34af94bb8e6243450b8120d604491ad9208a716525fbdc8485b3a4e636167";
 private static final String B_PREFLIGHT="f09d2b563f4622f03e2cb81a6f06620567d87a2c6330c86e75e27cffef8de2a3";
 private static final Set<String> A=Set.of("006f0970","007160d0","007160e0");
 private static final Set<String> B=Set.of("006f5810","006c50d0");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 21 precondition: "+what);}
 private void collect(String path,Set<String> allowed,String preflight,boolean micro,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen "+path);
  require(preflight.equals(doc.get("private_preflight_sha256").getAsString()),"proposal preflight "+path);
  JsonArray proposals=doc.getAsJsonArray(micro?"annotations":"proposals");
  Set<String> local=new HashSet<>();
  for(JsonElement item:proposals){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   require(a.matches("[0-9a-f]{8}")&&allowed.contains(a)&&local.add(a)&&seen.add(a),"proposal address "+a);
   if(!micro)require("function_name".equals(p.get("kind").getAsString()),"proposal kind "+a);
   String old=p.get(micro?"old_name":"old").getAsString(),name=p.get(micro?"new_name":"new").getAsString();
   require(old.equals("FUN_"+a)&&!name.isBlank()&&!name.equals(old),"proposal names "+a);
   if(micro)require(p.get("old_comment").isJsonNull()&&p.get("new_comment").isJsonNull(),"proposal comment "+a);
   var address=toAddr(Long.parseLong(a,16));Function f=currentProgram.getFunctionManager().getFunctionAt(address);
   require(f!=null&&old.equals(f.getName()),"old function "+a);
   require(f.getComment()==null||f.getComment().isBlank(),"old function comment "+a);
   require(currentProgram.getListing().getInstructionAt(address)!=null,"entry instruction "+a);
   JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
  }
  require(local.equals(allowed),"complete proposal set "+path);
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==3,"Use OUTPUT_JSON MICRO_PROPOSALS STATE_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function corrected=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x006f09f0L));
  require(corrected!=null&&corrected.getBody().getNumAddresses()==14547,"corrected match body size");
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collect(args[1],A,A_PREFLIGHT,true,rows,seen);
  collect(args[2],B,B_PREFLIGHT,false,rows,seen);
  require(rows.size()==5,"five reviewed names");
  int tx=currentProgram.startTransaction("Investigation 21 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows)currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get(0).getAsString(),16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",21);
  receipt.addProperty("scope","Five reviewed working names only; three bounded execution validations and two static local contracts. No prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-microhelpers-21-annotations-proposal.json");sources.add("match-state-21-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 21: "+rows.size()+" working names");
 }
}
