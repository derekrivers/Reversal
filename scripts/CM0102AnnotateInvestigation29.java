// Apply reviewed R29 names, two comments and one return width to checkpoint 28.
// Requires the exact checkpoint-28 preflight and pinned proposal bytes.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.UnsignedShortDataType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation29 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String PREFLIGHT="cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c";
 private static final String KEEPER="01ab9e5078319f4314935181ceaf9da21fa694aee6b7decdd9ad1f8dc01783d8";
 private static final String TACTICAL="1b2835273618470b2f6004cd7435c73ca1bce7c8fd42a4b0b78c545d6c53926c";
 private static final String COLLECTION="86c3fb2e5f0a332e90db394707ccce0351a69b4f7631fe27b2dd3218c9689391";
 private static final Map<String,Long> SIZES=Map.of("006ce110",500L,"006c38c0",42L,"006c38f0",42L,
  "0068d080",77L,"0068d280",96L,"0068d2e0",13L,"0068d2f0",128L);
 private static final Map<String,String> NAMES=Map.of(
  "006c38f0","cm0102_lookup_tactical_offset8ec4_word",
  "0068d080","cm0102_clear_collection_nodes_candidate",
  "0068d280","cm0102_remove_collection_node_candidate",
  "0068d2e0","cm0102_read_current_collection_payload_candidate",
  "0068d2f0","cm0102_clear_and_append_collection_prefix_candidate");
 private void need(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 29 precondition: "+what);}
 private String hash(String path) throws Exception {
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Paths.get(path))));
 }
 private JsonObject read(String path) throws Exception {
  return JsonParser.parseString(Files.readString(Paths.get(path),StandardCharsets.UTF_8)).getAsJsonObject();
 }
 private Function function(String address) throws Exception {
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
  need(f!=null&&f.getBody().getNumAddresses()==SIZES.get(address)&&
   currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"body/entry "+address);
  return f;
 }
 private JsonArray nameRow(String address,String oldName,String newName,long bytes,Set<String> seen) throws Exception {
  need(NAMES.containsKey(address)&&seen.add(address),"unique proposal "+address);
  need(oldName.equals("FUN_"+address)&&newName.equals(NAMES.get(address))&&bytes==SIZES.get(address),
   "proposal name/body "+address);
  Function f=function(address);need(oldName.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),
   "exact-old native name/comment "+address);
  JsonArray row=new JsonArray();row.add(address);row.add(oldName);row.add(newName);return row;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();need(args.length==5,"Use OUTPUT_JSON PREFLIGHT_JSON KEEPER_PROPOSAL TACTICAL_PROPOSAL COLLECTION_PROPOSAL");
  need(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  need(PREFLIGHT.equals(hash(args[1]))&&KEEPER.equals(hash(args[2]))&&TACTICAL.equals(hash(args[3]))&&
   COLLECTION.equals(hash(args[4])),"pinned preflight/proposal bytes");
  JsonObject pre=read(args[1]),keeper=read(args[2]),tactical=read(args[3]),collection=read(args[4]);
  need(SHA.equals(pre.get("sha256").getAsString()),"preflight specimen");
  need("R29-A".equals(keeper.get("unit").getAsString())&&SHA.equals(keeper.get("specimen_sha256").getAsString()),"keeper provenance");
  need("R29-B".equals(tactical.get("work_unit").getAsString())&&SHA.equals(tactical.get("specimen_sha256").getAsString())&&
   PREFLIGHT.equals(tactical.get("preflight_sha256").getAsString()),"tactical provenance");
  need("R29-C".equals(collection.get("work_unit").getAsString())&&SHA.equals(collection.get("specimen_sha256").getAsString())&&
   PREFLIGHT.equals(collection.get("preflight_sha256").getAsString()),"collection provenance");
  JsonArray sites=pre.getAsJsonArray("sites");need(sites.size()==SIZES.size(),"seven exact-old sites");
  Set<String> preSeen=new HashSet<>();
  for(JsonElement item:sites){JsonObject site=item.getAsJsonObject();String address=site.get("address").getAsString();
   need(SIZES.containsKey(address)&&preSeen.add(address),"unique preflight site "+address);
   Function f=function(address);
   need(site.get("body_addresses").getAsLong()==SIZES.get(address)&&site.get("instruction_exists").getAsBoolean()&&
    site.get("function_name").getAsString().equals(f.getName()),"preflight body/name "+address);
   if(site.has("function_comment"))need(site.get("function_comment").getAsString().equals(f.getComment()),"preflight comment "+address);
   else need(f.getComment()==null||f.getComment().isBlank(),"empty old comment "+address);
  }
  need(preSeen.equals(SIZES.keySet()),"complete preflight");
  Function k=function("006ce110"),oldTactical=function("006c38c0");
  need(keeper.get("function_va").getAsString().equals("006ce110")&&
   keeper.get("old_name").getAsString().equals(k.getName())&&
   keeper.get("new_name").getAsString().equals(k.getName())&&
   k.getComment().endsWith(keeper.get("old_comment_end").getAsString()),"keeper exact-old annotation");
  need(oldTactical.getReturnType().getLength()==2,"preserved tactical return width");
  JsonObject preserve=tactical.getAsJsonObject("preserve_existing");
  need(preserve.get("address").getAsString().equals("006c38c0")&&
   preserve.get("name").getAsString().equals(oldTactical.getName())&&
   preserve.get("return_width_bytes").getAsInt()==2,"preserved tactical annotation");
  String keeperComment=k.getComment()+"\n\n"+keeper.get("proposed_appended_comment").getAsString();
  JsonArray rows=new JsonArray();Set<String> seen=new HashSet<>();
  JsonArray tacticalRows=tactical.getAsJsonArray("annotations");need(tacticalRows.size()==1,"one tactical proposal");
  JsonObject t=tacticalRows.get(0).getAsJsonObject();
  need(t.get("old_comment").isJsonNull()&&t.get("new_return_width_bytes").getAsInt()==2&&
   t.get("body_addresses").getAsLong()==42,"tactical comment/return proposal");
  rows.add(nameRow(t.get("address").getAsString(),t.get("old_name").getAsString(),
   t.get("new_name").getAsString(),t.get("body_addresses").getAsLong(),seen));
  String tacticalComment=t.get("new_comment").getAsString();
  JsonArray collectionRows=collection.getAsJsonArray("annotations");need(collectionRows.size()==4,"four collection proposals");
  for(JsonElement item:collectionRows){JsonObject c=item.getAsJsonObject();
   rows.add(nameRow(c.get("address").getAsString(),c.get("old_name").getAsString(),
    c.get("new_name").getAsString(),c.get("body_addresses").getAsLong(),seen));}
  need(seen.equals(NAMES.keySet()),"all five new names");
  JsonArray comments=new JsonArray();
  for(String[] pair:new String[][]{{"006ce110",keeperComment},{"006c38f0",tacticalComment}}){
   JsonArray row=new JsonArray();row.add(pair[0]);row.add(pair[1]);comments.add(row);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",29);
  receipt.addProperty("status","transaction-applied; native save and independent reopen verification pending");
  receipt.addProperty("scope","Five reviewed working names, two function comments and one 16-bit return type. No body, code comment, global label or structure changed.");
  receipt.add("annotations",rows);receipt.add("function_comments",comments);receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("keeper-selector-29-annotations-proposal.json");
  sources.add("tactical-word-29-annotations-proposal.json");sources.add("collection-continuation-29-annotations-proposal.json");
  receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();need(!Files.exists(output),"new output path");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-29-",".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n",StandardCharsets.UTF_8);
  boolean published=false;int tx=currentProgram.startTransaction("Investigation 29 reviewed annotations");boolean apply=false;
  try {
   for(JsonElement item:rows){JsonArray row=item.getAsJsonArray();
    function(row.get(0).getAsString()).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);}
   k.setComment(keeperComment);Function tacticalFunction=function("006c38f0");
   tacticalFunction.setComment(tacticalComment);
   tacticalFunction.setReturnType(UnsignedShortDataType.dataType,SourceType.USER_DEFINED);
   for(JsonElement item:rows){JsonArray row=item.getAsJsonArray();
    need(function(row.get(0).getAsString()).getName().equals(row.get(2).getAsString()),"applied name "+row.get(0));}
   need(keeperComment.equals(k.getComment())&&tacticalComment.equals(tacticalFunction.getComment())&&
    tacticalFunction.getReturnType().getLength()==2,"applied comments/return width");
   Files.move(temporary,output);published=true;apply=true;
  } finally {
   currentProgram.endTransaction(tx,apply);Files.deleteIfExists(temporary);
   if(published&&!apply)Files.deleteIfExists(output);
  }
  println("Applied investigation 29 in memory; native save and independent reopen still required");
 }
}
