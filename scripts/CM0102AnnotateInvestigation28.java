// Apply five reviewed name-only proposals to the preserved checkpoint 27.
// Existing allocator library names/comments and all bodies/types are preserved.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation28 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String ARCHIVE="d2836fd1b28d194dbfda32454106f9af23495809f09a408ed1ee072e6c4b7de1";
 private static final String PREFLIGHT="9f9e52088fc32356aebecb6fc39ba78fea96e14f359383afb01362287409fbb2";
 private static final String SORT_PROPOSAL="3b956643bcff39c2e505e9d4a66d5c4185dd5b1604277da7ac85cfd9183e1aa8";
 private static final String MERGE_PROPOSAL="0dd3b32ae424b39fc5fe73e6d5a296740fe57f659a81a804fd21eb166c1a37f7";
 private static final String COLLECTION_PROPOSAL="ac8c32977d013569183b89d911e84c22a69770440eebdd3a1840fc9b70270c64";
 private static final Map<String,Long> SIZES=Map.of(
  "00945487",78L,"009454d5",44L,"0068d020",17L,"0068d0d0",221L,
  "0068cfc0",66L,"00944cf1",14L,"00944e58",44L);
 private static final Map<String,String> NEW_NAMES=Map.of(
  "00945487","cm0102_select_tail_record_with_callback_candidate",
  "009454d5","cm0102_swap_record_bytes_candidate",
  "0068d020","cm0102_zero_14_byte_collection_header",
  "0068d0d0","cm0102_append_copied_record_to_collection",
  "0068cfc0","cm0102_construct_collection_node_copy_candidate");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 28 precondition: "+what);}
 private String fileHash(String path) throws Exception {
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Paths.get(path))));
 }
 private JsonObject read(String path) throws Exception {
  return JsonParser.parseString(Files.readString(Paths.get(path),StandardCharsets.UTF_8)).getAsJsonObject();
 }
 private Function function(String address) throws Exception {
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
  require(f!=null&&f.getBody().getNumAddresses()==SIZES.get(address)&&
          currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"function/body/entry "+address);
  return f;
 }
 private JsonArray proposal(String address,String oldName,String newName,long size,Set<String> seen) throws Exception {
  require(NEW_NAMES.containsKey(address)&&seen.add(address),"unique proposal address "+address);
  require(oldName.equals("FUN_"+address)&&newName.equals(NEW_NAMES.get(address))&&size==SIZES.get(address),
          "exact proposal name/body "+address);
  Function f=function(address);
  require(oldName.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"exact-old native state "+address);
  JsonArray out=new JsonArray();out.add(address);out.add(oldName);out.add(newName);return out;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==5,"Use OUTPUT_JSON PREFLIGHT_JSON SORT_PROPOSAL MERGE_PROPOSAL COLLECTION_PROPOSAL");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  require(PREFLIGHT.equals(fileHash(args[1])),"exact-old preflight bytes");
  JsonObject pre=read(args[1]);require(SHA.equals(pre.get("sha256").getAsString()),"preflight specimen");
  JsonArray sites=pre.getAsJsonArray("sites");require(sites.size()==7,"seven preflight sites");
  Set<String> preSeen=new HashSet<>();
  for(JsonElement element:sites){
   JsonObject site=element.getAsJsonObject();String address=site.get("address").getAsString();
   require(SIZES.containsKey(address)&&preSeen.add(address),"preflight unique address "+address);
   Function f=function(address);
   require(site.get("body_addresses").getAsLong()==SIZES.get(address)&&
           site.get("instruction_exists").getAsBoolean()&&
           site.get("function_name").getAsString().equals(f.getName()),"preflight exact-old function "+address);
   if(site.has("function_comment"))require(site.get("function_comment").getAsString().equals(f.getComment()),"preserved comment "+address);
   else require(f.getComment()==null||f.getComment().isBlank(),"old empty comment "+address);
  }
  require(preSeen.equals(SIZES.keySet()),"all preflight sites");
  require("operator_new".equals(function("00944cf1").getName()),"operator_new sentinel");
  require("__nh_malloc".equals(function("00944e58").getName()),"__nh_malloc sentinel");
  require(SORT_PROPOSAL.equals(fileHash(args[2])),"reviewed sort proposal bytes");
  require(MERGE_PROPOSAL.equals(fileHash(args[3])),"reviewed merge proposal bytes");
  require(COLLECTION_PROPOSAL.equals(fileHash(args[4])),"reviewed collection proposal bytes");
  JsonObject sort=read(args[2]),merge=read(args[3]),collection=read(args[4]);
  require("R28-A".equals(sort.get("unit").getAsString())&&SHA.equals(sort.get("specimen_sha256").getAsString())&&
          ARCHIVE.equals(sort.get("native_checkpoint_archive_sha256").getAsString())&&
          PREFLIGHT.equals(sort.get("exact_old_preflight_sha256").getAsString()),"sort provenance");
  require("R28-B".equals(merge.get("work_unit").getAsString())&&SHA.equals(merge.get("specimen_sha256").getAsString())&&
          ARCHIVE.equals(merge.get("checkpoint_archive_sha256").getAsString())&&
          PREFLIGHT.equals(merge.get("preflight_sha256").getAsString()),"merge provenance");
  require("R28-C".equals(collection.get("work_unit").getAsString())&&SHA.equals(collection.get("specimen_sha256").getAsString())&&
          ARCHIVE.equals(collection.get("checkpoint_archive_sha256").getAsString())&&
          PREFLIGHT.equals(collection.get("annotation_preflight_sha256").getAsString()),"collection provenance");
  Set<String> seen=new HashSet<>();JsonArray rows=new JsonArray();
  JsonArray sortRows=sort.getAsJsonArray("proposals");require(sortRows.size()==2,"two sort proposals");
  for(JsonElement item:sortRows){JsonObject r=item.getAsJsonObject();
   rows.add(proposal(r.get("entry_va").getAsString(),r.get("old_name").getAsString(),
          r.get("new_name").getAsString(),r.get("old_body_addresses").getAsLong(),seen));}
  JsonArray mergeRows=merge.getAsJsonArray("proposals");require(mergeRows.size()==2,"two merge proposals");
  for(JsonElement item:mergeRows){JsonObject r=item.getAsJsonObject();
   rows.add(proposal(r.get("address").getAsString(),r.get("old_function_name").getAsString(),
          r.get("new_function_name").getAsString(),r.get("body_addresses").getAsLong(),seen));}
  JsonArray collectionRows=collection.getAsJsonArray("annotations");require(collectionRows.size()==1,"one collection proposal");
  for(JsonElement item:collectionRows){JsonObject r=item.getAsJsonObject();
   rows.add(proposal(r.get("address").getAsString(),r.get("old_name").getAsString(),
          r.get("new_name").getAsString(),r.get("body_addresses").getAsLong(),seen));}
  require(seen.equals(NEW_NAMES.keySet()),"five reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",28);
  receipt.addProperty("status","transaction-applied; native save and independent reopen verification pending");
  receipt.addProperty("scope","Five reviewed working names only; six complete local static contracts and two bounded TypeScript entry domains. Existing allocator library names/comments preserved. No prototype, comment, body or data type applied.");
  receipt.add("annotations",rows);receipt.add("function_comments",new JsonArray());
  receipt.add("code_comments",new JsonArray());receipt.add("global_labels",new JsonArray());
  receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("sort-helpers-28-annotations-proposal.json");
  sources.add("merge-dependencies-28-annotations-proposal.json");sources.add("collection-runtime-28-annotations-proposal.json");
  receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-28-",".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  boolean published=false;
  try {
   int tx=currentProgram.startTransaction("Investigation 28 reviewed names");boolean apply=false;
   try {
    for(JsonElement item:rows){JsonArray r=item.getAsJsonArray();
     function(r.get(0).getAsString()).setName(r.get(2).getAsString(),SourceType.USER_DEFINED);}
    for(JsonElement item:rows){JsonArray r=item.getAsJsonArray();
     require(r.get(2).getAsString().equals(function(r.get(0).getAsString()).getName()),"transaction name "+r.get(0).getAsString());}
    Files.move(temporary,output);published=true;apply=true;
   } finally {currentProgram.endTransaction(tx,apply);}
  } catch(Exception failure) {
   if(published)Files.deleteIfExists(output);
   throw failure;
  } finally {Files.deleteIfExists(temporary);}
  println("Applied investigation 28 in memory; native save and independent reopen still required");
 }
}
