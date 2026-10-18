// Apply three independently reviewed R25 working names to checkpoint 24.
// Historical R10-A names/comments are preserved; prototypes and types are unchanged.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation25 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String ARCHIVE="77fb2072a25ff030ab3c0e58c5cd289730a9a8c5345ceaaf56e948e727c1dd0b";
 private static final String PREFLIGHT="34ca2e277634b5a4bdbde668ffcc7d3b91a65a4c1689844f54c454b644834899";
 private static final String STATUS_PROPOSAL_SHA="98efd333b16d7ec268858057c3169b44279c7ba268540b1c73434e9fee0d3a5c";
 private static final String COPY_PROPOSAL_SHA="7adb2f1890682cf4e91d5ccf5b75ba1120e93d2874b8381c3e58d9572356da14";
 private static final Map<String,Long> SIZES=Map.of("0062ec00",18L,"0062ece0",70L,"0062ed70",187L,"006d0980",473L,"00948851",138L);
 private static final Map<String,String> NEW_NAMES=Map.of(
  "0062ec00","status_signed_byte_table_lookup_0062ec00",
  "0062ece0","status_row_byte_condition_0062ece0",
  "00948851","locale_aware_bounded_copy_00948851");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 25 precondition: "+what);}
 private Function function(String address) throws Exception {
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
  require(f!=null&&f.getBody().getNumAddresses()==SIZES.get(address)&&
          currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"function/body/entry "+address);
  return f;
 }
 private String hash(String value) throws Exception {
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
 }
 private String fileHash(String path) throws Exception {
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Paths.get(path))));
 }
 private void preserve(String address,String oldName,String commentHash) throws Exception {
  Function f=function(address);
  require(oldName.equals(f.getName())&&f.getComment()!=null&&commentHash.equals(hash(f.getComment())),
          "preserved exact name/comment "+address);
 }
 private JsonObject document(String path) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen "+path);
  return doc;
 }
 private JsonArray proposal(JsonObject p,Set<String> seen) throws Exception {
  String address=p.get("address").getAsString().toLowerCase();
  require(NEW_NAMES.containsKey(address)&&seen.add(address),"unique proposal address "+address);
  String old=p.get("old_name").getAsString(),name=p.get("new_name").getAsString();
  require(old.equals("FUN_"+address)&&name.equals(NEW_NAMES.get(address)),"exact proposal names "+address);
  Function f=function(address);
  require(old.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"exact-old native state "+address);
  JsonArray row=new JsonArray();row.add(address);row.add(old);row.add(name);return row;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==3,"Use OUTPUT_JSON STATUS_PROPOSALS COPY_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  preserve("0062ed70","cm0102_get_refreshed_status_record_candidate","e4c9460602c6eeb57d0963fc09dfa85b846f6ff2032fad0c716c1694160a5fa5");
  preserve("006d0980","cm0102_apply_slot_condition_effect_candidate","7f4efaa3f7b455804e9804dd019ba7a2dedf24d69ce5f0047298ac87093b47a3");
  for(var sentinel:Map.of("0054cc30","DatePairDifference",
                           "00944cff","split_path_components_00944cff",
                           "00944c9f","format_buffer_variadic_00944c9f").entrySet()){
   Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(sentinel.getKey(),16)));
   require(f!=null&&sentinel.getValue().equals(f.getName()),"checkpoint-24 sentinel "+sentinel.getKey());
  }
  JsonObject status=document(args[1]);
  require(STATUS_PROPOSAL_SHA.equals(fileHash(args[1])),"reviewed status proposal bytes");
  require("R25-A".equals(status.get("work_unit").getAsString()),"status work unit");
  require(ARCHIVE.equals(status.get("checkpoint_archive_sha256").getAsString()),"status checkpoint");
  require(PREFLIGHT.equals(status.get("exact_old_preflight_sha256").getAsString()),"status preflight");
  JsonObject copy=document(args[2]);
  require(COPY_PROPOSAL_SHA.equals(fileHash(args[2])),"reviewed copy proposal bytes");
  require("R25-C".equals(copy.get("unit").getAsString()),"copy work unit");
  Set<String> seen=new HashSet<>();JsonArray rows=new JsonArray();
  JsonArray statusRows=status.getAsJsonArray("proposals");require(statusRows.size()==2,"two status proposals");
  for(JsonElement item:statusRows)rows.add(proposal(item.getAsJsonObject(),seen));
  JsonArray copyRows=copy.getAsJsonArray("proposals");require(copyRows.size()==1,"one copy proposal");
  JsonObject cp=copyRows.get(0).getAsJsonObject();
  require(cp.has("old_comment")&&cp.get("old_comment").isJsonNull()&&
          cp.has("new_comment")&&cp.get("new_comment").isJsonNull(),"copy name-only proposal");
  rows.add(proposal(cp,seen));require(seen.equals(NEW_NAMES.keySet()),"three reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",25);
  receipt.addProperty("scope","Three reviewed working names only; two historical R10-A names/comments retained. Five complete local static bodies and bounded TypeScript paths; no prototype, comment or data type applied.");
  receipt.add("annotations",rows);receipt.add("function_comments",new JsonArray());
  receipt.add("code_comments",new JsonArray());receipt.add("global_labels",new JsonArray());
  receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("status-lookup-25-annotations-proposal.json");sources.add("copy-helper-25-annotations-proposal.json");
  receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-25-", ".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  int tx=currentProgram.startTransaction("Investigation 25 reviewed names");boolean commit=false;
  try {
   for(JsonElement item:rows){JsonArray row=item.getAsJsonArray();
    function(row.get(0).getAsString()).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);}
   Files.move(temporary,output);commit=true;
  } finally {
   currentProgram.endTransaction(tx,commit);if(!commit)Files.deleteIfExists(temporary);
  }
  println("Applied investigation 25: three working names; historical comments preserved");
 }
}
