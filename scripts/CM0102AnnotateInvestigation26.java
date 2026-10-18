// Apply three independently reviewed R26 name-only proposals to checkpoint 25.
// Runtime _strncpy and historical annotations are preserved; prototypes/types unchanged.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation26 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String ARCHIVE="670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a";
 private static final String PREFLIGHT="b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd";
 private static final String MATCH_PROPOSAL="e77f9617d5fac7a905431d227b631a40d4d5101c0a403b7fc76ca3a0cdf3d0e6";
 private static final String LEAGUE_PROPOSAL="94493f618888d789d1a4bd7d55c5a9a4935b23abae83e811386866ccdb94fe0c";
 private static final Map<String,Long> SIZES=Map.of(
  "0062e700",284L,"0062be00",342L,"007160e0",10L,"006834f0",178L,"009466d0",254L);
 private static final Map<String,String> NEW_NAMES=Map.of(
  "0062e700","cm0102_invalidate_linked_status_record_candidate",
  "0062be00","cm0102_merge_keyed_kind_severity_candidate",
  "006834f0","cm0102_compare_league_rows_by_shared_rules_candidate");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 26 precondition: "+what);}
 private String fileHash(String path) throws Exception {
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Paths.get(path))));
 }
 private Function function(String address) throws Exception {
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
  require(f!=null&&f.getBody().getNumAddresses()==SIZES.get(address)&&
          currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"function/body/entry "+address);
  return f;
 }
 private JsonObject document(String path) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path),StandardCharsets.UTF_8)).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen "+path);
  require(ARCHIVE.equals(doc.get("checkpoint_archive_sha256").getAsString()),"proposal checkpoint "+path);
  return doc;
 }
 private JsonArray proposal(String address,String oldName,String newName,long body,Set<String> seen) throws Exception {
  require(NEW_NAMES.containsKey(address)&&seen.add(address),"unique proposal address "+address);
  require(oldName.equals("FUN_"+address)&&newName.equals(NEW_NAMES.get(address))&&body==SIZES.get(address),
          "exact proposal name/body "+address);
  Function f=function(address);
  require(oldName.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"exact-old native state "+address);
  JsonArray row=new JsonArray();row.add(address);row.add(oldName);row.add(newName);return row;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==4,"Use OUTPUT_JSON PREFLIGHT_JSON MATCH_PROPOSAL LEAGUE_PROPOSAL");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  require(PREFLIGHT.equals(fileHash(args[1])),"exact-old preflight bytes");
  JsonObject pre=JsonParser.parseString(Files.readString(Paths.get(args[1]),StandardCharsets.UTF_8)).getAsJsonObject();
  require(SHA.equals(pre.get("sha256").getAsString()),"preflight specimen");
  JsonArray sites=pre.getAsJsonArray("sites");require(sites.size()==5,"five preflight sites");
  Set<String> preSeen=new HashSet<>();
  for(JsonElement element:sites){
   JsonObject site=element.getAsJsonObject();String address=site.get("address").getAsString();
   require(SIZES.containsKey(address)&&preSeen.add(address),"preflight unique address "+address);
   Function f=function(address);
   require(site.get("body_addresses").getAsLong()==SIZES.get(address)&&
           site.get("instruction_exists").getAsBoolean()&&
           site.get("function_name").getAsString().equals(f.getName()),"preflight exact old function "+address);
   if(site.has("function_comment"))require(site.get("function_comment").getAsString().equals(f.getComment()),"preserved comment "+address);
   else require(f.getComment()==null||f.getComment().isBlank(),"old empty comment "+address);
  }
  require(preSeen.equals(SIZES.keySet()),"all preflight sites");
  require("MatchSlot_SetByte2b".equals(function("007160e0").getName()),"R21 setter sentinel");
  require("_strncpy".equals(function("009466d0").getName()),"runtime library sentinel");
  require("locale_aware_bounded_copy_00948851".equals(
    currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00948851)).getName()),"checkpoint-25 sentinel");
  require(MATCH_PROPOSAL.equals(fileHash(args[2])),"reviewed match proposal bytes");
  require(LEAGUE_PROPOSAL.equals(fileHash(args[3])),"reviewed league proposal bytes");
  JsonObject match=document(args[2]);require("R26-A".equals(match.get("work_unit").getAsString()),"match work unit");
  require(PREFLIGHT.equals(match.get("annotation_preflight_sha256").getAsString()),"match preflight");
  JsonObject league=document(args[3]);require("R26-C".equals(league.get("unit").getAsString()),"league work unit");
  require(PREFLIGHT.equals(league.get("preflight_sha256").getAsString()),"league preflight");
  Set<String> seen=new HashSet<>();JsonArray rows=new JsonArray();
  JsonArray matchRows=match.getAsJsonArray("annotations");require(matchRows.size()==2,"two match proposals");
  for(JsonElement item:matchRows){JsonObject row=item.getAsJsonObject();rows.add(proposal(
    row.get("address").getAsString(),row.get("old_name").getAsString(),row.get("new_name").getAsString(),
    row.get("body_addresses").getAsLong(),seen));}
  JsonArray leagueRows=league.getAsJsonArray("function_names");require(leagueRows.size()==1,"one league proposal");
  JsonObject row=leagueRows.get(0).getAsJsonObject();rows.add(proposal(
    row.get("address").getAsString(),row.get("expected_old_name").getAsString(),
    row.get("proposed_name").getAsString(),row.get("expected_body_addresses").getAsLong(),seen));
  require(seen.equals(NEW_NAMES.keySet()),"three reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",26);
  receipt.addProperty("status","transaction-applied; native save and independent reopen verification pending");
  receipt.addProperty("scope","Three reviewed working names only; four new complete local static contracts, three bounded TypeScript entry domains. Existing R21 setter and _strncpy name/comment preserved. No prototype, comment, body or data type applied.");
  receipt.add("annotations",rows);receipt.add("function_comments",new JsonArray());
  receipt.add("code_comments",new JsonArray());receipt.add("global_labels",new JsonArray());
  receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-dependencies-26-annotations-proposal.json");
  sources.add("league-comparator-26-annotations.json");receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-26-",".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  boolean published=false;
  try {
   int tx=currentProgram.startTransaction("Investigation 26 reviewed names");boolean apply=false;
   try {
    for(JsonElement item:rows){JsonArray r=item.getAsJsonArray();
     function(r.get(0).getAsString()).setName(r.get(2).getAsString(),SourceType.USER_DEFINED);}
    for(JsonElement item:rows){JsonArray r=item.getAsJsonArray();
     require(r.get(2).getAsString().equals(function(r.get(0).getAsString()).getName()),"transaction name "+r.get(0).getAsString());}
    Files.move(temporary,output);published=true;
    apply=true;
   } finally {currentProgram.endTransaction(tx,apply);}
  } catch(Exception failure) {
   if(published)Files.deleteIfExists(output);
   throw failure;
  } finally {Files.deleteIfExists(temporary);}
  println("Applied investigation 26 in memory; native save and independent reopen still required");
 }
}
