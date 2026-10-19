// Apply three reviewed name-only proposals to checkpoint 26.
// The existing league caller and runtime _strlen name/comment are preserved.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation27 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String ARCHIVE="4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4";
 private static final String PREFLIGHT="fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d";
 private static final String ITERATOR_PROPOSAL="0a96a9b96524f6eebe55f3ba1904bf53c8bb178e6c3b43da9f21dbfe50dfd8f0";
 private static final String LEAGUE_PROPOSAL="b2d928bcd12fe6b9be122fa8019d996f1c417bc8ef265d7f19626d861f987373";
 private static final Map<String,Long> SIZES=Map.of(
  "0068d1b0",19L,"0068d1d0",19L,"00682b30",730L,"00945333",340L,"009488e0",123L);
 private static final Map<String,String> NEW_NAMES=Map.of(
  "0068d1b0","cm0102_advance_cursor_link6_candidate",
  "0068d1d0","cm0102_advance_cursor_linka_candidate",
  "00945333","cm0102_sort_records_with_callback_candidate");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 27 precondition: "+what);}
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
  require(PREFLIGHT.equals(doc.get("annotation_preflight_sha256").getAsString()),"proposal preflight "+path);
  return doc;
 }
 private JsonArray proposal(JsonObject row,Set<String> seen) throws Exception {
  String address=row.get("address").getAsString();
  require(NEW_NAMES.containsKey(address)&&seen.add(address),"unique proposal address "+address);
  String oldName=row.get("old_name").getAsString(),newName=row.get("new_name").getAsString();
  require(oldName.equals("FUN_"+address)&&newName.equals(NEW_NAMES.get(address))&&
          row.get("body_addresses").getAsLong()==SIZES.get(address),"exact proposal name/body "+address);
  Function f=function(address);
  require(oldName.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"exact-old native state "+address);
  JsonArray out=new JsonArray();out.add(address);out.add(oldName);out.add(newName);return out;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==4,"Use OUTPUT_JSON PREFLIGHT_JSON ITERATOR_PROPOSAL LEAGUE_PROPOSAL");
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
  require("cm0102_write_league_peer_bucket_bytes_candidate".equals(function("00682b30").getName()),"R10-C league caller sentinel");
  require("_strlen".equals(function("009488e0").getName()),"runtime library sentinel");
  require(ITERATOR_PROPOSAL.equals(fileHash(args[2])),"reviewed iterator proposal bytes");
  require(LEAGUE_PROPOSAL.equals(fileHash(args[3])),"reviewed league proposal bytes");
  JsonObject iterator=document(args[2]);require("R27-A".equals(iterator.get("work_unit").getAsString()),"iterator work unit");
  JsonObject league=document(args[3]);require("R27-C".equals(league.get("unit").getAsString()),"league work unit");
  Set<String> seen=new HashSet<>();JsonArray rows=new JsonArray();
  JsonArray iteratorRows=iterator.getAsJsonArray("annotations");require(iteratorRows.size()==2,"two iterator proposals");
  for(JsonElement item:iteratorRows)rows.add(proposal(item.getAsJsonObject(),seen));
  JsonArray leagueRows=league.getAsJsonArray("annotations");require(leagueRows.size()==1,"one league proposal");
  for(JsonElement item:leagueRows)rows.add(proposal(item.getAsJsonObject(),seen));
  require(seen.equals(NEW_NAMES.keySet()),"three reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",27);
  receipt.addProperty("status","transaction-applied; native save and independent reopen verification pending");
  receipt.addProperty("scope","Three reviewed working names only; four new complete local static contracts, three bounded TypeScript entry domains. Existing R10-C caller and _strlen name/comment preserved. No prototype, comment, body or data type applied.");
  receipt.add("annotations",rows);receipt.add("function_comments",new JsonArray());
  receipt.add("code_comments",new JsonArray());receipt.add("global_labels",new JsonArray());
  receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("iterator-helpers-27-annotations-proposal.json");
  sources.add("league-sort-27-annotations-proposal.json");receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-27-",".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  boolean published=false;
  try {
   int tx=currentProgram.startTransaction("Investigation 27 reviewed names");boolean apply=false;
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
  println("Applied investigation 27 in memory; native save and independent reopen still required");
 }
}
