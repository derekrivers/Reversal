// Apply three independently reviewed investigation-24 working names to checkpoint 23.
// Status-refresh already has its R10-A name/comment and is not renamed here.
// This is a name-only transaction; original bytes, prototypes and types are unchanged.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class CM0102AnnotateInvestigation24 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String PREFLIGHT="1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193";
 private static final String STATUS_COMMENT_SHA="a158c8f8f61a7fd36684a61cd5beeaf74504b219be1bdffbdf9f66acb17d9544";
 private static final Map<String,Long> SIZES=Map.of("0062c680",1909L,"0054cc30",358L,"00944cff",327L,"00944c9f",82L);
 private static final Map<String,String> NAMES=Map.of(
  "0054cc30","DatePairDifference",
  "00944cff","split_path_components_00944cff",
  "00944c9f","format_buffer_variadic_00944c9f");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 24 precondition: "+what);}
 private Function function(String address) throws Exception {
  Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(address,16)));
  require(f!=null&&f.getBody().getNumAddresses()==SIZES.get(address)&&
          currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"function/body/entry "+address);
  return f;
 }
 private void collectDate(String path,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require("R24-B".equals(doc.get("work_unit").getAsString()),"date work unit");
  require("checkpoint 23".equals(doc.get("native_baseline").getAsString()),"date baseline");
  JsonArray proposals=doc.getAsJsonArray("proposals");require(proposals.size()==1,"one date proposal");
  JsonObject p=proposals.get(0).getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
  require("0054cc30".equals(a)&&seen.add(a),"date address");
  String old=p.get("old_name").getAsString(),name=p.get("new_name").getAsString();
  require(old.equals("FUN_"+a)&&name.equals(NAMES.get(a)),"date names");
  Function f=function(a);require(old.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"date exact-old state");
  JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
 }
 private void collectPath(String path,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  require(SHA.equals(doc.get("specimen_sha256").getAsString()),"path specimen");
  require("2026-10-18-investigation-23".equals(doc.get("native_checkpoint").getAsString()),"path baseline");
  require(PREFLIGHT.equals(doc.get("preflight_sha256").getAsString()),"path preflight");
  JsonArray proposals=doc.getAsJsonArray("proposals");require(proposals.size()==2,"two path proposals");
  for(JsonElement item:proposals){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   require(Set.of("00944cff","00944c9f").contains(a)&&seen.add(a),"path address "+a);
   require("function_name".equals(p.get("kind").getAsString()),"path proposal kind "+a);
   String old=p.get("old").getAsString(),name=p.get("new").getAsString();
   require(old.equals("FUN_"+a)&&name.equals(NAMES.get(a)),"path names "+a);
   Function f=function(a);require(old.equals(f.getName())&&(f.getComment()==null||f.getComment().isBlank()),"path exact-old state "+a);
   JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
  }
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==3,"Use OUTPUT_JSON DATE_PROPOSALS PATH_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function corrected=function("0062c680");
  require("cm0102_refresh_player_status_row_candidate".equals(corrected.getName())&&
          corrected.getComment()!=null&&STATUS_COMMENT_SHA.equals(HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(corrected.getComment().getBytes(StandardCharsets.UTF_8)))),
          "preserved exact status name/comment");
  for(var sentinel:Map.of("0062c400","MatchClassifyIndexedStatusBand",
                           "00945956","dispatch_exit_callbacks_00945956",
                           "00601070","probe_mode5_record_00601070").entrySet()){
   Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(sentinel.getKey(),16)));
   require(f!=null&&sentinel.getValue().equals(f.getName()),"checkpoint-23 sentinel "+sentinel.getKey());
  }
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collectDate(args[1],rows,seen);collectPath(args[2],rows,seen);
  require(rows.size()==3&&seen.equals(NAMES.keySet()),"three reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",24);
  receipt.addProperty("scope","Three reviewed working names only; 0062c680 retains its historical name/comment. Four complete local static bodies and two bounded TypeScript paths; no prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("date-difference-24-annotations-proposal.json");sources.add("path-format-24-annotations-proposal.json");receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-24-", ".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  int tx=currentProgram.startTransaction("Investigation 24 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows)currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get(0).getAsString(),16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);
   Files.move(temporary,output);
   commit=true;
  } finally {
   currentProgram.endTransaction(tx,commit);
   if(!commit)Files.deleteIfExists(temporary);
  }
  println("Applied investigation 24: "+rows.size()+" working names; existing status name/comment preserved");
 }
}
