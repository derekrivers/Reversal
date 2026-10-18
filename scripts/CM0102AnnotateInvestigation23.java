// Apply four independently reviewed investigation-23 working names to checkpoint 22.
// This is a name-only transaction; original bytes, prototypes and types are unchanged.
// @category CM0102

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation23 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final String PREFLIGHT="c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a";
 private static final Map<String,Long> SIZES=Map.of("0062c400",271L,"00945956",153L,"009459ef",26L,"00601070",399L);
 private static final Map<String,String> NAMES=Map.of(
  "0062c400","MatchClassifyIndexedStatusBand",
  "00945956","dispatch_exit_callbacks_00945956",
  "009459ef","invoke_nonnull_callback_range_009459ef",
  "00601070","probe_mode5_record_00601070");
 private void require(boolean ok,String what) throws Exception {if(!ok)throw new Exception("Investigation 23 precondition: "+what);}
 private void collect(String path,Set<String> allowed,String preflightKey,boolean scalar,List<JsonArray> rows,Set<String> seen) throws Exception {
  JsonObject doc=JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();
  if(scalar) {
   require("R23-A".equals(doc.get("work_unit").getAsString()),"proposal work unit "+path);
   require("checkpoint 22".equals(doc.get("native_baseline").getAsString()),"proposal baseline "+path);
  } else {
   require(SHA.equals(doc.get("specimen_sha256").getAsString()),"proposal specimen "+path);
   require(PREFLIGHT.equals(doc.get(preflightKey).getAsString()),"proposal preflight "+path);
  }
  Set<String> local=new HashSet<>();
  for(JsonElement item:doc.getAsJsonArray("proposals")){
   JsonObject p=item.getAsJsonObject();String a=p.get("address").getAsString().toLowerCase();
   require(a.matches("[0-9a-f]{8}")&&allowed.contains(a)&&local.add(a)&&seen.add(a),"proposal address "+a);
   if(!scalar)require("function_name".equals(p.get("kind").getAsString()),"proposal kind "+a);
   String old=p.get(scalar?"old_name":"old").getAsString(),name=p.get(scalar?"new_name":"new").getAsString();
   require(old.equals("FUN_"+a)&&name.equals(NAMES.get(a)),"proposal names "+a);
   Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(a,16)));
   require(f!=null&&old.equals(f.getName()),"old function "+a);
   require(f.getBody().getNumAddresses()==SIZES.get(a),"body size "+a);
   require(f.getComment()==null||f.getComment().isBlank(),"old function comment "+a);
   require(currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null,"entry instruction "+a);
   JsonArray row=new JsonArray();row.add(a);row.add(old);row.add(name);rows.add(row);
  }
  require(local.equals(allowed),"complete proposal set "+path);
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();require(args.length==4,"Use OUTPUT_JSON STATUS_PROPOSALS EXIT_PROPOSALS PROBE_PROPOSALS");
  require(SHA.equals(currentProgram.getExecutableSHA256()),"specimen SHA-256");
  Function corrected=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x006f09f0L));
  require(corrected!=null&&corrected.getBody().getNumAddresses()==14547,"corrected match body size");
  for(var sentinel:Map.of("0062c3d0","MatchReadIndexedSignedWord31",
                           "006ceb90","match_select_scored_slot_006ceb90",
                           "00945934","forward_argument_with_two_zeroes_00945934").entrySet()) {
   Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(sentinel.getKey(),16)));
   require(f!=null&&sentinel.getValue().equals(f.getName()),"checkpoint-22 sentinel "+sentinel.getKey());
  }
  List<JsonArray> rows=new ArrayList<>();Set<String> seen=new HashSet<>();
  collect(args[1],Set.of("0062c400"),null,true,rows,seen);
  collect(args[2],Set.of("00945956","009459ef"),"preflight_sha256",false,rows,seen);
  collect(args[3],Set.of("00601070"),"private_preflight_sha256",false,rows,seen);
  require(rows.size()==4,"four reviewed names");
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",23);
  receipt.addProperty("scope","Four reviewed working names only. Two bounded TypeScript paths and four complete static local bodies; no prototype, comment or data type applied.");
  JsonArray names=new JsonArray();for(JsonArray row:rows)names.add(row);receipt.add("annotations",names);
  receipt.add("function_comments",new JsonArray());receipt.add("code_comments",new JsonArray());
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-status-23-annotations-proposal.json");sources.add("exit-runtime-23-annotations-proposal.json");sources.add("selection-probe-23-annotations-proposal.json");receipt.add("proposal_files",sources);
  Path output=Paths.get(args[0]).toAbsolutePath();
  require(!Files.exists(output),"output must not already exist");
  Path temporary=Files.createTempFile(output.getParent(),"investigation-23-", ".json.tmp");
  Files.writeString(temporary,new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  int tx=currentProgram.startTransaction("Investigation 23 reviewed names");boolean commit=false;
  try {
   for(JsonArray row:rows)currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row.get(0).getAsString(),16))).setName(row.get(2).getAsString(),SourceType.USER_DEFINED);
   Files.move(temporary,output);
   commit=true;
  } finally {
   currentProgram.endTransaction(tx,commit);
   if(!commit)Files.deleteIfExists(temporary);
  }
  println("Applied investigation 23: "+rows.size()+" working names");
 }
}
