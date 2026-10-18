// Apply independently reviewed investigation-10 proposals to the saved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation10 extends GhidraScript {
 private static final String INPUT_SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Map<String,String> OLD_NAMES=Map.of(
  "006cfe10","FUN_006cfe10", "0062ed70","FUN_0062ed70",
  "0062c680","FUN_0062c680", "006d0980","FUN_006d0980",
  "00896290","FUN_00896290", "00896660","FUN_00896660",
  "008967d0","FUN_008967d0", "00682b30","FUN_00682b30",
  "00682e10","FUN_00682e10", "00682f70","FUN_00682f70");
 private ghidra.program.model.address.Address address(String hex) throws Exception {
  if(!hex.matches("[0-9a-f]{8}"))throw new Exception("Invalid address: "+hex);
  return toAddr(Long.parseLong(hex,16));
 }
 private JsonArray triple(String a,String b,String c){JsonArray row=new JsonArray();row.add(a);row.add(b);row.add(c);return row;}
 private JsonArray pair(String a,String b){JsonArray row=new JsonArray();row.add(a);row.add(b);return row;}
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=4)throw new Exception("Use OUTPUT_JSON SHOT_PROPOSAL TACTICS_PROPOSAL LEAGUE_PROPOSAL");
  if(!INPUT_SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  JsonArray names=new JsonArray(),comments=new JsonArray();
  Set<String> nameSites=new HashSet<>(),commentSites=new HashSet<>();
  for(int i=1;i<4;i++){
   JsonObject proposal=JsonParser.parseString(Files.readString(Paths.get(args[i]))).getAsJsonObject();
   if(!INPUT_SHA.equals(proposal.get("sha256").getAsString()))throw new Exception("Proposal specimen mismatch: "+args[i]);
   if(proposal.has("functions"))for(JsonElement e:proposal.getAsJsonArray("functions")){
    JsonObject item=e.getAsJsonObject();String site=item.get("address").getAsString();
    if(!OLD_NAMES.get(site).equals(item.get("old_name").getAsString()))throw new Exception("Proposal old-name mismatch: "+site);
    if(!nameSites.add(site))throw new Exception("Duplicate function annotation: "+site);
    names.add(triple(site,item.get("proposed_name").getAsString(),item.get("comment").getAsString()));
   }
   if(proposal.has("annotations"))for(JsonElement e:proposal.getAsJsonArray("annotations")){
    JsonArray item=e.getAsJsonArray();String site=item.get(0).getAsString();
    if(item.size()!=3||!nameSites.add(site))throw new Exception("Duplicate/invalid function annotation: "+site);
    names.add(item.deepCopy());
   }
   if(proposal.has("code_comments"))for(JsonElement e:proposal.getAsJsonArray("code_comments")){
    JsonArray item=e.isJsonArray()?e.getAsJsonArray():null;
    String site=item!=null?item.get(0).getAsString():e.getAsJsonObject().get("address").getAsString();
    String note=item!=null?item.get(1).getAsString():e.getAsJsonObject().get("comment").getAsString();
    if((item!=null&&item.size()!=2)||!commentSites.add(site))throw new Exception("Duplicate/invalid code comment: "+site);
    comments.add(pair(site,note));
   }
  }
  if(names.size()!=10||comments.size()!=16||!nameSites.equals(OLD_NAMES.keySet()))
   throw new Exception("Unexpected proposal set: "+names.size()+"/"+comments.size());
  for(JsonElement e:names){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   Function f=currentProgram.getFunctionManager().getFunctionAt(address(site));
   if(f==null||!OLD_NAMES.get(site).equals(f.getName()))throw new Exception("Unexpected old function: "+site);
  }
  for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   if(currentProgram.getListing().getInstructionAt(address(site))==null)throw new Exception("Missing instruction: "+site);
   String old=currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT,address(site));
   if(old!=null&&!old.isBlank())throw new Exception("Refusing to replace existing code comment: "+site);
  }
  int tx=currentProgram.startTransaction("Investigation 10 reviewed annotations");boolean commit=false;
  try{
   for(JsonElement e:names){JsonArray row=e.getAsJsonArray();Function f=currentProgram.getFunctionManager().getFunctionAt(address(row.get(0).getAsString()));
    f.setName(row.get(1).getAsString(),SourceType.USER_DEFINED);
    String old=f.getComment();f.setComment((old==null||old.isBlank()?"":old+"\n\n")+"CM0102 investigation10 (2026-10-18): "+row.get(2).getAsString());
   }
   for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();currentProgram.getListing().setComment(address(row.get(0).getAsString()),CodeUnit.EOL_COMMENT,row.get(1).getAsString());}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",INPUT_SHA);receipt.addProperty("investigation",10);
  receipt.addProperty("scope","Reviewed static mapping annotations; no new behavior oracle, prototype or data type applied.");
  receipt.add("annotations",names);receipt.add("code_comments",comments);
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("shot-dependencies-10-annotations.json");sources.add("tactics-boundary-10-annotations.json");sources.add("league-boundary-10-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 10: "+names.size()+" function notes/names, "+comments.size()+" code comments");
 }
}
