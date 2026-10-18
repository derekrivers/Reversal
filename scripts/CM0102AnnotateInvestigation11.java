// Apply independently reviewed investigation-11 proposals to a preserved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation11 extends GhidraScript {
 private static final String INPUT_SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Set<String> NAME_SITES=Set.of("008bba30","005a0590","005999a0","0059a370","0059b2a0");
 private static final Set<String> COMMENT_SITES=Set.of("007103e0","00710449","00710654","007109d1","00703e8c",
  "008bbc7b","008bbccd","008bbd2c","008bbe05");
 private ghidra.program.model.address.Address address(String hex) throws Exception {
  if(!hex.matches("[0-9a-f]{8}"))throw new Exception("Invalid address: "+hex);
  return toAddr(Long.parseLong(hex,16));
 }
 private JsonArray triple(String a,String b,String c){JsonArray r=new JsonArray();r.add(a);r.add(b);r.add(c);return r;}
 private JsonArray pair(String a,String b){JsonArray r=new JsonArray();r.add(a);r.add(b);return r;}
 private String proposalSha(JsonObject p){
  if(p.has("sha256"))return p.get("sha256").getAsString();
  return p.get("specimen_sha256").getAsString();
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=4)throw new Exception("Use OUTPUT_JSON SHOT_PROPOSAL TRANSFER_PROPOSAL FINANCE_PROPOSAL");
  if(!INPUT_SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  JsonObject shot=JsonParser.parseString(Files.readString(Paths.get(args[1]))).getAsJsonObject();
  JsonObject transfer=JsonParser.parseString(Files.readString(Paths.get(args[2]))).getAsJsonObject();
  JsonObject finance=JsonParser.parseString(Files.readString(Paths.get(args[3]))).getAsJsonObject();
  for(JsonObject p:List.of(shot,transfer,finance))if(!INPUT_SHA.equals(proposalSha(p)))throw new Exception("Proposal specimen mismatch");
  JsonArray names=new JsonArray(),comments=new JsonArray();
  Set<String> nameSites=new HashSet<>(),commentSites=new HashSet<>();
  for(JsonElement e:transfer.getAsJsonArray("annotations")){
   JsonArray row=e.getAsJsonArray();if(row.size()!=3)throw new Exception("Invalid transfer annotation");
   String site=row.get(0).getAsString();if(!nameSites.add(site))throw new Exception("Duplicate name "+site);
   names.add(row.deepCopy());
  }
  for(JsonElement e:finance.getAsJsonArray("functions")){
   JsonObject row=e.getAsJsonObject();String site=row.get("address").getAsString();
   if(!("FUN_"+site).equals(row.get("old_name").getAsString())||!nameSites.add(site))throw new Exception("Unexpected finance name "+site);
   names.add(triple(site,row.get("new_name").getAsString(),row.get("comment").getAsString()));
  }
  for(JsonElement e:shot.getAsJsonArray("comments")){
   JsonObject row=e.getAsJsonObject();String site=row.get("address").getAsString();
   if(!commentSites.add(site))throw new Exception("Duplicate comment "+site);
   comments.add(pair(site,row.get("proposed").getAsString()));
  }
  for(JsonElement e:transfer.getAsJsonArray("code_comments")){
   JsonArray row=e.getAsJsonArray();if(row.size()!=2)throw new Exception("Invalid transfer comment");
   String site=row.get(0).getAsString();if(!commentSites.add(site))throw new Exception("Duplicate comment "+site);
   comments.add(row.deepCopy());
  }
  if(!nameSites.equals(NAME_SITES)||!commentSites.equals(COMMENT_SITES))throw new Exception("Unexpected proposal sites");
  for(JsonElement e:names){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   Function f=currentProgram.getFunctionManager().getFunctionAt(address(site));
   if(f==null||!("FUN_"+site).equals(f.getName()))throw new Exception("Unexpected old function "+site);
   if(row.get(1).getAsString().isBlank()||row.get(2).getAsString().isBlank())throw new Exception("Empty function proposal "+site);
  }
  for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   if(currentProgram.getListing().getInstructionAt(address(site))==null)throw new Exception("Missing instruction "+site);
   String old=currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT,address(site));
   if(old!=null&&!old.isBlank())throw new Exception("Refusing to replace comment "+site);
   if(row.get(1).getAsString().isBlank())throw new Exception("Empty comment "+site);
  }
  int tx=currentProgram.startTransaction("Investigation 11 reviewed annotations");boolean commit=false;
  try {
   for(JsonElement e:names){JsonArray row=e.getAsJsonArray();Function f=currentProgram.getFunctionManager().getFunctionAt(address(row.get(0).getAsString()));
    f.setName(row.get(1).getAsString(),SourceType.USER_DEFINED);
    String old=f.getComment();f.setComment((old==null||old.isBlank()?"":old+"\n\n")+"CM0102 investigation11 (2026-10-18): "+row.get(2).getAsString());
   }
   for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();currentProgram.getListing().setComment(address(row.get(0).getAsString()),CodeUnit.EOL_COMMENT,row.get(1).getAsString());}
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",INPUT_SHA);receipt.addProperty("investigation",11);
  receipt.addProperty("scope","Reviewed static mapping annotations; no behavior oracle, prototype or data type applied.");
  receipt.add("annotations",names);receipt.add("code_comments",comments);
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("shot-helper-11-annotations.json");sources.add("transfer-boundary-11-annotations.json");sources.add("finance-boundary-11-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 11: "+names.size()+" function notes/names, "+comments.size()+" code comments");
 }
}
