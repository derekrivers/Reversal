// Apply independently reviewed investigation-09 proposals to the saved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation09 extends GhidraScript {
 private static final String INPUT_SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Map<String,String> OLD_NAMES=Map.of(
  "0054d5e0","FUN_0054d5e0", "0054d740","FUN_0054d740",
  "006ec010","FUN_006ec010", "006eecb0","FUN_006eecb0",
  "006ce110","cm0102_select_goalkeeper_slot_candidate");
 private static final String[][] STARTUP_COMMENTS={
  {"00945910","PE entry00947a13 calls00945907 before application0068d370. Original pointer00ad6c14=009455b2; this computed call takes the normal startup precision request. Later initializer callbacks and match-entry CW remain unobserved."},
  {"009455c1","Normal startup calls0094a698 here; mask30000h/value10000h sets x87 precision-control bits0200h (53-bit) but does not by itself prove full CW027fh or match-entry precision. FNCLEX009455c6 clears exceptions."}
 };
 private ghidra.program.model.address.Address address(String hex) throws Exception {
  if(!hex.matches("[0-9a-f]{8}"))throw new Exception("Invalid address: "+hex);
  return toAddr(Long.parseLong(hex,16));
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=4)throw new Exception("Use OUTPUT_JSON SHOT_PROPOSAL KEEPER_PROPOSAL DATABASE_PROPOSAL");
  if(!INPUT_SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  JsonArray names=new JsonArray(),comments=new JsonArray();
  Set<String>nameSites=new HashSet<>(),commentSites=new HashSet<>();
  for(int i=1;i<4;i++){
   JsonObject proposal=JsonParser.parseString(Files.readString(Paths.get(args[i]))).getAsJsonObject();
   if(!INPUT_SHA.equals(proposal.get("sha256").getAsString()))throw new Exception("Proposal specimen mismatch: "+args[i]);
   if(proposal.has("annotations"))for(JsonElement e:proposal.getAsJsonArray("annotations")){
    JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
    if(row.size()!=3||!nameSites.add(site))throw new Exception("Duplicate/invalid function annotation: "+site);
    names.add(row.deepCopy());
   }
   if(proposal.has("code_comments"))for(JsonElement e:proposal.getAsJsonArray("code_comments")){
    JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
    if(row.size()!=2||!commentSites.add(site))throw new Exception("Duplicate/invalid code comment: "+site);
    comments.add(row.deepCopy());
   }
  }
  for(String[] item:STARTUP_COMMENTS){
   if(!commentSites.add(item[0]))throw new Exception("Duplicate startup comment: "+item[0]);
   JsonArray row=new JsonArray();row.add(item[0]);row.add(item[1]);comments.add(row);
  }
  if(names.size()!=5||comments.size()!=24)throw new Exception("Unexpected proposal counts: "+names.size()+"/"+comments.size());
  // Validate all old state before entering the writing transaction.
  for(JsonElement e:names){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   Function f=currentProgram.getFunctionManager().getFunctionAt(address(site));
   if(f==null||!OLD_NAMES.get(site).equals(f.getName()))throw new Exception("Unexpected old function: "+site);
   if(site.equals("006ce110")&&(f.getComment()==null||f.getComment().isBlank()))throw new Exception("Missing prior function comment: "+site);
  }
  for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();String site=row.get(0).getAsString();
   if(currentProgram.getListing().getInstructionAt(address(site))==null)throw new Exception("Missing instruction: "+site);
   String old=currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT,address(site));
   if(old!=null&&!old.isBlank())throw new Exception("Refusing to replace existing code comment: "+site);
  }
  int tx=currentProgram.startTransaction("Investigation 09 reviewed annotations");boolean commit=false;
  try{
   for(JsonElement e:names){JsonArray row=e.getAsJsonArray();Function f=currentProgram.getFunctionManager().getFunctionAt(address(row.get(0).getAsString()));
    f.setName(row.get(1).getAsString(),SourceType.USER_DEFINED);
    String old=f.getComment();f.setComment((old==null||old.isBlank()?"":old+"\n\n")+"CM0102 investigation09 (2026-10-18): "+row.get(2).getAsString());
   }
   for(JsonElement e:comments){JsonArray row=e.getAsJsonArray();currentProgram.getListing().setComment(address(row.get(0).getAsString()),CodeUnit.EOL_COMMENT,row.get(1).getAsString());}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",INPUT_SHA);receipt.addProperty("investigation",9);
  receipt.addProperty("scope","Reviewed static mapping annotations; no new behavior oracle, prototype or data type applied.");
  receipt.add("annotations",names);receipt.add("code_comments",comments);
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("shot-resolver-09-annotations.json");sources.add("keeper-producers-09-annotations.json");sources.add("database-boundary-09-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 09: "+names.size()+" function notes/names, "+comments.size()+" code comments");
 }
}
