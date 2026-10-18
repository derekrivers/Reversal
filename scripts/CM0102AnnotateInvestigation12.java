// Apply independently reviewed investigation-12 proposals to a preserved project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class CM0102AnnotateInvestigation12 extends GhidraScript {
 private static final String SHA="0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86";
 private static final Set<String> NAME_SITES=Set.of("006f09b0","006cb960","006bce20","004c7560","004c79a0","00727e20","00727f00");
 private static final Set<String> NOTE_SITES=Set.of("006f09b0","006cb960","006bce20","00727e20","00727f00");
 private static final Set<String> EOL_SITES=Set.of("00727ed3","00727f8e");
 private ghidra.program.model.address.Address at(String hex) throws Exception {
  if(!hex.matches("[0-9a-f]{8}"))throw new Exception("Invalid address: "+hex);
  return toAddr(Long.parseLong(hex,16));
 }
 private JsonObject read(String path) throws Exception {return JsonParser.parseString(Files.readString(Paths.get(path))).getAsJsonObject();}
 private String getSha(JsonObject o){return o.has("sha256")?o.get("sha256").getAsString():o.get("specimen_sha256").getAsString();}
 private void addName(JsonArray rows,Set<String> seen,String site,String old,String proposed) throws Exception {
  if(!seen.add(site)||!NAME_SITES.contains(site)||!("FUN_"+site).equals(old)||proposed.isBlank())throw new Exception("Invalid name proposal: "+site);
  JsonArray r=new JsonArray();r.add(site);r.add(old);r.add(proposed);rows.add(r);
 }
 private void addText(JsonArray rows,Set<String> seen,Set<String> allowed,String site,JsonElement old,String proposed) throws Exception {
  if(!seen.add(site)||!allowed.contains(site)||!old.isJsonNull()||proposed.isBlank())throw new Exception("Invalid comment proposal: "+site);
  JsonArray r=new JsonArray();r.add(site);r.add(proposed);rows.add(r);
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=4)throw new Exception("Use OUTPUT_JSON MATCH_PROPOSAL CONTRACT_PROPOSAL UI_PROPOSAL");
  if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new Exception("Specimen hash mismatch");
  JsonObject a=read(args[1]),b=read(args[2]),c=read(args[3]);
  for(JsonObject p:List.of(a,b,c))if(!SHA.equals(getSha(p)))throw new Exception("Proposal specimen mismatch");
  JsonArray names=new JsonArray(),notes=new JsonArray(),eols=new JsonArray();
  Set<String> seenNames=new HashSet<>(),seenNotes=new HashSet<>(),seenEols=new HashSet<>();
  for(JsonElement item:a.getAsJsonArray("functions")){
   JsonObject p=item.getAsJsonObject();String site=p.get("address").getAsString();
   addName(names,seenNames,site,p.get("old_name").getAsString(),p.get("new_name").getAsString());
   addText(notes,seenNotes,NOTE_SITES,site,p.get("old_comment"),p.get("new_comment").getAsString());
  }
  for(JsonElement item:b.getAsJsonArray("proposals")){
   JsonObject p=item.getAsJsonObject();if(!"function_name".equals(p.get("kind").getAsString()))throw new Exception("Unexpected contract proposal");
   addName(names,seenNames,p.get("address").getAsString(),p.get("old").getAsString(),p.get("new").getAsString());
  }
  for(JsonElement item:c.getAsJsonArray("changes")){
   JsonObject p=item.getAsJsonObject();String site=p.get("address").getAsString(),kind=p.get("kind").getAsString();
   switch(kind){
    case "function_name":addName(names,seenNames,site,p.get("old").getAsString(),p.get("new").getAsString());break;
    case "function_comment":addText(notes,seenNotes,NOTE_SITES,site,p.get("old"),p.get("new").getAsString());break;
    case "eol_comment":addText(eols,seenEols,EOL_SITES,site,p.get("old"),p.get("new").getAsString());break;
    default:throw new Exception("Unexpected UI proposal kind: "+kind);
   }
  }
  if(!seenNames.equals(NAME_SITES)||!seenNotes.equals(NOTE_SITES)||!seenEols.equals(EOL_SITES))throw new Exception("Incomplete proposal sites");
  for(JsonElement item:names){JsonArray r=item.getAsJsonArray();String site=r.get(0).getAsString();
   Function f=currentProgram.getFunctionManager().getFunctionAt(at(site));
   if(f==null||!r.get(1).getAsString().equals(f.getName()))throw new Exception("Unexpected old function: "+site);
  }
  for(JsonElement item:notes){JsonArray r=item.getAsJsonArray();String site=r.get(0).getAsString();
   Function f=currentProgram.getFunctionManager().getFunctionAt(at(site));
   if(f==null||f.getComment()!=null&&!f.getComment().isBlank())throw new Exception("Refusing to replace function comment: "+site);
  }
  for(JsonElement item:eols){JsonArray r=item.getAsJsonArray();String site=r.get(0).getAsString();
   if(currentProgram.getListing().getInstructionAt(at(site))==null)throw new Exception("Missing instruction: "+site);
   String old=currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT,at(site));
   if(old!=null&&!old.isBlank())throw new Exception("Refusing to replace EOL comment: "+site);
  }
  int tx=currentProgram.startTransaction("Investigation 12 reviewed annotations");boolean commit=false;
  try {
   for(JsonElement item:names){JsonArray r=item.getAsJsonArray();currentProgram.getFunctionManager().getFunctionAt(at(r.get(0).getAsString())).setName(r.get(2).getAsString(),SourceType.USER_DEFINED);}
   for(JsonElement item:notes){JsonArray r=item.getAsJsonArray();currentProgram.getFunctionManager().getFunctionAt(at(r.get(0).getAsString())).setComment("CM0102 investigation12 (2026-10-18): "+r.get(1).getAsString());}
   for(JsonElement item:eols){JsonArray r=item.getAsJsonArray();currentProgram.getListing().setComment(at(r.get(0).getAsString()),CodeUnit.EOL_COMMENT,r.get(1).getAsString());}
   commit=true;
  } finally {currentProgram.endTransaction(tx,commit);}
  JsonObject receipt=new JsonObject();receipt.addProperty("sha256",SHA);receipt.addProperty("investigation",12);
  receipt.addProperty("scope","Reviewed static names and comments only; no behavior oracle, prototype or data type applied.");
  receipt.add("annotations",names);receipt.add("function_comments",notes);receipt.add("code_comments",eols);
  receipt.add("global_labels",new JsonArray());receipt.add("partial_data_types",new JsonArray());
  JsonArray sources=new JsonArray();sources.add("match-helpers-12-annotations.json");sources.add("contract-boundary-12-annotations.json");sources.add("match-ui-12-annotations.json");receipt.add("proposal_files",sources);
  Files.writeString(Paths.get(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(receipt)+"\n");
  println("Applied investigation 12: "+names.size()+" names, "+notes.size()+" function comments, "+eols.size()+" code comments");
 }
}
