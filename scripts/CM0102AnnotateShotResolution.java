// Preserve bounded penalty/keeper findings in the existing native project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102AnnotateShotResolution extends GhidraScript {
 public void run() throws Exception {
  String[][] names={
   {"00702050","cm0102_resolve_shot_candidate","Action33h threshold120. Classification703b25..703be7 checked for all65536 raw quality words with variant0/1. Only categories1/14/15 reach706cba ratio gate: float32(quality*100/(keeperTerm+quality)), zero denominator->0; match-state2/8 adds2 when ratio<=68; strict ratio>71 enters scoring branch. This is not a probability or complete goal/save reconstruction; upstream quality/keeper adjustments, score changes and presentation remain open."},
   {"00700420","cm0102_compute_keeper_response_candidate","Valid keeper action33h branch7004d6..7004ec: bound=sign16(selected signed16 slot+168/+16a +220), first=random(bound), base=random(bound-first). Verified4096 synthetic cases incl signed wrap/zero bound/table wrap. Common700a4f..700b87 postlude performs more RNG and x87 scaling; base is not final response. Prelude position/validity checks excluded from oracle."},
   {"006ce110","cm0102_select_goalkeeper_slot_candidate","Returns cached side0/side1 slot from match+f59e/+f5a2. Searches20 slots per side using tactical position value1, invalidates negative slot status, includes fallback/reassignment paths. Selected opposite side by tiebreak and shot callers. Static identification; complete selection behavior has not been reconstructed or tested."}
  };
  for(String[] row:names){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
   String note="CM0102 investigation06 (2026-10-18): "+row[2];String old=f.getComment();if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
  }
  String[][] labels={{"0096d808","cm0102_shot_ratio_goal_threshold"},{"0096d80c","cm0102_shot_ratio_adjustment_ceiling"}};
  for(String[] row:labels)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
  String[][] comments={
   {"007004d6","Penalty keeper base only: sign16(rating+220), random twice (second bound=first bound-first draw). Shared postlude follows at700a4f."},
   {"00700a4f","Unreconstructed common keeper postlude: additional RNG, float slot+d1, byte+f, match+8eaa, fallback rating+3b and x87 constants. Do not connect base-only oracle directly to final shot gate."},
   {"00703b25","Penalty threshold120; quality compared as signed16; category selection verified independently with original RNG."},
   {"00706cba","Eligible categories1/14/15 only. Signed16 terms enter float32 ratio quality*100/(keeperTerm+quality). Not a probability."},
   {"00706d26","Strict ratio>71 scoring-branch gate. Equal71 does not pass. State2/8 adds2 only to ratios<=68; this cannot itself change this gate's Boolean result."},
   {"00713eeb","Action33h takes early exit with return byte2 and output adjustment word0; full function not reconstructed."}
  };
  for(String[] row:comments)currentProgram.getListing().setComment(toAddr(Long.parseLong(row[0],16)),CodeUnit.EOL_COMMENT,row[1]);
  CategoryPath category=new CategoryPath("/CM0102/Recovered");
  Structure slot=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/MatchRosterSlotPartial");
  slot.replaceAtOffset(0x168,ShortDataType.dataType,2,"keeper_rating_variant0_raw","Selected when variant byte=0; source/stat formula unresolved");
  slot.replaceAtOffset(0x16a,ShortDataType.dataType,2,"keeper_rating_variant1_raw","Selected when variant byte!=0; source/stat formula unresolved");
  List<Object>types=new ArrayList<>();
  for(String name:new String[]{"MatchRosterSlotPartial","MatchSideDescriptorPartial","CommentaryEvent14","CommentaryBufferPartial","MatchContextPartial","CommentaryEventDefinition18","CommentaryVariant272","PlayerAttributesPrefixPartial"}){
   Structure s=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/"+name);Map<String,Object>row=new LinkedHashMap<>();row.put("path",s.getPathName());row.put("bytes",s.getLength());List<Object>fields=new ArrayList<>();
   for(DataTypeComponent c:s.getDefinedComponents()){Map<String,Object>x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());fields.add(x);}row.put("fields",fields);types.add(row);
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("annotations",names);root.put("global_labels",labels);root.put("code_comments",comments);root.put("partial_data_types",types);
  root.put("type_application","Two observed signed16 keeper-rating fields; no guessed complete prototype or record layout applied");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");println("Saved shot-resolution boundary annotations");
 }
}
