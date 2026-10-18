// Save calculation-slice evidence and measured partial fields.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102AnnotatePenalty extends GhidraScript {
 CategoryPath category=new CategoryPath("/CM0102/Recovered");
 void field(Structure s,int offset,DataType dt,String name,String comment){s.replaceAtOffset(offset,dt,dt.getLength(),name,comment);}
 Structure existing(String name)throws Exception {DataType dt=currentProgram.getDataTypeManager().getDataType(category.getPath()+"/"+name);if(!(dt instanceof Structure))throw new Exception("Missing "+name);return (Structure)dt;}
 public void run()throws Exception {
  String[][] names={
   {"00700bd0","cm0102_prepare_shot_quality_candidate","Action-kind33h branch at00700d19 emits1f7f (config63 EVENT_TAKE_PENALTY) and returns AX of150+random(signed16(slot+180)*5). Slot+180 semantics remain unresolved. Prelude and other action kinds are not reconstructed. Calculation branch checked with synthetic frames and original RNG instructions."},
   {"006be710","cm0102_advance_tiebreak_sequence","Preparation slice6be9d7..6beacc uses signed player+35 (community OneOnOnes, not Penalties+38). Base error budget=2*(200-draw*(remaining+4)); must-score adds random(trunc(base*2.25)), score-to-win adds random(trunc(base*.75)), first condition wins. For penalty mode3, final quality=signed16(base preparation)-random(errorBudget). 3584 original-slice fixtures match. Commentary suppressed with sudden-death flag1; no shared shot/goal outcome equivalence."},
   {"006d6f70","cm0102_enqueue_commentary_event","Port architecture note: variant selection consumes shared RNG. Keeping React rendering separate must preserve original event-selection draws in the simulation pipeline, including hidden events. Penalty preparation oracle suppresses commentary and does not reproduce its RNG consumption."}
  };
  for(String[] row:names){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
   String note="CM0102 investigation05 (2026-10-18): "+row[2];String old=f.getComment();if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
  }
  String[][] labels={{"00968ec8","cm0102_must_score_error_multiplier"},{"00969040","cm0102_score_to_win_error_multiplier"}};
  for(String[] row:labels)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
  String[][] comments={{"006be9dd","Signed player+35; community layout OneOnOnes. Penalties is+38, not used at this read."},
   {"006bea6e","Must-score error-budget bound multiplier: double2.25; not a scoring probability."},
   {"006beaaf","Score-to-win error-budget bound multiplier: double0.75; FIST conversion truncates."},
   {"00700d20","Action33h writes event1f7f, config63 EVENT_TAKE_PENALTY."},
   {"006beb04","Penalty quality argument = sign-extended returned AX minus bounded random error budget; goal/save decision is downstream."}};
  for(String[] row:comments)currentProgram.getListing().setComment(toAddr(Long.parseLong(row[0],16)),CodeUnit.EOL_COMMENT,row[1]);
  StructureDataType player=new StructureDataType(category,"PlayerAttributesPrefixPartial",0x39);
  player.setDescription("Minimum observed/corroborated prefix only; not an established full player-record size.");
  field(player,0x35,SignedByteDataType.dataType,"one_on_ones_candidate","Read by shootout budget; label corroborated by pinned community TPlayer layout");
  field(player,0x38,SignedByteDataType.dataType,"penalties_candidate","Community TPlayer label; this offset is not read by the verified budget slice");
  currentProgram.getDataTypeManager().resolve(player,DataTypeConflictHandler.REPLACE_HANDLER);
  Structure slot=existing("MatchRosterSlotPartial");field(slot,0x180,ShortDataType.dataType,"shot_rating_raw","Meaning unresolved; signed16*5 supplies penalty base-quality random bound");
  field(slot,0x19c,ShortDataType.dataType,"shot_quality_raw","Used in action state; 35-yard sequence clamps one write to[-200,200]");
  field(slot,0x19e,Pointer32DataType.dataType,"match_context","Corrects earlier activity-word-unknown label; dereferenced as match receiver by006f0630 and multiple action routines");
  List<Object>types=new ArrayList<>();
  for(String name:new String[]{"MatchRosterSlotPartial","MatchSideDescriptorPartial","CommentaryEvent14","CommentaryBufferPartial","MatchContextPartial","CommentaryEventDefinition18","CommentaryVariant272","PlayerAttributesPrefixPartial"}){
   Structure s=existing(name);Map<String,Object>row=new LinkedHashMap<>();row.put("path",s.getPathName());row.put("bytes",s.getLength());List<Object>fields=new ArrayList<>();
   for(DataTypeComponent c:s.getDefinedComponents()){Map<String,Object>x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());fields.add(x);}row.put("fields",fields);types.add(row);
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("annotations",names);root.put("global_labels",labels);root.put("code_comments",comments);root.put("partial_data_types",types);
  root.put("type_application","Partial definitions saved; no guessed full prototype applied; player prefix extent is not a full allocation size");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");println("Saved penalty preparation annotations and8 structures");
 }
}
