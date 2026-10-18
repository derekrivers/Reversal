// Record the config-to-runtime bridge and measured commentary structures.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102AnnotateEvents extends GhidraScript {
 CategoryPath category=new CategoryPath("/CM0102/Recovered");
 void field(Structure s,int offset,DataType dt,String name,String note){s.replaceAtOffset(offset,dt,dt.getLength(),name,note);}
 Structure existing(String name)throws Exception {
  DataType dt=currentProgram.getDataTypeManager().getDataType(category.getPath()+"/"+name);
  if(!(dt instanceof Structure))throw new Exception("Missing existing structure "+name);
  return (Structure)dt;
 }
 public void run()throws Exception {
  String[][] labels={
   {"006d9e50","cm0102_load_event_configuration","Loads localized events_*.cfg, falls back to English. Initializes677 records at B68788, stride18. Config IDs0..676; runtime event index=(code&7fff)-8000. Variants stride110h; G/R strings at+108/+10c. EOF converts divisor values to inverse weights using maxDivisor*10/divisor, then sums. Full loader not emulated."},
   {"006d5b50","cm0102_release_event_configuration","Frees game/report text and variant arrays for677 event definitions, excluding fallback B68670; clears loaded/language globals."},
   {"006d5cd0","cm0102_event_priority","Returns signed-byte priority from record18*((code&7fff)-8000), or0 if index outside0..676. Original instructions checked for all65536 raw event codes under two synthetic priority tables."},
   {"006d78b0","cm0102_next_commentary_segment","Advances display ring cursor at companion+C, reads game-text variant, handles pipe-separated segments and event-code bit8000. Event record+D is a signed segment cursor initialized-1. Exact original class/prototype not recovered."},
   {"006d7b00","cm0102_format_game_commentary_candidate","Uses event variant+108 game text and token substitution. Pseudocode stack/prototype damaged around stack-probe helper; semantic role based on assembly/data accesses, not guessed signature."},
   {"006d8d10","cm0102_format_report_commentary_candidate","Uses event variant+10c report text and token substitution. Stack-probe confuses decompiler prototype; do not apply inferred full signature."},
   {"006d4250","cm0102_stop_after_goal_rule","Literal predicate: 16-bit period target !=495 and !=990, and fixture flags byte+38 bit80 set. Goal callers set match+1a8 and emit runtime1fd2, config146 EVENT_GOLDEN_GOAL. Predicate checked against original x86 for every16-bit target with flags0/80/7f/ff. Does not itself test tie/goal/valid-period conditions."},
   {"006be710","cm0102_advance_tiebreak_sequence","Config/announcement bridge identifies phases1/2/3 as35-yard shootout and4/5/6 aspenalty shootout. Dispatcher phase1 emits2003 (config195); other nonzero entry emits2002 (config194). First variant starts side1, second chooses first side through RNG. Full attempts/outcomes not emulated."},
   {"006b98c0","cm0102_advance_match_candidate","Event mapping resolves exceptional status8 to pitch-condition abandonment (runtime217b/config571). Threshold+F638 is a signed minute threshold, -1disabled. Phase1 announces35-yard shootout; phase4 announcespenalties. Config meanings from pinned community data, not pristine publisher-authenticated text."},
   {"006d6f70","cm0102_enqueue_commentary_event","Runtime event definition index=(eventCode&7fff)-8000 atB68788 with18-byte stride. Weighted variant choices refer to272-byte entries; variant count short+C and weight total int+E. Event record+D is segment cursor, initially-1, rather than an unidentified flag."}
  };
  for(String[] row:labels){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));
   if(f==null)throw new Exception("Missing function "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
   String note="CM0102 event investigation04 (2026-10-18; supersedes earlier unknowns): "+row[2];String old=f.getComment();
   if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
   if(row[0].equals("006d4250")||row[0].equals("006d5cd0"))f.setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED);
  }
  String[][] globals={{"00b68788","cm0102_event_definitions_677"},{"00b6b723","cm0102_event_config_loaded"},{"00a1599c","cm0102_event_config_language"}};
  for(String[] row:globals)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
  String[][] notes={{"006ba9e7","Phase1 announcement2003 -> config195:35-yard shootout"},
   {"006baa06","Other nonzero entry phase announcement2002 -> config194:penalty shootout"},
   {"00706eaf","Post-goal rule true sets golden-goal stop latch; predicate006d4250"},
   {"007084a5","Golden-goal event1fd2 -> config146; latch+1a8 is nonzero"}};
  for(String[] row:notes)currentProgram.getListing().setComment(toAddr(Long.parseLong(row[0],16)),CodeUnit.EOL_COMMENT,row[1]);
  StructureDataType definition=new StructureDataType(category,"CommentaryEventDefinition18",18);
  String[] flagNames={"priority","silent_flag","follow_on_flag","flashing_flag","report_count","sound_centre","wait_on_sound","no_rollback"};
  for(int i=0;i<8;i++)field(definition,i,SignedByteDataType.dataType,flagNames[i],i==4?"Loader clamps to0..11":"Config header field");
  field(definition,8,Pointer32DataType.dataType,"variants","Array of0x110-byte records");
  field(definition,12,ShortDataType.dataType,"variant_count","");
  field(definition,14,IntegerDataType.dataType,"weight_total","After EOF normalization; maxDivisor*10/divisor weights are summed");
  StructureDataType variant=new StructureDataType(category,"CommentaryVariant272",0x110);
  field(variant,0,ShortDataType.dataType,"weight","Config divisor replaced by normalized inverse weight at EOF");
  field(variant,2,ShortDataType.dataType,"delay_milliseconds","");
  field(variant,4,new ArrayDataType(ByteDataType.dataType,0x104,1),"sound_filename_buffer","Storage up to game-text pointer; original declared buffer type unknown");
  field(variant,0x108,Pointer32DataType.dataType,"game_text","");field(variant,0x10c,Pointer32DataType.dataType,"report_text","");
  for(DataType dt:new DataType[]{definition,variant})currentProgram.getDataTypeManager().resolve(dt,DataTypeConflictHandler.REPLACE_HANDLER);
  Structure event=existing("CommentaryEvent14");field(event,13,SignedByteDataType.dataType,"segment_index","Initialized-1; pipe-separated game text advances this signed cursor; code bit8000 marks continuation");
  Structure buffer=existing("CommentaryBufferPartial");field(buffer,5,ByteDataType.dataType,"display_pending_flag","Zero makes006d78b0 return null");
  field(buffer,12,ShortDataType.dataType,"ring_display_index","Used by006d78b0;0..11");
  field(buffer,14,ShortDataType.dataType,"history_cursor_index","Used by enqueue history-copy path");
  Structure match=existing("MatchContextPartial");field(match,0x1a8,ByteDataType.dataType,"golden_goal_stop_latch","Set by inspected goal paths after predicate006d4250; emitted event1fd2 identifies golden-goal semantics");
  field(match,0xf638,SignedByteDataType.dataType,"pitch_abandonment_minute_threshold","-1disables; threshold*11 compared with signed clock in path emitting217b/config571");
  List<Object> types=new ArrayList<>();
  for(String name:new String[]{"MatchRosterSlotPartial","MatchSideDescriptorPartial","CommentaryEvent14","CommentaryBufferPartial","MatchContextPartial","CommentaryEventDefinition18","CommentaryVariant272"}){
   Structure s=existing(name);Map<String,Object> row=new LinkedHashMap<>();row.put("path",s.getPathName());row.put("bytes",s.getLength());List<Object>fields=new ArrayList<>();
   for(DataTypeComponent c:s.getDefinedComponents()){Map<String,Object>x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());fields.add(x);}
   row.put("fields",fields);types.add(row);
  }
  Map<String,Object> root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("annotations",labels);root.put("global_labels",globals);root.put("partial_data_types",types);root.put("code_comments",notes);
  root.put("type_application","Saved type definitions only; full prototypes and global data-array applications remain unapplied");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");
  println("Saved event bridge,7 structures and updated semantic labels");
 }
}
