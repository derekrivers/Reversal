// Preserve keeper-response arithmetic/precision findings in the existing native project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102AnnotateKeeperEntry extends GhidraScript {
 public void run() throws Exception {
  String[][] names={
   {"00700420","cm0102_compute_keeper_response_candidate","Investigation08: action33 now checked from original entry through return in9056 cases with original tactical lookup/RNG/ftol and synthetic tactical/grid data. Initializes both output bytes0 before guard. Signed8(slot+2b)>1 rejects; tactical helper006c38c0 low-word result must equal1. Variant0 selects rating+168; nonzero selects+16a. Grid index=abs(signed8(slot+103)-signed8(match+8ea8))*9+abs(signed8(slot+102)-signed8(match+8ea7)) within tested x0..8/y0..11 domain. Lookup occurs before rejection. Preserves callee registers, CW and input slot/context; ret18h. Other actions, real state producers and shot outcomes remain open."},
   {"006c38c0","cm0102_lookup_tactical_position_word","Reads signed8 slot+19. Only0..10 indexes the side-selected11-word table at match+8ebc+4*signed8(slot+27); invalid index returns AX0. Other path returns table word in AX. Upper EAX is not a semantic return contract. Side0/1 and valid mapped tables are reconstruction preconditions; return width2 measured in assembly and applied."}
  };
  for(String[] row:names){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
   String note="CM0102 investigation08 (2026-10-18): "+row[2];String old=f.getComment();if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
  }
  Function lookup=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x006c38c0L));lookup.setReturnType(UnsignedShortDataType.dataType,SourceType.USER_DEFINED);
  String[][] labels={{"00a15e44","cm0102_grid_distance_lookup_candidate"}};
  for(String[] row:labels)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
  String[][] comments={
   {"00700420","Action33 entry-to-return oracle9056 cases; original callee ABI preserved. Synthetic108-entry grid and side tactical tables; no whole-function/all-actions or shot-outcome claim."},
   {"00700438","Variant byte0 selects signed16 slot+168; any nonzero byte selects+16a. Output pointers already initialized to0."},
   {"0070049f","Signed8 slot+2b >1 rejects; raw128..255 are negative and pass this guard. Tactical position must still equal1."},
   {"007004a4","Grid read occurs before validity guards. Supported coordinates x0..8/y0..11 give108-index window atA15E44. Original lookup differs from exact hypot; public oracle supplies explicit synthetic values."},
   {"007004be","Original tactical lookup006c38c0 executes; only low word AX compared with1. Side0/1 table pointers at match+8ebc/+8ec0."},
   {"006c38c0","Low-word tactical position contract: slot+19 signed8 index0..10; side index selects11-word table; invalid slot returns AX0, upper EAX irrelevant."}
  };
  for(String[] row:comments)currentProgram.getListing().setComment(toAddr(Long.parseLong(row[0],16)),CodeUnit.EOL_COMMENT,row[1]);
  CategoryPath category=new CategoryPath("/CM0102/Recovered");
  Structure slot=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/MatchRosterSlotPartial");
  slot.replaceAtOffset(0x19,SignedByteDataType.dataType,1,"tactical_slot_index_raw","Refines prior status_raw label: signed8 index0..10 into side tactical-position table");
  slot.replaceAtOffset(0x2b,SignedByteDataType.dataType,1,"keeper_activity_raw","Signed8 >1 rejects keeper response; enum/source unresolved");
  slot.replaceAtOffset(0x102,SignedByteDataType.dataType,1,"grid_x_candidate","Keeper coordinate used by distance window; checked domain0..8");
  slot.replaceAtOffset(0x103,SignedByteDataType.dataType,1,"grid_y_candidate","Keeper coordinate used by distance window; checked domain0..11");
  Structure match=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/MatchContextPartial");
  match.replaceAtOffset(0x8ebc,new ArrayDataType(Pointer32DataType.dataType,2,4),8,"tactical_position_tables","Side0/1 pointers to11-word tactical-position tables; runtime addresses, not saved-file IDs");
  StructureDataType table=new StructureDataType(category,"TacticalPositionTable22Partial",22);
  table.replaceAtOffset(0,new ArrayDataType(UnsignedShortDataType.dataType,11,2),22,"position_words","Low-word position codes;1 is the keeper role in observed callers; other codes unresolved");
  currentProgram.getDataTypeManager().resolve(table,DataTypeConflictHandler.REPLACE_HANDLER);
  List<Object>types=new ArrayList<>();
  for(String name:new String[]{"MatchRosterSlotPartial","MatchSideDescriptorPartial","CommentaryEvent14","CommentaryBufferPartial","MatchContextPartial","CommentaryEventDefinition18","CommentaryVariant272","PlayerAttributesPrefixPartial","TacticalPositionTable22Partial"}){
   Structure s=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/"+name);Map<String,Object>row=new LinkedHashMap<>();row.put("path",s.getPathName());row.put("bytes",s.getLength());List<Object>fields=new ArrayList<>();
   for(DataTypeComponent c:s.getDefinedComponents()){Map<String,Object>x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());fields.add(x);}row.put("fields",fields);types.add(row);
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("annotations",names);root.put("global_labels",labels);root.put("code_comments",comments);root.put("partial_data_types",types);
  root.put("type_application","Measured tactical-table/coordinate fields and lookup return width2; complete class layouts remain partial");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");println("Saved keeper-entry and tactical lookup annotations");
 }
}
