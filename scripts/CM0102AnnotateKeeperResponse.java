// Preserve keeper-response arithmetic/precision findings in the existing native project.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
public class CM0102AnnotateKeeperResponse extends GhidraScript {
 public void run() throws Exception {
  String[][] names={
   {"00700420","cm0102_compute_keeper_response_candidate","Investigation07 supersedes earlier base-only gap: common700a4f..700b87 postlude and connected penalty base+postlude checked in8192 fixtures under explicit53/64-bit x87 precision. Two initial postlude draws select retained vs fallback; fallback uses rating+3b and random285, then raw base redraw or represented-double0.7/0.3 weighted redraw. Final trunc(trunc(selectedRating/6)+sign16(value)*represented-double4/7+20), with x87 rounding after each operation. Prelude validity/grid lookup and other actions remain outside reconstructed scope; no full goal/save outcome."},
   {"0094a698","cm0102_crt_request_precision53_candidate","Pushes mask30000h and value10000h into0094f5b0 ->0094f57b ->0094f658, mapping to x87 precision bits0200h (53-bit). Static request observed; no runtime trace establishes match-entry control word or complete startup path."}
  };
  for(String[] row:names){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
   String note="CM0102 investigation07 (2026-10-18): "+row[2];String old=f.getComment();if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
  }
  String[][] labels={{"00968e40","cm0102_keeper_redraw_weight_double"},{"00968e80","cm0102_keeper_base_weight_double"},{"0096d698","cm0102_keeper_response_scale_double"}};
  for(String[] row:labels)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
  String[][] comments={
   {"00700a4f","Verified keeper postlude: first bound=trunc(2*float(slot+d1)+uint8(slot+f)+10); second=trunc((2-float(distance))*signed8(match+8eaa)*10). Compare draws; first<=second selects fallback. Both53/64-bit x87 modes tested; no full function/caller equivalence."},
   {"00700ab2","first<=second sets output flag1; fallback compares random(signed16(slot+3b)) > random285 to choose weighted vs raw base redraw."},
   {"00700b12","Bound trunc(sign16(base)*binary64(0.7)); x87 precision matters. Then random(bound)+sign16(base)*binary64(0.3), truncated before signed16 cast."},
   {"00700b75","Final response: trunc(trunc(selected signed16 rating/6)+sign16(value)*binary64(4/7)+20). Do not round this whole expression with JavaScript Number under assumed64-bit x87 precision."},
   {"0094a698","Static CRT precision request: value10000h under mask30000h maps to x87 precision53 via0094f5b0/0094f57b/0094f658; runtime match-entry state remains unobserved."}
  };
  for(String[] row:comments)currentProgram.getListing().setComment(toAddr(Long.parseLong(row[0],16)),CodeUnit.EOL_COMMENT,row[1]);
  CategoryPath category=new CategoryPath("/CM0102/Recovered");
  Structure slot=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/MatchRosterSlotPartial");
  slot.replaceAtOffset(0xf,ByteDataType.dataType,1,"keeper_counter_raw","Unsigned counter used in postlude bound; semantic label unresolved");
  slot.replaceAtOffset(0x3b,ShortDataType.dataType,2,"keeper_fallback_rating_raw","Signed16 fallback draw bound; source formula unresolved");
  slot.replaceAtOffset(0xd1,FloatDataType.dataType,4,"keeper_adjustment_float_raw","Finite float input to first postlude bound; source formula unresolved");
  Structure match=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/MatchContextPartial");
  match.replaceAtOffset(0x8eaa,SignedByteDataType.dataType,1,"keeper_adjustment_state_raw","Signed8 factor of second postlude bound; enum/source unresolved");
  List<Object>types=new ArrayList<>();
  for(String name:new String[]{"MatchRosterSlotPartial","MatchSideDescriptorPartial","CommentaryEvent14","CommentaryBufferPartial","MatchContextPartial","CommentaryEventDefinition18","CommentaryVariant272","PlayerAttributesPrefixPartial"}){
   Structure s=(Structure)currentProgram.getDataTypeManager().getDataType(category.getPath()+"/"+name);Map<String,Object>row=new LinkedHashMap<>();row.put("path",s.getPathName());row.put("bytes",s.getLength());List<Object>fields=new ArrayList<>();
   for(DataTypeComponent c:s.getDefinedComponents()){Map<String,Object>x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());fields.add(x);}row.put("fields",fields);types.add(row);
  }
  Map<String,Object>root=new LinkedHashMap<>();root.put("sha256",currentProgram.getExecutableSHA256());root.put("annotations",names);root.put("global_labels",labels);root.put("code_comments",comments);root.put("partial_data_types",types);
  root.put("type_application","Four measured postlude fields; no guessed complete prototype or full record layout applied");
  Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(root)+"\n");println("Saved keeper-response and precision annotations");
 }
}
