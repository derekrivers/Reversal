// Saves measured layouts as PARTIAL data types; does not apply guessed prototypes.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.nio.file.*;
import java.io.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class CM0102AnnotateProgression extends GhidraScript {
    CategoryPath category=new CategoryPath("/CM0102/Recovered");
    void field(StructureDataType s,int offset,DataType t,String name,String note){s.replaceAtOffset(offset,t,t.getLength(),name,note);}
    public void run() throws Exception {
        Map<String,Object> receipt=new LinkedHashMap<>();receipt.put("sha256",currentProgram.getExecutableSHA256());
        String[][] labels={
            {"006bd930","cm0102_check_period_boundary","Helper enum 0..4 is distinct from dispatcher statuses. Targets495/990/1155/1320 =45/90/105/120 minutes*11. Normal expiry is strictly clock>target+signed-byte allowance. Rule-bit names and early-stop semantics remain partly unverified."},
            {"006be710","cm0102_advance_tiebreak_sequence","Special phases1/2/3 and4/5/6 are init/attempt/finish triplets, five attempts per side and sudden-death behavior. Ordinary-penalty versus US-style mapping is not yet established."},
            {"006d6f70","cm0102_enqueue_commentary_event","Builds a14-byte event, queues in12-entry ring and copies into capped700-record history. Detailed-mode minute is uint8(trunc(signed16(clock)/11)); nonzero-mode takes low clock byte. Timestamp code slice checked exhaustively across signed16 inputs in modes0/1/255."},
            {"006d1210","cm0102_process_auxiliary_event_candidate","Called when match+8EB4==1 and for selected slot events. Full meaning remains unresolved."},
            {"006b98c0","cm0102_advance_match_candidate","ABI correction: stack work argument and status are bytes. -1 supplies255 charged work units. Some loop paths consume no work unit, so no fixed255-iteration/runtime bound. Return1 yields,2 finalises,4 phase-yields,8 exceptional terminal path."}
        };
        List<Object> annotations=new ArrayList<>();
        for(String[] row:labels){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing "+row[0]);f.setName(row[1],SourceType.USER_DEFINED);
            String note="CM0102 progression investigation 2026-10-18: "+row[2];String old=f.getComment();if(old==null||!old.contains(note))f.setComment((old==null?"":old+"\n\n")+note);
            if(row[0].equals("006b98c0")||row[0].equals("006bd930"))f.setReturnType(UnsignedCharDataType.dataType,SourceType.USER_DEFINED);
            annotations.add(Arrays.asList(row));
        }
        DataType ptr=Pointer32DataType.dataType;
        StructureDataType slot=new StructureDataType(category,"MatchRosterSlotPartial",0x1be);
        field(slot,0x19,SignedByteDataType.dataType,"status_raw","Nonnegative values enter inspected valid-slot paths; enum unresolved");
        field(slot,0x27,ByteDataType.dataType,"side_index","Observed0/1 side selector");
        field(slot,0x69,ptr,"staff_record","Runtime pointer, not saved-file ID");
        field(slot,0x6d,ptr,"player_record_candidate","Pointee layout incomplete");
        field(slot,0x198,ShortDataType.dataType,"action_code_candidate","Observed action comparisons; enum incomplete");
        field(slot,0x19e,DWordDataType.dataType,"activity_word_unknown","Zero can cause slot status to become -5; exact meaning unknown");
        StructureDataType side=new StructureDataType(category,"MatchSideDescriptorPartial",0xd0);
        field(side,0x12,ptr,"match_context","");field(side,0x17,ByteDataType.dataType,"substitute_limit_candidate","Exact meaning unresolved");
        field(side,0x18,ByteDataType.dataType,"side_index","");field(side,0x19,ByteDataType.dataType,"team_kind_selector","");
        field(side,0x1b,ptr,"manager_staff","");field(side,0x1f,ptr,"manager_nonplayer","");field(side,0x23,ptr,"match_roster","");
        field(side,0x27,ptr,"club_squad","");field(side,0x2b,ptr,"side_state_buffer","");field(side,0x2f,ptr,"team","");field(side,0x33,ptr,"opponent","");field(side,0x37,ptr,"fixture","");
        StructureDataType event=new StructureDataType(category,"CommentaryEvent14",14);
        field(event,0,WordDataType.dataType,"event_code","");field(event,2,WordDataType.dataType,"text_variant_index","");
        field(event,4,ByteDataType.dataType,"minute_byte","Detailed mode converts signed clock/11 then truncates to byte");
        field(event,5,ByteDataType.dataType,"player_argument","");field(event,6,ByteDataType.dataType,"side_argument","");
        field(event,7,ByteDataType.dataType,"argument_6","");field(event,8,ByteDataType.dataType,"argument_7","");
        field(event,9,DWordDataType.dataType,"argument_8","");field(event,13,ByteDataType.dataType,"flag_unknown","Initially0xff in inspected enqueue path");
        StructureDataType buffer=new StructureDataType(category,"CommentaryBufferPartial",0x2db1);
        field(buffer,6,ShortDataType.dataType,"history_count","Capped at700 in inspected append path");
        field(buffer,8,ShortDataType.dataType,"ring_write_index","Wraps after11");field(buffer,0xe,ShortDataType.dataType,"ring_read_index_candidate","");
        field(buffer,0x30,new ArrayDataType(event,12,14),"ring_events","");
        field(buffer,0xd8,new ArrayDataType(ByteDataType.dataType,12*0x86,1),"formatted_slot_area_unknown","Observed stride0x86; internal layout unknown");
        field(buffer,0x720,new ArrayDataType(event,700,14),"history_events","");
        field(buffer,0x2d68,IntegerDataType.dataType,"cached_period_target","");
        StructureDataType match=new StructureDataType(category,"MatchContextPartial",0xf63b);
        field(match,0,ByteDataType.dataType,"simulation_mode","");field(match,0x1a8,ByteDataType.dataType,"early_period_stop_candidate","Golden-goal interpretation needs write-site evidence");
        field(match,0x1ca,ByteDataType.dataType,"initial_event_latch","");field(match,0x4792,ptr,"fixture","");
        field(match,0x4796,new ArrayDataType(slot,20,0x1be),"home_roster","");field(match,0x6a6e,new ArrayDataType(slot,20,0x1be),"away_roster","");
        field(match,0x8ea7,ByteDataType.dataType,"coordinate_a_candidate","");field(match,0x8ea8,ByteDataType.dataType,"coordinate_b_candidate","");
        field(match,0x8eae,ByteDataType.dataType,"current_side","");field(match,0x8eb2,ByteDataType.dataType,"play_event_state","");
        field(match,0x8eb3,ByteDataType.dataType,"tiebreak_phase","");field(match,0x8eb4,ByteDataType.dataType,"auxiliary_event_state","");
        field(match,0x8eb6,ByteDataType.dataType,"next_restart_side","");field(match,0x8eb7,SignedByteDataType.dataType,"added_time_units","");
        field(match,0x8eb8,SignedByteDataType.dataType,"active_list_count","");
        field(match,0x8ed0,ShortDataType.dataType,"clock_units","11 units per event minute in detailed mode; not uniform wall-clock ticks");
        field(match,0x8ed2,ShortDataType.dataType,"step_accumulator","");field(match,0x8ed4,ShortDataType.dataType,"period_end_units","495/990/1155/1320 or terminal sentinel0/1");
        field(match,0x8f7a,ptr,"commentary_companion","");field(match,0x8f7e,ptr,"active_list_first_entry","Total capacity not established");
        field(match,0x9032,new ArrayDataType(side,2,0xd0),"side_descriptors","");
        field(match,0xf5bc,ByteDataType.dataType,"home_tiebreak_score","");field(match,0xf5bd,ByteDataType.dataType,"home_match_score","");
        field(match,0xf5f2,ByteDataType.dataType,"away_tiebreak_score","");field(match,0xf5f3,ByteDataType.dataType,"away_match_score","");
        field(match,0xf638,SignedByteDataType.dataType,"exceptional_stop_threshold","-1 disables; exact game-facing meaning unresolved");
        List<Object> types=new ArrayList<>();
        for(DataType data:new DataType[]{slot,side,event,buffer,match}){
            DataType stored=currentProgram.getDataTypeManager().resolve(data,DataTypeConflictHandler.REPLACE_HANDLER);
            Map<String,Object> type=new LinkedHashMap<>();type.put("path",stored.getPathName());type.put("bytes",stored.getLength());
            List<Object> components=new ArrayList<>();for(DataTypeComponent c:((Structure)stored).getDefinedComponents()){
                Map<String,Object> x=new LinkedHashMap<>();x.put("offset",c.getOffset());x.put("name",c.getFieldName());x.put("bytes",c.getLength());x.put("type",c.getDataType().getDisplayName());x.put("comment",c.getComment());components.add(x);
            }type.put("fields",components);types.add(type);
        }
        receipt.put("annotations",annotations);receipt.put("partial_data_types",types);receipt.put("type_application","Saved in data-type manager only; no guessed this-pointer or full prototype applied");
        try(Writer w=Files.newBufferedWriter(Paths.get(getScriptArgs()[0]))){new GsonBuilder().setPrettyPrinting().create().toJson(receipt,w);}
        println("Saved progression annotations and5 partial data types");
    }
}
