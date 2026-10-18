// Adds explicitly provisional research names/comments to the analysis database.
// Original executable bytes are never patched.
// @category CM0102
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;

public class CM0102AnnotateMatch extends GhidraScript {
    public void run() throws Exception {
        String[][] names={
            {"006b7f20","cm0102_prepare_match_candidate","Working lifecycle name. Binds fixture, resets context and builds two side rosters. Return zero is not generally a failure code; caller 006b5260 uses it for a simulation branch. Preserve hidden ECX receiver."},
            {"006b98c0","cm0102_advance_match_candidate","Working lifecycle name. Callers advance until state 2 or 8; exact return-state meanings and clock units remain unverified."},
            {"006db500","cm0102_build_side_descriptor_candidate","Hidden ECX receiver is match+9032 or match+9102 (stride D0). First stack argument is the match context. Returns a roster count; builds side descriptor and roster."},
            {"006bbb60","cm0102_prepare_side_candidate","Two passes over 20 roster slots. Updates a per-side short aggregate at match+1CE+2*side and prepares valid slots. Aggregate semantics unresolved."},
            {"006bbf60","cm0102_assign_opponent_slots_candidate","Working hypothesis based on role-mask filtering and opposite-side slot lookup; exact marking/opponent semantics unresolved."},
            {"00897590","cm0102_find_designated_staff_slot","ECX receiver is global service [DE1D08], not team. Selects 91-byte tactics record, scans 20 staff indices and matches designated staff ID at +52. Captain interpretation remains provisional."},
            {"0090cfc0","cm0102_random_bounded","Observed table-based random helper. Zero bound returns without state consumption. Small branch accepts -65535..65535; larger branch uses x87 scaling and recursion. Narrow TypeScript reconstruction checked against original x86 emulation."},
            {"0090d0a0","cm0102_seed_random","Sets CRT state, derives table cursor and offset, installs table end AD4130. Zero seed calls a time-related helper; exact time source not checked."},
            {"00946a04","cm0102_crt_rand","32-bit state = state*214013+2531011, wraps modulo 2^32. Returns (state>>16)&32767. Instruction-emulation oracle checked 1024 generator steps."},
            {"009469fa","cm0102_crt_srand","Stores supplied 32-bit state at AD6C30."}
        };
        StringBuilder receipt=new StringBuilder("Analysis database annotations; all names are working research labels.\n");
        for(String[] row:names){Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.parseLong(row[0],16)));if(f==null)throw new Exception("Missing function "+row[0]);
            f.setName(row[1],SourceType.USER_DEFINED);
            String comment="CM0102 match investigation 2026-10-18: "+row[2];
            String old=f.getComment();if(old==null||!old.contains(comment))f.setComment((old==null?"":old+"\n\n")+comment);
            receipt.append(row[0]+" "+row[1]+"\n");
        }
        String[][] globals={{"00de1f60","cm0102_rng_cursor"},{"00de2798","cm0102_rng_table_last"},{"00de1f5c","cm0102_rng_offset"},{"00ad6c30","cm0102_crt_state"},{"00aa2454","cm0102_random_table_51000"}};
        for(String[] row:globals)createLabel(toAddr(Long.parseLong(row[0],16)),row[1],true,SourceType.USER_DEFINED);
        Files.writeString(Paths.get(getScriptArgs()[0]),receipt.toString());
        println("Saved research annotations; input SHA-256 "+currentProgram.getExecutableSHA256());
    }
}
